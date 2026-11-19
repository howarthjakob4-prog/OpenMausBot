package com.ferrum.mausbot;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * A minimal WebSocket client over TLS (RFC 6455), just what the relay dial
 * needs: one subprotocol, binary + text messages, client masking, ping/pong,
 * close. Messages are delivered whole (fragmentation reassembled) to the
 * listener on the reader thread.
 */
public final class WsClient {
    public interface Listener {
        void onText(String text);

        void onBinary(byte[] data);

        void onClose(int code);
    }

    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private final Listener listener;
    private final SecureRandom rng = new SecureRandom();
    private SSLSocket socket;
    private Socket plainSocket; // harness bridge mode only
    private InputStream in;
    private OutputStream out;
    private final Object writeLock = new Object();
    private volatile boolean closed;
    private boolean closeNotified;

    private WsClient(Listener listener) {
        this.listener = listener;
    }

    public static WsClient connect(String host, String path, String subprotocol,
                                   Listener listener) throws Exception {
        WsClient client = new WsClient(listener);
        client.open(host, path, subprotocol);
        return client;
    }

    private void open(String host, String path, String subprotocol) throws Exception {
        // Desktop-harness only: maus.wsPlainPort points the client at a local
        // plaintext bridge (tools/java-test/ws-bridge.mjs) because this VM's
        // egress gate denies raw TCP from a JVM. The phone never sets it.
        String plainPort = System.getProperty("maus.wsPlainPort");
        if (plainPort != null && !plainPort.isEmpty()) {
            plainSocket = new Socket("127.0.0.1", Integer.parseInt(plainPort));
            plainSocket.setSoTimeout(30000);
            in = plainSocket.getInputStream();
            out = plainSocket.getOutputStream();
            handshake(host, path, subprotocol);
            plainSocket.setSoTimeout(0);
            return;
        }
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        // Optional HTTP CONNECT proxy (system property maus.proxy, a URL like
        // http://user:pass@host:port). The phone never sets it — direct TLS is
        // the normal path; the desktop JVM harness runs behind a proxy.
        String proxy = System.getProperty("maus.proxy");
        if (proxy != null && !proxy.isEmpty()) {
            URI uri = new URI(proxy);
            Socket plain = new Socket(uri.getHost(), uri.getPort());
            plain.setSoTimeout(30000);
            OutputStream pout = plain.getOutputStream();
            InputStream pin = plain.getInputStream();
            StringBuilder connect = new StringBuilder();
            connect.append("CONNECT ").append(host).append(":443 HTTP/1.1\r\n");
            connect.append("Host: ").append(host).append(":443\r\n");
            if (uri.getUserInfo() != null) {
                connect.append("Proxy-Authorization: Basic ").append(Base64.getEncoder()
                        .encodeToString(uri.getUserInfo().getBytes(StandardCharsets.UTF_8))).append("\r\n");
            }
            connect.append("\r\n");
            pout.write(connect.toString().getBytes(StandardCharsets.US_ASCII));
            pout.flush();
            String head = readHeadFrom(pin);
            if (!head.startsWith("HTTP/1.1 200") && !head.startsWith("HTTP/1.0 200")) {
                plain.close();
                throw new IOException("proxy CONNECT refused: " + head.split("\r\n")[0]);
            }
            socket = (SSLSocket) factory.createSocket(plain, host, 443, true);
        } else {
            socket = (SSLSocket) factory.createSocket(host, 443);
        }
        socket.setSoTimeout(30000);
        socket.startHandshake();
        in = socket.getInputStream();
        out = socket.getOutputStream();
        handshake(host, path, subprotocol);
        socket.setSoTimeout(0);
    }

    private void handshake(String host, String path, String subprotocol) throws Exception {
        byte[] keyBytes = new byte[16];
        rng.nextBytes(keyBytes);
        String key = Base64.getEncoder().encodeToString(keyBytes);
        String request = "GET " + path + " HTTP/1.1\r\n"
                + "Host: " + host + "\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Key: " + key + "\r\n"
                + "Sec-WebSocket-Version: 13\r\n"
                + "Sec-WebSocket-Protocol: " + subprotocol + "\r\n"
                + "\r\n";
        out.write(request.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        String head = readHead();
        if (!head.startsWith("HTTP/1.1 101")) {
            throw new IOException("websocket upgrade refused: " + head.split("\r\n")[0]);
        }
        String expected = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1")
                .digest((key + GUID).getBytes(StandardCharsets.US_ASCII)));
        if (!head.contains(expected)) throw new IOException("websocket accept mismatch");

        Thread reader = new Thread(this::readLoop, "ws-reader");
        reader.setDaemon(true);
        reader.start();
    }

    private String readHead() throws IOException {
        return readHeadFrom(in);
    }

    private static String readHeadFrom(InputStream stream) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int matched = 0;
        byte[] terminator = {'\r', '\n', '\r', '\n'};
        while (matched < 4) {
            int b = stream.read();
            if (b < 0) throw new EOFException("socket closed during upgrade");
            buf.write(b);
            matched = (b == terminator[matched]) ? matched + 1 : (b == '\r' ? 1 : 0);
            if (buf.size() > 16384) throw new IOException("upgrade head too large");
        }
        return buf.toString(StandardCharsets.US_ASCII);
    }

    private void readLoop() {
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        int messageOpcode = -1;
        try {
            for (;;) {
                int b0 = in.read();
                if (b0 < 0) break;
                int b1 = in.read();
                if (b1 < 0) break;
                boolean fin = (b0 & 0x80) != 0;
                int opcode = b0 & 0x0f;
                boolean masked = (b1 & 0x80) != 0;
                long len = b1 & 0x7f;
                if (len == 126) len = readU16();
                else if (len == 127) len = readU64();
                if (len > 16 * 1024 * 1024) throw new IOException("frame too large");
                byte[] mask = masked ? readN(4) : null;
                byte[] payload = readN((int) len);
                if (mask != null) {
                    for (int i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
                }
                switch (opcode) {
                    case 0: // continuation
                        message.write(payload);
                        if (fin) {
                            deliver(messageOpcode, message.toByteArray());
                            message.reset();
                            messageOpcode = -1;
                        }
                        break;
                    case 1:
                    case 2:
                        if (fin) {
                            deliver(opcode, payload);
                        } else {
                            messageOpcode = opcode;
                            message.write(payload);
                        }
                        break;
                    case 8: { // close
                        int code = payload.length >= 2
                                ? ((payload[0] & 0xff) << 8) | (payload[1] & 0xff) : 1005;
                        notifyClose(code);
                        closeSocket();
                        return;
                    }
                    case 9: // ping -> pong
                        sendFrame(0xA, payload);
                        break;
                    case 10: // pong: ignore
                        break;
                    default:
                        throw new IOException("bad opcode " + opcode);
                }
            }
        } catch (IOException ignored) {
            // fall through to close notification
        }
        notifyClose(1006);
    }

    private void deliver(int opcode, byte[] payload) {
        if (opcode == 1) listener.onText(new String(payload, StandardCharsets.UTF_8));
        else if (opcode == 2) listener.onBinary(payload);
    }

    private synchronized void notifyClose(int code) {
        if (closeNotified) return;
        closeNotified = true;
        closed = true;
        listener.onClose(code);
    }

    private int readU16() throws IOException {
        byte[] b = readN(2);
        return ((b[0] & 0xff) << 8) | (b[1] & 0xff);
    }

    private long readU64() throws IOException {
        byte[] b = readN(8);
        long v = 0;
        for (byte x : b) v = (v << 8) | (x & 0xff);
        return v;
    }

    private byte[] readN(int n) throws IOException {
        byte[] buf = new byte[n];
        int got = 0;
        while (got < n) {
            int r = in.read(buf, got, n - got);
            if (r < 0) throw new EOFException("socket closed mid-frame");
            got += r;
        }
        return buf;
    }

    public void sendText(String text) throws IOException {
        sendFrame(0x1, text.getBytes(StandardCharsets.UTF_8));
    }

    public void sendBinary(byte[] data) throws IOException {
        sendFrame(0x2, data);
    }

    private void sendFrame(int opcode, byte[] payload) throws IOException {
        synchronized (writeLock) {
            if (closed) throw new IOException("websocket closed");
            byte[] mask = new byte[4];
            rng.nextBytes(mask);
            ByteArrayOutputStream frame = new ByteArrayOutputStream();
            frame.write(0x80 | opcode);
            int len = payload.length;
            if (len < 126) {
                frame.write(0x80 | len);
            } else if (len <= 0xffff) {
                frame.write(0x80 | 126);
                frame.write((len >>> 8) & 0xff);
                frame.write(len & 0xff);
            } else {
                frame.write(0x80 | 127);
                for (int i = 7; i >= 0; i--) frame.write((int) (len >>> (8 * i)) & 0xff);
            }
            frame.write(mask);
            byte[] masked = new byte[len];
            for (int i = 0; i < len; i++) masked[i] = (byte) (payload[i] ^ mask[i % 4]);
            frame.write(masked);
            out.write(frame.toByteArray());
            out.flush();
        }
    }

    public void close(int code) {
        if (closed) {
            closeSocket();
            return;
        }
        closed = true;
        try {
            byte[] payload = {(byte) (code >>> 8), (byte) code};
            sendFrameRaw(0x8, payload);
        } catch (IOException ignored) {
        }
        closeSocket();
        notifyClose(code);
    }

    private void sendFrameRaw(int opcode, byte[] payload) throws IOException {
        synchronized (writeLock) {
            byte[] mask = new byte[4];
            rng.nextBytes(mask);
            ByteArrayOutputStream frame = new ByteArrayOutputStream();
            frame.write(0x80 | opcode);
            frame.write(0x80 | payload.length);
            frame.write(mask);
            for (int i = 0; i < payload.length; i++) frame.write(payload[i] ^ mask[i % 4]);
            out.write(frame.toByteArray());
            out.flush();
        }
    }

    private void closeSocket() {
        try {
            if (socket != null) socket.close();
        } catch (IOException ignored) {
        }
        try {
            if (plainSocket != null) plainSocket.close();
        } catch (IOException ignored) {
        }
    }

    public boolean isClosed() {
        return closed;
    }
}
