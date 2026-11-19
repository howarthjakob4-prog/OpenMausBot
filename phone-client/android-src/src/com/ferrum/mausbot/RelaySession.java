package com.ferrum.mausbot;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * A live E2E session to the computer through MausBot Relay: the Noise
 * handshake, AEAD records carrying yamux frames, phone-role streams, and the
 * 20 s ping keepalive. Java twin of the RelaySession in tools/relay-lib.mjs.
 */
public final class RelaySession {
    // yamux profile (spec section 7)
    public static final int TYPE_DATA = 0;
    public static final int TYPE_WINDOW = 1;
    public static final int TYPE_PING = 2;
    public static final int TYPE_GOAWAY = 3;
    public static final int FLAG_SYN = 0x1;
    public static final int FLAG_ACK = 0x2;
    public static final int FLAG_FIN = 0x4;
    public static final int FLAG_RST = 0x8;
    static final int INITIAL_WINDOW = 256 * 1024;
    static final int OPEN_DELTA = 2 * 1024 * 1024 - INITIAL_WINDOW;
    static final int MAX_DATA = 65507;

    public interface Listener {
        /** GoAway(3): the computer removed this device. */
        void onRemoved();

        void onClosed(int code);
    }

    private final WsClient ws;
    private final E2e.SessionKeys keys;
    private final Object sendLock = new Object();
    final Map<Integer, MuxStream> streams = new ConcurrentHashMap<>();
    private int highestId = 0;
    volatile boolean closed;
    volatile int closeCode = -1;
    volatile boolean removed;
    private volatile Listener listener;

    private int pingCounter = 0;
    private volatile Integer awaitingPong = null;
    private volatile long pongDeadlineMs = 0;
    private Thread pingThread;

    private RelaySession(WsClient ws, E2e.SessionKeys keys) {
        this.ws = ws;
        this.keys = keys;
    }

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    // ------------------------------------------------------------------
    // Frame codec
    public static final class Frame {
        public int type;
        public int flags;
        public int streamId;
        public int length;
        public byte[] data; // data frames only
    }

    public static byte[] encodeFrame(int type, int flags, int streamId, int length, byte[] data) {
        byte[] payload = type == TYPE_DATA && data != null ? data : new byte[0];
        byte[] out = new byte[12 + payload.length];
        out[0] = 0;
        out[1] = (byte) type;
        out[2] = (byte) (flags >>> 8);
        out[3] = (byte) flags;
        out[4] = (byte) (streamId >>> 24);
        out[5] = (byte) (streamId >>> 16);
        out[6] = (byte) (streamId >>> 8);
        out[7] = (byte) streamId;
        out[8] = (byte) (length >>> 24);
        out[9] = (byte) (length >>> 16);
        out[10] = (byte) (length >>> 8);
        out[11] = (byte) length;
        System.arraycopy(payload, 0, out, 12, payload.length);
        return out;
    }

    public static Frame decodeFrame(byte[] bytes) throws Exception {
        if (bytes.length < 12) throw new Exception("short_frame");
        if (bytes[0] != 0) throw new Exception("version");
        Frame f = new Frame();
        f.type = bytes[1] & 0xff;
        if (f.type > 3) throw new Exception("type");
        f.flags = ((bytes[2] & 0xff) << 8) | (bytes[3] & 0xff);
        if ((f.flags & ~0xf) != 0) throw new Exception("flags");
        f.streamId = ((bytes[4] & 0xff) << 24) | ((bytes[5] & 0xff) << 16)
                | ((bytes[6] & 0xff) << 8) | (bytes[7] & 0xff);
        long len = ((long) (bytes[8] & 0xff) << 24) | ((bytes[9] & 0xff) << 16)
                | ((bytes[10] & 0xff) << 8) | (bytes[11] & 0xff);
        f.length = (int) len;
        if (f.type == TYPE_DATA) {
            if (f.length > MAX_DATA || bytes.length != 12 + f.length) throw new Exception("data_length");
            if (f.streamId == 0) throw new Exception("stream_zero");
            f.data = Arrays.copyOfRange(bytes, 12, bytes.length);
        } else {
            if (bytes.length != 12) throw new Exception("trailing_bytes");
        }
        return f;
    }

    // ------------------------------------------------------------------
    // Dial: relay admission, then the Noise handshake, all blocking.
    private static final class TextMsg {
        final String text;

        TextMsg(String t) {
            text = t;
        }
    }

    private static final class BinaryMsg {
        final byte[] data;

        BinaryMsg(byte[] d) {
            data = d;
        }
    }

    private static final class CloseMsg {
        final int code;

        CloseMsg(int c) {
            code = c;
        }
    }

    public static RelaySession dial(String relayHost, byte[] remoteStatic, byte[] psk,
                                    String app, byte[] hostId, byte[] adm) throws Exception {
        final BlockingQueue<Object> inbox = new LinkedBlockingQueue<>();
        final RelaySession[] liveRef = new RelaySession[1];
        WsClient ws = WsClient.connect(relayHost, "/v1/phone", "omb-relay.v1", new WsClient.Listener() {
            @Override
            public void onText(String text) {
                RelaySession s = liveRef[0];
                if (s == null) inbox.offer(new TextMsg(text));
                else s.close(4000); // no text after the handshake
            }

            @Override
            public void onBinary(byte[] data) {
                RelaySession s = liveRef[0];
                if (s == null) inbox.offer(new BinaryMsg(data));
                else s.receiveRecord(data);
            }

            @Override
            public void onClose(int code) {
                RelaySession s = liveRef[0];
                if (s == null) inbox.offer(new CloseMsg(code));
                else s.transportClosed(code);
            }
        });
        try {
            long deadline = System.currentTimeMillis() + 25000;
            String auth = "{\"t\":\"phone\",\"v\":1,\"hid\":\"" + E2e.b64u(hostId)
                    + "\",\"adm\":\"" + E2e.b64u(adm) + "\"}";
            ws.sendText(auth);
            Object first = take(inbox, deadline);
            if (first instanceof CloseMsg) {
                throw new Exception("relay closed the connection (" + ((CloseMsg) first).code + ")");
            }
            if (!(first instanceof TextMsg) || !isReady(((TextMsg) first).text)) {
                throw new Exception("expected relay ready");
            }
            byte[] conn = E2e.randomBytes(16);
            String connText = E2e.b64u(conn);
            E2e.PhoneHello hello = E2e.phoneHello(remoteStatic, psk, E2e.TRANSPORT_RELAY,
                    null, E2e.encodePayload1(conn, app), connText);
            ws.sendBinary(hello.message1);
            Object second = take(inbox, deadline);
            if (second instanceof CloseMsg) {
                throw new Exception("socket closed during handshake (" + ((CloseMsg) second).code + ")");
            }
            if (!(second instanceof BinaryMsg)) throw new Exception("expected binary message 2");
            E2e.SessionKeys keys = hello.finish(((BinaryMsg) second).data);
            RelaySession session = new RelaySession(ws, keys);
            liveRef[0] = session;
            session.startPing();
            return session;
        } catch (Exception e) {
            try {
                ws.close(1000);
            } catch (Exception ignored) {
            }
            throw e;
        }
    }

    private static Object take(BlockingQueue<Object> inbox, long deadlineMs) throws Exception {
        long wait = deadlineMs - System.currentTimeMillis();
        if (wait <= 0) throw new Exception("handshake deadline");
        Object item = inbox.poll(wait, TimeUnit.MILLISECONDS);
        if (item == null) throw new Exception("handshake deadline");
        return item;
    }

    private static boolean isReady(String text) {
        return text != null && text.contains("\"t\":\"ready\"");
    }

    // ------------------------------------------------------------------
    // Session machinery
    private void startPing() {
        pingThread = new Thread(() -> {
            long lastPingAt = System.currentTimeMillis();
            while (!closed) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    return;
                }
                if (closed) return;
                long now = System.currentTimeMillis();
                if (awaitingPong != null && now > pongDeadlineMs) {
                    close(1001);
                    return;
                }
                if (awaitingPong == null && now - lastPingAt >= 20000) {
                    pingCounter = (pingCounter + 1) & 0xffffffff;
                    awaitingPong = pingCounter;
                    pongDeadlineMs = now + 10000;
                    lastPingAt = now;
                    sendFrame(TYPE_PING, FLAG_SYN, 0, pingCounter, null);
                }
            }
        }, "relay-ping");
        pingThread.setDaemon(true);
        pingThread.start();
    }

    void sendFrame(int type, int flags, int streamId, int length, byte[] data) {
        if (closed) return;
        byte[] record;
        try {
            synchronized (sendLock) {
                record = keys.send.seal(encodeFrame(type, flags, streamId, length, data));
            }
        } catch (Exception e) {
            close(4000);
            return;
        }
        try {
            ws.sendBinary(record);
        } catch (IOException e) {
            transportClosed(1006);
        }
    }

    void receiveRecord(byte[] record) {
        byte[] plaintext;
        try {
            synchronized (sendLock) {
                // receive cipher is independent of send, but keep both under
                // the one lock: records are cheap and order is everything.
                plaintext = keys.receive.open(record);
            }
        } catch (Exception e) {
            close(4000);
            return;
        }
        Frame frame;
        try {
            frame = decodeFrame(plaintext);
        } catch (Exception e) {
            close(4000);
            return;
        }
        receiveFrame(frame);
    }

    private void receiveFrame(Frame frame) {
        if (frame.type == TYPE_PING) {
            if (frame.flags == FLAG_SYN) {
                sendFrame(TYPE_PING, FLAG_ACK, 0, frame.length, null);
            } else if (awaitingPong != null && frame.length == awaitingPong) {
                awaitingPong = null;
            }
            return;
        }
        if (frame.type == TYPE_GOAWAY) {
            if (frame.length == 3) {
                removed = true;
                Listener l = listener;
                if (l != null) l.onRemoved();
            } else if (frame.length != 0) {
                close(4000);
            }
            return;
        }
        MuxStream stream = streams.get(frame.streamId);
        if ((frame.flags & FLAG_ACK) != 0) {
            if (stream == null) return;
            stream.markEstablished();
            if (frame.type == TYPE_WINDOW && frame.length > 0) stream.addWindow(frame.length);
            if ((frame.flags & FLAG_FIN) != 0) stream.remoteEnded();
            return;
        }
        if (stream == null) return;
        if ((frame.flags & FLAG_RST) != 0) {
            stream.interrupt();
            streams.remove(frame.streamId);
            return;
        }
        if (frame.type == TYPE_DATA) {
            if (frame.length > stream.receiveWindow()) {
                close(4000);
                return;
            }
            stream.deliver(frame.data);
            if ((frame.flags & FLAG_FIN) != 0) stream.remoteEnded();
        } else if (frame.type == TYPE_WINDOW) {
            if (frame.length > 0) stream.addWindow(frame.length);
            if ((frame.flags & FLAG_FIN) != 0) stream.remoteEnded();
        }
    }

    public MuxStream openStream() throws IOException {
        if (closed) throw new IOException("session closed");
        int id = highestId == 0 ? 1 : highestId + 2;
        highestId = id;
        MuxStream stream = new MuxStream(this, id);
        streams.put(id, stream);
        sendFrame(TYPE_WINDOW, FLAG_SYN, id, OPEN_DELTA, null);
        return stream;
    }

    void streamFinished(MuxStream stream) {
        streams.remove(stream.id);
    }

    public void close(int code) {
        if (closed) return;
        closed = true;
        closeCode = code;
        try {
            ws.close(code);
        } catch (Exception ignored) {
        }
        teardown();
    }

    void transportClosed(int code) {
        if (closed) return;
        closed = true;
        closeCode = code;
        teardown();
    }

    private void teardown() {
        for (MuxStream stream : streams.values()) stream.interrupt();
        Listener l = listener;
        if (l != null) l.onClosed(closeCode);
    }

    public boolean isClosed() {
        return closed;
    }

    // ------------------------------------------------------------------
    // One mux stream. Blocking read/write for the proxy and HTTP helper.
    public static final class MuxStream {
        final RelaySession session;
        final int id;
        private int sendWindow = INITIAL_WINDOW;
        private int receiveWindow = INITIAL_WINDOW + OPEN_DELTA;
        private int uncredited = 0;
        private boolean established = false;
        private boolean localFin = false;
        private boolean remoteFin = false;
        private boolean reset = false;
        private final List<byte[]> readBuffer = new ArrayList<>();
        private int buffered = 0;

        MuxStream(RelaySession session, int id) {
            this.session = session;
            this.id = id;
        }

        synchronized int receiveWindow() {
            return receiveWindow;
        }

        synchronized void markEstablished() {
            established = true;
            notifyAll();
        }

        synchronized void addWindow(int delta) {
            sendWindow += delta;
            notifyAll();
        }

        synchronized void deliver(byte[] data) {
            receiveWindow -= data.length;
            if (data.length > 0) {
                readBuffer.add(data);
                buffered += data.length;
            }
            notifyAll();
        }

        synchronized void remoteEnded() {
            remoteFin = true;
            notifyAll();
        }

        synchronized void interrupt() {
            reset = true;
            notifyAll();
        }

        public void write(byte[] data) throws IOException {
            write(data, 0, data.length);
        }

        public void write(byte[] data, int off, int len) throws IOException {
            int pos = off;
            int remaining = len;
            while (remaining > 0) {
                int size;
                synchronized (this) {
                    while (sendWindow == 0 && !reset && !session.closed) {
                        try {
                            wait(5000);
                        } catch (InterruptedException e) {
                            throw new IOException("interrupted");
                        }
                    }
                    if (reset) throw new IOException("stream reset");
                    if (session.closed) throw new IOException("session closed");
                    size = Math.min(remaining, Math.min(sendWindow, MAX_DATA));
                    if (size == 0) continue;
                    sendWindow -= size;
                }
                session.sendFrame(TYPE_DATA, 0, id, size,
                        Arrays.copyOfRange(data, pos, pos + size));
                pos += size;
                remaining -= size;
            }
        }

        /** Blocks until at least one byte, EOF (-1), or reset. */
        public int read(byte[] buf, int off, int len) throws IOException {
            int grant = 0;
            int take;
            synchronized (this) {
                while (buffered == 0 && !remoteFin && !reset && !session.closed) {
                    try {
                        wait(5000);
                    } catch (InterruptedException e) {
                        throw new IOException("interrupted");
                    }
                }
                if (buffered == 0) return -1;
                take = Math.min(len, buffered);
                int written = 0;
                while (written < take) {
                    byte[] head = readBuffer.get(0);
                    int need = take - written;
                    if (head.length <= need) {
                        System.arraycopy(head, 0, buf, off + written, head.length);
                        written += head.length;
                        readBuffer.remove(0);
                    } else {
                        System.arraycopy(head, 0, buf, off + written, need);
                        readBuffer.set(0, Arrays.copyOfRange(head, need, head.length));
                        written += need;
                    }
                }
                buffered -= take;
                uncredited += take;
                if (uncredited >= 1024 * 1024 && !remoteFin) {
                    grant = uncredited;
                    uncredited = 0;
                    receiveWindow += grant;
                }
            }
            if (grant > 0) session.sendFrame(TYPE_WINDOW, 0, id, grant, null);
            return take;
        }

        public void end() {
            synchronized (this) {
                if (localFin) return;
                localFin = true;
            }
            session.sendFrame(TYPE_WINDOW, FLAG_FIN, id, 0, null);
        }
    }

    // ------------------------------------------------------------------
    // Minimal HTTP/1.1 over one stream (pairing + health checks).
    public static final class HttpResponse {
        public int status;
        public Map<String, String> headers = new LinkedHashMap<>();
        public byte[] body;
    }

    public HttpResponse httpRequest(String method, String path, Map<String, String> headers,
                                    byte[] body, int timeoutMs) throws Exception {
        MuxStream stream = openStream();
        StringBuilder head = new StringBuilder();
        head.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        head.append("Host: e2e.invalid\r\n");
        head.append("Connection: close\r\n");
        Map<String, String> all = new LinkedHashMap<>();
        if (headers != null) all.putAll(headers);
        if (body != null) all.put("Content-Length", String.valueOf(body.length));
        for (Map.Entry<String, String> e : all.entrySet()) {
            head.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
        }
        head.append("\r\n");
        Thread watchdog = new Thread(() -> {
            try {
                Thread.sleep(timeoutMs);
            } catch (InterruptedException ignored) {
                return;
            }
            stream.interrupt();
        }, "http-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        try {
            byte[] headBytes = head.toString().getBytes(StandardCharsets.UTF_8);
            if (body != null) {
                byte[] both = new byte[headBytes.length + body.length];
                System.arraycopy(headBytes, 0, both, 0, headBytes.length);
                System.arraycopy(body, 0, both, headBytes.length, body.length);
                stream.write(both);
            } else {
                stream.write(headBytes);
            }
            // No FIN after the request: the computer side drops a request whose
            // FIN lands before its origin pipe is up (seen live with the JS
            // reference). Content-Length frames the request; the server's
            // "Connection: close" ends the response.
            StreamReader reader = new StreamReader(stream);
            return readResponse(reader);
        } finally {
            watchdog.interrupt();
            try {
                stream.end();
            } catch (Exception ignored) {
            }
            streamFinished(stream);
        }
    }

    private static final class StreamReader {
        private final MuxStream stream;
        private byte[] buf = new byte[0];
        private int pos = 0;
        private boolean eof = false;

        StreamReader(MuxStream stream) {
            this.stream = stream;
        }

        private void fill() throws IOException {
            if (eof) return;
            byte[] chunk = new byte[16384];
            int n = stream.read(chunk, 0, chunk.length);
            if (n < 0) {
                eof = true;
                return;
            }
            if (pos > 0) {
                buf = Arrays.copyOfRange(buf, pos, buf.length);
                pos = 0;
            }
            byte[] grown = new byte[buf.length + n];
            System.arraycopy(buf, 0, grown, 0, buf.length);
            System.arraycopy(chunk, 0, grown, buf.length, n);
            buf = grown;
        }

        int available() {
            return buf.length - pos;
        }

        /** Read until the delimiter (consumed), or EOF. Null if EOF with nothing. */
        byte[] readUntil(String delim) throws IOException {
            byte[] d = delim.getBytes(StandardCharsets.US_ASCII);
            for (;;) {
                int idx = indexOf(buf, pos, d);
                if (idx >= 0) {
                    byte[] out = Arrays.copyOfRange(buf, pos, idx);
                    pos = idx + d.length;
                    return out;
                }
                if (eof) {
                    if (available() == 0) return null;
                    byte[] out = Arrays.copyOfRange(buf, pos, buf.length);
                    pos = buf.length;
                    return out;
                }
                fill();
            }
        }

        byte[] readN(int n) throws IOException {
            while (available() < n && !eof) fill();
            int take = Math.min(n, available());
            byte[] out = Arrays.copyOfRange(buf, pos, pos + take);
            pos += take;
            return out;
        }

        byte[] readAll() throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (;;) {
                if (available() > 0) {
                    out.write(buf, pos, available());
                    pos = buf.length;
                }
                if (eof) break;
                fill();
            }
            return out.toByteArray();
        }

        private static int indexOf(byte[] hay, int from, byte[] needle) {
            outer:
            for (int i = from; i + needle.length <= hay.length; i++) {
                for (int j = 0; j < needle.length; j++) {
                    if (hay[i + j] != needle[j]) continue outer;
                }
                return i;
            }
            return -1;
        }
    }

    private HttpResponse readResponse(StreamReader reader) throws Exception {
        byte[] headBytes = reader.readUntil("\r\n\r\n");
        if (headBytes == null) throw new IOException("stream closed before response head");
        String headText = new String(headBytes, StandardCharsets.UTF_8);
        String[] lines = headText.split("\r\n");
        HttpResponse res = new HttpResponse();
        res.status = Integer.parseInt(lines[0].split(" ")[1]);
        for (int i = 1; i < lines.length; i++) {
            int idx = lines[i].indexOf(':');
            if (idx > 0) {
                res.headers.put(lines[i].substring(0, idx).trim().toLowerCase(),
                        lines[i].substring(idx + 1).trim());
            }
        }
        String te = res.headers.get("transfer-encoding");
        String cl = res.headers.get("content-length");
        if (te != null && te.contains("chunked")) {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            for (;;) {
                byte[] sizeLine = reader.readUntil("\r\n");
                if (sizeLine == null) throw new IOException("stream closed inside chunked body");
                String sizeText = new String(sizeLine, StandardCharsets.US_ASCII).split(";")[0].trim();
                int size = Integer.parseInt(sizeText, 16);
                if (size == 0) {
                    // trailer part runs to the blank line / EOF; body is complete
                    reader.readUntil("\r\n");
                    break;
                }
                byte[] chunk = reader.readN(size);
                if (chunk.length < size) throw new IOException("stream closed inside chunk");
                body.write(chunk);
                reader.readN(2); // trailing CRLF
            }
            res.body = body.toByteArray();
        } else if (cl != null) {
            res.body = reader.readN(Integer.parseInt(cl.trim()));
        } else {
            res.body = reader.readAll();
        }
        return res;
    }
}
