package com.ferrum.mausbot;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * The in-app bridge between the WebView and the E2E session: a tiny HTTP
 * proxy on 127.0.0.1. Each browser connection becomes one yamux stream to the
 * computer's companion origin. The proxy rewrites every request head to add
 * the device Authorization (the companion authenticates per request), then
 * pipes raw bytes both ways.
 *
 * Loopback safety: the first request on the app must carry a per-launch
 * secret path prefix. Later requests are only given the Authorization header
 * when they carry the secret prefix or a Referer from inside our own pages —
 * a random other app on the phone can reach the port but cannot ride the
 * device token.
 */
public final class LocalProxy {
    private final RelaySession session;
    private final String deviceToken;
    private final String secret;
    private ServerSocket server;
    private Thread acceptThread;
    private volatile boolean running;
    private int port = -1;

    public LocalProxy(RelaySession session, String deviceToken, String secret) {
        this.session = session;
        this.deviceToken = deviceToken;
        this.secret = secret;
    }

    public int start() throws IOException {
        server = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        port = server.getLocalPort();
        running = true;
        acceptThread = new Thread(() -> {
            while (running) {
                try {
                    Socket client = server.accept();
                    Thread t = new Thread(() -> handle(client), "proxy-conn");
                    t.setDaemon(true);
                    t.start();
                } catch (IOException e) {
                    if (running) {
                        // transient accept failure; keep serving
                        try {
                            Thread.sleep(50);
                        } catch (InterruptedException ignored) {
                            return;
                        }
                    }
                }
            }
        }, "proxy-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        return port;
    }

    public int port() {
        return port;
    }

    public String secret() {
        return secret;
    }

    public void stop() {
        running = false;
        try {
            if (server != null) server.close();
        } catch (IOException ignored) {
        }
    }

    private void handle(Socket client) {
        RelaySession.MuxStream stream = null;
        try {
            client.setTcpNoDelay(true);
            InputStream cin = client.getInputStream();
            OutputStream cout = client.getOutputStream();
            stream = session.openStream();
            final RelaySession.MuxStream upstream = stream;

            // server -> browser: raw pipe
            Thread down = new Thread(() -> {
                byte[] buf = new byte[16384];
                try {
                    int n;
                    while ((n = upstream.read(buf, 0, buf.length)) >= 0) {
                        cout.write(buf, 0, n);
                        cout.flush();
                    }
                } catch (IOException ignored) {
                }
                try {
                    client.shutdownOutput();
                } catch (IOException ignored) {
                }
            }, "proxy-down");
            down.setDaemon(true);
            down.start();

            // browser -> server: request-aware pipe (injects Authorization)
            new RequestPipe(cin, upstream).run();
        } catch (IOException e) {
            // stream or client went away; teardown below
        } finally {
            if (stream != null) {
                try {
                    stream.end();
                } catch (Exception ignored) {
                }
                session.streamFinished(stream);
            }
            try {
                client.close();
            } catch (IOException ignored) {
            }
        }
    }

    /** Forwards browser requests to the stream, rewriting each head. */
    private final class RequestPipe {
        private final InputStream in;
        private final RelaySession.MuxStream stream;
        private byte[] pending = new byte[0];
        private int pendingPos = 0;
        private boolean eof = false;

        RequestPipe(InputStream in, RelaySession.MuxStream stream) {
            this.in = in;
            this.stream = stream;
        }

        void run() throws IOException {
            boolean raw = false;
            while (!eof) {
                if (raw) {
                    pipeRaw();
                    return;
                }
                byte[] head = readHead();
                if (head == null) return; // clean close between requests
                HeadInfo info = parseHead(head);
                byte[] rewritten = rewriteHead(info);
                stream.write(rewritten);
                if (info.upgrade) {
                    raw = true;
                    // any bytes already buffered past the head go raw too
                    flushPending();
                    continue;
                }
                if (info.chunked) {
                    forwardChunked();
                } else if (info.contentLength > 0) {
                    forwardN(info.contentLength);
                }
            }
        }

        private void pipeRaw() throws IOException {
            flushPending();
            byte[] buf = new byte[16384];
            int n;
            while ((n = readSome(buf, 0, buf.length)) >= 0) {
                stream.write(buf, 0, n);
            }
        }

        private void flushPending() throws IOException {
            if (pendingPos < pending.length) {
                stream.write(pending, pendingPos, pending.length - pendingPos);
                pendingPos = pending.length;
            }
        }

        /** Next bytes from the browser, buffered first. -1 at EOF. */
        private int readSome(byte[] buf, int off, int len) throws IOException {
            if (pendingPos < pending.length) {
                int take = Math.min(len, pending.length - pendingPos);
                System.arraycopy(pending, pendingPos, buf, off, take);
                pendingPos += take;
                return take;
            }
            if (eof) return -1;
            int n = in.read(buf, off, len);
            if (n < 0) eof = true;
            return n;
        }

        private void fill() throws IOException {
            if (eof) return;
            byte[] chunk = new byte[16384];
            int n = in.read(chunk, 0, chunk.length);
            if (n < 0) {
                eof = true;
                return;
            }
            if (pendingPos > 0) {
                pending = java.util.Arrays.copyOfRange(pending, pendingPos, pending.length);
                pendingPos = 0;
            }
            byte[] grown = new byte[pending.length + n];
            System.arraycopy(pending, 0, grown, 0, pending.length);
            System.arraycopy(chunk, 0, grown, pending.length, n);
            pending = grown;
        }

        private byte[] readHead() throws IOException {
            for (;;) {
                int idx = indexOfCrlfCrlf();
                if (idx >= 0) {
                    byte[] head = java.util.Arrays.copyOfRange(pending, pendingPos, idx + 4);
                    pendingPos = idx + 4;
                    return head;
                }
                if (eof) {
                    if (pendingPos >= pending.length) return null;
                    // partial head at EOF: forward what exists
                    byte[] head = java.util.Arrays.copyOfRange(pending, pendingPos, pending.length);
                    pendingPos = pending.length;
                    return head;
                }
                if (pending.length - pendingPos > 65536) throw new IOException("request head too large");
                fill();
            }
        }

        private int indexOfCrlfCrlf() {
            for (int i = pendingPos; i + 3 < pending.length; i++) {
                if (pending[i] == '\r' && pending[i + 1] == '\n'
                        && pending[i + 2] == '\r' && pending[i + 3] == '\n') return i;
            }
            return -1;
        }

        private void forwardN(long n) throws IOException {
            byte[] buf = new byte[16384];
            long left = n;
            while (left > 0) {
                int take = (int) Math.min(buf.length, left);
                int got = readSome(buf, 0, take);
                if (got < 0) return;
                stream.write(buf, 0, got);
                left -= got;
            }
        }

        private void forwardChunked() throws IOException {
            for (;;) {
                byte[] line = readLine();
                if (line == null) return;
                String text = new String(line, StandardCharsets.US_ASCII).trim();
                stream.write(line);
                int semi = text.indexOf(';');
                int size = Integer.parseInt(semi >= 0 ? text.substring(0, semi) : text, 16);
                if (size == 0) {
                    // trailer lines until a blank line
                    for (;;) {
                        byte[] trailer = readLine();
                        if (trailer == null) return;
                        stream.write(trailer);
                        if (trailer.length <= 2) return;
                    }
                }
                forwardN(size);
                forwardN(2); // trailing CRLF after each chunk
            }
        }

        private byte[] readLine() throws IOException {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            int prev = -1;
            byte[] one = new byte[1];
            for (;;) {
                int got = readSome(one, 0, 1);
                if (got < 0) return line.size() == 0 ? null : line.toByteArray();
                line.write(one[0]);
                if (prev == '\r' && one[0] == '\n') return line.toByteArray();
                prev = one[0];
                if (line.size() > 8192) throw new IOException("chunk line too long");
            }
        }

        private HeadInfo parseHead(byte[] head) {
            String text = new String(head, StandardCharsets.ISO_8859_1);
            String[] lines = text.split("\r\n");
            HeadInfo info = new HeadInfo();
            info.raw = head;
            info.requestLine = lines.length > 0 ? lines[0] : "";
            String[] parts = info.requestLine.split(" ");
            info.method = parts.length > 0 ? parts[0] : "";
            info.path = parts.length > 1 ? parts[1] : "/";
            info.version = parts.length > 2 ? parts[2] : "HTTP/1.1";
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];
                int colon = line.indexOf(':');
                if (colon < 0) continue;
                String name = line.substring(0, colon).trim().toLowerCase(Locale.US);
                String value = line.substring(colon + 1).trim();
                if (name.equals("content-length")) {
                    try {
                        info.contentLength = Long.parseLong(value);
                    } catch (NumberFormatException ignored) {
                    }
                } else if (name.equals("transfer-encoding") && value.toLowerCase(Locale.US).contains("chunked")) {
                    info.chunked = true;
                } else if (name.equals("authorization")) {
                    info.hasAuth = true;
                } else if (name.equals("upgrade")) {
                    info.upgrade = true;
                } else if (name.equals("referer")) {
                    info.referer = value;
                }
            }
            return info;
        }

        private byte[] rewriteHead(HeadInfo info) {
            String path = info.path;
            boolean trusted = false;
            String prefix = "/" + secret;
            if (path.equals(prefix)) {
                path = "/";
                trusted = true;
            } else if (path.startsWith(prefix + "/")) {
                path = path.substring(prefix.length());
                trusted = true;
            } else if (info.referer != null && port > 0
                    && info.referer.startsWith("http://127.0.0.1:" + port + prefix)) {
                trusted = true;
            }
            StringBuilder out = new StringBuilder();
            out.append(info.method).append(' ').append(path).append(' ').append(info.version).append("\r\n");
            String text = new String(info.raw, StandardCharsets.ISO_8859_1);
            String[] lines = text.split("\r\n");
            for (int i = 1; i < lines.length; i++) {
                if (lines[i].isEmpty()) continue;
                out.append(lines[i]).append("\r\n");
            }
            if (trusted && !info.hasAuth) {
                out.append("Authorization: Bearer ").append(deviceToken).append("\r\n");
            }
            out.append("\r\n");
            return out.toString().getBytes(StandardCharsets.ISO_8859_1);
        }
    }

    private static final class HeadInfo {
        byte[] raw;
        String requestLine;
        String method = "";
        String path = "/";
        String version = "HTTP/1.1";
        long contentLength = 0;
        boolean chunked = false;
        boolean hasAuth = false;
        boolean upgrade = false;
        String referer = null;
    }
}
