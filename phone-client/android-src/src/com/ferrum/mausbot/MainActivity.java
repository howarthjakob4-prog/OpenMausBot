package com.ferrum.mausbot;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * OpenMausBot phone client (Jakob Howarth's fork) — Ferrum build.
 *
 * The phone reaches its server through MausBot Relay with the E2E wire
 * protocol implemented natively in this app (E2e / RelaySession / WsClient —
 * no subscription, no official app). Pairing is one paste of the
 * openmausbot:// link (or tapping a mauspair:// link Muse sends); the server
 * issues a device credential, and from then on the app connects itself on
 * every launch. The server's real web workspace is served to the WebView
 * through LocalProxy, an in-app 127.0.0.1 proxy riding the encrypted session.
 *
 * The bundled page (assets/www, served from the local https host
 * "maus.local") is only the launcher: shield, status, and the paste box.
 */
public class MainActivity extends Activity {
    private static final String HOST = "maus.local";
    private static final String APP_STRING = "ferrum/0.1.3";
    private static final String DEVICE_NAME = "Jakob's S22";

    private WebView webView;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private RelaySession session;
    private LocalProxy proxy;
    private volatile boolean deliberateClose;
    private volatile boolean workspaceShowing;
    private int reconnectAttempts;

    private static final Map<String, String> MIME = new HashMap<>();
    static {
        MIME.put("html", "text/html");
        MIME.put("js", "text/javascript");
        MIME.put("css", "text/css");
        MIME.put("json", "application/json");
        MIME.put("webmanifest", "application/manifest+json");
        MIME.put("png", "image/png");
        MIME.put("jpg", "image/jpeg");
        MIME.put("jpeg", "image/jpeg");
        MIME.put("gif", "image/gif");
        MIME.put("svg", "image/svg+xml");
        MIME.put("ico", "image/x-icon");
        MIME.put("woff", "font/woff");
        MIME.put("woff2", "font/woff2");
        MIME.put("txt", "text/plain");
        MIME.put("map", "application/json");
    }

    private static String mimeFor(String path) {
        int dot = path.lastIndexOf('.');
        if (dot >= 0) {
            String mime = MIME.get(path.substring(dot + 1).toLowerCase());
            if (mime != null) return mime;
        }
        return "application/octet-stream";
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        webView.addJavascriptInterface(new RelayBridge(), "FerrumRelay");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                Uri url = request.getUrl();
                if (!HOST.equals(url.getHost())) {
                    return super.shouldInterceptRequest(view, request);
                }
                String path = url.getEncodedPath();
                if (path == null || path.isEmpty() || path.equals("/")) path = "/index.html";
                try {
                    InputStream in = getAssets().open("www" + path);
                    return new WebResourceResponse(mimeFor(path), "utf-8", in);
                } catch (IOException e) {
                    if (!path.contains(".")) {
                        try {
                            return new WebResourceResponse("text/html", "utf-8", getAssets().open("www/index.html"));
                        } catch (IOException ignored) {
                            // fall through to 404
                        }
                    }
                    return new WebResourceResponse("text/plain", "utf-8", 404, "Not Found", null,
                            new ByteArrayInputStream(new byte[0]));
                }
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame() && workspaceShowing) {
                    Uri url = request.getUrl();
                    if (url != null && "127.0.0.1".equals(url.getHost())) {
                        workspaceShowing = false;
                        showLauncher("error", null);
                        reconnect();
                    }
                }
                super.onReceivedError(view, request, error);
            }
        });

        setContentView(webView);

        String link = linkFromIntent(getIntent());
        if (link != null) {
            showLauncher("pair", link);
        } else if (RelayStore.load(this) != null) {
            showLauncher("connecting", null);
            connectFromStore();
        } else {
            showLauncher("", null);
        }
    }

    /** A pairing link arrives as mauspair://?link=<openmausbot://...> or as a
     *  raw openmausbot:// deep link. Returns the full link, or null. */
    private String linkFromIntent(android.content.Intent intent) {
        if (intent == null || !android.content.Intent.ACTION_VIEW.equals(intent.getAction())) return null;
        Uri data = intent.getData();
        if (data == null) return null;
        if ("openmausbot".equals(data.getScheme())) return data.toString();
        if ("mauspair".equals(data.getScheme())) {
            String link = data.getQueryParameter("link");
            if (link != null && link.startsWith("openmausbot://")) return link;
        }
        return null;
    }

    @Override
    protected void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        String link = linkFromIntent(intent);
        if (link != null) {
            workspaceShowing = false;
            showLauncher("pair", link);
        }
    }

    private void showLauncher(String state, String pairLink) {
        StringBuilder url = new StringBuilder("https://" + HOST + "/");
        boolean first = true;
        if (state != null && !state.isEmpty()) {
            url.append("?state=").append(Uri.encode(state));
            first = false;
        }
        if (pairLink != null) {
            url.append(first ? "?" : "&").append("pair=").append(Uri.encode(pairLink));
        }
        webView.loadUrl(url.toString());
    }

    private void pageEvent(String state, String message) {
        main.post(() -> webView.evaluateJavascript(
                "window.__relay && window.__relay(" + jsString(state) + "," + jsString(message) + ")",
                null));
    }

    private static String jsString(String s) {
        if (s == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c == '\n') out.append("\\n");
            else if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
            else out.append(c);
        }
        return out.append('"').toString();
    }

    // ------------------------------------------------------------------
    // Connection flows (background thread)
    private void connectFromStore() {
        RelayStore store = RelayStore.load(this);
        if (store == null) {
            showLauncher("", null);
            return;
        }
        io.execute(() -> {
            try {
                RelaySession s = dial(store, store.deviceToken);
                onConnected(s, store.deviceToken);
            } catch (Exception e) {
                pageEvent("error", friendly(e));
                main.post(() -> showLauncher("error", null));
            }
        });
    }

    private void reconnect() {
        if (deliberateClose) return;
        if (reconnectAttempts >= 3) {
            main.post(() -> showLauncher("error", null));
            return;
        }
        reconnectAttempts++;
        long delay = reconnectAttempts == 1 ? 2000 : reconnectAttempts == 2 ? 5000 : 15000;
        main.postDelayed(() -> {
            if (deliberateClose || workspaceShowing) return;
            showLauncher("connecting", null);
            connectFromStore();
        }, delay);
    }

    private RelaySession dial(RelayStore descriptor, String credential) throws Exception {
        byte[] credHash = E2e.credentialHash(credential);
        byte[] psk = E2e.pskFor(credHash, E2e.keyIdOf(descriptor.transportPub));
        byte[] adm = descriptor.hostId == null ? null
                : E2e.admissionFor(credHash, descriptor.hostId);
        Exception last = null;
        for (String host : descriptor.relays) {
            try {
                return RelaySession.dial(host, descriptor.transportPub, psk, APP_STRING,
                        descriptor.hostId, adm);
            } catch (Exception e) {
                last = e;
            }
        }
        throw last != null ? last : new Exception("no relay hosts in the pairing link");
    }

    private void pairWithLink(String link) {
        io.execute(() -> {
            pageEvent("pairing", null);
            try {
                E2e.PairingLink parsed = E2e.parsePairingLink(link);
                RelayStore descriptor = new RelayStore();
                descriptor.transportPub = parsed.transportPub;
                descriptor.hostId = parsed.hostId;
                descriptor.relays = parsed.relays;
                descriptor.serverName = parsed.name;
                RelaySession s = dial(descriptor, parsed.token);
                Map<String, String> headers = new LinkedHashMap<>();
                headers.put("Authorization", "Bearer " + parsed.token);
                headers.put("Content-Type", "application/json");
                String body = "{\"credential\":" + jsString(parsed.token)
                        + ",\"deviceName\":" + jsString(DEVICE_NAME) + "}";
                RelaySession.HttpResponse res = s.httpRequest("POST", "/api/pair", headers,
                        body.getBytes(StandardCharsets.UTF_8), 30000);
                if (res.status != 200 && res.status != 201) {
                    s.close(1000);
                    throw new Exception("the server did not accept the pairing (" + res.status + ")");
                }
                String json = new String(res.body, StandardCharsets.UTF_8);
                String deviceToken = jsonStringValue(json, "token");
                String serverName = jsonStringValue(json, "serverName");
                if (deviceToken == null) {
                    s.close(1000);
                    throw new Exception("the server's answer had no device credential");
                }
                descriptor.deviceToken = deviceToken;
                if (serverName != null) descriptor.serverName = serverName;
                descriptor.save(MainActivity.this);
                onConnected(s, deviceToken);
            } catch (Exception e) {
                pageEvent("error", friendly(e));
                main.post(() -> showLauncher("error", null));
            }
        });
    }

    private void onConnected(RelaySession s, String deviceToken) {
        deliberateClose = false;
        reconnectAttempts = 0;
        if (proxy != null) proxy.stop();
        if (session != null && session != s) session.close(1000);
        session = s;
        String secret = E2e.b64u(E2e.randomBytes(12)).replace('-', 'a').replace('_', 'b');
        proxy = new LocalProxy(s, deviceToken, secret);
        final int port;
        try {
            port = proxy.start();
        } catch (IOException e) {
            pageEvent("error", "could not start the in-app bridge");
            return;
        }
        s.setListener(new RelaySession.Listener() {
            @Override
            public void onRemoved() {
                deliberateClose = true;
                RelayStore.clear(MainActivity.this);
                main.post(() -> {
                    workspaceShowing = false;
                    showLauncher("removed", null);
                });
            }

            @Override
            public void onClosed(int code) {
                if (deliberateClose) return;
                main.post(() -> {
                    if (workspaceShowing) {
                        workspaceShowing = false;
                        showLauncher("connecting", null);
                    }
                    reconnect();
                });
            }
        });
        main.post(() -> {
            workspaceShowing = true;
            webView.loadUrl("http://127.0.0.1:" + port + "/" + secret + "/");
        });
    }

    private static String friendly(Exception e) {
        String msg = e.getMessage();
        if (msg == null || msg.isEmpty()) msg = "connection failed";
        return msg;
    }

    /** Tiny extractor for flat JSON string fields in the pair response. */
    private static String jsonStringValue(String json, String key) {
        int i = json.indexOf("\"" + key + "\"");
        if (i < 0) return null;
        int colon = json.indexOf(':', i + key.length() + 2);
        if (colon < 0) return null;
        int start = json.indexOf('"', colon);
        if (start < 0) return null;
        StringBuilder out = new StringBuilder();
        for (int p = start + 1; p < json.length(); p++) {
            char c = json.charAt(p);
            if (c == '\\' && p + 1 < json.length()) {
                out.append(json.charAt(++p));
            } else if (c == '"') {
                return out.toString();
            } else {
                out.append(c);
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // The launcher page's bridge
    public final class RelayBridge {
        @JavascriptInterface
        public void pair(String link) {
            pairWithLink(link);
        }

        @JavascriptInterface
        public void reconnect() {
            reconnectAttempts = 0;
            showLauncherFromBridge("connecting");
            connectFromStore();
        }

        @JavascriptInterface
        public void forget() {
            deliberateClose = true;
            io.execute(() -> {
                if (proxy != null) proxy.stop();
                if (session != null) session.close(1000);
                RelayStore.clear(MainActivity.this);
                main.post(() -> {
                    workspaceShowing = false;
                    showLauncher("", null);
                });
            });
        }

        @JavascriptInterface
        public String savedServerName() {
            RelayStore store = RelayStore.load(MainActivity.this);
            return store == null ? "" : store.serverName;
        }

        private void showLauncherFromBridge(String state) {
            main.post(() -> showLauncher(state, null));
        }
    }

    @Override
    protected void onDestroy() {
        deliberateClose = true;
        if (proxy != null) proxy.stop();
        if (session != null) session.close(1000);
        io.shutdownNow();
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
