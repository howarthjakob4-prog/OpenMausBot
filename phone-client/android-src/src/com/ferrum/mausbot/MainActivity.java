package com.ferrum.mausbot;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * OpenMausBot phone client shell (Jakob Howarth's fork).
 *
 * A single WebView. The bundled page (assets/www, served from the local
 * https host "maus.local") is only the launcher: there is no login form —
 * the phone pairs from a mauspair:// link (or a pasted pairing link), and
 * afterwards the launcher auto-opens the saved server's workspace.
 * Pairing state lives in the server origin's cookies/storage inside this
 * WebView, so it persists across launches. If the saved server cannot be
 * reached, the WebView falls back to the launcher with an error banner
 * and recovery controls.
 */
public class MainActivity extends Activity {
    private static final String HOST = "maus.local";
    private WebView webView;
    private boolean showingErrorPage;

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

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                Uri url = request.getUrl();
                if (!HOST.equals(url.getHost())) {
                    // The real workspace on the user's server: straight to
                    // the network, untouched.
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
                // Only the top-level page matters: a failed workspace load
                // (server off, wrong address, no route) returns to the
                // launcher with its error banner instead of a dead screen.
                if (request.isForMainFrame() && !showingErrorPage) {
                    Uri url = request.getUrl();
                    if (url == null || !HOST.equals(url.getHost())) {
                        showingErrorPage = true;
                        view.loadUrl("https://" + HOST + "/?err=1");
                    }
                }
                super.onReceivedError(view, request, error);
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                if (url != null && url.contains("err=1")) {
                    // Allow the next real failure to trigger the fallback again.
                    showingErrorPage = false;
                }
                super.onPageFinished(view, url);
            }
        });

        setContentView(webView);
        webView.loadUrl(startUrl(getIntent()));
    }

    /**
     * A mauspair:// link (sent by Muse) carries ?server= and ?code=; the
     * bundled launcher page reads them and pairs with no form at all.
     * Anything else just opens the launcher, which auto-opens the saved
     * workspace.
     */
    private String startUrl(android.content.Intent intent) {
        if (intent != null && android.content.Intent.ACTION_VIEW.equals(intent.getAction())) {
            Uri data = intent.getData();
            if (data != null && "mauspair".equals(data.getScheme())) {
                String server = data.getQueryParameter("server");
                String code = data.getQueryParameter("code");
                if (server != null && code != null) {
                    return "https://" + HOST + "/?server=" + Uri.encode(server)
                            + "&code=" + Uri.encode(code);
                }
            }
        }
        return "https://" + HOST + "/";
    }

    @Override
    protected void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (webView != null) {
            String url = startUrl(intent);
            if (url.contains("server=")) webView.loadUrl(url);
        }
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
