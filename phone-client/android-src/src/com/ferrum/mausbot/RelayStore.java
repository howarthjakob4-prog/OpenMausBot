package com.ferrum.mausbot;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.List;

/**
 * What the app remembers after pairing: the device credential the server
 * issued, the server's E2E descriptor (transport key, host id, relay hosts),
 * and the server's name. App-private storage only.
 */
public final class RelayStore {
    private static final String PREFS = "relay";

    public String deviceToken;
    public byte[] transportPub;
    public byte[] hostId;
    public List<String> relays = new ArrayList<>();
    public String serverName = "";

    public static RelayStore load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String token = prefs.getString("cred", null);
        String tpub = prefs.getString("tpub", null);
        if (token == null || tpub == null) return null;
        RelayStore store = new RelayStore();
        store.deviceToken = token;
        store.transportPub = E2e.fromB64u(tpub);
        if (store.transportPub == null) return null;
        String hostId = prefs.getString("hostid", null);
        store.hostId = hostId == null ? null : E2e.fromB64u(hostId);
        String relays = prefs.getString("relays", "");
        if (!relays.isEmpty()) {
            for (String host : relays.split(",")) store.relays.add(host);
        }
        store.serverName = prefs.getString("name", "");
        return store;
    }

    public void save(Context context) {
        SharedPreferences.Editor edit = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit();
        edit.putString("cred", deviceToken);
        edit.putString("tpub", E2e.b64u(transportPub));
        edit.putString("hostid", hostId == null ? null : E2e.b64u(hostId));
        StringBuilder joined = new StringBuilder();
        for (int i = 0; i < relays.size(); i++) {
            if (i > 0) joined.append(',');
            joined.append(relays.get(i));
        }
        edit.putString("relays", joined.toString());
        edit.putString("name", serverName);
        edit.apply();
    }

    public static void clear(Context context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply();
    }
}
