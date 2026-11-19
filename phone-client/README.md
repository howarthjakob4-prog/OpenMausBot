# OpenMausBot phone client (Android) — Ferrum build

The phone version that the open-source OpenMausBot repo was missing, built
by Muse for Jakob Howarth's fork (howarthjakob4-prog/OpenMausBot), 2026-11-19.

Upstream ships the phone *plumbing* — the `companion` sidecar, the
`phone-protocol` package, pairing codes — and closed native apps. This is an
open Android client for the fork: a WebView shell (package
`com.ferrum.mausbot`) whose bundled page is a launcher. The launcher stores
the server address, takes a pairing code or link, and hands the WebView to
the real OpenMausBot web UI on the user's own server (pairing scope: chat
and approvals). Pairing state persists in the server origin's WebView
storage. An unreachable server falls back to the launcher with an error
banner and a change-server path.

## Build

```sh
python3 make_icons.py          # regenerates launcher icons (drawn in PIL)
bash build-apk.sh 0.1.0 1      # -> MausBot-v0.1.0-android.apk
```

Uses the Android SDK build-tools under ~/workspace/tools/android-sdk and
signs with the Ferrum prototype keystore (same signer as the Foundry
prototype builds). The build zips `assets/` from inside `android-src` so
entries land at `assets/www/...` in the APK — the standing packaging rule
(a root-level `www/` build is dead on a real phone; verified by
`unzip -l` after every build: `assets/www/index.html` present, root
`www/` entries = 0).

## Proof (2026-11-19)

`tools/proof.mjs` serves the bundled launcher and pairs it against a real
local OpenMausBot server (npm package `openmausbot` 0.1.171, running on
Ferrum Cloud): setup form renders, a freshly minted single-use code is
accepted from the link, the server's Connect confirm completes pairing,
the workspace loads (the Chief of Staff bot's first conversation), the
server registers the paired device, and the launcher remembers the
server. ALL CHECKS PASSED; screenshots in `release-check/`. The two proof
devices were revoked afterward.

## Honest limits

- The server on Ferrum Cloud currently answers on loopback only. A real
  phone connects once the cloud joins Jakob's Tailscale (the server's own
  `--tailscale` way in) — that sign-in is Jakob's step.
- The Chief of Staff bot exists out of the box, but doing real work needs
  an AI account connected on the server ("Connect an AI") — also Jakob's
  step, when he is ready.
- The APK was verified by web-level end-to-end proof plus packaging
  checks; the on-phone install verdict is Jakob's, as with every build.

## v0.1.1 (2026-11-19) — Jakob's branding
At Jakob's order the mouse is gone. The launcher icon and the launcher
page now carry his own Ferrum dragon shield (hand-composited in PIL from
his real logo by make_icons.py — no generated art), and the launcher is
signed "JAKOB HOWARTH · FERRUM". Same package and signing key as v0.1.0,
so it installs as an upgrade. Proof screenshot:
release-check/05-launcher-shield.png.

## v0.1.2 (2026-11-19) — login screen removed
At Jakob's order the server-address + pairing-code form is gone. The
client now pairs from a mauspair:// deep link (server + code carried in
the link; MainActivity forwards them to the launcher page, which pairs
with no form at all), or from one pasted pairing link. After pairing,
the launcher auto-opens the workspace on every launch — no login screen
ever again. The server's own one-tap Connect confirm (its anti-phishing
step) is the only tap left, and only on pairing day. Proof:
release-check/06-pair-confirm.png, 07-workspace-autopair.png,
08-waiting-screen.png (deep-link params auto-paired to the real server;
workspace loaded; proof device revoked afterwards).

## v0.1.3 (2026-11-19) — the relay, built in
The v0.1.2 client could only reach a server over plain HTTP routes, and
every such route from the Ferrum Cloud VM turned out to be a dead end
(Tailscale serve needs the upstream daemon this VM cannot run; the
cloudflared tunnel cannot leave the sealed network). The one route that
works — MausBot Relay — speaks an E2E protocol whose only shipped client
was the official app, which gates entry behind a subscription. Jakob
rejected that ("not happening") and ordered the relay built into this
app ("just do it").

So the protocol was implemented from the published wire spec
(companion/src/e2e/README.md, wire spec v1) — twice:

- `tools/relay-lib.mjs` — a Node reference implementation. Verified
  against the spec's vectors/v1.json (49/49) and then proven LIVE
  against the real server through relay1.openmausbot.com: Noise
  handshake accepted, POST /api/pair issued a device credential,
  endpoints + health + the workspace page + the bots list all read back
  over encrypted yamux streams. Two live lessons are baked in: no FIN
  right after a request (the computer side drops it), and pairing
  answers 200, not 201.
- The Android port (`E2e.java`, `WsClient.java`, `RelaySession.java`,
  `LocalProxy.java`, `RelayStore.java`) — the same protocol in Java/JCA.
  Verified against the same vectors (tools/java-test/TestE2e.java,
  40/40 phone-side checks). A live JVM run from this VM is blocked by
  the VM's egress gate (raw TCP from a JVM is denied: "other_tcp"), so
  the on-phone run is the live proof — as with every build here, the
  phone verdict is Jakob's.

In the app: paste the openmausbot:// pairing link once (or tap the
mauspair:// link Muse sends). The app derives the keys, dials the
relay, pairs natively (device name "Jakob's S22"), stores the device
credential in app-private storage, and serves the server's real web
workspace through an in-app 127.0.0.1 proxy that rides the encrypted
session and injects the device Authorization per request. Later
launches reconnect by themselves. No form, no subscription, Ferrum
shield throughout. Launcher proof: tools/proof-v013.mjs, 11/11
(release-check/09–11). Packaging check passed (assets/www/index.html
present, root www/ = 0); same package + signer, installs as an upgrade
over v0.1.2.

Still open after pairing: "Connect an AI" on the server (Jakob's
sign-in) before the Chief of Staff can do real work.
