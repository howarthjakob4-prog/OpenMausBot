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
