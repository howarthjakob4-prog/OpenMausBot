#!/usr/bin/env bash
# Package the OpenMausBot phone-client APK from android-src (whose
# assets/www holds the bundled launcher page). Usage: bash build-apk.sh X.Y.Z CODE
# Adapted from the Foundry packaging recipe; signs with the same prototype
# keystore. The zip step runs from android-src so entries land at
# assets/www/... — MainActivity reads them via AssetManager, which only
# sees assets/ (standing rule; a root-level www/ build is dead on a phone).
set -euo pipefail
cd "$(dirname "$0")"
VER="${1:?versionName}"; CODE="${2:?versionCode}"
BT="$HOME/workspace/tools/android-sdk/build-tools/35.0.1"
PLAT="$HOME/workspace/tools/android-sdk/platforms/android-35/android.jar"
KS="$HOME/workspace/projects/dots-team-ui/release/dots-prototype.keystore"
sed -i "s/versionCode=\"[0-9]*\"/versionCode=\"$CODE\"/; s/versionName=\"[^\"]*\"/versionName=\"$VER\"/" android-src/AndroidManifest.xml
grep -o 'versionCode="[^"]*"\|versionName="[^"]*"' android-src/AndroidManifest.xml
rm -rf build
mkdir -p build/compiled build/gen build/classes build/dex
"$BT/aapt2" compile --dir android-src/res -o build/compiled/res.zip
"$BT/aapt2" link -o build/unsigned.apk -I "$PLAT" --manifest android-src/AndroidManifest.xml \
  --java build/gen build/compiled/res.zip --min-sdk-version 26 --target-sdk-version 35
find android-src/src build/gen -name "*.java" > build/sources.txt
javac -encoding UTF-8 -cp "$PLAT" -d build/classes @build/sources.txt
(cd build/classes && jar cf ../classes.jar .)
"$BT/d8" --lib "$PLAT" --output build/dex build/classes.jar
cp build/unsigned.apk build/withdex.apk
(cd build/dex && zip -q ../withdex.apk classes.dex)
(cd android-src && zip -q -r ../build/withdex.apk assets/www)
"$BT/zipalign" -f 4 build/withdex.apk build/aligned.apk
OUT="MausBot-v${VER}-android.apk"
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:dots-prototype --ks-key-alias dots --out "$OUT" build/aligned.apk
"$BT/apksigner" verify --print-certs "$OUT" | grep SHA-256
"$BT/aapt2" dump badging "$OUT" | head -2
echo "www entries: $(unzip -l "$OUT" | grep -c 'assets/www')"
echo "root www entries (must be 0): $(unzip -l "$OUT" | grep -cE '^.*\swww/' || true)"
ls -la "$OUT"
