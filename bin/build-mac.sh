#!/usr/bin/env bash
# Builds a standalone macOS app (no Python needed by the end user).
# MUST be run on a Mac (PyInstaller cannot cross-build from Windows).
#
#   python3 -m pip install pyinstaller
#   bash bin/build-mac.sh
#
# Output: dist/LMSFuzzer.app  (and a dist/LMSFuzzer/ folder with the data dirs)
set -e
here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
cd "$root"

echo "Building LMS Fuzzer (macOS)..."
python3 -m PyInstaller --noconfirm --clean --windowed \
    --name LMSFuzzer \
    --icon "assets/logo.icns" \
    --add-data "assets:assets" \
    "bin/gui.py"

# Data folders live next to the .app so results/bodies are writable and users can
# drop their own Requests/payloads in.
for d in Requests payloads results bodies; do mkdir -p "dist/$d"; done
cp payloads/* "dist/payloads/" 2>/dev/null || true
cp Requests/sample* "dist/Requests/" 2>/dev/null || true
cp README.md "dist/" 2>/dev/null || true

echo ""
echo "Done. In dist/ you now have LMSFuzzer.app plus Requests/ payloads/ results/ bodies/."
echo "Zip the dist/ folder to share. First launch: right-click the app > Open"
echo "(unsigned apps need that once to get past Gatekeeper)."
