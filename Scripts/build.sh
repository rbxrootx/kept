#!/bin/zsh
# Builds Kept.app into ./build. Pass "install" to also copy it to /Applications.
set -euo pipefail
cd "$(dirname "$0")/.."

swift build -c release --product Kept
BIN="$(swift build -c release --product Kept --show-bin-path)/Kept"

APP=build/Kept.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Kept"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"

# Ad-hoc signature (use `security find-identity` + CODESIGN_IDENTITY to sign with a real certificate).
codesign --force --options runtime --sign "${CODESIGN_IDENTITY:--}" "$APP"
echo "Built $APP"

if [[ "${1:-}" == "install" ]]; then
  pkill -x Kept 2>/dev/null || true
  rm -rf /Applications/Kept.app
  cp -R "$APP" /Applications/Kept.app
  echo "Installed to /Applications/Kept.app"
fi
