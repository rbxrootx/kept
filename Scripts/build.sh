#!/bin/zsh
# Builds a universal (Apple Silicon + Intel) Kept.app into ./build.
#   Scripts/build.sh            build
#   Scripts/build.sh install    build and copy to /Applications
#   Scripts/build.sh zip        build and create build/Kept.zip for distribution
# Set CODESIGN_IDENTITY="Developer ID Application: …" to sign with a real certificate (default: ad-hoc).
set -euo pipefail
cd "$(dirname "$0")/.."

ARCHS=(--arch arm64 --arch x86_64)
swift build -c release --product Kept $ARCHS
BIN="$(swift build -c release --product Kept $ARCHS --show-bin-path)/Kept"

APP=build/Kept.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Kept"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
if [[ -n "${VERSION:-}" ]]; then
  plutil -replace CFBundleShortVersionString -string "${VERSION#v}" "$APP/Contents/Info.plist"
fi

IDENTITY="${CODESIGN_IDENTITY:--}"
# Notarization needs a secure timestamp; ad-hoc signatures can't have one.
[[ "$IDENTITY" == "-" ]] && TIMESTAMP=--timestamp=none || TIMESTAMP=--timestamp
codesign --force --options runtime $TIMESTAMP --sign "$IDENTITY" "$APP"
echo "Built $APP ($(lipo -archs "$APP/Contents/MacOS/Kept"))"

case "${1:-}" in
  install)
    pkill -x Kept 2>/dev/null || true
    rm -rf /Applications/Kept.app
    cp -R "$APP" /Applications/Kept.app
    echo "Installed to /Applications/Kept.app" ;;
  zip)
    rm -f build/Kept.zip
    ditto -c -k --sequesterRsrc --keepParent "$APP" build/Kept.zip
    echo "Created build/Kept.zip" ;;
esac
