#!/bin/zsh
# Regenerates docs/*.png from Demo/Demo.kdbx using an isolated debug build
# (separate bundle ID, so your real Kept preferences and keychain are untouched).
# Requires: python3 with pykeepass (for Scripts/make_demo.py).
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
WORK=$(mktemp -d)
DOMAIN=local.kept.Screenshots
DEMO="$PWD/Demo/Demo.kdbx"

IDS=$($PY Scripts/make_demo.py)
swift build -c debug --product Kept -Xswiftc -O >/dev/null
BIN="$(swift build -c debug --show-bin-path)/Kept"

APP="$WORK/Kept.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Kept"
cp Resources/AppIcon.icns "$APP/Contents/Resources/"
sed "s/local.kept.Kept/$DOMAIN/" Resources/Info.plist > "$APP/Contents/Info.plist"
codesign --force --sign - "$APP" 2>/dev/null

cat > "$WORK/winid.swift" <<'SWIFT'
import CoreGraphics
let pid = Int(CommandLine.arguments[1])!
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as! [[String: Any]]
if let w = list.first(where: { ($0["kCGWindowOwnerPID"] as? Int) == pid && ($0["kCGWindowLayer"] as? Int) == 0 }) {
    print(w["kCGWindowNumber"]!)
}
SWIFT
swiftc -O "$WORK/winid.swift" -o "$WORK/winid"

# shot <output> <sidebar> <entry-id> <appearance> <password>
shot() {
  $PY - "$IDS" "$DEMO" "$2" "$3" "$WORK/prefs.plist" <<'PY'
import json, os, plistlib, sys
ids, demo, sidebar, entry = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
plistlib.dump({
    "recentDatabases": [demo],
    "favorites": {ids["root"]: ids["favorites"]},
    "lastSelection": {ids["root"]: {"sidebar": sidebar, "entry": ids.get(entry, "")}},
    "NSWindow Frame main": "160 160 1100 680 0 0 1920 1050 ",
}, open(sys.argv[5], "wb"))
PY
  defaults import $DOMAIN "$WORK/prefs.plist"  # goes through cfprefsd, so no stale cache
  if [[ -n "$5" ]]; then
    KEPT_DEBUG_APPEARANCE="$4" KEPT_DEBUG_PASSWORD="$5" "$APP/Contents/MacOS/Kept" >/dev/null 2>&1 &
  else
    KEPT_DEBUG_APPEARANCE="$4" "$APP/Contents/MacOS/Kept" >/dev/null 2>&1 &
  fi
  local pid=$!
  sleep 4
  screencapture -x -o -l "$("$WORK/winid" $pid)" "docs/$1.png"
  kill $pid; wait $pid 2>/dev/null || true
  echo "docs/$1.png"
}

mkdir -p docs
FINANCE=$($PY -c 'import json,sys; print("group:" + json.loads(sys.argv[1])["finance"])' "$IDS")
shot main-light all selected light demo
shot main-dark "$FINANCE" bank dark demo
shot favorites favorites selected light demo
shot unlock all "" light ""

defaults delete $DOMAIN 2>/dev/null || true
rm -rf "$WORK"
