#!/bin/sh
# Wraps the macOS binary in a menu-bar-only .app bundle (no Dock icon).
# usage: scripts/macos-bundle.sh path/to/binchk [version]
# With APPEX=path/to/BinchkPreview.appex the Quick Look preview extension is
# embedded at Contents/PlugIns (make app builds it first).
set -eu
BIN=${1:?usage: $0 path/to/binchk [version]}
VERSION=${2:-dev}
VERSION=${VERSION#v}   # Apple wants 0.1.0, not v0.1.0
MACOS_MIN=${MACOS_MIN:-13.0}   # must match the binary's minos (Makefile)
APPEX=${APPEX:-}
APP=dist/binchk.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/binchk"
cp assets/icon/binchk.icns "$APP/Contents/Resources/binchk.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>binchk</string>
  <key>CFBundleIdentifier</key><string>com.binchk.app</string>
  <key>CFBundleExecutable</key><string>binchk</string>
  <key>CFBundleIconFile</key><string>binchk</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><true/>
  <key>LSMinimumSystemVersion</key><string>${MACOS_MIN}</string>
</dict>
</plist>
PLIST
# Ad-hoc sign so it runs on Apple Silicon; replace "-" with a Developer ID
# identity for distribution. Sign inside-out: the extension (with its sandbox
# entitlements) first, then the app, whose seal covers the signed extension.
if [ -n "$APPEX" ]; then
  mkdir -p "$APP/Contents/PlugIns"
  # No xattrs or resource forks: codesign --strict rejects that detritus.
  ditto --norsrc --noextattr --noqtn --noacl "$APPEX" "$APP/Contents/PlugIns/BinchkPreview.appex"
  codesign --force --sign - --options runtime \
    --entitlements macos/QuickLook/BinchkPreview.entitlements \
    "$APP/Contents/PlugIns/BinchkPreview.appex"
fi
codesign --force --sign - --options runtime "$APP"
echo "built $APP"
