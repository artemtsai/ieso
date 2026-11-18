#!/bin/bash
# Builds build/demo-app/DemoApp.app (Swift + AppKit, ad-hoc signed). No Xcode project needed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/demo-app/DemoApp.app"
rm -rf "$OUT"
mkdir -p "$OUT/Contents/MacOS"
swiftc -swift-version 5 -Onone -g \
  -target "$(uname -m)-apple-macos13.0" \
  "$ROOT/demo-app/DemoApp/main.swift" -o "$OUT/Contents/MacOS/DemoApp"
cat > "$OUT/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.ieso.demoapp</string>
  <key>CFBundleName</key><string>DemoApp</string>
  <key>CFBundleExecutable</key><string>DemoApp</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.4.2</string>
  <key>CFBundleVersion</key><string>142</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$OUT" >/dev/null 2>&1
echo "built $OUT"
