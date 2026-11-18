#!/bin/sh
set -eu
cd "$(dirname "$0")"
output="$PWD/build"
bundle="$output/NodeGuard.app"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
xcrun swiftc -swift-version 5 -O -parse-as-library -target "$(uname -m)-apple-macosx14.0" \
    Main.swift Service.swift Probe.swift ClashConnection.swift IPv4Entry.swift AgentCloser.swift Card.swift -o "$staging/NodeGuard"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp Marks/*.svg "$bundle/Contents/Resources/"
cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>NodeGuard</string>
    <key>CFBundleIdentifier</key><string>local.nodeguard.app</string>
    <key>CFBundleName</key><string>节点保护器</string>
    <key>CFBundleDisplayName</key><string>节点保护器</string>
    <key>CFBundleVersion</key><string>7</string>
    <key>CFBundleShortVersionString</key><string>1.4.2</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleDevelopmentRegion</key><string>zh_CN</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSUIElement</key><true/>
    <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
mv -f "$staging/NodeGuard" "$bundle/Contents/MacOS/NodeGuard"
/usr/bin/codesign --force --sign - "$bundle"

for name in Antigravity Gemini; do
    bundle="$output/$name IPv4.app"
    id=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
    xcrun swiftc -swift-version 5 -O -target "$(uname -m)-apple-macosx14.0" \
        "Launchers/$name.swift" -o "$staging/Launcher"
    mkdir -p "$bundle/Contents/MacOS"
    cat > "$bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>Launcher</string>
    <key>CFBundleIdentifier</key><string>local.$id.ipv4-launcher</string>
    <key>CFBundleName</key><string>$name IPv4</string>
    <key>CFBundleDisplayName</key><string>$name IPv4</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSUIElement</key><true/>
</dict></plist>
PLIST
    mv -f "$staging/Launcher" "$bundle/Contents/MacOS/Launcher"
    /usr/bin/codesign --force --sign - "$bundle"
done
