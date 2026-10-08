#!/bin/sh
# Builds the Quick Look preview extension as a universal, ad-hoc signed
# BinchkPreview.appex. Needs only the Command Line Tools (swiftc, lipo,
# codesign); no Xcode project.
# usage: macos/QuickLook/build.sh OUT.appex [version]
set -eu
OUT=${1:?usage: $0 OUT.appex [version]}
VERSION=${2:-dev}
VERSION=${VERSION#v}
MACOS_MIN=${MACOS_MIN:-13.0}   # QLPreviewProvider needs macOS 12; binchk needs 13
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(dirname "$OUT")/.quicklook-build
SDK=$(xcrun --sdk macosx --show-sdk-path)

rm -rf "$WORK" "$OUT"
mkdir -p "$WORK"
# The Command Line Tools ship libswiftCompatibilityPacks.a without an x86_64
# slice, so ld warns about it on the Intel link; nothing here needs it.
for arch in arm64 x86_64; do
	# An app extension has no main(): -parse-as-library keeps swiftc from
	# emitting one, and the entry point is Foundation's NSExtensionMain.
	swiftc -O -whole-module-optimization -parse-as-library -application-extension \
		-swift-version 6 \
		-module-name BinchkPreview \
		-sdk "$SDK" -target "$arch-apple-macos$MACOS_MIN" \
		-framework Foundation -framework QuickLookUI -framework UniformTypeIdentifiers \
		-Xlinker -e -Xlinker _NSExtensionMain \
		-Xlinker -application_extension \
		-o "$WORK/BinchkPreview-$arch" \
		"$HERE/Sources/Core/BinchkIndex.swift" \
		"$HERE/Sources/Extension/PreviewProvider.swift"
done

mkdir -p "$OUT/Contents/MacOS"
lipo -create -output "$OUT/Contents/MacOS/BinchkPreview" \
	"$WORK/BinchkPreview-arm64" "$WORK/BinchkPreview-x86_64"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@MACOS_MIN@/$MACOS_MIN/g" \
	"$HERE/Info.plist" > "$OUT/Contents/Info.plist"
plutil -lint -s "$OUT/Contents/Info.plist"
for a in arm64 x86_64; do
	otool -arch $a -l "$OUT/Contents/MacOS/BinchkPreview" | awk '/ minos /{print $2}' | grep -qx "$MACOS_MIN" \
		|| { echo "BinchkPreview $a: minos is not $MACOS_MIN" >&2; exit 1; }
done
rm -rf "$WORK"

# The sandbox entitlements are part of the signature: without them the
# extension would not be sandboxed and pluginkit refuses it.
codesign --force --sign - --options runtime \
	--entitlements "$HERE/BinchkPreview.entitlements" "$OUT"
echo "built $OUT"
