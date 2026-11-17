#!/bin/sh
# Signs "DNS Checker.app" with a Developer ID, has Apple notarize it, and
# packs it into a signed, notarized disk image ready for download.
#
#   packaging/macos/sign_and_package.sh <path/to/DNS Checker.app> <version> <output directory>
#
# Environment:
#   SIGN_IDENTITY        the signing identity, default "Developer ID Application"
#                        (the one certificate of that kind in the keychain);
#                        "-" signs ad hoc, for test builds without a certificate
#   NOTARY_PROFILE       a notarytool keychain profile (xcrun notarytool store-credentials), or
#   APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD
#                        an Apple ID with an app-specific password
# Without notary credentials the app and image are signed but not notarized,
# which is enough to test the signature but not for downloads.
set -eu

app="$1"
version="$2"
output_dir="$3"
identity="${SIGN_IDENTITY:-Developer ID Application}"
image="$output_dir/DNSChecker-$version-macOS.dmg"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

has_notary_credentials() {
    [ -n "${NOTARY_PROFILE:-}" ] || { [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; }
}

notarize() {
    if [ -n "${NOTARY_PROFILE:-}" ]; then
        xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait --timeout 30m
    else
        xcrun notarytool submit "$1" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
            --password "$APPLE_APP_PASSWORD" --wait --timeout 30m
    fi
}

# a secure timestamp is required for notarization, and impossible ad hoc
timestamp="--timestamp"
[ "$identity" = "-" ] && timestamp="--timestamp=none"

echo "== Signing the app with \"$identity\""
# hardened runtime and a timestamp: both are required for notarization
codesign --force --options runtime "$timestamp" --sign "$identity" "$app"
codesign --verify --strict --verbose=2 "$app"

if has_notary_credentials; then
    echo "== Notarizing the app"
    ditto -c -k --keepParent "$app" "$work_dir/app.zip"
    notarize "$work_dir/app.zip"
    xcrun stapler staple "$app"
else
    echo "== No notary credentials: the app stays signed but not notarized"
fi

echo "== Building the disk image"
mkdir -p "$work_dir/image" "$output_dir"
ditto "$app" "$work_dir/image/$(basename "$app")"
ln -s /Applications "$work_dir/image/Applications"
rm -f "$image"
hdiutil create -volname "DNS Checker $version" -srcfolder "$work_dir/image" -ov -format UDZO "$image"
codesign --force "$timestamp" --sign "$identity" "$image"

if has_notary_credentials; then
    echo "== Notarizing the disk image"
    notarize "$image"
    xcrun stapler staple "$image"
    echo "== Gatekeeper's verdict"
    spctl --assess --type open --context context:primary-signature --verbose=2 "$image"
fi
echo "== Done: $image"
