#!/bin/sh
# Packs DNSChecker.exe into a zip archive. The program is linked statically,
# so it needs no DLLs beside it; this script fails if one slipped back in.
# Runs in an MSYS2 UCRT64 shell after the build:
#
#   packaging/windows/package.sh <build directory> <version> <output directory>
set -eu

build_dir="$1"
version="$2"
output_dir="$3"
name="DNSChecker-$version-Windows-x64"
stage="$output_dir/$name"

rm -rf "$stage"
mkdir -p "$stage"
msys2_dlls=$(ldd "$build_dir/DNSChecker.exe" | awk '/\/ucrt64\// { print $1 }')
if [ -n "$msys2_dlls" ]; then
    echo "DNSChecker.exe still loads DLLs from MSYS2, so it would not start elsewhere:" >&2
    echo "$msys2_dlls" >&2
    exit 1
fi
cp "$build_dir/DNSChecker.exe" "$stage/"
cp LICENSE "$stage/LICENSE.txt"
cat > "$stage/README.txt" <<TEXT
DNS Checker $version for Windows (64-bit)

Start DNSChecker.exe. It is a single file: copy it wherever you like.
Nothing is installed.

The program is not signed with a Windows certificate, so SmartScreen may
ask before the first start: "More info", then "Run anyway".

Source and license: https://github.com/marchildmann/DNSChecker (MIT)
TEXT
(cd "$output_dir" && rm -f "$name.zip" && zip -qr "$name.zip" "$name")
ls -l "$stage"
echo "== Done: $output_dir/$name.zip"
