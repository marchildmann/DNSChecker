#!/bin/sh
# Packs DNSChecker.exe with the DLLs it needs from MSYS2 into a zip archive.
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
cp "$build_dir/DNSChecker.exe" "$stage/"
# every DLL the program loads from MSYS2 (libxml2, zlib, winpthreads, ...); Windows' own stay out
ldd "$build_dir/DNSChecker.exe" | awk '/\/ucrt64\// { print $3 }' | sort -u | while read -r dll; do cp "$dll" "$stage/"; done
cp LICENSE "$stage/LICENSE.txt"
cat > "$stage/README.txt" <<TEXT
DNS Checker $version for Windows (64-bit)

Start DNSChecker.exe; the DLL files beside it belong to it and must stay in
the same folder. Nothing is installed.

The program is not signed with a Windows certificate, so SmartScreen may
ask before the first start: "More info", then "Run anyway".

Source and license: https://github.com/marchildmann/DNSChecker (MIT)
TEXT
(cd "$output_dir" && rm -f "$name.zip" && zip -qr "$name.zip" "$name")
ls -l "$stage"
echo "== Done: $output_dir/$name.zip"
