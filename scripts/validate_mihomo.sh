#!/usr/bin/env bash
set -euo pipefail

# Pin the Mihomo parser release and verify the downloaded artifact before use.
VERSION="v1.19.34"
ARCHIVE="mihomo-linux-amd64-${VERSION}.gz"
URL="https://github.com/MetaCubeX/mihomo/releases/download/${VERSION}/${ARCHIVE}"
SHA256="223fab877e5795ce780ba39902e5f0b1113c1256ae244a7160f1165e017e9ccc"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl --fail --location --retry 3 --retry-delay 2 "$URL" --output "$TMP_DIR/mihomo.gz"
printf '%s  %s\n' "$SHA256" "$TMP_DIR/mihomo.gz" | sha256sum --check -
gzip --decompress --stdout "$TMP_DIR/mihomo.gz" > "$TMP_DIR/mihomo"
chmod +x "$TMP_DIR/mihomo"

for profile in output/clash-iran.yaml output/clash-china.yaml output/clash-russia.yaml; do
  test -s "$profile"
  echo "Validating $profile with Mihomo ${VERSION}"
  "$TMP_DIR/mihomo" -t -f "$profile"
done
