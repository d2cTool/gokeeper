#!/usr/bin/env bash
# Собирает gRPC CLI под Linux x64 (GOOS=linux GOARCH=amd64).
# Запуск из корня репозитория или из scripts/:
#   ./scripts/build-client-linux.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || true)}"
version="${version:-dev}"
date="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
ldflags="-s -w -X gokeeper/pkg/version.Version=${version} -X gokeeper/pkg/version.BuildDate=${date}"

out="${root}/bin/clients"
mkdir -p "$out"
name="gophkeeper-linux-amd64"

echo "building ${name}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$ldflags" -o "${out}/${name}" ./cmd/client
chmod +x "${out}/${name}"

cat > "${out}/manifest.json" <<EOF
{
  "version": "${version}",
  "build_date": "${date}",
  "binaries": [
    {"platform": "windows", "arch": "amd64", "filename": "gophkeeper-windows-amd64.exe"},
    {"platform": "linux", "arch": "amd64", "filename": "gophkeeper-linux-amd64"},
    {"platform": "darwin", "arch": "amd64", "filename": "gophkeeper-darwin-amd64"}
  ]
}
EOF

echo "linux client -> ${out}/${name}"
ls -lh "${out}/${name}"
