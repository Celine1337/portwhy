#!/usr/bin/env bash
# Build portwhy with the Go toolchain (stdlib only, offline).
set -euo pipefail
cd "$(dirname "$0")"
export TC="$HOME/.local/toolchains"
export PATH="$TC/go/go/bin:$PATH"
command -v go >/dev/null 2>&1 || { echo "FATAL: go not found"; exit 1; }
mkdir -p bin
go vet ./...
go build -o bin/portwhy .
echo "built bin/portwhy"