#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/third_party"
if [[ ! -f libbpf-install/lib64/libbpf.a ]]; then
  if [[ ! -d libbpf-1.5.0 ]]; then
    curl -fsSL -o libbpf.tar.gz https://github.com/libbpf/libbpf/archive/refs/tags/v1.5.0.tar.gz
    tar xzf libbpf.tar.gz
  fi
  make -C libbpf-1.5.0/src -j"$(nproc)" BUILD_STATIC_ONLY=y \
    OBJDIR="$ROOT/third_party/libbpf-build" \
    DESTDIR="$ROOT/third_party/libbpf-install" PREFIX=/ install
fi
echo "libbpf ready"
