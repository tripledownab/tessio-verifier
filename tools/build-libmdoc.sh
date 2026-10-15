#!/usr/bin/env bash
# Builds libmdoc.so for linux-x64 in a container and places it where the zero knowledge package and its
# tests load it from: src/Tessio.Verifier.Core.Mdoc.Zk/runtimes/linux-x64/native/. Needs Docker.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/src/Tessio.Verifier.Core.Mdoc.Zk/runtimes/linux-x64/native"
mkdir -p "$out"
docker build --progress=plain --platform linux/amd64 --output "type=local,dest=$out" "$root/src/Tessio.Verifier.Core.Mdoc.Zk/native"
sha256sum "$out/libmdoc.so"
