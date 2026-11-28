#!/bin/sh
# Reproducible local WASM build. Never download or execute an unverified toolchain.
set -eu
cd "$(dirname "$0")"
GO=${GO_BIN:-go}
"$GO" version
"$GO" mod verify
overlay_dir=$(mktemp -d)
trap 'chmod -R u+w "$overlay_dir"; rm -rf "$overlay_dir"' EXIT
crypto_dir=$("$GO" list -m -f '{{.Dir}}' golang.org/x/crypto)
cp -R "$crypto_dir" "$overlay_dir/crypto"
cp go.mod go.sum "$overlay_dir/"
python3 prepare-overlay.py "$overlay_dir/crypto"
"$GO" mod edit -modfile="$overlay_dir/go.mod" -replace="golang.org/x/crypto=$overlay_dir/crypto"
"$GO" test -modfile="$overlay_dir/go.mod" ./...
"$GO" run ./cmd/probe-offer > ../app/ssh/probe-offer.js
GOOS=js GOARCH=wasm "$GO" build -modfile="$overlay_dir/go.mod" -trimpath -o ../app/ssh/engine.wasm ./cmd/wasm
cp "$("$GO" env GOROOT)/lib/wasm/wasm_exec.js" ../app/ssh/wasm_exec.js
cp "$("$GO" env GOROOT)/LICENSE" ../app/ssh/GO-LICENSE.txt
cp "$("$GO" list -m -f '{{.Dir}}' golang.org/x/crypto)/LICENSE" ../app/ssh/X-CRYPTO-LICENSE.txt
cp "$("$GO" list -m -f '{{.Dir}}' golang.org/x/sys)/LICENSE" ../app/ssh/X-SYS-LICENSE.txt
