#!/bin/sh
# Reproducible local WASM build. Never download or execute an unverified toolchain.
set -eu
cd "$(dirname "$0")"
GO=${GO_BIN:-go}
"$GO" version
"$GO" mod verify
"$GO" test ./...
GOOS=js GOARCH=wasm "$GO" build -trimpath -o ../app/ssh/engine.wasm ./cmd/wasm
cp "$("$GO" env GOROOT)/lib/wasm/wasm_exec.js" ../app/ssh/wasm_exec.js
cp "$("$GO" env GOROOT)/LICENSE" ../app/ssh/GO-LICENSE.txt
cp "$("$GO" list -m -f '{{.Dir}}' golang.org/x/crypto)/LICENSE" ../app/ssh/X-CRYPTO-LICENSE.txt
cp "$("$GO" list -m -f '{{.Dir}}' golang.org/x/sys)/LICENSE" ../app/ssh/X-SYS-LICENSE.txt
