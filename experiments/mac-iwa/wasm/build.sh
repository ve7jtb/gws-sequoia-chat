#!/bin/sh
# Build matching baseline and wide public verifiers; never change crypto features.
set -eu
cd "$(dirname "$0")"
BINDGEN=${WASM_BINDGEN:-wasm-bindgen}
[ "$("$BINDGEN" --version)" = "wasm-bindgen 0.2.130" ] || {
  echo 'Requires wasm-bindgen-cli 0.2.130' >&2; exit 1;
}
# Isolate artifacts so the compiler feature cannot leak into the baseline.
RUSTFLAGS='' cargo +1.88.0 build --release --locked --target wasm32-unknown-unknown
RUSTFLAGS='-C target-feature=+wide-arithmetic' CARGO_TARGET_DIR=target-wide \
  cargo +1.88.0 build --release --locked --target wasm32-unknown-unknown
for variant in baseline wide; do
  target=target; out=pkg; dest=../app/wasm
  if [ "$variant" = wide ]; then target=target-wide; out=pkg-wide; dest=../app/wasm-wide; fi
  "$BINDGEN" --target web --out-dir "$out" "$target/wasm32-unknown-unknown/release/sequoia_iwa_verify.wasm"
  printf '%s\n' '{"type":"module"}' > "$out/package.json"
  mkdir -p "$dest"
  cp "$out/sequoia_iwa_verify.js" "$out/sequoia_iwa_verify_bg.wasm" "$dest/"
done
