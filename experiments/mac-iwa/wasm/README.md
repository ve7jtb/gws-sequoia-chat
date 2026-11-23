# Experimental Sequoia WASM verifier

This prototype exposes **detached public signature verification only** inside an
IWA Web Worker. Preview 0.6 uses this baseline verifier for Gmail and decrypted
Chat messages, with MIME parsing/composition in a separate browser module.
OpenPGP encryption/decryption, YubiKey signing and OAuth remain native. The WASM
worker has no extension/native connection and never falls back to native crypto.

The pinned Sequoia fork's RustCrypto backend supports the Level 3
ML-DSA-65 + Ed25519 signatures exercised here. The explicit
`allow-experimental-crypto` and `allow-variable-time-crypto` features are required
by that backend. This is not approval to move secret-key operations into it.
Only public keys and signed data enter this exported API; secret certificates
are excluded. Saved certificate trust remains a separate decision.

## Build and reproduce

Install Rust 1.88.0, its `wasm32-unknown-unknown` target, and
`wasm-bindgen-cli` **0.2.130**. From the repository root:

```sh
sh experiments/mac-iwa/wasm/build.sh
mkdir -p /tmp/iwa-public-fixtures
IWA_PUBLIC_TEST_FIXTURES=/tmp/iwa-public-fixtures \
  cargo test --locked --manifest-path experiments/mac-iwa/crypto/Cargo.toml \
  detached_public_verification_v4_v6_and_tampering
cargo build --release --locked --manifest-path experiments/mac-iwa/crypto/Cargo.toml
python3 experiments/mac-iwa/wasm/tests/prepare.py \
  --fixtures /tmp/iwa-public-fixtures \
  --native experiments/mac-iwa/crypto/target/release/sequoia-iwa-crypto \
  --output experiments/mac-iwa/app/wasm-fixtures.json
node experiments/mac-iwa/wasm/tests/run.mjs experiments/mac-iwa/app/wasm-fixtures.json
```

The native build needs OpenSSL 3.5; set `OPENSSL_DIR` when needed. The native
OpenSSL verifier supplies independent expected results for the WASM RustCrypto
implementation. The fixtures contain newly generated public certificates,
signed MIME bytes and signatures, never private keys. Generated assets and
fixtures are ignored by git. Build them before running the IWA `build.mjs`.

For an existing Proton test, additionally pass `--proton original.eml` and
`--tampered body-altered.eml` to `prepare.py`, writing the result to a **private**
local directory, not `app/`. MIME is extracted using the existing native parser;
the resulting vectors contain exact signed bytes. In the IWA's Hardware test
tab, run the bundled tests or select the private JSON with **Run selected WASM
test vectors**. Files are not uploaded. Expected results are test assertions,
not trust grants. The worker is terminated after each run or a 30-second timeout.

## Validation so far

The actual browser-target WASM module passed eight cases under Node: v4 valid,
v4 altered body, v4 missing certificate; hybrid v6 valid, hybrid v6 altered body,
hybrid v6 missing certificate; original Proton valid and altered Proton invalid.
Status, primary fingerprint, signing fingerprint, algorithm and candidate-only
markers matched the native OpenSSL verifier. Malformed/oversized requests were
rejected. The same eight cases also passed visibly in the installed Chrome Canary IWA
preview **0.5.1**, using a Web Worker with no native fallback. In that single run,
v4 valid verification took 13.8 ms, hybrid v6 10.0 ms, Proton original 1.1 ms and
the altered Proton copy 0.2 ms. These are diagnostic timings, not a controlled
benchmark. Original-message, saved-certificate and trust-file hashes remained
unchanged. The IWA required a Trusted Types policy permitting only the fixed
bundled worker URL; it does not accept user-supplied script URLs.

The signed bundle enables only same-origin asset fetches, same-origin workers
and `wasm-unsafe-eval`; it does not enable JavaScript eval or remote network
origins. The module is about 3.5 MB before transport compression. Baseline builds
do not require experimental wide-arithmetic browser flags. Wide arithmetic remains experimental and is not a prerequisite for the baseline.

## Wide-arithmetic comparison

Preview 0.5.2 includes a second module compiled with
`RUSTFLAGS="-C target-feature=+wide-arithmetic"`, using a separate target directory
and the same Rust 1.88.0 toolchain, dependencies and wasm-bindgen 0.2.130.
`build.sh` builds and copies both variants; set `WASM_BINDGEN` to an isolated CLI
path if needed. Older wasm-bindgen 0.2.105 cannot process these wide opcodes.

The instruction inspector in `inspect/` uses wasmparser to count decoded
operators: baseline has none; wide has 2,966 add128, 91 sub128, one signed wide
multiply and 805 unsigned wide multiplies. Baseline size is 3,536,805 bytes;
wide is 3,512,446 bytes (24,359 bytes smaller).

Choose the public verification JSON, then **Benchmark baseline / wide arithmetic**.
Both modules run in the same fresh worker, with five warmups per case and
21 alternating rounds of five calls per variant. Every call is checked against
the independent native expected result. Medians and p10/p90 summarize batch
means; loading and initialization are excluded. The downloadable report contains
only case names, results, timings, module sizes and browser version, not message
bytes or certificates. No native fallback is allowed.

Canary 160 rejects the wide module with default settings. A separate test-profile
launch with `--js-flags=--wasm-wide_arithmetic` is required; quit its
existing browser process first, since an already running process ignores new
flags. Runtime validation stops explicitly if wide arithmetic is unavailable.
The in-IWA comparison completed successfully on 2026-11-21; results follow.

The installed Canary 160 / V8 16.0.102 binary names this flag
`wasm_wide_arithmetic`; its decoder explicitly requests `--wasm-wide_arithmetic`.
The older `--experimental-wasm-wide-arithmetic` spelling is rejected by this
build. Runtime validation and all eight cases passed with the corrected flag.

### Observed IWA benchmark (2026-11-21)

Installed preview 0.5.2, Canary 160.0.8176.0 arm64, V8 16.0.102 on macOS.
The active isolated-profile process was checked for `--js-flags=--wasm-wide_arithmetic`.
All eight cases matched the native expected verification result in both variants,
for every warmup and measured call. Two UI runs completed successfully; the saved
second run reported these median milliseconds per verification:

| Case | Baseline | Wide | Expected result |
|---|---:|---:|---|
| v4 valid | 0.120 | 0.120 | valid |
| v4 altered body | 0.180 | 0.180 | invalid |
| v4 missing certificate | 0.020 | 0.020 | unknown-key |
| hybrid v6 valid | 0.420 | 0.400 | valid |
| hybrid v6 altered body | 0.860 | 0.740 | invalid |
| hybrid v6 missing certificate | 0.120 | 0.120 | unknown-key |
| Proton original | 0.080 | 0.080 | valid |
| Proton altered body | 0.120 | 0.120 | invalid |

The valid hybrid case was about 5% faster by median, but its timing ranges
overlap (baseline p10–p90 0.380–0.480 ms; wide 0.400–0.440 ms).
The altered hybrid case had a larger measured difference. These short calls
are affected by browser timer quantization and scheduling; no broad speedup is
established. Keep the baseline as the portable default. This measures the full
public verifier, including parsing, not isolated curve or ML-DSA arithmetic.
No native fallback or token operations ran. Original Proton message and saved
certificate/trust file hashes remained unchanged.

## Public encryption

Preview 0.7 adds `encrypt_signed` to the baseline module. It accepts a verified
native signed-packet stream, the exact browser-composed payload, and public sender
and selected recipient certificates. It re-verifies the Level 3 hybrid signature,
requires the expected v6 recipient fingerprint and current email binding, and
selects exactly one live, non-revoked ML-KEM-768 + X25519 transport subkey. It then
compresses the signed packets with ZLIB and encrypts them with fresh randomness
provided by the WASM `getrandom` Web Crypto integration. No secret keys or PINs are
accepted. The browser sends only the resulting ciphertext back for native packet
inspection, one-use review and transport.

`tests/encrypt.mjs` runs the browser-target baseline under Node and independently
decrypts/verifies its output with `TEST_SQ`. Generate its disposable fixture with
`IWA_ENCRYPTION_FIXTURE_DIR` and the native Rust test
`browser_encryption_fixture_and_packet_guards`; use a private temporary directory
and delete it afterward, since it contains a disposable software secret key.
Pass that directory to `node tests/encrypt.mjs`. Set `IWA_CRYPTO_TEST_BIN` to also
exercise the native public packet guard against WASM ciphertext. The test checks
two exact-byte round trips, fresh ciphertext randomness, and rejection cases.
The existing `tests/run.mjs` verification cases remain unchanged.

## Session-key decryption

Preview 0.8 adds `decrypt_with_session_key`. Native YubiKey decapsulation and
OpenPGP key unwrapping return only the per-message session key, symmetric
algorithm, recipient-key fingerprint and exact-ciphertext SHA-256. The baseline
worker authenticates and decrypts the complete AEAD stream, decompresses and
extracts the signed MIME, then uses the existing verification/trust pipeline.
No plaintext result is released on an integrity, signature or trust failure.

The session key is sensitive and exists transiently in Native Messaging and WASM
memory. It is never written to a file or log, and no long-term private key or PIN
crosses into the browser. Main-page references are dropped after worker posting;
the disposable worker is terminated after completion/error/timeout. This limits
lifetime but cannot guarantee erasure of JavaScript/IPC/OS memory copies.

`tests/decrypt.mjs` checks the exact browser-target WASM using a disposable native
Sequoia fixture generated by `native_decapsulation_for_wasm_fixture` with
`IWA_DECRYPTION_FIXTURE_DIR`. Use a private temporary directory and remove it when
finished: this software-only fixture contains a test session key. Tests cover
exact MIME recovery and hybrid verification, wrong keys/lengths/algorithms,
recipient mismatch, ciphertext substitution, final-tag corruption, truncation
and plaintext rejection. Hardware session keys never use the fixture export path.
