# Production hardware worker and separate test oracle

`sequoia-iwa-crypto` is the production worker installed behind the scoped native
host. It accepts public identity/card inspection and only two private operations:
`sign-digest` and `decapsulate-components`. The native host still owns the PIN
prompt, validates its one-use operation grant, checks the selected signed bundle
against the physical card, and fixes backend paths. The worker independently
checks certificate/key/operation bindings. No provisioning API is added.

The browser owns MIME, OpenPGP message packets, verification, hybrid combining,
session-key recovery and message encryption/decryption. The production worker
rejects the former `seal`, `open`, `sign-browser`, `open-browser`,
`decapsulate-browser`, `verify-detached` and `check-ciphertext` modes before
parsing a PIN or backend configuration. Public certificate inspection remains
native where needed to validate hardware authority and safely export an explicit
legacy public-store migration.

## Build and install the production executable

From the repository root, using Rust 1.88 or newer:

```sh
cargo build --locked --release \
  --manifest-path experiments/mac-iwa/crypto/Cargo.toml \
  --bin sequoia-iwa-crypto
experiments/mac-iwa/crypto/target/release/sequoia-iwa-crypto --capabilities
```

With no `CARGO_TARGET_DIR` override, the path above is the production executable.
The capabilities command is a side-effect-free public contract: it does not read
stdin, configuration, credentials or a card. `install_native.py` and
`install_chat.py` check its exact operation set and reject a test oracle or old
broad worker before copying files. A production update must preserve the existing
native enrollment and PKCS#11 binaries unless separately authorized.

## Explicitly build the historical message oracle

`examples/message_oracle.rs` retains the independent OpenSSL-backed message
algorithms used by earlier interoperability tests and vector generation. It is
not an installed helper, not a native-host RPC and not a fallback. Historical
Terminal hardware diagnostics must explicitly select it; that selection never
authorizes an automatic retry or a change to a key/policy.

```sh
cargo build --locked --release \
  --manifest-path experiments/mac-iwa/crypto/Cargo.toml \
  --example message_oracle
export IWA_CRYPTO_ORACLE_BIN="$PWD/experiments/mac-iwa/crypto/target/release/examples/message_oracle"
export IWA_CRYPTO_TEST_BIN="$PWD/experiments/mac-iwa/crypto/target/release/sequoia-iwa-crypto"
```

`IWA_CRYPTO_TEST_BIN` continues to mean the production worker for identity and
component-boundary tests. `IWA_CRYPTO_ORACLE_BIN` is separate: only historical
MIME/trust fixtures and public message oracles use it. WASM vector preparation
now takes `--oracle "$IWA_CRYPTO_ORACLE_BIN"`; `wasm/tests/encrypt.mjs` uses the
same variable for its optional independent packet check. `piv_soak.py` requires
`--oracle PATH` and rejects the production executable before any PIN prompt.

`cargo test --locked --manifest-path experiments/mac-iwa/crypto/Cargo.toml` runs
production unit tests and the explicitly declared oracle example tests. The
fixture example and its private disposable test files must never be shipped,
used with account credentials, or confused with hardware-only key storage.

Python process-boundary tests additionally verify that retired modes cannot be
invoked on the production worker and that installation rejects the oracle:

```sh
python3 -m unittest discover -s experiments/mac-iwa/tests \
  -p 'test_production_worker.py'
```

All tests described here use disposable software data unless an operator
explicitly chooses and authorizes a separate hardware diagnostic. No card
write, key generation or touch-policy command exists in the production worker.
