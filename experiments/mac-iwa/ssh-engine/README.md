# Browser SSH engine

Go 1.27.4, golang.org/x/crypto 0.59.0 and x/sys 0.50.0. The browser receives only
WASM and the matching Go runtime; no Go toolchain or SSH executable is installed
on the user's computer. Rebuild after updating the pinned dependencies.
The build uses Python 3 to expose RFC 8308's `server-sig-algs` in a temporary
copy of the pinned Go module. The module cache and committed Go pins are
unchanged. The extra field lets authorization review the server's advertised
login algorithms before it asks for a password.

```sh
GO_BIN=/path/to/go ./build.sh
/path/to/go build -o /tmp/pqmail-ssh-testserver ./cmd/testserver
SSH_TEST_SERVER=/tmp/pqmail-ssh-testserver node test-wasm.mjs
```

Use Node 24 for the test. The server binds only loopback and generates disposable
Ed25519 user/host keys in memory. Its stdout contains only these disposable test
credentials. Do not use the test server with real credentials or package it.

`engine.go` owns the SSH connection and PTY. `composite.go` implements the draft
ML-DSA-44/Ed25519 transcript and verifies external signatures before sending.
`cmd/wasm` adapts asynchronous worker streams to `net.Conn`. The app worker opens
Direct Sockets, delegates host trust and scoped signing to the unlocked vault,
and terminates on lock/disconnect. This is an experimental implementation,
not a claim of audited cryptography or live composite-server interoperability.

The xterm.js distribution is bundled locally. The IWA build adds a style nonce
to its generated style elements and the matching CSP, without enabling arbitrary
inline scripts or styles. No clipboard/link addons are enabled. Host certificates
and composite server host keys are not supported yet; imported CA records are
preserved but cannot authorize an unsupported host-certificate handshake.
