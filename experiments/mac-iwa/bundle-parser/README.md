# Shared public certificate bundle parser

`sequoia-public-bundle` is the single public decoder used by the IWA's WASM
identity worker and the native helper's independent authorization path. It
accepts immutable compressed public bytes, validates the bounded `PQMZIP01`
container and pure/composite envelope signature, and checks the supported
Level 3 OpenPGP/S/MIME component bindings. There is no device, PIN, subprocess,
filesystem, network or persistence API.

- `verify(bytes)` returns a `VerifiedBundle` whose fields cannot be constructed
  by callers. `serial()` and `public_keys()` expose the authenticated serial and
  canonical component SPKIs for independent physical-card checks.
- `VerifiedBundle::preview()` emits only public inventory material and always
  reports `liveKeysMatched: false`, `source: file` and generation zero.
- `inspect(json)` is the strict browser request wrapper. Its only accepted
  field is the canonical base64 `bundle`; callers cannot inject authority flags.

The parser accepts the three-key RFC 9980 profile created by backup-first
provisioning. The optional experimental NIST certificate is carried as opaque,
signed data in a noncritical `PQMAILB3` extension. The B3 envelope may expand
to 80 KiB, above the base format's 64 KiB limit, to fit the complete additional
certificate. The stored single-bank limit remains 64 KiB.

Native authorization reads the committed bank itself, calls `verify`, compares
all expected SPKIs against live card reads, and rereads the same objects, keys
and serial before adding live-match evidence. Sharing code does not share a
browser decision or weaken native authorization. File freshness is not inferred
from a successful signature or key match. The transport's checksum alone is not
signature verification.

Public-only cross-implementation fixtures are shared with the native and WASM
integration suites. They cover both envelope signature components, complete
OpenPGP role bindings, classical compatibility views, malformed compression,
trailing data, substituted public keys and secret-key rejection. Run:

```sh
cargo +1.88.0 test --locked --manifest-path experiments/mac-iwa/bundle-parser/Cargo.toml
```

The crate uses the same pinned public Sequoia/RustCrypto backend on native and
WASM targets. The native PIV operation adapter retains its separately pinned
OpenSSL backend; only owned public JSON and SPKI bytes cross this boundary, not
Sequoia types. The original adapter decoder remains independently usable by the
standalone project, but it is no longer invoked by the IWA native restore path.
