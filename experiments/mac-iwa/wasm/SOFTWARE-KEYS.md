# Experimental software OpenPGP custody

The IWA creates, imports, signs with, decrypts with, and exports software
identities without sending their private keys or passwords to the extension,
native helper, `gws`, Sequoia CLI, or hardware adapter. The encrypted identity and
its independent random storage password live inside the existing PRF/PIV vault.
Only an explicit encrypted export asks for a user-chosen export password.

This is software custody, not hardware-equivalent storage. Private operations
use a fresh disposable WASM worker. Locking, cancellation, account changes and
navigation terminate pending work and discard late results. Whole-vault backup
and restore already includes these entries; portable per-identity exports are
an additional option and do not alter the vault's password or enrolled methods.

## Accepted profiles

| Profile | Public version | Certification / signing | Encryption |
| --- | --- | --- | --- |
| `level3` (default) | v6 | Separate ML-DSA-65 + Ed25519 certification and signing keys | ML-KEM-768 + X25519 |
| `level5` | v6 | Separate ML-DSA-87 + Ed448 certification and signing keys | ML-KEM-1024 + X448 |
| `level3-v4-hybrid` | v4 | Dedicated classical Ed25519 certification/signing primary | ML-KEM-768 + X25519 |
| `level3-v4-classical` | v4 | Dedicated classical Ed25519 certification/signing primary | Classical X25519 using RFC 6637 |
| `level5-v4-hybrid` | v4 | Dedicated classical P-521 certification/signing primary | ML-KEM-768 + X25519 |
| `level5-v4-classical` | v4 | Dedicated classical P-521 certification/signing primary | Classical P-521 using RFC 6637 |
| `level3-v5-hybrid` (optional) | LibrePGP v5 | Dedicated classical Ed25519 certification/signing primary | LibrePGP ML-KEM-768 + X25519 |

The Level 5 v4 hybrid compatibility profile intentionally uses ML-KEM-768, not
ML-KEM-1024: that is its compatibility algorithm, not Level 5 encryption. All
v4/v5 signing listed above is classical. It requires the UI's compatibility
warning; hybrid encryption does not make a classical signature post-quantum.
The v5 combiner and signature hashing differ from RFC 9580/RFC 9980 and have a
separate implementation. The default remains v6 hybrid.

Creation generates independent software keys for the selected profile. It does
not repurpose a composite component as a standalone classical key, write a
YubiKey, or grant trust to a contact. v6 identities have exactly three encrypted
key packets: certification primary, signing subkey and encryption subkey. v4
views have exactly two: certification/signing primary and one encryption subkey.
Ambiguous message-key selections are rejected.

## Import and portable encrypted export

v4/v6 imports accept one password-encrypted OpenPGP transferable secret key
(TSK), binary `.pgp`/`.gpg` or armored `.asc`. Every private packet must be
protected. Public-only files, plaintext/mixed key packets, multiple certificates,
expired/revoked identities, unsupported profiles and mismatched private seeds
are rejected. Sequoia checks self-certifications, current certified mailboxes,
subkey bindings, flags, revocations and expiration. Seed-derived public keys
must match every private packet's certified public key.

Portable v4/v6 export re-encrypts the existing secret packets using a new export
password of at least 12 UTF-8 bytes. It preserves all public packet bytes,
self-signatures and fingerprints, and never exports a plaintext secret key.
Restoring is the same validated import path; duplicate exact certificates are
rejected. Different hybrid/classical views with the same primary fingerprint
are allowed because their full certificate hashes differ.

The optional v5 identity uses a **`.pqidentity` encrypted backup**, not an
OpenPGP secret-key packet. Its standard LibrePGP public certificate is carried
with the three private seeds in an authenticated AES-256-GCM envelope.
PBKDF2-HMAC-SHA256 uses a random 16-byte salt and 600,000 iterations; each export
has a random 12-byte nonce and a fixed domain-specific AAD. Import permits only
100,000–1,000,000 iterations and validates the decrypted seeds against the full
v5 public certificate before use. Public certificate exports remain ordinary
LibrePGP certificates. Do not rename `.pqidentity` as `.pgp` or expect GnuPG to
import the private backup directly.

## Operational PQ Mail `.p12` import

The importer supports **PQ Mail's Level 5 software OpenPGP PKCS#12 keyset**,
not arbitrary PKCS#12/X.509 identities or S/MIME-only `.p12` files. It imports
existing key material and certificate signatures; it does not issue replacement
OpenPGP certificates or change their fingerprints.

The disposable software worker:

1. Bounds the PFX/BER structure (1 MiB, 8,192 nodes, depth 24) and authenticates
   the complete `AuthenticatedSafe` before decrypting bags.
2. Accepts PKCS#12 HMAC-SHA1 or HMAC-SHA256 MACs with bounded password derivation.
   SHA-1 is supported only for the legacy PFX password MAC, never new OpenPGP
   signatures. MAC comparison is constant-time in the Rust HMAC implementation.
3. Decrypts PBES2 AES-128/AES-256-CBC with explicit PBKDF2-HMAC-SHA256/384/512
   and bounded iterations. Legacy bag ciphers and implicit SHA-1 PBKDF2 are
   rejected. Keys remain in worker memory.
4. Requires all ten `pgp5-*` aliases and matching certificate/key local IDs.
   The metadata extension `2.25.302661978184745645819285730512635507321` supplies
   the existing v6 and v4 public keyrings.
5. Reads only the recognized PKCS#8 algorithms and seed encodings. Where Bouncy
   Castle stores both PQ seed and expanded private key, it regenerates and
   compares the expanded bytes as well as the derived public components.
6. Reconstructs password-protected OpenPGP secret packets and returns the v6
   identity plus hybrid/classical v4 views for atomic vault import. The classical
   view retains its already-signed subkey binding; no new signature is created.

The ten aliases are `cert-ml`, `cert-ed`, `sign-ml`, `sign-ed`, `kem-ml`, `kem-x`,
`v4-sign`, `v4-ml`, `v4-x`, and `v4-ec`, each prefixed with `pgp5-`. Other `.p12`
formats fail with a fixed import error and are not silently converted.

## Cryptographic and lifecycle boundaries

All request schemas are closed and bounded. Errors contain no supplied password,
key, ciphertext, subprocess output or internal stack. v4/v6 key protection uses
AES plus modern iterated SHA-256/384/512 S2K (1,024–65,011,712 hashed bytes), or
Argon2 with time 1–4, parallelism 1–4 and memory exponent 10–16 (at most 64 MiB).
These lower import bounds are compatibility limits, not password-strength
recommendations. Newly encrypted TSKs use the pinned Sequoia defaults; the vault
adds separate authenticated encryption and a random 256-bit storage password.

Signing permits only the selected certified signing key and a bound SHA-512
request. Decryption permits only the selected recipient and its exact algorithm
component sizes. ML-KEM implicit rejection is preserved. Noncontributory X25519
and X448 inputs and invalid P-521 points are rejected. No partial component
reply escapes, and the message worker independently authenticates the recovered
session key and message. Hardware and software errors never fall back to one
another's keys.

The backend pins Sequoia commit `65979cf360ec0908c793d8801dd4491da2b8398d` and
Cargo.lock versions. Its RustCrypto backend requires
`allow-variable-time-crypto`; that flag is an acknowledgement, not a constant-
time or side-channel guarantee. The selected private primitives now include
`ed25519-dalek`, `x25519-dalek`, `cx448`, `p521`, `ml-dsa` and `ml-kem`. This work
is not an independent cryptographic audit; the ML crates themselves state that
they have not been independently audited.

`zeroize` features, `Protected` buffers and worker termination reduce private
material lifetime. JavaScript strings, JSON/structured-clone copies, browser
internals, allocators, swap and crash dumps cannot be reliably erased by this
code. A compromised unlocked browser or operating system can access software
private material. An identity cannot unlock the vault protecting itself; an
independently enrolled passkey or hardware wrapper is required.

## Regression coverage and disposable browser fixture

The Rust suites exercise profile generation, wrong-password/tamper rejection,
exact private/public correspondence, key roles, re-encrypted export with
unchanged fingerprints, v5 authenticated backups, MAC vectors, malformed/large
requests and message round trips. Browser tests exercise atomic import, lock,
restart, duplicate handling, cancellation, account matching and provider routing.
Independent Sequoia/GnuPG message tests are separate from these in-process tests.

Run `cargo +1.88.0 test --locked --manifest-path experiments/mac-iwa/wasm/Cargo.toml`.
For a disposable PQ Mail PFX decoded fixture, set `IWA_P12_DECODED_FIXTURE` to a
private local JSON file produced by the authenticated worker decoder. The
optional test imports it and confirms the original v6 and both v4 public views.
Never commit that fixture: its decoded PKCS#8 bags contain private software keys.
The earlier `IWA_SOFTWARE_FIXTURE_DIR` generator remains available for disposable
Level 3 worker tests; its test inputs also contain a synthetic password and must
stay outside the source tree.
