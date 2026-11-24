# Experimental software OpenPGP custody

The IWA can import a password-encrypted OpenPGP transferable secret key (TSK),
then keep that encrypted file and its password inside its PRF-encrypted vault.
This is a separate provider from the public-only hardware workers. It never
sends a software key or its password to the extension, native helper, `gws`,
Sequoia CLI, or a hardware adapter.

## Accepted identity and operations

The initial provider deliberately accepts only one v6 Level 3 certificate with
exactly these three password-encrypted key packets:

| Role | Algorithm | Requirements |
| --- | --- | --- |
| Certification primary | ML-DSA-65 + Ed25519 | Certification flag, no signing/encryption flags |
| Message signing subkey | ML-DSA-65 + Ed25519 | Current valid signing binding, separate from primary |
| Message encryption subkey | ML-KEM-768 + X25519 | Current valid transport-encryption binding |

Sequoia policy validation checks the certificate, current self-certified email
addresses, revocations, expiration and subkey bindings. Import checks *all*
three encrypted private packets and derives their public components to compare
against the certificate. A valid public certificate with unrelated private
seeds is rejected. Public-only files, plaintext or mixed plaintext/encrypted
TSKs, missing keys, extra or ambiguous message keys, v4/v5 and other algorithms
are rejected. A password-encrypted `.pgp` or ASCII-armored `.asc` file is accepted;
PKCS#12, hardware companion storage and new-key generation are outside this API.

`software_inspect` returns only the existing canonical public identity metadata.
`software_sign` signs the selected signing-subkey digest and returns the same
Ed25519/ML-DSA component reply as the hardware provider. `software_decapsulate`
returns only the two bound ML-KEM/X25519 component shares. Recipient parsing,
hybrid combining, session-key recovery, AEAD checks, final packet construction
and signature verification stay in the existing signing/decryption workers.
ML-KEM implicit rejection remains intact; a damaged ML-KEM ciphertext yields a
different component secret and fails the envelope authentication check. X25519
low-order/noncontributory inputs are rejected before a reply is returned.

## Closed request schemas and limits

All exports take one JSON string and return one JSON string. Unknown or missing
object fields are rejected. Error strings are fixed and contain no supplied
password, key, ciphertext, internal exception or diagnostic stack.

- Inspect: `{encryptedSecret, password}`.
- Sign: `{encryptedSecret, password, request}` where request has exactly
  `{requestId, signingFingerprint, hashAlgorithm, digest}`.
- Decapsulate: `{encryptedSecret, password, request}` where request has exactly
  `{requestId, cipherHash, recipientKey, mlkemCiphertext, x25519Ephemeral}`.

`encryptedSecret` is canonical base64 of at most 256 KiB of the original binary
or armored encrypted file. Passwords contain 1–1024 UTF-8 bytes; the JSON request
is at most 400,000 bytes. Request IDs and fingerprints are 64 uppercase hex
characters; cipher hashes are 64 lowercase hex characters. Signing permits only
SHA-512 (OpenPGP algorithm 10) and a 64-byte digest. Decapsulation requires an
1088-byte ML-KEM-768 ciphertext and a 32-byte X25519 public input. Encodings must
be canonical base64 with the exact component lengths. A selected fingerprint
must equal the currently valid message subkey in the decrypted certificate.

Before deriving any password key, every secret packet is checked. Protection
must use AES-128, AES-192 or AES-256, plus either:

- Iterated S2K with SHA-256/384/512 and a decoded count from 1,024 to 65,011,712
  bytes; or
- Argon2 with time cost 1–4, parallelism 1–4, and memory exponent 10–16 (at most
  64 MiB per derivation).

The lower import bounds permit existing password-encrypted files; they are not
password-strength recommendations. The standalone Sequoia identity helper's
normal v6 protection uses AES-128/OCB and SHA-256 iterated S2K at the maximum
representable count, 65,011,712. The fixture test exercises those real defaults.
The vault supplies a separate authenticated encryption layer for persistent
storage. These resource limits and the worker deadline prevent an imported
file from choosing unbounded KDF work; they do not guarantee a fixed latency.

## Review of the pinned private implementations

This review covers the selected source paths, not an independent cryptographic
or side-channel audit. The build pins Sequoia commit
`65979cf360ec0908c793d8801dd4491da2b8398d` and Cargo.lock versions.

- Sequoia's `openpgp/build.rs` requires `allow-variable-time-crypto` for its
  **whole RustCrypto backend**. That feature flag is an acknowledgement, not a
  guarantee that any particular private algorithm is safe. Enabling it does
  not authorize arbitrary private-key algorithms in this provider.
- `openpgp/src/crypto/backend/rust/asymmetric.rs` routes the accepted Ed25519
  signing to `ed25519-dalek` 2.2.0 and the accepted ML-DSA signing to `ml-dsa`
  0.1.2. X25519 uses `x25519-dalek` 2.0.1; ML-KEM uses `ml-kem` 0.3.4.
- The ML-DSA implementation has explicit constant-time division and selection
  code; the ML-KEM implementation preserves constant-time implicit rejection.
  These observations do **not** establish constant-time behavior for compiled
  WebAssembly, the browser/JIT, every code path, or the complete application.
  The pinned ML-DSA and ML-KEM crate READMEs explicitly state that their
  implementations have not been independently audited.
- The `zeroize` features are enabled for the four selected private primitives.
  Sequoia's `crypto/mem.rs` clears `Protected` buffers on drop. This module
  clears its owned password string after constructing `Password`, scopes
  decrypted keypairs to one call, and uses `Zeroizing` for transient buffers
  where practical. RSA/DSA/ECDSA/Ed448/X448 private operations are not reachable
  through this provider even though dependencies for other public operations
  occur in Sequoia's broader backend graph.

Relevant primary sources: [pinned Sequoia backend](https://github.com/ve7jtb/sequoia/tree/65979cf360ec0908c793d8801dd4491da2b8398d/openpgp/src/crypto/backend/rust),
[RustCrypto ML-DSA](https://github.com/RustCrypto/signatures/tree/master/ml-dsa),
[RustCrypto ML-KEM](https://github.com/RustCrypto/KEMs/tree/master/ml-kem), and
[dalek cryptography](https://github.com/dalek-cryptography/curve25519-dalek).
The reviewed versions are the locked local sources, not the moving default
branches linked for project context.

## Memory and lifecycle boundary

Each private call runs in a fresh dedicated worker. The worker is terminated on
success, failure, cancellation or vault lock; the main thread rejects stale
results after vault epoch or identity revisions change. No unlocked long-term
key object, password handle, signing state or private-key cache persists inside
this module. The vault remains the sole persistent store of the encrypted file
and password. It never stores the derived private components or session shares.

JavaScript strings, structured clones, JSON buffers, browser internals, allocator
copies, swap and crash dumps cannot be reliably erased by this code. Zeroization
and worker termination reduce lifetime; they do not establish absence of copies
or hardware-equivalent custody. A compromised unlocked browser or operating
system can access software private material. The UI therefore labels this
provider experimental software custody and requires an explicit import review.
A software identity also cannot bootstrap unlocking the vault that protects it;
use an independently enrolled PRF credential or hardware vault wrapper.

## Regression coverage and disposable browser fixture

Rust tests cover binary/armored import, public-only/mixed/plaintext/incomplete
identities, multiple certificates, wrong passwords, tampered encrypted files,
private/public mismatches, expiration/revocation, unsupported profiles, wrong
roles, excessive KDFs, obsolete ciphers, input limits, exact request bindings,
wrong selected keys, noncontributory X25519 and ML-KEM implicit rejection. A full
round trip uses the existing split-signing exports, independent Sequoia
signature validation/encryption, split decapsulation and signature verification.
The existing decryption suite separately rejects changed bindings, changed
shares and final AEAD tag tampering.

Run the Rust suites with `cargo +1.88.0 test --locked --manifest-path
experiments/mac-iwa/wasm/Cargo.toml`. The optional
`software::tests::export_disposable_encrypted_software_fixture` test writes a new
private directory only when `IWA_SOFTWARE_FIXTURE_DIR` is supplied. Optional
`IWA_SOFTWARE_FIXTURE_EMAIL` and `IWA_SOFTWARE_FIXTURE_PASSWORD` configure a newly
generated test identity; no existing user secret is read. Its files are an
encrypted TSK, public certificate and synthetic browser-test inputs. Keep the
directory outside the source tree; the JSON test inputs contain the disposable
password and must never be treated as a user credential export format.
