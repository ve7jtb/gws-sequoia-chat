# gws + Sequoia Chat

Standalone encrypted Google Chat bundles using [Google Workspace CLI (`gws`)](https://github.com/googleworkspace/cli) for transport and [Sequoia `sq`](https://sequoia-pgp.org/) for OpenPGP. No PQ Mail installation, Java runtime, `.p12` identity, or PQ Mail vault is needed.

This is an experimental command-line integration, not an official Google or Sequoia product. The transport uses Google's documented Chat API. A local browser interface is not implemented yet.

## What gets sent

Each bundle uses two linked Chat messages, with one attachment per message. Google Chat rejects multiple non-media attachments in a single message:

* `message.pgp`: standard signed-and-encrypted OpenPGP containing ZIP- or ZLIB-compressed multipart MIME, with text, optional HTML, and files. From, To and Subject are inside the signature and encryption.
* `pq-mail-sender-key.pgp`: the sender's public v6 OpenPGP certificate, separately downloadable. Its email addresses and fingerprint are visible to Google and everyone in the space.

The bundle caption is generic and references the certificate message. The receiver accepts only references in the same conversation from the same Google sender; this is a transport check, not a trust decision. A recipient can download both files and use Sequoia directly; no proprietary archive or PQ Mail parser is needed. A certificate arriving with a message is **not automatically trusted**. The wrapper requires an explicitly selected sender certificate and full primary fingerprint, checks the signature before exposing MIME, and compares signed From/To with the selected identities. The Google account name is not treated as proof of the OpenPGP sender's email address.

Supported software profiles:

| Profile | Certification/signing | Encryption |
| --- | --- | --- |
| Level 3 | ML-DSA-65 + Ed25519 | ML-KEM-768 + X25519 |
| Level 5 | ML-DSA-87 + Ed448 | ML-KEM-1024 + X448 |

Both use v6 certificates and RFC 9980 hybrid algorithms. The wrapper rejects classical-only certificates rather than silently falling back. Mixed v6 recipient/signer certificates are filtered to their hybrid subkeys without changing primary-key packets, binding signatures, or the primary fingerprint; Sequoia validates those bindings. Sequoia performs cryptographic validation, key selection, expiry/revocation checks and the private operations.

## Install

Requirements: Python 3.9+, `sq` with RFC 9980 support (tested with sq 1.5.0 / sequoia-openpgp 2.4.1), and its native crypto dependencies. Obtain Sequoia through its [installation documentation](https://sequoia-pgp.org/download/), using a supported, patched crypto backend. Ordinary older `sq` packages may not implement the hybrid algorithms; check `sq key generate --help` for `mldsa65-ed25519` and `mldsa87-ed448`.

```sh
python3 install.py --sq /absolute/path/to/sq
```

The installer downloads official gws v0.22.5 and verifies its published SHA-256. It copies only the executables; dynamically linked Sequoia libraries must remain installed. The current shell wrapper is tested on macOS Apple Silicon; Linux is intended but untested. Windows binaries exist upstream, but this wrapper currently requires a POSIX environment such as WSL. Android/iOS and a browser UI are not included.

## Separate Google authorization

Someone must register a Google OAuth **Desktop app** client, enable and configure Google Chat API, and add permitted test accounts while the OAuth app is in Testing. Multiple users can share that client registration; each grants their own access. This project does not ship a universal client or any credentials. Workspace administrators can also restrict third-party apps. Google documents Workspace prerequisites for Chat API; personal Gmail availability must be tested, not assumed.

Save the downloaded client JSON at `private/gws/client_secret.json` and restrict its permissions:

```sh
mkdir -p private/gws
chmod 700 private private/gws
chmod 600 private/gws/client_secret.json
python3 chat.py login
python3 chat.py spaces
```

Select **all three Chat permission checkboxes** before Continue: list spaces, read messages/attachments, and create messages/attachments. gws also requests OpenID, email and basic profile information. Its login success message reports requested scopes; `spaces` verifies actual API permission. This login requests no Gmail access.

gws stores its own Google OAuth refresh token in `private/gws/credentials.enc`. On macOS the encryption key is in the `gws-cli` Keychain item. No PQ Mail refresh token or passkey vault is read. This is gws's ordinary OS-keyring protection, **not** PRF or a guaranteed biometric-per-operation gate. gws's Linux backend can fall back to a local encryption-key file; review that before using persistent credentials on Linux. Do not use `gws auth export --unmasked` for routine operation.

Use isolated account profiles without replacing the default session:

```sh
GWS_CHAT_PROFILE=second-account python3 chat.py login
GWS_CHAT_PROFILE=second-account python3 chat.py spaces
```

Each profile has its own encrypted credential files under `private/profiles/`. The wrapper copies only OAuth client registration metadata into a new profile. It never copies account tokens. `gws-chat` also exposes ordinary gws commands with this isolation. Run real authenticated commands outside a restricted sandbox: upstream gws may delete its encrypted credential file if a sandbox denies Keychain access and it mistakes that for undecryptable storage.

## Create an independent identity

```sh
python3 chat.py identity --email alice@example.org --level 3 --output private/alice
python3 chat.py inspect private/alice/public.pgp
```

Sequoia prompts in Terminal to password-protect `secret.pgp`. Keep that key and `revocation.pgp` private. Share only `public.pgp`. There is no public CLI option for creating an unprotected identity. Tests use disposable, automatically removed fixtures.

## Prepare, send, receive, verify

Obtain the recipient's public certificate and verify its **full fingerprint independently**. Supplying a fingerprint copied from an untrusted attachment is only consistency checking, not identity authentication.

```sh
python3 chat.py pack --identity private/alice \
  --recipient-cert private/bob-public.pgp --recipient-fingerprint FULL_64_HEX_FINGERPRINT \
  --sender alice@example.org --recipient bob@example.org \
  --subject 'Encrypted Chat test' --text-file private/body.txt \
  --html-file private/body.html --attachment private/example.pdf --output private/outgoing-1

python3 chat.py spaces
python3 chat.py send --space spaces/SPACE_ID --bundle private/outgoing-1
python3 chat.py messages spaces/SPACE_ID
python3 chat.py receive --message spaces/SPACE_ID/messages/MESSAGE_ID --output private/download-1

python3 chat.py unpack --identity private/bob --bundle private/download-1/message.pgp \
  --signer-cert private/alice-public.pgp --fingerprint ALICE_FULL_64_HEX_FINGERPRINT \
  --sender alice@example.org --recipient bob@example.org --output private/verified-1
```

`send` shows the destination, recipient fingerprint and public-certificate disclosure, and requires typing `SEND`. It does not automatically retry a failed POST. A saved request ID helps investigate an uncertain send. Reusing an attempted output directory is refused to avoid duplicate sends. `spaces` and `messages` return next-page tokens; pass `--page-token` for the next page.

`unpack` saves verified MIME, plain text, HTML **source as text**, numbered attachment files, and a verification report. It never launches a browser or executes HTML, scripts, links or attachments. Input filenames cannot choose filesystem paths. Failed signature/decryption output remains in temporary staging and is deleted. Content is not automatically saved to a contacts/trust store.

For direct Sequoia interoperability:

```sh
sq --home=none --cert-store=none --key-store=none decrypt \
  --recipient-file private/bob/secret.pgp --signer-file private/alice-public.pgp \
  --signatures 1 --output verified.mime message.pgp
```

Limits: 20 MiB encoded/decompressed MIME, 10 MiB total files, 20 attachments, 100 MIME parts and 12 nesting levels. Temporary compose MIME is deleted after encryption; explicitly exported verified content stays on disk until you remove it. Files/directories use owner-only permissions. No claimed secure erasure guarantee is made for filesystem deletion.

## Independent YubiKey adapter

The separate Rust crate is [`sequoia-pqmail-piv`](https://github.com/ve7jtb/sequoia/tree/development/yubikey6-piv/piv-adapter), on branch [`development/yubikey6-piv`](https://github.com/ve7jtb/sequoia/tree/development/yubikey6-piv). It implements Sequoia's `Signer` and `Decryptor` interfaces for Level 3 YubiKey 6 PIV, with no provisioning or policy changes. It is a separate library dependency, not copied into this transport project, and is not published on crates.io.

This initial Chat CLI uses software OpenPGP keys. Stock `sq` does not automatically discover that adapter. A future helper can expose the adapter through a fixed local API, reuse the PKCS#11 native helpers, and add FIDO PRF protection for local keys. It must preserve the separation between Google authorization, OpenPGP identity trust, and token PIN/touch authorization. No such hardware/PRF integration is claimed by this repository yet.

## Successful live two-way test — 2026-11-20

Signed and encrypted Level 3 Google Chat messages passed in both directions
between a Workspace account using this standalone CLI and a personal Gmail
account using the installed Mac [PQ Mail app](https://github.com/ve7jtb/pq-mail/tree/feature/on-key-certificates).
The CLI used an encrypted software identity and its own gws OAuth profile;
PQ Mail used its PRF-vault Chat session and a YubiKey 6 PIV identity through PKCS#11.

| Direction | Confirmed result |
| --- | --- |
| gws + Sequoia → PQ Mail | Downloaded files matched uploaded bytes; PQ Mail decrypted with the YubiKey, verified the trusted hybrid signer, and displayed the formatted HTML body. |
| PQ Mail → gws + Sequoia | The bundle and linked certificate downloaded; the certificate matched the independently selected signer; Sequoia decrypted and returned a valid signature. Signed From/To, Subject and body matched. |

Both directions used **ML-DSA-65 + Ed25519** and **ML-KEM-768 + X25519**.
The return encrypted packet used AES-256/OCB. Existing token keys and policies
were reused. This live result is limited to the tested accounts and Level 3;
it does not establish universal personal-Gmail eligibility or Level 5 hardware
Chat support. Accounts, certificates, message IDs, raw results and secrets remain
local. The separate offline suite below covers additional software profiles.

## Tests

```sh
python3 -B -m unittest -v test_chat
```

Fourteen tests passed locally on macOS: real Sequoia Level 3 and Level 5 signed/encrypted round trips with ZIP/ZLIB, text/HTML alternatives and binary attachments; wrong-signer and tampering rejection; mixed-certificate hybrid-only selection; fingerprint/email checks; secret-key rejection; bounded reads; path/header guards; and mocked Chat attachment transport, isolated transfer staging, and linked-certificate sender/conversation checks. These tests do not send messages or use account tokens. Live Google Chat send/receive status is recorded separately when performed; offline tests alone do not establish it.

Source license: MIT. Google Workspace CLI and Sequoia retain their own licenses. No third-party binaries, OAuth configuration, accounts, private keys, messages or local test reports are committed.

## Level 3 identity with compatibility certificates

The optional `identity-helper` generates three certificate views from eight
independent private components. It is a standalone Sequoia Rust program; it
neither invokes PQ Mail nor accesses a YubiKey.

| Certificate | Certification/signing | Encryption |
| --- | --- | --- |
| v6 | Separate ML-DSA-65 + Ed25519 certification primary and signing subkey | ML-KEM-768 + X25519 |
| v4 hybrid | Dedicated legacy Ed25519 primary (certify/sign) | The same hybrid KEM components as v6 |
| v4 classical | Same v4 Ed25519 primary | Dedicated classical X25519 |

The two v4 views share their primary fingerprint. Classical keys are separate
from the components of hybrid keys. The Chat wrapper always uses the v6 hybrid
identity; compatibility certificates are available for other OpenPGP clients.

Build the helper from its pinned public Sequoia fork revision (requires Rust 1.87 or newer,
OpenSSL development libraries and the Sequoia build prerequisites):

```sh
cargo build --locked --release --manifest-path identity-helper/Cargo.toml
identity-helper/target/release/chat-software-identity alice@example.org private/alice-compatible
TEST_SQ="$PWD/bin/sq" cargo test --locked --manifest-path identity-helper/Cargo.toml
```

The helper takes `EMAIL NEW-DIRECTORY` and prompts twice for a
new password in Terminal. The output contains encrypted `secret.pgp`,
`v4-hybrid-secret.pgp`, and `v4-classical-secret.pgp`; public equivalents;
revocations; and a public `migration-plan.txt`. Keep secret and revocation files
private. No unencrypted private-key staging file is created. Existing output
directories are refused.

The future empty-device PIV import layout is 86/87 for hybrid certification,
9c/84 for hybrid signing, 9d/85 for hybrid decryption, and 88/89 for classical
signing/decryption. These are eight components, not eight OpenPGP certificates.
Preserving the components, creation times and certificate packets permits later
hardware use without changing fingerprints. This generator does **not** perform
hardware import or claim that an import has been tested. Software backups remain
capable of private operations after migration. Extra S/MIME P-384 keys are not
part of this OpenPGP-only identity.

The helper pins the public Sequoia fork by commit in its Cargo manifest and lockfile. Its tests check password protection, wrong-password rejection,
public-only exports, shared KEM material, refusal to overwrite, and signed and
encrypted round trips for all three certificate views using `TEST_SQ=/path/to/sq`.
