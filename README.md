# gws + Sequoia Mail & Chat

A standalone local browser app and CLI for encrypted Google Chat bundles and OpenPGP email, using [Google Workspace CLI (`gws`)](https://github.com/googleworkspace/cli) for transport and [Sequoia `sq`](https://sequoia-pgp.org/) for OpenPGP. No PQ Mail installation, Java runtime, `.p12` identity, or PQ Mail vault is needed.

This is an experimental integration, not an official Google or Sequoia product. The local browser UI uses a native Python helper with gws and Sequoia. Chat uses Google's documented Chat API; the new mail preview uses Gmail API and standard signed-and-encrypted PGP/MIME. See [Local browser app](#local-browser-app-mac-preview) and [Gmail preview](#gmail-preview).

**IWA 0.20.15 fixes the direct Web Smart Card mail path and makes Enter
submit FIDO PIN dialogs.** A Chromebook Gmail self-test passed on 2026-11-25:
v6 ML-DSA-65 + Ed25519 signing, ML-KEM-768 + X25519 encryption, Gmail delivery,
and decryption with trusted-signature verification. The successful receive
retry used 0.20.14; 0.20.15 adds the regression-tested FIDO keyboard behavior.
No YubiKey keys or touch policies were changed. See the
[validation and fixes](experiments/mac-iwa/README.md#chromebook-gmail-validation-and-web-smart-card-fixes-02015)
and [signed preview download](https://github.com/ve7jtb/gws-sequoia-chat/releases/tag/iwa-v0.20.15).

**IWA 0.20.11 adds direct CTAP2 PRF vault access and previewSign diagnostics
through Web Smart Card.** The FIDO tests tab includes a ten-key ARKG-P256
OpenPGP certificate/message test with Sequoia verification and public downloads.
Thirty-one targeted regression tests passed, including native Sequoia verification
of ten software-generated packet streams. Single-message previewSign hardware
verification and PRF lock/unlock passed. The ten-key hardware batch and native
Sequoia CLI checks also passed: all ten signatures verified with exact payload
recovery; all ten altered messages and wrong-certificate checks were rejected.
See the [ARKG interoperability report](docs/arkg-openpgp-interop.md). After updating Chromium, use **View → Force Reload This Page** if a new
button is unresponsive because an older script remains loaded. See
[FIDO tests and setup](experiments/mac-iwa/README.md).

**Chromebook validation passed on 2026-11-25:** the published IWA 0.20.11
installed on Google Eve (Chrome 150.0.7871.289). Google’s **Smart Card Connector**
enabled Web Smart Card reader access and CTAP2 GetInfo. An existing IWA PRF
credential successfully protected the local vault, followed by a verified
lock/unlock with FIDO PIN and touch. The Chromebook’s ten-key ARKG batch also
passed: ten distinct public keys, ten self-certified OpenPGP certificates and
ten signed messages; Sequoia WASM verified all and rejected all altered messages.
See [ChromeOS installation, Smart Card Connector setup and test details](experiments/mac-iwa/README.md#install-the-preview-on-chromeos).
The Chromebook batch has not separately been checked with the native CLI.

**IWA 0.19 adds manifest-bound hardware Level 5 and v4/v5 compatibility
selection, and encrypted on-key companion restore.** Read-only discovery chooses
an inserted YubiKey by serial without changing the vault’s default hardware
identity. Companion ciphertext and public metadata are stored separately from
the ordinary certificate bundle; private software components are unwrapped only
inside a disposable WASM worker. The native helper continues independently
checking the live card and performing required hardware operations. v6 remains
preferred, and classical compatibility is clearly labeled and warned. This
increment changes no YubiKey keys or touch policies. See [hardware profiles,
custody and validation status](experiments/mac-iwa/README.md#hardware-profiles-and-encrypted-on-key-companions-019-preview).

**Level 5 hardware validation passed on 2026-11-24:** ML-DSA-87 + Ed448
signing and ML-KEM-1024 + X448 decryption, including exact recovered content,
passed with the original installed PKCS#11 backend. All 24 PIV slot records,
nine hardware public keys and PIN/touch policies were unchanged; PIN retries
remained 3/3. The native dialog now explicitly separates PIV PIN entry from
waiting for the key to flash and touching its sensor. See the
[validation details](experiments/mac-iwa/README.md#level-5-hardware-validation-2026-11-24).

**The IWA 0.18 preview adds software identity creation and portable encrypted
backup/restore, Level 5 v6, explicit v4/v5 compatibility, and operational PQ Mail
Level 5 OpenPGP `.p12` import.** Software keys and independent random storage
passwords stay in the encrypted PRF/PIV vault; private operations use disposable
WASM workers. v6 remains the default, and classical signing/encryption requires
explicit compatibility warnings. The automated baseline-worker matrix passed all
seven created profiles and three imported `.p12` views, including restart and
exact signed/encrypted message recovery, with zero native/card calls. The v5
private backup is IWA-specific `.pqidentity`; arbitrary PKCS#12 files are not
supported. See [current profiles, custody limits and validation](experiments/mac-iwa/README.md#software-creation-portable-backup-and-compatibility-profiles-018-preview).

**IWA 0.17.2 adds experimental vault-protected software OpenPGP identities and
separates the production helper from test-only message code.** Import an encrypted
Level 3 v6 OpenPGP secret-key file into the existing PRF/PIV vault, then select it
in Compose or for matching encrypted messages. Software operations run in fresh
WASM workers and stop on vault lock; hardware authorization and private-key
operations remain native. PKCS#12 operation support and other software profiles
are not included yet. Installed tests on **2026-11-23** passed software import,
Compose signing, lock/unlock, signing and decryption after a full app restart,
and disposable-identity cleanup. Independent Sequoia tests passed in both
directions; the physical key/policy audit remained unchanged. See
[software custody, limits and test results](experiments/mac-iwa/README.md#vault-protected-software-identities-and-production-helper-0172).

**IWA 0.16.0 moves the hardware-test workflow into the browser and shares its
public bundle parser with native authorization.** The IWA builds and verifies
a local synthetic signing/encryption/decryption test; the helper supplies
native PIN/private operations and stable public key/policy audits. Fresh helper
installation no longer requires the old mail runtime, Java test harness or
standalone CLI tools. Independent live-card authorization remains native. The
installed 0.16.0 passed hybrid signing/decryption and exact MIME/attachment checks
on the Level 3 YubiKey, with all keys and policies unchanged; 373 automated
checks passed. See
[the implementation and test boundary](experiments/mac-iwa/README.md#iwa-hardware-tests-and-shared-public-parser-0160).

**IWA 0.15.1 moves public bundle inspection and account startup into the IWA.**
The browser WASM worker parses and authenticates compressed certificate bundles;
native discovery returns bounded public card bytes and slot-key hashes. Bundle
files can be reviewed and saved offline, but remain unavailable for private
operations until an explicit live-key match is reviewed and saved. The native
signing/decryption path still independently authenticates the current signed
bundle and selected hardware identity before PIN entry. Account email is now an
explicitly reviewed IWA setting, with optional user-triggered migration and no
automatic native startup read. Existing vault enrollment remains unchanged;
Google tokens remain memory-only, so restart still requires Google authorization.
Local validation passes **187 JavaScript, 102 Python, 21 native Rust, 20 WASM Rust
and 11 actual-worker tests**, plus actual baseline WASM bundle vectors. A physical
public-only comparison also matched three certificate views and ten public-key
hashes between the new browser path and the native reader. **The signed 0.15.1
update passed account restart, on-key restore and offline bundle-review UI checks,
followed by a fresh two-way offline exchange with independent Sequoia.** Sequoia
decrypted and verified the IWA's hybrid signature; the IWA automatically matched
the reply to its saved YubiKey identity and displayed **Valid hybrid / Trusted**.
Text, HTML and exact attachment bytes passed, with all 24 PIV slot records,
ten existing keys and PIN/touch policies unchanged. No email was sent. See
[the current implementation, parser limitation and validation scope](experiments/mac-iwa/README.md#browser-owned-bundle-inspection-and-account-startup-0151).

**IWA 0.14.0 connects restored identities to message operations.** Compose now
selects a saved Level 3 v6 identity matching the account, with its certificate,
algorithms and YubiKey serial visible. Incoming ciphertext is matched in WASM to
saved recipient subkeys, then reviewed before the selected key's PIN prompt.
Native code re-authenticates the live signed bundle and exact certificate binding;
it never falls back to the default vault identity. Vault enrollment and recipient
trust remain separate. The installed preview passed offline signing/encryption
to independent Sequoia and automatic recipient matching/decryption of its reply,
with valid hybrid signatures, exact attachments and unchanged keys/touch policies.
See [selection and recipient matching](experiments/mac-iwa/README.md#selected-sending-identities-and-recipient-matching-0140-preview).

The separate [signed Mac IWA experiment](experiments/mac-iwa/README.md) now also
constructs Level 3 v6 OpenPGP signatures in a browser WASM worker. Its native
PKCS#11 bridge receives only the signing digest and returns hybrid signature
components. Preview **0.11** moves public certificates and per-email/full-primary-
fingerprint trust into the IWA's IndexedDB store. Existing native public records
can be reviewed and copied once; subsequent deletion or trust removal is not
undone by a restart or repeated migration. Saving a certificate and granting
trust remain separate actions. Compose drafts, send reviews and PGP/MIME wrapping
also stay in browser memory, while fixed-identity YubiKey signing and
decapsulation remain native. Automated tests and the installed 0.11 migration/
restart checks pass: two reviewed public certificates and their two existing
email/fingerprint trust bindings persisted in a fresh app window. A subsequent
**0.11.2 physical-YubiKey test** used those migrated certificates for offline
Compose signing/encryption and local encrypted-message decryption/verification.
Independent Sequoia verified the exported message; the IWA verified the incoming
hybrid signature and its 308-byte attachment. All 24 slot records and PIN/touch
policies were unchanged, with no email sent. Explicit encrypted `.eml` export
and local encrypted-file opening are now available without Google sign-in. See
the [new storage boundary and validation](experiments/mac-iwa/README.md#iwa-owned-certificates-and-trust-011-preview).

**Live Gmail tests passed in both directions on 2026-11-23**, using the actual
IWA 0.11.2 interface, migrated certificates and a physical YubiKey. Sequoia
decrypted and verified the IWA's hybrid-signed message; the IWA decrypted the
reply and displayed **Valid hybrid / Trusted**. Protected headers, text and HTML
matched, as did all 48 reply-attachment bytes. The run sent two synthetic emails;
all 24 PIV slot records, PIN/touch policies and migrated trust entries remained
unchanged. Gmail's unsigned outer MIME rewrite exposed an armor-only parser
assumption. Both receiver implementations now accept the exact two-part
binary/base64 rewrite without relaxing cryptographic or trust checks. **94 IWA
JavaScript tests and 16 standalone mail tests pass.** That 0.11.2 return used the
existing armor support; the subsequent binary receive test below covers the
installed fix. See the [two-way test scope](experiments/mac-iwa/README.md#live-gmail-exchange-using-migrated-certificates-2026-11-23).

**Installed IWA 0.11.3 passed binary PGP/MIME reception through Gmail on
2026-11-23.** One synthetic email reused the previously signed Sequoia ciphertext
in a fresh binary/base64 envelope. Captured pre-upload and Gmail Sent copies used
`multipart/encrypted`; the recipient copy used `multipart/mixed`. All **5,626
ciphertext bytes** matched. The old parser rejects that actual delivery, while
the updated IWA decrypted it with the existing YubiKey and displayed **Valid
hybrid / Trusted**, the expected text/HTML and an exact 48-byte attachment.
All 24 slot records, PIN/touch policies and retry counts were unchanged. The
native PIN helper now presents and focuses its window after AppKit launches,
with a temporary Dock entry and specific pre-submission timeout/cancel errors.
**65 Python tests pass**, including four regressions ensuring those failures
never start private cryptography. See the [0.11.3 test and PIN fix](experiments/mac-iwa/README.md#binary-gmail-reception-and-native-pin-dialog-0113)
and [MIME investigation](docs/gmail-mime-rewriting.md#captured-binary-delivery-in-installed-iwa-0113).

**IWA 0.13.0 adds an Identities screen** for own public certificates, algorithms,
YubiKey serial and slot mappings. Restore from the configured Level 3 YubiKey or
import a public certificate/bundle from file, review it, then save in the IWA.
Bundle authentication and live public-key matching are read-only; no PIN or card
write is needed. Own identities remain separate from recipient trust and do not
change the helper’s active identity. The installed preview passed physical
YubiKey restore of all three OpenPGP certificate views and ten slot mappings,
including persistence after a full restart. All 24 slot records and PIN/touch
policies were unchanged, with PIN retries at 3/3 and no PIN operation or card
write. See [identity restore and its scope](experiments/mac-iwa/README.md#own-identities-and-reviewed-public-restore-0130-preview).

**IWA 0.12.0 moves recipient-packet parsing, the hybrid combiner and session-key
recovery into WASM**, including existing PIV vault unlocks. The native helper
performs only the fixed ML-KEM-768/X25519 private operations for this flow; full
encrypted messages and recovered session keys stay in the IWA. One-use grants,
response bindings and cancellation checks replace the retired native envelope
routes. Software validation passes 136 JavaScript tests, five actual-worker
integration tests, 74 Python tests and 21 Rust tests. The installed update passed
physical YubiKey vault unlock and local reception of the prior binary Gmail test:
**Valid hybrid / Trusted**, exact 48-byte attachment, unchanged keys/policies and
PIN retries **3/3**. No new message was sent. See the
[new decryption boundary](experiments/mac-iwa/README.md#browser-owned-recipient-parsing-and-hybrid-recovery-0120-preview).

**Installed IWA 0.11.4 passed signed-and-encrypted Google Chat in both directions
on 2026-11-23.** Sequoia decrypted and verified the IWA's delivered hybrid message;
the IWA decrypted the fresh reply and displayed **Valid hybrid / Trusted**. Signed
headers, text and HTML matched, and the downloaded 50-byte attachment matched
exactly. All public PIV key/slot records and touch policies were unchanged; the
final PIN retry count was 3/3. The test sent two encrypted bundles and their two
linked public certificates. It exposed an upload CORS restriction, corrected by
an approved, bounded extension broker for Chat attachments. Certificates, trust
and message cryptography stay in the IWA. **123 JavaScript tests plus the
formatting test pass.** See the [transport correction and live test](experiments/mac-iwa/README.md#chat-attachment-transport-correction-0114-preview).

In the earlier hardware run on **2026-11-23**, the installed **0.10.1** preview passed a physical
YubiKey test through its actual **Compose interface**: native Sequoia `sq`
independently decrypted the WASM-encrypted message and verified its hybrid
signature, signed headers, plain text, formatted HTML and all 1,024 attachment
bytes. The Send confirmation was cancelled; no email was sent. All 24 PIV slot
records and PIN/touch policies were unchanged. This IWA remains separate from
the standalone loopback app. See the [Compose test and its scope](experiments/mac-iwa/README.md#live-compose-interface--sequoia-verification-2026-11-23).

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

Certificate previews and trust selections list only email addresses with current,
policy-valid self-certifications. Unsigned, expired or revoked User IDs do not
establish an email binding; expired or revoked certificates are rejected. The
native helper's complete fingerprint must agree with the Python packet parser.
Saved contacts are checked again when loaded and before sending or opening mail
or Chat: another valid email on the same certificate cannot keep an expired or
revoked selected address usable. These checks authenticate the certificate's
claim, not ownership of an email account. Trust still requires the user's
independent fingerprint verification and explicit email selection.

## Install

Requirements: Python 3.9+, `sq` with RFC 9980 support (tested with sq 1.5.0 / sequoia-openpgp 2.4.1), and its native crypto dependencies. Obtain Sequoia through its [installation documentation](https://sequoia-pgp.org/download/), using a supported, patched crypto backend. Ordinary older `sq` packages may not implement the hybrid algorithms; check `sq key generate --help` for `mldsa65-ed25519` and `mldsa87-ed448`.

```sh
python3 install.py --sq /absolute/path/to/sq
cargo build --locked --release --manifest-path identity-helper/Cargo.toml
cp identity-helper/target/release/chat-software-identity bin/chat-software-identity
```

The installer downloads official gws v0.22.5 and verifies its published SHA-256. It copies only the executables; dynamically linked Sequoia libraries must remain installed. The current shell wrapper is tested on macOS Apple Silicon; Linux is intended but untested. Windows binaries exist upstream, but this wrapper currently requires a POSIX environment such as WSL. Native Android/iOS clients are not included. The local browser UI is tested on macOS.

The Rust helper is required for public-certificate inspection, even when you do
not use its identity generator. It checks live self-certified email bindings,
certificate expiry, and UID/certificate revocations before offering addresses
for selection or trust. Raw or unsigned User ID claims are not trustable. Rust
and the native dependencies for Sequoia's OpenSSL backend are needed to build it.
Fingerprint verification and explicit user trust are still required.

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

The optional identity-generation mode of `identity-helper` creates three certificate views from eight
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

## Local browser app (Mac preview)

Double-click **`Sequoia Chat.command`** on macOS, or run:

```sh
python3 -B webapp.py
```

Keep the launcher running while using the app. It starts an HTTP helper on
`127.0.0.1` with a random port and opens your browser with a per-launch capability.
It does not listen on the LAN. Close the browser when finished and press Ctrl-C
in the launcher to stop the helper. Reloading the page loses its in-memory
capability; launch again for a fresh page. This is a local browser preview, not
an installed/offline PWA. Python 3.9 or newer and the project's installed `gws`,
`sq`, and `chat-software-identity` binaries are required. Start it outside restricted sandboxes so gws can
read its macOS Keychain item safely.

1. Select a previously configured gws profile and **Connect / reconnect**.
   **Sign in with Google** renews authorization when necessary. Initial OAuth
   registration and identity creation still use the setup instructions above.
2. Choose a conversation. Filter the loaded conversation list; **Older/Newer**
   page through messages. Google does not receive decrypted message contents or
   plaintext search queries from this interface. This preview has no full-text
   encrypted-message search.
3. In **Contacts & trust**, review a public certificate, independently verify
   its full primary fingerprint, and trust the selected email. Trust persists
   locally and can be removed. Attached certificates never grant trust.
4. In **Compose**, select the conversation, trusted recipient and software
   identity. Add a prominent subject, plain text, optional HTML alternative and
   attachments. Enter the identity password to prepare a compressed, signed and
   encrypted v6 hybrid bundle. Review its destination and fingerprint before
   explicitly sending. The certificate and encrypted payload are two linked
   Google Chat messages; do not select a group conversation unless you intend
   to disclose the public certificate there.
5. **Decrypt and verify** asks for your identity, expected trusted sender and
   software-key password. Plaintext appears only after signature, certificate
   and signed From/To checks pass. Formatting is sanitized and shown inside a
   sandboxed frame with no scripts, remote images or active links. Attachments
   are saved only when you choose their download links.

The helper discovers `private/*/public.pgp` paired with `secret.pgp`. It supports
Level 3 and Level 5 software hybrid identities and the v6 view of the compatible
identity generator above. It does not yet expose classical/v4 sending, hardware
private-key operations, PRF vault unlock, or identity provisioning in the browser.
The standalone YubiKey adapter remains a separate project.

Passwords and decrypted MIME travel through bounded memory/pipes, not temporary
plaintext files, subprocess arguments or logs. Passwords are requested for each
operation and are not saved. Python/JavaScript cannot guarantee memory erasure,
and OS swap or crash dumps can persist memory. gws still owns Google token
storage under its existing OS-keyring model; this UI does not add PRF protection
or biometric enforcement.

Public contacts/trust, encrypted outgoing bundles, public sender certificates
and transport receipts persist under `private/web/`. **Clear session** clears
browser drafts/displayed messages and prepared ciphertext, disconnects the local
session and stops pending sign-in; it does not revoke Google access or erase
saved credentials. HTTP responses are `no-store`, and there is no service worker,
cookie, browser message database, analytics or remote frontend dependency.
Host, Origin and per-launch capability checks guard the fixed JSON API against
cross-site requests and DNS rebinding. There is no arbitrary command or file API.
A compromised local OS/browser remains outside this boundary.

### Browser helper tests

```sh
python3 -B -m unittest -v test_chat test_webapp
```

The combined suite passed **27 tests on macOS**: the 14 CLI tests plus 13 browser
helper tests covering real password-protected Level 3/5 hybrid round trips,
wrong passwords/signers, tampering, MIME path and HTML safety, explicit one-time
send confirmation, trust persistence/removal and loopback access controls. The
certificate-policy regressions reject an appended unsigned User ID during
preview/trust and reject cached contacts whose selected email binding is no
longer valid before either Chat or Gmail fetches/decrypts a message.
The new helper tests mock Google transport and never access account credentials.
A browser walkthrough also exercised connection, Older/Newer paging, composition,
password unlock, send review/completion, verified text/HTML reading and session
clearing using disposable fixtures. These simulated sends are separate from the
live two-way Chat interoperability result documented above.

For repeatable UI testing only, `python3 -B test_webapp.py --serve` starts a
loopback fixture with disposable Alice/Bob identities and simulated Google APIs.
It prints its launch URL; its password is the public test constant in
`test_webapp.py`. It cannot send messages to Google. Stop it with Ctrl-C to delete
its temporary identities. Never use those identities or that password for real
messages.

The local browser preview also passed a **live receive test on macOS**: its
existing standalone gws session reconnected without another Google login, loaded
the prior PQ Mail interoperability conversation, and downloaded the encrypted
return bundle. After the software identity was unlocked in the local browser,
Sequoia decrypted it and verified the independently trusted hybrid signature.
The signed sender/recipient, subject and synthetic body matched. This used the
existing message; the browser check sent no new live messages and performed no
YubiKey operations.

## Gmail preview

The browser uses a Gmail/Google Chat-inspired layout: a left sidebar for **Mail**,
**Chat**, **Compose**, contacts and settings; a message list and reading area;
and a prominent search field and Compose action. It retains this project's
branding and local cryptographic checks rather than embedding Google's web UI.

Choose **Gmail** on the initial account screen, or **Mail → Connect / reconnect
Gmail** after connecting Chat. Gmail uses a separate `<base-profile>-mail` gws
profile. The app copies only OAuth client registration metadata into that new
profile, never the Chat account token. To authorize it:

1. Enable **Gmail API** in the OAuth client's Google Cloud project and configure
   its consent screen/test users as required. This app does not silently enable
   APIs or change a Google Cloud registration.
2. Choose **Authorize Gmail read & send** (or Gmail → Sign in with Google at the
   initial screen). Consent requests `gmail.readonly` and `gmail.send`, plus the
   basic identity scopes used by gws. It does not request `gmail.modify` or full
   `mail.google.com` access.
3. Complete Google's consent, then click **Connect / reconnect Gmail**.
   For a different OAuth registration, place its client JSON in
   `private/profiles/<base-profile>-mail/client_secret.json` before authorizing.
   Google credentials remain in gws's separate OS-keyring-backed storage, not in
   the browser or PQ Mail vault.

Inbox, Sent and All mail use 20-message pages. Search uses Gmail query syntax and
runs on Google's server; encrypted bodies and protected inner subjects are not
searchable there. The list requests metadata; full MIME is fetched when a message
is opened. Reading does not mark messages read or modify mailbox state. The
helper buffers Gmail responses in bounded memory and maintains no mailbox cache.

Select **Gmail** in Compose, choose a supported trusted recipient and a software
identity whose email matches the connected Gmail account. The preview sends one
recipient per message and always signs and encrypts using v6 hybrid keys. Plain
text, optional HTML, attachments and the public sender certificate are inside
the encrypted MIME payload. The outer RFC 3156 `multipart/encrypted` envelope has
a generic subject; routing addresses remain visible to Google. Other clients may
display that generic outer subject instead of the protected inner subject.

Opening encrypted mail requires the selected software identity and a previously
trusted hybrid signer. Sequoia must decrypt and verify before plaintext is shown;
verified inner From/To headers must match the selected identities. Standard
PGP/MIME with a signed body but no inner address headers is also supported: the
viewer explicitly warns that its outer From/To/Subject headers are not signed.
The outer sender must still match the selected trusted signer. Unencrypted
mail can be read with safe formatting and explicit **unverified** status. This
preview does not verify detached `multipart/signed` mail, handle inline PGP,
S/MIME, classical/v4 certificates, or unsigned encrypted messages. Those formats
must not be mistaken for verified hybrid mail.

The complete offline command is:

```sh
TEST_SQ="$PWD/bin/sq" cargo test --locked --manifest-path identity-helper/Cargo.toml
python3 -B -m unittest -v test_chat test_webapp test_mail_transport
node --check web/app.js
node --check web/mail.js
```

**Four Rust tests and 39 Python tests passed on macOS on 2026-11-21**; both
JavaScript syntax checks also passed. Rust tests cover self-certified mailbox
bindings, unsigned/expired/revoked User IDs, expired/revoked primary certificates,
and the software identity generator's encrypted-key round trips. The Python suite
includes twelve Gmail tests with real protected
Level 3/5 Sequoia keys and mocked Gmail transport. They cover RFC 3156 wrappers,
text/HTML/files, protected subjects, wrong passwords, tampering, forged outer
headers, unverified ordinary mail, search/paging metadata, one-time send review,
account matching and separation of Chat/Gmail credentials. These regression
tests use disposable software keys and mocked transport; they access no account
credentials or hardware, send no email, and change no keys or touch policies.

A live two-way Gmail test passed on 2026-11-20 between the standalone Level 3
software v6 identity and PQ Mail's Level 3 YubiKey identity. Both recipients
successfully decrypted and verified the other's hybrid signature using pinned
public certificates. Testing used the local updated readers. The Mac development app has been rebuilt
with this compatibility patch; public release packages have not been updated.

Gmail delivery rewrote the outgoing root `multipart/encrypted` into
`multipart/mixed`; the ciphertext was unchanged. Both media-upload and raw-message
API sends reproduced this behavior. The reader accepts only the observed two-leaf
shape: one `application/pgp-encrypted` version-control part and one armored
ciphertext part (`text/plain` or `application/octet-stream`). Extra parts,
non-armor text and multiple armor blocks are rejected. Decryption and signature
verification still precede display; unsigned outer content is never merged into
the verified body. The test message was classified as Spam, so the diagnostic
searched its exact Message-ID across folders without changing mailbox labels.
The current browser Inbox view does not include Spam. The earlier live **Chat**
result above is a separate test.

## Experimental Mac IWA with a native YubiKey helper

The separate [Mac IWA experiment](experiments/mac-iwa/README.md) packages a signed
Isolated Web App, a restricted Chrome extension and a Native Messaging host. It
reuses the Sequoia PKCS#11 PIV adapter without a loopback HTTP server. It is a
Google Chat and Gmail preview alongside the separate main Mail/Chat browser app. The IWA
uses its own gws OAuth session and native PIN dialogs; it does not share PQ
Mail’s vault or Google session.

On **2026-11-21**, Chrome Canary 160 completed the full IWA-to-YubiKey path:
Level 3 hybrid signing verified by both Sequoia and PQ Mail, plus authenticated
hybrid decryption of Sequoia and independent PQ Mail ciphertexts. Three native
PIN dialogs authorized the operations. All 24 PIV slot records, including public
keys and PIN/touch policies, matched before and after. No email was sent and no
keys were provisioned. Timings including touch wait were 3,114 ms for signing
and 1,010 / 897 ms for the two decryptions; these are single-run observations.

The **two-way encrypted Google Chat test also passed on 2026-11-21**. The
IWA decrypted and verified the standalone Sequoia peer's hybrid bundle, including
recognizing its embedded attachment. In the return direction, the IWA signed
with the YubiKey and encrypted to the peer's v6 certificate; standalone Sequoia
retrieved it through its separate Google session, decrypted it, and verified the
hybrid signature. Recovered text matched exactly. All 24 PIV slot records and
PIN/touch policies remained unchanged.

The Chat preview includes connection/reconnection, paged conversations/messages,
explicit certificate trust, and separate preparation/send confirmation. It uses
ML-DSA-65 + Ed25519 signing and ML-KEM-768 + X25519 encryption. Composition supports simple heading/bold/italic/list formatting, plain-text and
HTML alternatives, and attachments. The reader offers inert formatted text and
explicit verified-attachment downloads. A live formatted attachment test on
**2026-11-21** passed Sequoia decryption/signature verification, exact plain-text
and HTML-markup checks, and byte-for-byte recovery of a 66-byte binary fixture.
All 24 PIV slot records and PIN/touch policies remained unchanged.
The reverse **Sequoia → IWA** formatted test also passed on **2026-11-21**:
YubiKey decryption and trusted hybrid-signature verification succeeded; visual
inspection confirmed heading, bold, italic and bullet-list rendering. The IWA
attachment download matched all **308 bytes exactly**. All 24 PIV slot records
and PIN/touch policies remained unchanged.

The **two-way encrypted Gmail test passed on 2026-11-21** using the same
Level 3 YubiKey and Sequoia peer identities. IWA-helper → Sequoia verified the
hybrid signature, authenticated sender/recipient and subject, exact plain-text
and HTML alternatives, and all **289 attachment bytes**. Sequoia → IWA passed
YubiKey decryption and trusted hybrid-signature verification; the IWA displayed
heading, bold, italic and list formatting, and its downloaded attachment matched
all **308 bytes exactly**. All 24 PIV slot records, including public-key hashes
and PIN/touch policies, matched before and after each hardware test.

IWA preview **0.4.1** follows the selected service throughout sign-in,
inbox/conversations, Compose, send confirmation and decryption prompts. Native
PIN dialogs say **“Sign and encrypt Gmail email”** / **“Decrypt and verify Gmail
email”**, or the corresponding **Chat bundle** labels. Switching services hides
irrelevant controls and clears pending message selections; the service selector
is disabled while a native operation runs. Both Gmail and Chat views were
checked in the installed Mac preview, with 18 Python tests and the HTML-rendering
test passing. This label update required no mail sends or YubiKey operations.

IWA preview **0.4.2** also opens ordinary unencrypted Gmail messages without a
YubiKey PIN or trusted-contact selection. The reader explicitly labels their
sender and signature as **not verified**. Plain text, inert HTML and explicit
attachment downloads use the same safe display path. Each text/HTML view is
limited to 32,768 characters, with at most ten attachments / 128 KiB combined;
omitted attachments are reported.

The inbox shows a lock only for a recognized encrypted PGP/MIME envelope,
including Gmail's supported rewritten form—not because of its subject or a
`.pgp` filename alone. This indicator describes encryption packaging, not
signature verification or sender trust, and does not recognize every encrypted
mail format. Classification fetches up to ten raw messages in memory per page;
it does not create a persistent mailbox cache.

The installed Mac preview was checked with an ordinary message opening without
a PIN prompt and an encrypted test message retaining its lock. All **21 Python
tests** and the HTML-rendering test passed, including MIME classification,
unverified ordinary mail, bounded output and exact attachment bytes.

IWA preview **0.4.3** verifies signed, unencrypted PGP/MIME with separate
**Encryption**, **Signature** and **Certificate trust** results. Public
verification needs no YubiKey PIN. Saved certificates and attached public keys
can verify v4 classical or v6 hybrid signatures; attachments never acquire trust
automatically. Trust is matched to the saved email and full primary fingerprint,
while outer email headers remain explicitly unauthenticated.

The installed Mac preview verified the existing Proton test message as **not
encrypted / valid signature / untrusted certificate**, using its attached key.
No message was sent, PIN requested or trust changed. Regression coverage passed
26 Python tests (including real v4/v6 MIME pipelines), two Rust tests and the
HTML/security-label tests. Inline/clear-signed and nested signed envelopes remain
unsupported; see the [IWA limits](experiments/mac-iwa/README.md).

IWA preview **0.4.4** adds separate **Save certificate (no trust)** and
**Mark trusted for the sender email** actions beneath verified signed mail.
Trust confirmation displays the full fingerprint and exact email; the helper
re-verifies the message and requires a current self-certified mailbox. The live
Proton test passed both steps: saving left trust unset, then explicit confirmation
showed **Not encrypted / Valid signature / Trusted certificate**. Public material
and the email/fingerprint binding persist locally; classical verification keys
do not become hybrid encryption recipients.

IWA preview **0.4.5** lists saved certificates in **Contacts**, including version,
algorithms, full fingerprint and trusted email bindings. Separate confirmed
controls remove one email's trust or delete the saved certificate and its local
trust. The installed Mac list and confirmation dialogs were checked; actual
removal/deletion passed with temporary v4/v6 fixtures. All 30 Python tests, two
Rust tests and display tests passed. Existing user contacts were preserved.

A subsequent live Proton trust-removal/restoration test passed in the installed
Mac IWA. Removing the sender's email/fingerprint trust kept the public certificate
and displayed **Not encrypted / Valid signature / Untrusted certificate**.
Explicitly trusting the same email and full fingerprint again displayed
**Not encrypted / Valid signature / Trusted certificate**. The restored binding
was confirmed in local storage. No email was sent or YubiKey operation performed.

The live Proton **delete / verify attached key / save / trust** test also passed.
Deleting the saved certificate removed both its local public copies and trust
bindings. Reopening the existing message still showed **Valid signature /
Untrusted certificate / Not saved**, using the attached public key; encryption
remained **Not encrypted**. Saving it again did not grant trust. Explicit trust
confirmation restored **Valid signature / Trusted certificate / Saved locally**,
with the exact email/full-fingerprint binding confirmed in local storage. The
test left the certificate and trust restored, without sending mail or using the
YubiKey.

A full IWA quit-and-relaunch test also passed. After confirming the app had
stopped, reopening Contacts showed Proton's saved certificate and the same
trusted sender email. Reconnecting Gmail and reopening the existing message
still displayed **Not encrypted / Valid signature / Trusted certificate**.
Read-only local storage checks confirmed that the public certificate and exact
email/full-fingerprint trust binding persisted. No mail was sent or YubiKey
operation performed.

An isolated **saved-certificate-only Proton verification test** also passed
through the installed reader and Sequoia worker: **Not encrypted / Valid
signature / Trusted certificate**. The test supplied only the saved public
certificate to the worker and excluded the attached key as a verification-key
source, preserving the signed bytes. A no-certificate control returned
**unknown-key**. Proton's key attachment is itself inside the signed MIME content;
physically removing it from a local copy changed that content and correctly
produced an **invalid signature**. This helper-level test left saved certificates
and trust unchanged and performed no mail sends or YubiKey operations.

A local **Proton body-tampering test** also passed through the installed IWA
verification path. The original copy verified as **Valid signature / Trusted
certificate**. Altering its body while preserving the signature and attached-key
bytes produced **Invalid signature / Trusted certificate** in preview 0.4.6.
Signature validity and saved email/fingerprint trust are independent. The reader
shows an explicit warning that the message may have been altered or forged and
that certificate trust does not authenticate it; the message remains unverified.
Hashes confirmed every saved certificate and trust binding, and the original
local message copy, were unchanged. Gmail was not accessed or modified; no mail
was sent and no YubiKey operation was performed.

Select **Gmail** in the IWA service selector, authorize `gmail.readonly` and
`gmail.send`, and enable Gmail API in the OAuth project's Cloud configuration.
The preview supports inbox search/paging and encrypted PGP/MIME composition with
HTML and attachments. It does not request mailbox modification/deletion access.
These live tests exercised the installed Gmail helper in both directions and the
IWA inbox/reader/download UI for the return; outgoing preparation/send was driven
through the helper test harness, not a complete automated Compose UI test.

Google credentials use gws's separate Keychain-backed encrypted storage. See the
[experiment README](experiments/mac-iwa/README.md) for installation, limits and
security boundaries.

The experiment requires local native dependencies, an unpacked extension and
experimental Canary flags. It does not establish production macOS IWA support
or native Web Smart Card support. Local credentials, device identifiers, browser
profiles, development signing keys and hardware transcripts are excluded.

### Experimental IWA WebAssembly verification

Mac preview 0.5.2 includes a public-only Sequoia WASM verifier in a browser
worker. Eight comparisons with the native OpenSSL verifier passed in the
installed IWA: valid/altered/missing-certificate cases for v4 and Level 3 hybrid
v6, plus valid original and invalid altered Proton messages. Saved certificates,
trust and the original message stayed unchanged. Preview 0.6 subsequently moves
MIME composition/reading and ordinary/decrypted-message verification into an IWA
worker. In that preview, YubiKey signing/decryption and AEAD integrity checks
remained native. Preview 0.8 moves authenticated message decryption into WASM;
YubiKey decapsulation/signing, OAuth, transport and trust persistence remain native. See the [browser/native boundary and tests](experiments/mac-iwa/README.md#browser-mime-and-baseline-wasm-verification-preview-06). **Baseline WASM remains the default**; wide arithmetic runs only
when its explicit benchmark button is selected.

The wide-arithmetic build passed all eight cases in Canary 160 on Apple Silicon,
using `--js-flags=--wasm-wide_arithmetic`. Median milliseconds per verification:

| Case | Baseline | Wide arithmetic |
|---|---:|---:|
| v4 valid | 0.120 | 0.120 |
| Level 3 hybrid v6 valid | 0.420 | 0.400 |
| Proton original (valid) | 0.080 | 0.080 |
| Proton altered body (invalid) | 0.120 | 0.120 |

Each variant ran five warmups and 21 alternating rounds of five calls per case;
every result matched the native expected result. The approximately 5% median
improvement for valid hybrid v6 has overlapping timing ranges and does not
establish a general speedup. The wide module is 24,359 bytes smaller. Original
messages, saved certificates and trust were unchanged; no token operations ran.
See [build instructions, complete results and limitations](experiments/mac-iwa/wasm/README.md).


### Live Gmail and Chat verification with baseline WASM

Mac IWA preview **0.6.2** passed live encrypted-message reads on **2026-11-22**
using the existing Level 3 YubiKey and the Sequoia peer:

| Check | Gmail | Google Chat |
|---|---|---|
| Native YubiKey decryption | Passed | Passed |
| Baseline WASM hybrid signature verification | Valid | Valid |
| Saved sender certificate trust | Trusted | Trusted |
| Text and 308-byte attachment displayed | Passed | Passed |

Chat HTML rendering also passed. These tests reopened existing synthetic
messages; no messages were sent and no keys or touch policies were changed.
Original-message and saved-certificate/trust hashes remained unchanged. The
308-byte result is the displayed attachment size; exact downloaded bytes were
verified in the earlier interoperability tests, not repeated in this run.

In preview 0.6.2, MIME composition/reading and message verification run in the IWA worker.
YubiKey operations, PIN handling, authenticated decryption, OAuth credentials
and trust persistence stay native. Baseline WASM is the default; wide arithmetic
remains an opt-in benchmark. See the [implementation boundaries and regression tests](experiments/mac-iwa/README.md#browser-mime-and-baseline-wasm-verification-preview-06).

### Live IWA MIME composer → Sequoia tests

On **2026-11-22**, Mac IWA preview **0.6.2** composed and sent new synthetic
signed-and-encrypted messages through both **Gmail and Google Chat** to the
standalone Sequoia peer. These tests exercised the installed IWA Compose UI,
including its formatting option, attachment picker and explicit send review.
The browser worker built the MIME; the native helper used the existing Level 3
YubiKey for **ML-DSA-65 + Ed25519** signatures and encrypted to the peer with
**ML-KEM-768 + X25519**.

| Sequoia-side check | Gmail | Google Chat |
|---|---|---|
| Received ciphertext matches the IWA's sent copy | Exact match | Exact match |
| Decryption and hybrid signature verification | Passed | Passed |
| Expected full signer fingerprint, signed From/To and subject | Matched | Matched |
| Multipart plain-text and HTML alternatives | Exact match | Exact match |
| Attachment filename and all **308 bytes** | Exact match | Exact match |

The HTML comparison covered heading, bold, italic and list markup, with Unicode
preserved in both text and HTML. The binary fixture contained every byte value;
both recovered attachments matched the original byte-for-byte and had SHA-256
`6a2eba9c8f2ebd7e2a9ff4746da112449e131cef2dc5ba68bc223c27ef26f769`.
This run checked decoded HTML source on the CLI peer, not visual rendering there.
The peer used its separate Google sessions and password-protected software
identity. No YubiKey keys or touch policies were changed. Account details,
ciphertexts, decrypted test content and local reports remain excluded from Git.

### Live baseline WASM encryption → Sequoia tests

Mac IWA preview **0.7.0** passed live outgoing **Gmail and Google Chat** tests on
**2026-11-22** with OpenPGP encryption in the baseline WASM worker. The native
helper signed through the existing Level 3 YubiKey; WASM reverified the signed
MIME and encrypted it with **ML-KEM-768 + X25519**. The standalone Sequoia peer
used its separate Google sessions and password-protected software identity.

| Sequoia-side check | Gmail | Google Chat |
|---|---|---|
| Received ciphertext matches the IWA's sent copy | Exact match | Exact match |
| Decryption and **ML-DSA-65 + Ed25519** signature verification | Passed | Passed |
| Expected signer fingerprint, signed From/To and subject | Matched | Matched |
| Plain-text and HTML alternatives, including Unicode | Exact match | Exact match |
| Attachment filename and all **308 bytes** | Exact match | Exact match |

Both recovered attachments matched the original byte-for-byte and had SHA-256
`6a2eba9c8f2ebd7e2a9ff4746da112449e131cef2dc5ba68bc223c27ef26f769`.
HTML source preserved heading, bold, italic and list markup; the CLI peer did not
render HTML. This run specifically tested browser encryption, unlike the 0.6.2
composer tests above. YubiKey signing/decryption, PIN entry, OAuth credentials,
trust persistence and transport remain native. No keys or touch policies were
changed, and no private reports, messages or credentials are published.

Offline checks also passed: 36 Python tests, four native Rust tests, seven MIME
worker tests, eight v4/v6/Proton verification cases, and two independent native
Sequoia round trips of WASM-encrypted data. Tests cover fresh randomness,
recipient/mailbox mismatch, altered content, secret-key rejection, public packet
validation and one-use completion tickets. Baseline remains the default, with no
native encryption fallback. See the [encryption boundary](experiments/mac-iwa/README.md#browser-openpgp-encryption-preview-07).


### Live Sequoia → baseline WASM decryption tests

Mac IWA preview **0.8.0** passed incoming **Gmail and Google Chat** tests on
**2026-11-22**, reopening existing synthetic messages from the standalone Sequoia
peer. The native helper used the existing Level 3 YubiKey to decapsulate
**ML-KEM-768 + X25519** and unwrap the per-message session key. The baseline WASM
worker performed authenticated OpenPGP message decryption, MIME processing and
**ML-DSA-65 + Ed25519** signature verification.

| Installed IWA check | Gmail | Google Chat |
|---|---|---|
| Native YubiKey decapsulation + baseline WASM AEAD decryption | Passed | Passed |
| Hybrid signature / saved certificate trust | Valid / Trusted | Valid / Trusted |
| HTML heading, bold/italic text and lists displayed | Passed | Passed |
| Downloaded attachment compared with original, all **308 bytes** | Exact match | Exact match |

Both downloaded attachments had SHA-256
`dcfa99c88a6aab863d39ffe61851ec8a93c10e81634306740c662fac87c74030`.
These checks include actual HTML display and byte-for-byte comparison of the
IWA downloads, not only the displayed attachment size. An initial Gmail attempt
stopped without a result; a fresh user-authorized attempt passed. No automatic
private-key retry occurred. No messages were sent and no keys or touch policies
were changed.

Only the per-message session key crosses into browser memory; long-term private
keys and PINs remain outside the browser. The worker authenticates the complete
AEAD message and verifies its signature before releasing a message result.
Session keys are not persisted or logged; worker termination and reference
removal do not guarantee erasure of JavaScript/IPC/OS memory copies. There is no
native decryption fallback. Baseline WASM remains the default.

Offline checks passed: five native Rust tests, 37 Python tests, seven MIME tests,
eight v4/v6/Proton verification cases, and native-decapsulation/WASM-decryption
interoperability with exact MIME recovery. Negative tests reject wrong session
keys, key lengths, algorithms and recipients, ciphertext substitution, corrupted
final AEAD tags, truncation and plaintext input. See the
[decryption boundary](experiments/mac-iwa/README.md#browser-decryption-with-native-decapsulation-preview-08).


### Proposed provisioning and recovery application

The [provisioning and recovery design](docs/provisioning-recovery-design.md)
describes a separate restricted boot environment, reusable encrypted vault format,
backup YubiKeys, per-device PUK/management-key records, interrupted-operation
recovery, and authenticated SCP11 connections. It distinguishes recoverable
externally generated identity keys from non-exportable on-device keys and keeps
provisioning authority separate from the daily mail vault. This is a design
proposal, not an implemented or hardware-validated provisioning application.
