# Sequoia Chat Lab — experimental Mac IWA

A signed Isolated Web App calls a tightly scoped Chrome extension, which calls
an installed native host through Chrome Native Messaging. There is no listening
HTTP server for the IWA. The preview adds Google Chat and Gmail through a separately
authorized gws session; gws itself uses its usual OAuth callback listener.
The repository’s main loopback Mail/Chat application remains separate.

## Gmail preview (0.4.0)

Choose **Gmail** in the service selector. Sign-in adds `gmail.readonly` and
`gmail.send` to the existing Chat permissions. Enable **Gmail API** in the same
Google Cloud project; OAuth consent alone does not enable the API. Reconnect
checks that Gmail's account matches the configured sending identity. Inbox
search and ten-message pages use Gmail; composition sends signed/encrypted
PGP/MIME with the same trusted contacts, HTML alternatives and attachment limits.
No mailbox modification/deletion operation is exposed.

Version **0.4.5** shows all saved public OpenPGP certificates in **Contacts**,
with v4/v6 version, algorithms, full primary fingerprint and saved trusted email
bindings. The local inventory works without connecting to Gmail or Chat.
**Remove trust** targets one email/fingerprint and keeps the public certificate;
**Delete saved certificate** removes its saved copies and all associated local
trust. Both actions have a confirmation dialog and update recipient selectors.
No device keys, identities or messages are removed. A deleted key can still be
supplied by a message attachment for mathematical verification, without restoring
trust or automatically saving the certificate again.

The installed Mac preview showed the saved Proton verification certificate and
hybrid sending contact with their email bindings. Both confirmation dialogs and
Cancel paths were checked without deleting existing contacts. Thirty Python
tests, two Rust tests and display tests passed; temporary v4/v6 fixtures exercised
actual trust removal, deletion, unrelated-binding preservation and subsequent
attached-key verification without trust.

The subsequent live Proton test exercised **Remove trust** in Contacts, then
reopened the existing message: **Encryption: Not encrypted**, **Signature:
Valid**, **Certificate trust: Untrusted**. The public certificate remained saved.
After confirming **Mark trusted** for the same sender email and full primary
fingerprint, the reader showed **Not encrypted / Valid signature / Trusted
certificate**. Read-only storage checks confirmed both removal and restoration
of the exact email/fingerprint binding. Trust was left restored; no certificate
was deleted, no mail was sent and no YubiKey operation was performed.

A separate live Proton deletion/restoration test then passed in the Mac IWA:

1. **Delete saved certificate** removed both possible local public-certificate
   copies and every associated trust binding, confirmed with read-only storage
   checks.
2. Reopening the existing message verified with its attached key and showed
   **Not encrypted / Valid signature / Untrusted certificate**, plus **Not saved**.
   Verification did not automatically save the key or restore trust.
3. **Save certificate (no trust)** restored the public certificate only; the
   reader still showed **Saved locally / Not trusted**.
4. Explicit **Mark trusted** confirmation for the same sender email and full
   primary fingerprint restored **Saved locally / Trusted**, while the signature
   remained valid and the message remained unencrypted. Local storage confirmed
   the restored certificate and exact trust binding.

The test finished with the original certificate and trust restored. No email was
sent and no YubiKey operation was performed.

The subsequent **restart persistence test** passed after fully quitting the IWA
and confirming it was no longer running. On relaunch, Contacts still listed
Proton's saved public certificate and its trusted sender email. Read-only storage
checks confirmed the same full-primary-fingerprint/email binding persisted.
After reconnecting Gmail, reopening the existing Proton message again showed
**Encryption: Not encrypted**, **Signature: Valid**, **Certificate trust:
Trusted**, and **Saved locally**. Trust did not need to be granted again. No mail
was sent and no YubiKey operation was performed.

The **saved-certificate-only Proton verification test** used the installed
reader and Sequoia worker with a local test harness, rather than a new UI mode:

- The harness preserved the exact signed MIME bytes but replaced the worker's
  candidate-key list with only Proton's saved public certificate. The reader
  returned **Not encrypted / Valid signature / Trusted certificate**.
- A negative control supplied no verification certificates and returned
  **unknown-key**, confirming the worker did not independently use the embedded
  attachment as a key source.
- A separate local copy physically removed the key attachment. Proton includes
  that attachment inside the signed MIME entity, so removing it changes signed
  content; the original detached signature correctly became **invalid**.

Excluding an attachment as a verification-key source is different from deleting
its signed bytes. The former proves the saved certificate works independently;
the latter tests tamper detection and cannot retain the original valid signature.
Read-only hashes confirmed saved certificates and trust bindings were unchanged.
No email was sent, no YubiKey operation ran, and no local message copies or test
artifacts are included in the public repository.

The **Proton body-tampering test** exercised the installed IWA reader and
Sequoia worker through a local harness. The untouched local copy first returned
**Valid signature / Trusted certificate**. The test then changed text in the
signed body of a separate copy, retaining the exact detached-signature and
attached-public-key bytes. That copy returned **Invalid signature / Trusted certificate** with
`verified: false` in preview 0.4.6.

Signature validity and saved email/full-primary-fingerprint trust are displayed
independently. Invalid signatures retain a prominent warning that the message
may have been altered or forged and must not be relied upon, even when the
candidate certificate is trusted. A candidate key is not an authenticated sender.
Results without an identified certificate show unknown trust; invalid signatures
do not offer certificate save/trust actions. Rust, Python pipeline and renderer
regressions cover the invalid/trusted combination. Before/after hashes
confirmed that all saved certificates and trust bindings remained unchanged,
as did the original local message copy. Gmail was not accessed or modified, no
mail was sent and no YubiKey operation was performed. Local message copies and
test artifacts remain excluded from the public repository.

Version **0.4.4** offers **Save certificate (no trust)** and **Mark trusted for
[the sender email]** beneath a successfully verified signed Gmail message.
Saving stores only the public certificate for later verification. Trust requires
a confirmation showing the full primary fingerprint and exact sender email;
the native helper re-fetches and verifies the message and checks a current,
policy-valid, non-revoked self-certified mailbox before writing that binding.
Neither action changes the encryption indicator or authenticates outer headers.
Verification-only classical certificates are stored separately from the Level 3
hybrid contacts used for encrypted sending. Attached keys never gain automatic
trust, and no PIN or hardware operation is required.

The installed Mac preview passed both Proton-message actions: saving showed
**Saved locally / Not trusted**, then the explicit fingerprint/email confirmation
changed only certificate trust to **Trusted**. Encryption stayed **Not encrypted**
and the signature stayed **Valid**. The public certificate and exact email/full-
fingerprint binding were confirmed on disk and reloaded by the next helper
operation. No message was sent and no PIN, token key or policy was changed.
All 26 Python tests, two Rust tests and HTML/security-label tests passed, including
v4/v6 save-without-trust, rejected unrelated emails and persisted trust reload.

Version **0.4.3** verifies signed, unencrypted **PGP/MIME** using Sequoia,
without a PIN or a connected YubiKey. The reader reports **Encryption**,
**Signature** and **Certificate trust** independently. Supported v4 classical
and v6 hybrid signatures are checked against saved contact certificates and
attached `application/pgp-keys` public certificates. Attached certificates are
never automatically saved or trusted. Trust requires the full primary-key
fingerprint and the displayed From email to match an explicitly trusted contact.
The outer From, To and Subject remain unauthenticated by the body signature.

Invalid/policy-rejected signatures, missing certificates and unsupported formats
have distinct results; none is displayed as a valid trusted signature. This
preview verifies a root RFC 3156 multipart/signed envelope, preserving its signed
bytes rather than regenerating MIME. Inline/clear-signed messages and nested
signed wrappers are not yet verified. Verification is bounded to 256 KiB of
signed content, 64 KiB of signatures and 200,000 bytes of candidate certificates.
No keyserver lookup, trust changes or hardware operations occur during verification.

The installed Mac preview verified the existing Proton test as **not encrypted,
valid signature, untrusted certificate**, using its attached public key, without
a PIN, mail send or trust change. The public-fixture pipeline also passed v4/v6
valid-untrusted, valid-trusted and tamper-rejection cases. To reproduce the full
26 Python / two Rust tests (use an absolute target directory):

```sh
mkdir -p /tmp/iwa-public-fixtures
export IWA_PUBLIC_TEST_FIXTURES=/tmp/iwa-public-fixtures
export CARGO_TARGET_DIR=/tmp/iwa-crypto-target
cargo test --locked --manifest-path experiments/mac-iwa/crypto/Cargo.toml
cargo build --locked --release --manifest-path experiments/mac-iwa/crypto/Cargo.toml
export IWA_CRYPTO_TEST_BIN="$CARGO_TARGET_DIR/release/sequoia-iwa-crypto"
python3 -m unittest discover -s experiments/mac-iwa/tests -p 'test_*.py'
node experiments/mac-iwa/tests/test_format.cjs
```

These fixtures contain temporary public certificates and signatures, not private
keys or user messages. Without the two fixture environment variables, the two
Python integration tests are skipped; the other 24 run normally.

Version **0.4.2** reads ordinary unencrypted Gmail messages without a YubiKey
prompt or trusted-contact selection. These messages are explicitly marked
**signature and sender not verified**, including any unverified signatures they
may contain. Plain text and HTML use the existing inert renderer; remote images,
links and active markup do not execute. Attachments require explicit download.
The ordinary reader limits each text/HTML view to 32,768 characters and attachments to ten
files / 128 KiB combined, reporting omitted attachments.

The inbox checks complete MIME envelopes before showing the encrypted indicator,
including Gmail's strict rewritten PGP/MIME form. Subjects and attachment names
alone do not qualify. A lock denotes encryption packaging, not sender trust or a
verified signature. The preview recognizes supported PGP/MIME, not all possible
encrypted email formats. Listing fetches up to ten raw messages in memory to
classify them accurately; it does not persist message bodies or a mailbox cache.

Version 0.4.1 labels sign-in, inbox/Compose, confirmation and native PIN dialogs
for the selected Gmail or Chat service. Gmail sender certificates
must already be independently imported and trusted; the email test does not rely
on automatic attached-key trust or send a linked Chat certificate.

The integration keeps the native login and subsequent gws commands on the same
OS Keychain account. Existing experimental logins used gws's `unknown-user`
account because their launch environment omitted USER; the IWA installer pins
that account in its own wrapper to preserve these encrypted credentials. Other
gws installations are untouched. Gmail uploads stage only the encrypted message
in a private temporary directory beneath gws's profile, respecting its upload
path boundary; staging is removed on success or failure. Send authorization is
consumed before upload, with no automatic retry. Connection errors distinguish
Gmail consent/account problems from YubiKey operations and never expose raw CLI
errors or tokens.

### Two-way Gmail interoperability — 2026-11-21

| Direction | Verified result |
| --- | --- |
| IWA Gmail helper → standalone Sequoia | Delivered encrypted payload matched the prepared payload. Sequoia decrypted and verified the expected hybrid signer, authenticated From/To and subject, exact plain text and HTML, and all **289 binary attachment bytes**. |
| Standalone Sequoia → IWA Gmail | The IWA decrypted with the YubiKey and verified the trusted hybrid signer. Visual inspection confirmed heading, bold, italic and two list items. The actual browser attachment download matched all **308 bytes exactly**. |

Both directions used **ML-DSA-65 + Ed25519** signing and **ML-KEM-768 + X25519**
encryption with existing keys. All **24 PIV slot records**, including public-key
hashes and PIN/touch policies, matched before/after each hardware operation.
No keys or policies were changed. Gmail rewrote the outer PGP/MIME envelope to
its two-part `multipart/mixed` form; the existing strict parser recognized it,
and authenticated inner MIME remained intact. The outgoing test used the
installed helper test harness; the return exercised the IWA inbox, reader, HTML
view and download UI. Local account details, device identifiers, credentials and
private test reports are excluded from this repository.

### Service-specific labels — 0.4.1

The selected service drives the page heading, sign-in/reconnect buttons,
inbox/conversation controls, Compose destination/help, send confirmation and
reader prompts. Gmail hides Chat conversation controls; Chat hides Gmail search.
Changing services clears pending message selections and send reviews. The
service selector is disabled during a native operation so its labels cannot
switch while a request is running.

Native routes choose fixed PIN descriptions: **Sign and encrypt Gmail email**
and **Decrypt and verify Gmail email**, or **Sign and encrypt Chat bundle** and
**Decrypt and verify Chat bundle**. Browser-supplied arbitrary prompt text is
not accepted. The Mac preview was updated to 0.4.1 and both service views were
checked. The 18 Python tests include both services' signing/decryption labels;
JavaScript syntax and inert HTML rendering checks also pass. No cryptographic
operation or message send was needed for this interface update.

## Google Chat preview

Version 0.2.0 adds Google sign-in/reconnect, paged conversations and messages,
trusted public-certificate review, and signed/encrypted text composition. The
configured Level 3 identity uses ML-DSA-65 + Ed25519 and ML-KEM-768 + X25519
through the existing PKCS#11 backend. The native worker verifies its signature
before encrypting; received plaintext is released only after authenticated
decryption and verification against the selected trusted certificate.

**Prepare encrypted message** prompts for the PIN outside Chrome. A separate
review confirms the recipient, fingerprints and conversation before sending.
The prepared ciphertext expires after ten minutes and its send authorization
is consumed before a network attempt, preventing an automatic duplicate send
following an ambiguous network failure. Public sender certificates travel in a
separate linked Chat message. Attached keys never automatically become trusted.

Version 0.3.0 adds bold, italic, headings and lists through simple Markdown
controls, with optional HTML alongside the plain-text alternative. Up to ten
attachments (128 KiB combined) fit within the 256 KiB encoded MIME limit.
The reader can switch between plain text and an inert HTML formatting allowlist,
and explicitly save verified attachments. It never creates remote images,
scripts, links, event handlers or other HTML attributes. Attachments are offered
as downloads, not automatically opened. Only the configured Level 3 hybrid
profile is supported.

### Formatted attachment interoperability — 2026-11-21

The installed IWA sent a signed/encrypted multipart bundle to the standalone
Sequoia peer through Google Chat. The peer decrypted it and verified the hybrid
signature against the explicitly selected public certificate. Its saved checks
confirmed `multipart/mixed` containing `multipart/alternative`, exact plain text,
and HTML heading, bold, italic and list markup. The synthetic binary attachment
matched all **66 bytes exactly**, including its non-text bytes. All **24 PIV
slot records**, public-key hashes and PIN/touch policies remained unchanged.
This verifies transmitted MIME and attachment interoperability; it is not a claim
that every external client's visual HTML layout is identical.

The reverse **Sequoia → IWA** formatted test also passed on **2026-11-21**.
The standalone peer sent a signed/encrypted bundle with plain-text and HTML
alternatives and a 308-byte binary attachment. The IWA decrypted it through the
existing YubiKey PKCS#11 backend and verified its hybrid signature against the
trusted peer certificate. Visual inspection confirmed the heading, bold and
italic text, and both bullet-list items. The IWA's **Save attachment** action
completed, and the downloaded file matched all **308 bytes exactly**, including
all byte values from 0 through 255 in the synthetic fixture. All **24 PIV slot
records**, including public-key hashes and PIN/touch policies, matched before
and after. Together these tests cover formatted bundles in both directions,
including actual IWA HTML display and browser attachment download.

Offline validation includes twenty-one Python tests, a Rust signed/compressed/
encrypted multipart round trip with wrong-signer/wrong-recipient/tampering
rejections, and a JavaScript inert-rendering/escaping test:

```sh
python3 -B -m unittest discover -s tests -v
node tests/test_format.cjs
cargo test --locked --manifest-path crypto/Cargo.toml
```


Google refresh credentials remain in this installation's **separate gws profile**
with gws's macOS Keychain-backed encryption, not PQ Mail's PRF vault. Public
contact certificates, fingerprints, ciphertext, and send metadata are persisted
locally. Decrypted message bodies and PINs are not deliberately written to disk;
process memory, swap and crash dumps are not guaranteed to be securely erased.
The browser displays decrypted plaintext after successful verification.

Build the worker (with the adapter's OpenSSL prerequisites installed):

```sh
cargo test --locked --manifest-path crypto/Cargo.toml
cargo build --locked --release --manifest-path crypto/Cargo.toml
```

After installing the baseline native runtime below, run `install_chat.py --help`
and supply that installation, this repository's transport root, the gws and sq
binaries (and the built `bin/chat-software-identity` policy helper in the
transport root), your OAuth desktop-client registration JSON, the built worker, and the
sending email. This copies registration metadata only, never another profile's
Google account tokens. Rebuild/update the signed IWA without changing its build
keys and reload the existing extension. Sign in through the IWA, reconnect, then
review/import the peer's public certificate and independently confirm its full
primary fingerprint before trusting it.

Offline validation passes twelve Python protocol/bridge tests plus a Rust hybrid
round-trip test covering wrong signer, wrong recipient and modified ciphertext.
On **2026-11-21**, the installed Mac IWA and standalone gws/Sequoia peer
passed a live two-way signed and encrypted Google Chat test:

- **Sequoia → IWA:** the IWA downloaded the linked bundle and public certificate,
  decrypted through the YubiKey, and verified the hybrid signature against the
  independently trusted peer. It displayed the expected text and recognized the
  embedded attachment.
- **IWA → Sequoia:** the IWA signed through the YubiKey and encrypted to the
  peer's v6 certificate. The peer retrieved the message using its separate gws
  account, decrypted with its password-protected software identity, and verified
  the hybrid signature against the explicitly selected sender fingerprint. The
  recovered plaintext matched the synthetic message exactly.
- All **24 PIV slot records** were identical before and after, including full
  public-key hashes and PIN/touch policies. No keys or policies were changed.

Google connection and message listing also passed after reconnecting the saved
IWA session. A sign-in fix now exposes gws's Google authorization URL explicitly
when gws does not open a browser; Google connection errors are distinguished
from hardware errors. That final sign-in-link UI correction has offline checks;
the successful live authorization used the same gws link opened manually.
The hardware-only IWA result below is a separate earlier test.

## Current scope

- Connection check for the explicitly configured YubiKey.
- One fixed synthetic Level 3 hybrid signing test: ML-DSA-65 in 9c + Ed25519 in 84.
- Two authenticated hybrid decryption tests: ML-KEM-768 in 9d + X25519 in 85,
  using Sequoia-generated and independent PQ Mail/Bouncy Castle ciphertexts.
- Independent PQ Mail verification of the Sequoia signature.
- Read-only comparisons of all 24 ordinary PIV slot states, full public-key
  hashes, algorithm/origin metadata, PIN policy and touch policy before/after.

The existing `sequoia-pqmail-piv` adapter and `piv-test` binary are reused. The
PKCS#11 helpers/provider/module are copied from the installed PQ Mail backend;
the hardware runner records their hashes. There are no reset, generate, import,
management-key, certificate-write or touch-policy commands in the test API.

## Architecture and authorization

`app/` is packaged as a signed `.swbn`. `extension/` allows precisely its
`isolated-app://` origin, and additionally checks the caller's root URL and
frame ID. Requests use a closed schema: hardware status/test and the explicitly
listed Chat actions in `native/chat_bridge.py`. Arbitrary commands, URLs, executable
paths, PINs and slot mappings are not accepted from the browser.
The native host manifest permits exactly the matching extension ID; the host
also checks Chrome's caller argument and bounds incoming native-message frames.
The host argument check is defense in depth, not authentication against another
local process running as the same OS user.

The browser and extension never receive the PIN. A native AppKit secure-text
field collects it for each operation. A private, non-echoing PTY feeds the existing
adapter test's controlling-terminal PIN prompt. No PIN is put in argv,
environment variables, persistent files or browser storage. Three authorization
operations are expected; each composite's components share one operation-scoped
PIN. The helper does not retry failed operations automatically. Swift, Python,
OS swap and crash dumps mean complete secure-memory erasure is not guaranteed.

Only fixed synthetic fixtures, public certificates, backend hashes and test
results are saved. An incomplete after-snapshot means unchanged status is
**unconfirmed**, never an automatic success. The test does not compare arbitrary
PIV data objects or FIDO/OATH state; it neither reads nor modifies those apps.

## Mac preview installation

This preview uses **Chrome Canary 160** with a separate profile and the
`IsolatedWebApps,IsolatedWebAppDevMode` feature flags. On this version the developer
UI is `chrome://iwa-dev`. The signed bundle is `build/sequoia-lab.swbn`.
Canary ignored `--load-extension`; load `extension/` with **Load unpacked** in
`chrome://extensions` after enabling Developer mode in the test profile.

The native host, PIN UI and required test runtimes are installed under
`~/Library/Application Support/Sequoia IWA Lab/`. Keeping executable helpers out
of Documents avoids granting Canary additional Documents-folder access.
The host registration is in this experiment's
`private/chrome-profile/NativeMessagingHosts/`; it does not change your normal
Chrome profile. Hardware output is under the installed helper's
`private/hardware-*/` directory.

`private/config.json` is local-only configuration: public certificate location,
serial, fixed executable paths and extension ID. Build keys and local browser
state are excluded from source control. The generated development signing key
is not a production distribution identity. Do not distribute `private/`.

## Build and tests

Node 22.13+ is required by `wbn-sign`; the local preview uses isolated Node 24.
Dependencies are pinned in `package-lock.json`. Build with:

```sh
npm ci
./node_modules/node/bin/node build.mjs
swiftc native/PinPrompt.swift -o build/pin-prompt
python3 -B -m unittest discover -s tests -v
```

The build creates a stable experiment signing key and extension ID on first use.
Never regenerate them to update an installed preview. A native host installation
must point at the matching fixed local configuration and preserve owner-only
private files. Hardware dependencies are local prerequisites, not bundled into
the web bundle. This preview is not a self-contained public installer.

Protocol tests cover valid framing, truncated/oversized input, non-object
messages and rejection of extra fields/arbitrary operations. Direct native-host
checks additionally confirmed correct-caller status and wrong-caller rejection.
`wbn-sign info` verified the bundle signature. Canary installed and opened the
signed bundle and successfully queried the connected key through the extension.
Live cryptographic results are recorded separately after user PIN authorization.

## Live Mac IWA hardware result — 2026-11-21

The installed signed IWA → extension → native helper path passed with an
existing Level 3 YubiKey in Chrome Canary 160. Three native PIN dialogs authorized
one composite signature and two hybrid decryption operations. Sequoia verified
the signature, PQ Mail independently verified it, and both Sequoia and PQ Mail
ciphertexts decrypted to the exact expected synthetic plaintext. The IWA displayed
the final PASS result. All 24 before/after slot records were identical, including
public-key hashes and PIN/touch policies. No mail was sent or keys provisioned.

This confirms the experimental Mac Native Messaging bridge, not native macOS
Web Smart Card support or a production IWA deployment path. The prototype still
requires local runtime installation and an unpacked extension.

Observed timings (including user touch wait) were **3,114 ms** for signing,
**1,010 ms** for Sequoia-ciphertext decryption and **897 ms** for independent
PQ Mail-ciphertext decryption. These are single-run measurements, not a benchmark.
The source generalizes device-specific display text to the configured serial;
local serial numbers, fingerprints, account data and hardware transcripts are
not included in this repository.

### Reproduce the local installation

1. Build the existing [`sequoia-pqmail-piv` adapter and hardware test](https://github.com/ve7jtb/sequoia/tree/development/yubikey6-piv/piv-adapter), following that fork's prerequisites. Prepare its `PqMailInterop` Java classes and the existing PQ Mail JAR/libraries. `piv-test` can depend on a separately installed OpenSSL; inspect `otool -L` and retain those dependencies. This experiment does not build or silently replace your PKCS#11 backend.
2. Run the build commands above. Copy `config.example.json` to ignored `private/config-input.json` and set the absolute paths, matching **public-only** v6 certificate, and explicit Level 3 serial. The test selects only 9c/84/9d/85; arbitrary slot mappings and Level 5 are not supported here.
3. Run `python3 install_native.py --config private/config-input.json`. It copies existing runtimes into a new directory under Application Support and registers the host only in this experiment's Canary profile. It refuses to overwrite an existing destination; `--destination` can select a new one. The source installer is additional packaging convenience; the successful hardware test used an equivalent local runtime copy, not a clean-machine installer test.
4. Run `python3 launch_canary.py`. In that profile, enable extension Developer mode and load the generated `extension/` directory with **Load unpacked**. Launch **Sequoia Chat Lab** from `chrome://iwa-dev`.
5. Choose **Check YubiKey**, then **Hardware test → Run signing & decryption test**. Confirm the fixed test, enter PINs only in the native dialogs, and touch as requested. A failure is not retried automatically. Keep the device connected for the after snapshot.

This requires user approval of developer-mode installation. The extension and
IWA are local experimental code; neither is a Chrome Web Store release. The
signed web bundle authenticates its contents, not a publicly vetted publisher.

To remove the experiment, close its Canary profile, unregister its dedicated
NativeMessagingHosts manifest and remove the dedicated installed helper and
profile only when you no longer need their local test records. No YubiKey reset
is involved. Do not remove your usual Chrome profile or PQ Mail installation.

## Verification-only WebAssembly prototype

Preview 0.5.2 includes a separate browser-worker diagnostic for Sequoia detached
signature verification using RustCrypto. Eight native-versus-WASM comparison
cases passed under Node and visibly in the installed IWA, including v4, Level 3 hybrid v6 and the original/altered
Proton message. Preview 0.6 subsequently moves message MIME processing and
normal verification into the IWA; see the browser MIME section below.
See [build instructions, limits and test scope](wasm/README.md). Private Proton
vectors are selected locally and are not bundled or published.

The baseline verifier remains the default diagnostic. Wide arithmetic is an
explicit comparison, never an automatic replacement or fallback. Both variants
passed all eight v4/hybrid-v6/Proton tests in the installed IWA. Valid hybrid v6
median time was 0.420 ms baseline versus 0.400 ms wide; v4 and Proton medians
were unchanged. Short-call timer quantization and overlapping timing ranges
limit the conclusion. See the [complete benchmark and reproduction notes](wasm/README.md).


## Browser MIME and baseline WASM verification (preview 0.6)

The IWA now composes multipart MIME (UTF-8 text/HTML alternatives and binary
attachments) and parses ordinary mail, PGP/MIME signed bodies, and decrypted
Chat/Gmail bundles in a disposable worker. PostalMime 4.2.1 is pinned and bundled;
it fetches no remote code. Detached signatures use the baseline Sequoia WASM
module, with no native fallback and no wide-arithmetic requirement. Signed MIME
bytes are extracted without reserialization. The parser handles Gmail's strict
two-leaf encrypted-envelope rewrite, including a text/plain armored payload.

YubiKey signing and decapsulation, AEAD integrity validation, OAuth credentials,
Google transport, and persistent public-certificate/trust storage stay native.
Decryption supplies exact literal bytes and signature packets to the IWA; the
browser verifies the signature and selected sender/recipient before display.
The helper retains defense-in-depth checks when signing outgoing data or
explicitly saving/trusting a certificate. It also checks compose address/subject
metadata and constructs the outer encrypted Gmail transport wrapper. Thus this
is a message-processing move, not elimination of every native MIME parser.

Limits are 256 KiB per MIME message, 64 parts, 16 nesting levels, 32 KiB total
headers, and ten displayed attachments totaling 128 KiB. Workers terminate after
30 seconds and on completion. HTML remains inert; no links, remote resources,
scripts or attachment previews execute. Signature validity, encryption and saved
email/fingerprint trust remain separate indicators. Local `.eml` copies can be
opened without upload, saving a certificate or changing trust.

Regression checks cover v4 and hybrid v6 detached signatures, attached keys,
body tampering, wrong sender, exact native-decrypted signature extraction,
AEAD corruption rejection, Gmail's rewritten envelope, and browser-composed
Unicode text/HTML plus a byte-for-byte 308-byte attachment round trip. The
installed preview also visibly rejected the local tampered Proton message while
retaining its saved trusted-certificate indicator. Live Gmail reading verified
the original Proton message as valid/trusted through baseline WASM. Both Google
sessions reconnected, Chat listed the test conversation, and the browser parser
recognized the existing Gmail encrypted test (8,272 ciphertext bytes). All five
original-message/public-certificate/trust snapshot hashes remained unchanged.
Live encrypted Gmail and Chat reads then passed on 2026-11-22 with the
configured Level 3 YubiKey: native decryption succeeded, the baseline WASM
verifier accepted the hybrid signature, and the IWA displayed the trusted
Sequoia peer and 308-byte attachment. Chat HTML rendering also passed. These
were reads of existing test messages; no new email/Chat send, key generation or
touch-policy change was performed. The attachment count here is the displayed
size; this run did not repeat the earlier exact download-byte comparison.


Reproduce the browser/native boundary checks (after `npm ci --ignore-scripts`
in `experiments/mac-iwa` and building the baseline WASM assets):

```sh
mkdir -p /tmp/iwa-public-fixtures
IWA_PUBLIC_TEST_FIXTURES=/tmp/iwa-public-fixtures cargo test --locked \
  --manifest-path experiments/mac-iwa/crypto/Cargo.toml
mkdir -p experiments/mac-iwa/app/vendor/postal-mime
cp experiments/mac-iwa/node_modules/postal-mime/dist/esm/*.js \
  experiments/mac-iwa/app/vendor/postal-mime/
IWA_PUBLIC_TEST_FIXTURES=/tmp/iwa-public-fixtures node --test \
  experiments/mac-iwa/tests/message-mime.test.mjs
python3 -m unittest discover -s experiments/mac-iwa/tests -p 'test*.py'
node experiments/mac-iwa/tests/test_format.cjs
```

`IWA_PROTON_ORIGINAL` and `IWA_PROTON_TAMPERED` optionally point to local `.eml`
fixtures for the additional Proton test; private mail is never bundled. The
three native crypto tests generate only temporary software keys/public fixtures.
The Python suite currently passes 31 tests with two optional native pipeline
tests skipped when their external fixtures/runtime are not configured.

### Browser OpenPGP encryption (preview 0.7)

The baseline Sequoia/RustCrypto WASM worker now encrypts outgoing Level 3 v6
messages with ML-KEM-768 + X25519. Native YubiKey signing returns an independently
verified signed packet stream; WASM verifies it again against the exact composed
MIME, checks the selected recipient fingerprint and current mailbox binding,
compresses the signed packets with ZLIB, and encrypts with fresh Web Crypto-backed
randomness. No private key, PIN or Google credential enters the browser.

The native helper retains YubiKey signing and authenticated decryption, Google
transport, saved trust, and explicit one-use send reviews. It checks that returned
ciphertext has one v6 recipient matching the selected hybrid key and one AEAD
packet. A ten-minute ticket binds the browser encryption completion to the
native-selected recipient, service and destination; trust is checked again before
staging. During the signing/encryption handoff, the owner-only ticket stores
routing and review metadata, including the subject, but no body or attachment
plaintext. Successful completion deletes it; an interrupted operation can leave
an expired ticket on disk. As with any client-side encryption, a compromised frontend could encrypt
different content: public packet inspection cannot establish plaintext equality
without the recipient's private key. The signed IWA and its worker are part of the
trusted application. Failures never retry the YubiKey or fall back to native
outgoing encryption.

Offline validation includes baseline browser-target WASM encryption decrypted and
signature-verified by native Sequoia, exact plaintext comparison, fresh ciphertext
randomness, and rejection of wrong recipient fingerprints/mailboxes, altered signed
content, malformed packets, secret certificates and oversized input. The native
packet guard rejects plaintext and wrong-recipient ciphertext. Completion tests
cover expired tickets, changed contacts, forbidden routing overrides and replay.
On **2026-11-22**, preview **0.7.0** passed live IWA → Sequoia tests through both
Gmail and Google Chat. Received ciphertext matched the sent copies exactly.
Sequoia decrypted both messages and verified their ML-DSA-65 + Ed25519 signatures
against the expected full sender fingerprint. Signed From/To and subjects,
plain-text and HTML alternatives (including Unicode), attachment filenames and
all **308 binary attachment bytes** matched the expected fixtures exactly.
HTML was compared as source on the CLI peer, not rendered there. No keys or touch
policies were changed. These tests used baseline WASM encryption; the earlier
0.6.2 composer tests used native encryption.

The complete offline run passed 36 Python tests (including both native pipeline
fixtures), four native Rust tests, seven MIME worker tests and eight public
verification cases, including original and tampered Proton messages. Two fresh
WASM encryptions independently decrypted and verified with native Sequoia and
passed the native recipient/AEAD packet guard.

### Browser decryption with native decapsulation (preview 0.8)

The live Gmail/Chat reader now asks the native helper only to decapsulate and
unwrap the per-message OpenPGP session key. ML-KEM and X25519 private operations
remain on the configured YubiKey through PKCS#11; signing and PIN entry also
remain native. The helper checks the selected v6 recipient and AEAD packet shape
before decapsulation. It returns a bounded session-key response bound to the exact
ciphertext SHA-256, recipient-key fingerprint and symmetric algorithm.

The disposable baseline WASM worker decrypts, authenticates the complete AEAD
message (including its final tag), decompresses and extracts its signed MIME,
then verifies the signature and existing sender/recipient/trust checks before
showing content. Failures release no message result and trigger no native fallback
or automatic hardware retry. The per-message session key necessarily crosses the
extension bridge into browser memory; it is never persisted or logged. Main-page
references are removed after posting to the worker and the worker is terminated
on completion/error/timeout. JavaScript strings, IPC copies and OS memory cannot
promise secure erasure. Long-term private keys and PINs never enter the browser.

Offline tests cover native Sequoia decapsulation followed by baseline WASM
decryption and hybrid verification with exact MIME recovery, wrong keys and key
lengths, invalid algorithms/recipients, ciphertext substitution, corrupted final
AEAD tags, truncated ciphertext and plaintext input.

Live preview **0.8.0** tests on **2026-11-22** passed for both Gmail and Chat:
native Level 3 YubiKey decapsulation, baseline WASM authenticated decryption,
valid ML-DSA-65 + Ed25519 signatures and trusted sender certificates. The IWA
visibly rendered HTML headings, bold/italic text and lists. Each downloaded
binary attachment matched the original **308 bytes** exactly, with SHA-256
`dcfa99c88a6aab863d39ffe61851ec8a93c10e81634306740c662fac87c74030`.
These were existing Sequoia peer messages, with no new sends or key/policy
changes. Gmail's first attempt stopped without a result; a fresh user-authorized
attempt passed, without an automatic private-key retry. Local test reports and
message content are excluded from Git. These results specifically exercise the
new WASM decryption boundary, unlike the earlier native-decryption tests.
