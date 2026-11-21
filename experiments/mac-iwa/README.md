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

This is an encrypted-mail preview, not a general-purpose Gmail reader. The
current list attempts encrypted-message opening for each row; ordinary mail
fails closed. Version 0.4.1 labels sign-in, inbox/Compose, confirmation and native PIN dialogs
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

Offline validation includes eighteen Python tests, a Rust signed/compressed/
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
