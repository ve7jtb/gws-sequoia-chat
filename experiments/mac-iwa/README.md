# Sequoia YubiKey Lab — experimental Mac IWA

A signed Isolated Web App calls a tightly scoped Chrome extension, which calls
an installed native host through Chrome Native Messaging. There is no listening
HTTP server. This is a hardware integration experiment, not a mail/chat client.
The repository’s main loopback Mail/Chat application remains separate.

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
frame ID. Only `status` and `test` requests without additional fields are accepted.
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

Five protocol tests cover valid framing, truncated/oversized input, non-object
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
4. Run `python3 launch_canary.py`. In that profile, enable extension Developer mode and load the generated `extension/` directory with **Load unpacked**. Launch **Sequoia YubiKey Lab** from `chrome://iwa-dev`.
5. Choose **Check connection**, then **Run signing & decryption test**. Confirm the fixed test, enter PINs only in the native dialogs, and touch as requested. A failure is not retried automatically. Keep the device connected for the after snapshot.

This requires user approval of developer-mode installation. The extension and
IWA are local experimental code; neither is a Chrome Web Store release. The
signed web bundle authenticates its contents, not a publicly vetted publisher.

To remove the experiment, close its Canary profile, unregister its dedicated
NativeMessagingHosts manifest and remove the dedicated installed helper and
profile only when you no longer need their local test records. No YubiKey reset
is involved. Do not remove your usual Chrome profile or PQ Mail installation.
