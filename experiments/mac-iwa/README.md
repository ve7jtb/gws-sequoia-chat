# Sequoia Chat Lab — experimental IWA

The top-level **FIDO tests** tab contains GetInfo diagnostics, cancellation and
public results. It also provides explicit one-time **previewSign** setup and
a repeatable synthetic signing test (experimental ARKG-P256, -65539). Setup
creates a separate non-discoverable credential with UP+UV; it never adds the
extension to or replaces the PRF vault credential. Public descriptors and opaque
handles stay locally; no PIN/private keys are saved. Verification checks both
the FIDO assertion and the derived-key signature, including a negative test
with altered message bytes. The single-message hardware test passed on the connected Beta0 key. The ten-key hardware batch and independent native Sequoia CLI checks passed. The implementation
is checked against Yubico’s ARKG reference vector. See [Yubico previewSign](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Signing_Extension_Preview.html).
The **Test 10 ARKG OpenPGP certificates and messages** action derives ten distinct
P-256 public keys, self-certifies ten v4 OpenPGP certificates, and signs ten
individual synthetic messages. Each certificate and message is checked with
Sequoia WASM, including rejection of altered messages. Public `.pgp` files and a
JSON report can be downloaded; nothing is mailed or added to trust stores.
There are twenty PIN/touch operations, labelled with the key and purpose.
Software regression tests validate all ten outputs with Sequoia WASM and native
`sq verify --message --signer-file`; the packet stream includes a one-pass
signature, literal data, and signature. No PIV keys or policies are modified.

After installing an update in Chromium, use **View → Force Reload This Page**
if a new button does not respond: an older loaded module can otherwise remain
active alongside the updated HTML. Current publication checks: 31 targeted tests
passed, including native Sequoia verification of all ten software test messages.
The ten-key hardware batch passed, followed by native Sequoia CLI verification
of all ten exported messages, exact payload recovery, altered-message rejection
and wrong-certificate rejection. See the [hardware interoperability report](../../docs/arkg-openpgp-interop.md).

**Vault** retains enrollment settings, credential creation and
lock/unlock controls.

## Guided empty-vault setup (0.20.29 testing)

Unconfigured installations select Web Smart Card with SCP11b and the temporary
beta SD certificate pin enabled. Explicit saved choices are preserved. The
beta pin remains visibly labeled as test trust, not manufacturer-root verification.

Restore uses a direct navigation button: IWA CSP blocks HTML form submissions.
Create a new vault has a dedicated two-step wizard: name, then verify an existing
FIDO PRF credential, explicitly create a new PRF credential, or use existing PIV
wrapping keys. It contains no backup restore controls. No unprotected vault is
saved before an unlock method is verified. After creation, setup offers existing
provisioned YubiKey identities or new software keys; hardware backup remains a
separate reviewed operation.

## Single-touch key-generation entropy (0.20.26 testing)

Software identity creation offers **Mix YubiKey entropy into key generation**
(default selected). It creates one temporary non-discoverable credential
under the signed IWA RP, using `hmac-secret-mc` at creation time: one touch, no follow-up assertions, and no saved credential handles. Every
operation uses a fresh user handle, challenge and 32-byte PRF input. The flow
requires Web Smart Card, SCP11b and advertised extension/protocol support.

PIN-free creation is used when policy permits. If Always UV is enabled, or
PIN-free creation is not advertised, the app prompts once and keeps the normalized
PIN in a mutable operation buffer for one RP-scoped token request. It clears
that buffer, tokens and contributions on completion, cancellation or failure.
There is no automatic retry. Browser runtimes may retain transient copies; this
is not a guarantee against memory/swap inspection. Existing FIDO credentials,
PIV slots and policies are not changed by entropy collection.

Inside the disposable WASM worker, HMAC-DRBG/SHA-512 mixes one 32-byte output
with 96 fresh OS-random bytes and a purpose label. Only the generation operation
uses this state; it is erased on exit. Other random calls retain their OS source.
The WASM backend checks that generation consumed the mixed RNG. The 256-bit output is supplemental input, not a measurement of physical entropy, and this is not a FIPS validation
or protection against a compromised host. Unchecking the option explicitly uses
OS randomness alone. Neither entropy values nor temporary handles enter vault
records or exports.

Validation: 115 automated JavaScript tests passed (one optional test skipped).
Protocol peer tests cover one PIN-free creation, Always-UV PIN handling,
cancellation and failure without retry. An independent HMAC reference test checks
DRBG generation/update and clearing. All seven software profiles passed the mixed
entropy WASM signing/decryption, encrypted export/restore and restart test with
simulated hardware contributions. Physical single-touch validation remains pending.

## Vault-first startup (0.20.25)

The app starts at **Log in** when a vault exists, with the saved FIDO PRF or PIV
unlock methods. A successful unlock opens the conversation workspace; locking
or the inactivity timeout returns to login. Google sign-in is a separate step.
An empty instance starts with **Restore complete encrypted backup**, **Create a
new vault**, and **Set up a new YubiKey**. Creation reuses the existing reviewed
FIDO/PIV enrollment controls; it never performs a private operation on page load.
Connection settings, including required SCP and the explicit beta pin, remain
available under a disclosure and are not changed by startup routing.

The new-key setup explains FIDO PIN initialization using Yubico Authenticator
and FIDO PRF credential creation here. After vault creation, it guides the user
to account setup and software OpenPGP key generation. Private keys and their
random file password remain encrypted in the vault. Optional hardware backup
provisioning is an explicit, separately reviewed action on a Level 3 software identity. SCP11b now defaults to required on new instances; an explicit saved
choice is preserved. The beta SD pin remains a separate opt-in trust choice. Imported vault-only backups must be explicitly
saved before the workspace opens; complete backups retain authenticated review
and readback verification.

### Empty-card backup import (0.20.25 testing channel)

The backup-import planner detects the card serial and requires all 24 user PIV
slots to contain neither keys nor certificates. Factory attestation is excluded;
no reset or overwrite is offered. The transaction coordinator journals public
progress, stops on partial failure, and keeps software keys unless public-key
matching, signing, decryption and persistence of a usable hardware identity all
succeed. Removal is a separate, unchecked-by-default decision; previously
exported encrypted backups can still contain private keys.

The import adapter and vault hardware bindings are integrated. The Level 3 v6
profile copies six existing software components over required SCP11b: ML-DSA-65
certification/signing in 86/9c, Ed25519 certification/signing in 87/84, ML-KEM-768
in 9d, and X25519 in 85. All require a PIN; 86, 9c and 9d require touch. Readback
checks every public key and policy before local signing/decryption tests. Level 5
Ed448/X448 backup is not offered on cards lacking those algorithms.

After verification, the encrypted vault retains the public certificate, detected
serial and six public-key hashes. Removing the software copy is a separate
confirmation; subsequent private operations use the serial-checked card. A fresh
encrypted vault backup is required to carry this mapping to another instance:
this flow does not write a self-contained public certificate bundle onto the card.
Imported private keys have software origin and cannot claim on-device generation
or generated-key attestation. Removal cannot erase copies in old backups or
promise physical erasure of browser memory, swap or storage remnants.

Automated validation: 90 targeted JavaScript tests passed, plus the real WASM seed export. Coverage includes simulated PIV management
authentication/import/readback, refusal of occupied slots and incorrect keys,
and vault persistence/removal across restart. Live provisioning and removal
validation is still pending; no hardware success is claimed by these tests.

## Backup restore and SCP (0.20.24)

Complete restore preserves the receiving device’s SCP requirement, temporary beta-pin selection and hardware transport. It never imports those connection settings from a backup; absent local settings retain normal defaults. Other conflicting settings, vaults, identities and certificate trust still stop restoration before writing. Readback verifies the restored records together with preserved local settings, and interrupted restore remains resumable. The backup page now loads the same SCP policy before PRF access. It does not silently bypass a required secure channel.

Validation: 25 backup, startup and secure-channel tests passed, including local-policy preservation, refusal to import beta trust, conflicting certificate trust and interrupted recovery. Live Chromebook validation also passed on 2026-11-25 with signed IWA 0.20.24:

- The existing FIDO PRF credential authenticated and decrypted the complete backup over required SCP11b.
- Restore displayed **Restore complete** and verified the restored vault, certificate/contact trust store and settings by reading them back. This backup contained no saved identity-database record; the test does not claim identity restore coverage.
- Returning to the main app showed the restored account and existing FIDO PRF unlock method. A fresh PIN-and-touch assertion displayed **Vault unlocked**.
- Both **Secure YubiKey connection** and **Beta YubiKey 6 testing** remained checked. After the operation, the status reported that the secure session had closed and SCP11b remained required for the next operation.

One unrelated public-account setting initially differed from the backup. Restore refused it before writing. The re-creatable local email/revision setting was explicitly cleared through Account, then restored from the authenticated backup; certificate trust and security preferences were not cleared. The general conflict checks remain enabled.

Only existing-credential authentication and public discovery were used: no card key/credential creation, deletion, PIN change, touch-policy change or Security Domain configuration was performed. FIDO assertions may advance the signature counter. This is an observed workflow result, not a full before/after audit of every card slot and policy. The temporary beta SD pin authenticates the pinned certificate chain; the unavailable Yubico preview root has not been independently verified.

## Temporary Beta YubiKey 6 SD pin (0.20.23)

The opt-in “Beta YubiKey 6 testing” checkbox selects the exact bundled SD attestation certificate as a temporary trust anchor. This is not a wildcard for beta models or serial numbers. Only SCP leaf certificates chaining to that certificate are accepted; other beta devices may need a different authenticated anchor. The certificate was obtained from a test device, not authenticated against the unavailable Yubico 2026 SD Preview CA, so this does not establish manufacturer provenance.

Production-root trust remains the default. The SHA-256 certificate pin is `e4e054c35c106f51541775d04da2055ca0190c84c1647719133acc6484ea0a54`. Validity, CA/path length, key usage, SD policies, leaf signature and SCP proof-of-possession checks remain enabled. Trust selection is frozen during card transactions; there is no fallback between anchors or to plaintext. Remove the temporary mode when the independently sourced preview CA becomes available.

Validation: 12 secure-channel/startup tests passed; the saved Beta0 public chain validates against the pin and a tampered leaf is rejected. Live secure-channel and PRF unlock validation subsequently passed with 0.20.24 as documented above. No card keys, credentials or policies were changed by that workflow.

## Secure-channel startup correction (0.20.22)

The Chromebook check of 0.20.21 stopped with “Secure-channel policy is not ready” before any card operation or PIN request. Its application bootstrap omitted the secure-channel UI module. Version 0.20.22 loads that module before the hardware and vault entry points, with a production-loader regression test. Hardware SCP and PRF validation subsequently passed with 0.20.24 and the explicit beta pin (see above); the application never silently falls back to plaintext.

## Secure YubiKey connection preview (0.20.21)

The optional **Secure YubiKey connection (SCP11b; Web Smart Card only)** toggle
requires an authenticated, encrypted card session for direct PIV and CTAP2.
New instances require it by default from 0.20.25; an explicit saved choice is preserved. When enabled it never silently falls back to plaintext or the
native helper. The existing serial/public-key checks still identify the intended
key. Failure of the manufacturer chain, handshake receipt, response MAC or
padding ends the operation before further commands.

The independent [secure-channel module](app/secure-channel/README.txt) can be
reused by other IWAs. Its pinned Yubico Attestation Root 1 and bundled SD
intermediates are offline signed application assets. Discovery and applet SELECT
are public; application traffic is protected after the SCP11b handshake.
SCP11b is classical transport protection, not post-quantum encryption or host
attestation. Revocation is not checked online. Beta devices with unrecognized
chains are rejected rather than implicitly trusted.

After integrating the 0.20.20 Drive/backup/OAuth changes, all 98 targeted
software tests passed with no skips, including independent
OpenSSL MAC/encryption checks, certificate and receipt rejection, secure applet
reselection, and refusal before PIN prompting. Physical SCP11b FIDO PRF validation subsequently passed with 0.20.24 and the explicit beta pin (see above); PIV signing/decryption under SCP is not established by that vault test. Existing 0.20.15 Chromebook results below did not enable SCP.
Enabling the toggle changes only an application preference, not key material,
PINs, touch policies or Security Domain configuration on the YubiKey.

## Chromebook Gmail validation and Web Smart Card fixes (0.20.15)

On 2026-11-25, the Google Eve Chromebook completed the existing-credential
FIDO PRF vault unlock and Google loopback OAuth sign-in. A synthetic Gmail
self-message was signed using the existing Level 3 v6 ML-DSA-65 + Ed25519
identity (PIV slots 9c/84), encrypted with ML-KEM-768 + X25519, sent and received.
With 0.20.14 installed, the received message decrypted using slots 9d/85 and the
IWA reported **“Gmail decryption and signature verification passed using IWA
trust.”** These operations used Web Smart Card and Sequoia WASM, without the Mac
native helper or PKCS#11. No new message was sent during the successful receive
retry, and no keys, card certificates or touch policies were changed. This was
not a separate before/after audit of every card slot or policy.

The fixes retained all live-card, signed-bundle, ciphertext-binding and trust
checks:

- Normalize armored bundle certificates with the same WASM inspector used by
  saved identities before comparing full certificate bytes, hash and fingerprint.
- Route the client’s `smartcard-signing-input` operation to the corresponding
  WASM export before requesting the PIV PIN.
- Return `mlkemSecret` and `x25519Secret` from Web Smart Card, matching the strict
  WASM component-response schema and its reference cleanup. The previous Share
  field names caused rejection after card operations. This is a shared-code
  defect, not a ChromeOS-specific cryptographic or transport limitation.
- In 0.20.15, Enter submits FIDO PIN dialogs for vault access, enrollment and
  previewSign just like the authorization button. Held-key repeats and IME
  composition are ignored, handlers are removed on completion/cancellation, and
  touch/progress/result dialogs remain visible. This keyboard change has local
  regression coverage and passed the Chromebook hardware test below.

### Chromebook FIDO PIN Enter-key and PRF unlock test

On 2026-11-25, ChromeOS confirmed **“Update to version 0.20.15 successful”**
for the existing installation. After reopening the app, the existing vault was
locked and its saved **“My YubiKey · FIDO PRF”** method remained selected.
The FIDO PIN dialog identified the expected key and the IWA package RP.
The tester entered the PIN locally, confirmed that **Enter submitted the dialog**
without clicking Authorize, and touched the YubiKey. The observed result was
**“Vault unlocked”** and **“Unlocked — auto-locks after five minutes of inactivity.”**
This verifies the keyboard submission and existing-credential PRF unlock through
Web Smart Card on the Chromebook, beyond the local keyboard regression test.

No credentials were created or replaced, and no PIV keys or PIN/touch policies
were changed. This was an existing-credential assertion, which may advance the
normal FIDO signature counter; it was not a full before/after audit of all slots
and policies. The update preserved the existing vault and saved identities.

All 42 targeted regression tests passed with no skips. Coverage includes the actual Web Smart Card response passed to the
shipped WASM decoder with a synthetic Sequoia fixture, plaintext recovery and
signature verification, plus rejection of changed bindings/secrets/trust and
cancelled or duplicate operations. Earlier APDU mocks alone did not cover this
adapter-to-WASM boundary. Existing successful native-helper mail tests and FIDO
PRF/ARKG tests exercise different paths and did not establish direct PIV message
decryption on the Mac.

## Install the preview on ChromeOS

These instructions target **ChromeOS with Chrome 143 or later**, using the
browser's IWA development installation path. Installation, Web Smart Card,
existing-credential FIDO PRF vault lock/unlock and the ten-key ARKG test passed
on a Google Eve Chromebook on 2026-11-25; see the results below. Updating
ChromeOS alone does not enable unsupported app profiles.

### Install the signed bundle

1. Update ChromeOS and check the Chrome version at `chrome://version`.
2. Download `sequoia-lab.swbn` and `SHA256SUMS.txt` from the
   [0.20.15 release](https://github.com/ve7jtb/gws-sequoia-chat/releases/tag/iwa-v0.20.15).
   Use the release bundle, not GitHub's source-code ZIP. If a checksum tool is
   available, compare the downloaded bundle with the published SHA-256.
3. Open `chrome://flags/#enable-isolated-web-app-dev-mode`, enable **Isolated
   Web App developer mode**, and relaunch Chrome. This is a **browser flag**, not
   Chromebook device Developer Mode: these instructions do not require disabling
   verified boot, a Powerwash, or installing Linux/Crostini.
4. Open `chrome://web-app-internals`. In **Isolated Web Apps**, select **Install
   IWA from Signed Web Bundle** and choose the downloaded `.swbn`. On newer
   builds that expose `chrome://iwa-dev/`, use its **Install** action instead.
5. Launch **Sequoia Chat Lab** from the installed-app entry or ChromeOS launcher.
   Confirm the package ID is
   `aj2ncwirtvyf4zn2hxc2c2gqps6cmcap77dpanzkgh2tlfj7inkqaaic`.

Google documents the development installation flow in its
[IWA guide](https://developer.chrome.com/docs/iwa/introduction) and
[ChromeOS developer-mode tutorial](https://chromeos.dev/en/tutorials/getting-started-with-isolated-web-apps/1).
A managed Chromebook can block these controls; ask its administrator rather
than changing device security settings. Managed deployment also has separate
[Google IWA allowlist requirements](https://developer.chrome.com/docs/iwa/allowlist)
and update-manifest/policy configuration. This GitHub preview does not establish
that this package is approved for enterprise deployment.

### Update manifest and preserving local data

The public [preview update manifest](https://raw.githubusercontent.com/ve7jtb/gws-sequoia-chat/main/experiments/mac-iwa/update-manifest.json)
points to the release-signed bundle. Where Chrome offers **Install IWA from
Update Manifest**, paste that URL and fetch the available versions. The default
channel is **Preview**, initially version **0.20.11**.

On the tested ChromeOS 150 build,
`chrome://flags/#enable-isolated-web-app-unmanaged-install` exposes **Enable
Isolated Web App unmanaged installation**. Availability does not yet establish
that the existing development installation can be converted to automatic updates;
that conversion is still under test. Do not uninstall a working installation to
switch installation methods.

Updates must retain package ID
`aj2ncwirtvyf4zn2hxc2c2gqps6cmcap77dpanzkgh2tlfj7inkqaaic` and use the same release
signing key. Save drafts before restarting Chrome. Do not clear app data or
uninstall the app: the vault, saved identities and trust are local to that app
origin. Publishing a manifest alone does not attach an existing development
installation to its update feed. Confirm the update source in Chrome before
relying on automatic updates.

For maintainers: upload and verify the signed release bundle first, then add its
exact version and immutable release URL to `update-manifest.json`. Keep previous
entries available; do not replace an existing version with different bytes.

### Connect the YubiKey

1. Install Google's **Smart Card Connector** extension from its
   [official Chrome Web Store listing](https://chrome.google.com/webstore/detail/smart-card-connector/khpfeaanjngmcnplbdlpegiifgpfgdco).
   Open this listing **on the Chromebook**, click **Add to Chrome**, then
   **Add extension**, and wait for the installation confirmation. Return to
   Sequoia Chat Lab and click **Check YubiKey**. At the reader permission prompt,
   **Allow this time** is sufficient for the test.
   This supplies ChromeOS's PC/SC service; it is distinct from this project's
   optional native-bridge extension. The
   [Web Smart Card setup guide](https://github.com/WICG/web-smart-card/blob/main/HOWTO.md)
   documents ChromeOS 143+ and this prerequisite.
2. Connect the YubiKey by USB with CCID/PIV enabled. Keep it connected to ChromeOS;
   do not pass it through to a Linux VM. No NFC workflow is claimed here.
3. In the app, choose **Hardware transport → Web Smart Card
   (navigator.smartCard)** and approve the expected reader-access prompt.
4. For FIDO diagnostics, set the expected YubiKey serial in **Vault → FIDO
   enrollment settings**, then choose **FIDO tests → Read FIDO GetInfo — no PIN**.
   This checks discovery before any private operation. PRF/previewSign also need
   a key with the corresponding FIDO capabilities; ordinary YubiKeys need not
   support experimental previewSign.
5. Use the normal vault enrollment or restore flow. FIDO operations ask for the
   **FIDO PIN**; PIV operations ask for the **PIV PIN**. Follow touch prompts and
   wait for the completion result before removing the key. Existing credentials
   must match their original RP; new IWA credentials use the full package-origin
   RP, as described below.

### Verified Chromebook results — 2026-11-25

Tested the published **0.20.11** signed bundle on a **Google Eve Chromebook**,
Chrome **150.0.7871.289**, ChromeOS platform **16700.70.0**, LTS channel:

- **Installation passed:** `chrome://web-app-internals` installed the release
  bundle and the ChromeOS launcher opened Sequoia Chat Lab. `chrome://iwa-dev/`
  returned `ERR_INVALID_URL` on this build; use the working internals page.
- **Web Smart Card passed:** initially the app reported **No smart card service
  available in the system**. Installing Google's Smart Card Connector and
  allowing reader access resolved this. The app identified the expected Beta0
  YubiKey, and **CTAP2 GetInfo** passed without a PIN, including `hmac-secret`
  capability discovery.
- **PRF vault enrollment and lock/unlock passed:** with the expected serial set
  in **Vault → FIDO enrollment settings** and **IWA package** selected as the RP,
  **Create software-only vault with FIDO PRF** used the existing discoverable
  credential. The app reported **Unlock method verified and saved**. After
  **Lock vault**, it reported **Vault locked**; a fresh FIDO PIN/touch assertion
  through **Unlock vault** produced **Vault unlocked**. This created a local
  encrypted vault, not a new authenticator credential. The separate **Create new
  discoverable IWA PRF credential** action was not used for this test.
- **Ten-key previewSign/ARKG test passed:** the user subsequently ran the FIDO
  ARKG tests. The displayed batch result confirmed **10 distinct ARKG public
  keys, 10 self-certified OpenPGP certificates and 10 signed messages**.
  **Sequoia WASM verified all; all altered messages were rejected.** Public
  certificate/message files and `previewSign-openpgp-report.json` were offered
  for download. These are the Chromebook's in-app results; the independent
  native Sequoia CLI checks documented above were from the earlier Mac run,
  not a separate CLI verification of this Chromebook batch.

The connection and vault tests used public reads and existing-credential
assertions, with no PIV key, certificate or PIN/touch-policy writes and no new
FIDO credential creation. Assertions may advance the FIDO signature counter.
This is a record of the operations performed, not a complete before/after card
inventory audit. The ARKG test is separate: its explicit previewSign setup can
create a non-discoverable test credential; the batch reuses that credential.
No ChromeOS restart-persistence or Gmail/Chat transport test is claimed here.

### Available paths and limitations

The direct path uses Web Smart Card and bundled WASM, without the Mac native
helper, PKCS#11 installation, Java, or `ykman`. In this release direct PIV private
operations support **native Level 3 v6**; Level 5, v4/v5 hardware operations and
companion restoration still require the native path and are not advertised as
working on ChromeOS. FIDO PRF and previewSign are separate diagnostic/vault paths.

For Google sign-in without the native bridge, choose **Google browser test →
Google OAuth mode → Direct Sockets loopback PKCE**. The shared Desktop client is
bundled. ChromeOS Gmail sign-in, signed/encrypted sending, and trusted-signature
verification after decryption passed as described above. Chat attachment transfers
currently depend on the
project's extension broker; the Smart Card Connector does not replace it. Installing
this bundle alone is not a claim of complete extension-free Chat support.

For updates, save drafts and use the installed application's **Update** action
(or **Dev Mode App Updates** on older internals pages) with a newer signed bundle
of the same package ID. Do not uninstall to update: local vault and app data may
be lost. If new buttons appear but do nothing, use Chrome's **Reload / bypass
cache** action (typically Ctrl+Shift+R) and reopen the app. If readers are absent,
check Smart Card Connector, USB connection, CCID, and administrator policy before
attempting PIN entry. Consult Google's
[smart-card deployment guide](https://support.google.com/chrome/a/answer/7014520)
for managed-device setup.

## Direct CTAP2 vault support and release signing (0.20.8)

The Web Smart Card transport can select the YubiKey FIDO application after
checking the expected serial through PIV in the same PC/SC transaction. Vault
controls provide PIN-free GetInfo and existing-credential PRF assertions using
PIN/UV protocol 2, RP-scoped GetAssertion permission, and WebAuthn PRF salt
processing. No extension/native helper is used for those operations. A separate
masked FIDO PIN dialog distinguishes this PIN from the PIV PIN. Explicit creation uses a fresh random 32-byte user handle, `rk=true`, scoped
MakeCredential permission and `hmac-secret-mc` to evaluate PRF during creation.
It only targets the signed package RP. Existing-credential enrollment never
falls back to creation. There is no reset, PIN-change or credential-management
path, and PIN errors
are never retried automatically. Successful assertions can advance the card's
FIDO signature counter; they do not replace keys or change policies.

New direct-FIDO vault bindings default to the **full IWA origin (`isolated-app://<signed-web-bundle-id>`, no trailing slash)** as
RP ID. This is an application-defined direct CTAP scope, not a claim that every
browser WebAuthn API uses that default. Existing bare-ID, extension or website wrappers
retain their original RP and salt. Merely changing the default cannot migrate a
credential to another RP. A local PIV-only vault must first be unlocked before
an existing FIDO credential can be added as another local wrapper. Multiple
discoverable matches require an imported wrapper's exact credential ID; this
preview does not silently select among them. This is a vault PRF client, not a
general-purpose WebAuthn assertion verifier: authenticated vault decryption
checks that the recovered PRF secret is the enrolled secret.

Recovery journals are scoped by RP; a prior bare-ID attempt never gets relabeled
as a URL-scoped credential. Creation keeps a public-only recovery journal (RP, serial, salt, user handle and,
once returned, credential ID). If enrollment fails after creation, it can resume
with the exact credential. An uncertain creation outcome blocks another creation
rather than silently generating duplicates. The existing vault wrapper remains.
Package-scoped credentials currently require Web Smart Card: the helper's
extension-origin WebAuthn path cannot use that RP. A native CTAP2 helper path is
needed before the same credential can be used through both transports.

Release packaging accepts `PQ_MAIL_IWA_KEY_FILE` pointing to the publisher's PEM
key; an explicit missing/invalid key fails instead of generating another app ID.
The private key remains in ignored local storage. The original development key
is retained separately. The build embeds `IWA_BUNDLE_ID` in generated app config
and the direct FIDO UI derives its default from that value.

Validation: 26 targeted CTAP2, vault, PIV and OAuth tests passed, including an
independent Node-crypto peer checking PIN/UV protocol 2, encrypted salt, PRF
output, command restrictions, APDU chaining and cancellation before submission.
The creation update passed 19 CTAP2/vault tests, including independent
MakeCredential PRF exchange and recovery-ID delivery. Chromium accepted the
release-key 0.20.5 update in place. Direct GetInfo passed
on the Level 3 test key, advertising FIDO 2.3 and hmac-secret. Subsequent package-origin PRF enrollment and a separate lock/unlock test passed
with interactive FIDO PIN/touch. These operations issued no PIV writes.

## Shared Desktop OAuth defaults (0.20.2)

The installed IWA includes the shared Google Desktop client ID and client secret
for loopback PKCE. Leave the secret override blank to use the bundled registration.
Custom client IDs never inherit the shared secret. Custom secrets remain in memory
and are cleared from the form after use. Account tokens are not build inputs and
retain the existing vault gate and memory-only lifetime.

Packagers set `PQ_MAIL_DESKTOP_OAUTH_JSON` to the downloaded Desktop client JSON
when running `node build.mjs`. Only `installed.client_id` and
`installed.client_secret` are included in the ignored generated `app/config.js`.
These installed-app configuration values are extractable from the signed bundle;
they are not a confidentiality boundary. No account refresh tokens are bundled.
All 33 targeted OAuth regression tests passed.

## Web Smart Card and loopback OAuth integration (0.20.1)

Optional direct Web Smart Card reads devices, all 24 slot records and the current
compressed bundle. Native PKCS#11 remains the default and supports Level 5,
v4/v5 and companions. Direct private operations currently support native Level 3
v6 only; unsupported profiles stop without silently changing transports.

The IWA authenticates a fresh bundle in WASM, matches the selected certificate,
and checks live keys again inside the PIN transaction. One-use tickets bind each
operation. ML-DSA external mu uses PIV tag 0x88, ML-KEM ciphertext uses tag 0x86,
and each component gets its own PIN verification for PIN Always. Private-operation
failures are not retried on another reader. Direct mode uses a masked browser PIN
dialog; PINs are not saved, but JavaScript strings cannot be reliably zeroized.
Native mode retains the existing native PIN boundary.

Optional Google loopback OAuth uses Direct Sockets, authorization code + PKCE,
random state and an ephemeral 127.0.0.1 listener. Access tokens remain in memory;
refresh tokens are not persisted. The Desktop OAuth client is separate from the
extension client. Secret input is cleared after capture. Extension OAuth and the
bounded Chat attachment broker remain available.

Browser support for these IWA APIs is required; a feature flag alone is not proof
of platform support. CTAP2 over PC/SC is not implemented. Mock APDU and OAuth tests
do not establish a physical-card or live Google authorization result.

Integration validation: 307 JavaScript tests passed (one optional skip),
139 Python tests passed, and 63 Rust tests passed. The signed 0.20.1 update
opened with existing account/identity data and both selectors visible. The
installed Chrome Canary reported Web Smart Card unavailable; no physical-card
private operation or live loopback consent was attempted during this update.


A signed Isolated Web App uses Sequoia WebAssembly for message cryptography and
browser REST APIs for Gmail/Google Chat. Chat attachments use a bounded extension
HTTPS broker. A scoped extension also connects it to native
YubiKey operations and the Google/passkey authorization UI. The repository's
main loopback Mail/Chat application remains separate. There is no listening HTTP
server for the IWA. Earlier preview milestones below describe their historical
native/gws transport and certificate storage; the current boundary is described
in the latest sections below. This change does not move the main loopback app's store.

## Level 5 hardware validation (2026-11-24)

The encrypted on-key companion restored successfully and completed the IWA's
local synthetic signing/encryption/decryption workflow using its real WASM
workers and native authorization boundary. The final confirmation used the
**original installed PKCS#11 backend**, with no diagnostic wrapper or backend
override. No email was sent.

- **ML-DSA-87 + Ed448:** signature verified.
- **ML-KEM-1024 + X448:** decryption succeeded and recovered text, HTML and
  attachment payloads matched exactly.
- All **24 PIV slot records**, including **nine occupied hardware keys**, their
  public-key hashes and PIN/touch policies matched before/after and the prior
  successful baseline. PIN retries remained **3/3**. No card writes occurred.
- Native-worker timings were **3.789 seconds signing** and **2.894 seconds
  decryption**, including any physical-touch wait; these are not isolated
  cryptographic benchmarks.

A preceding isolated diagnostic run also passed. Its three recorded PC/SC
transmissions returned success and card status `9000`; the largest response was
4,637 bytes in 2.767 seconds. Earlier attempts reached `C_Sign` and returned
`CKR_DEVICE_ERROR`, after successful PIN authentication. The user reported a
missed or unseen touch request. Missed user presence is consistent with those
failures, but a USB defect or exact earlier PC/SC failure was not established.

The installed native dialog now prominently identifies the **PIV PIN and key
serial**, distinguishes it from the FIDO/passkey PIN, and explains **Continue →
wait for flashing → touch the physical sensor**. Authentication and existing
touch policies are unchanged. Closed diagnostic stages distinguish adapter,
signature decoding and verification failures; bounded optional numeric PKCS#11
and PC/SC evidence excludes PINs, APDU bodies and private material. Temporary
tracing binaries and account-specific hardware artifacts are not shipped.

Validation for the diagnostic/native changes: **26 Rust tests** and **139
Python tests** passed (three optional skips), plus synthetic forwarding tests
under macOS hardened-runtime signing. The installed original-backend hardware
confirmation performed exactly one signing and one decryption operation.

## Hardware profiles and encrypted on-key companions (0.19 preview)

**My identities → Restore certificate bundle from inserted YubiKey** discovers
connected devices and lets you choose their serial. It authenticates the public
bundle in WASM and checks its mapped public keys before saving. This does not
change the helper’s default vault identity. The selected certificate’s full
fingerprint, exact public packet hash, bundle hash and serial bind every later
native operation; the helper independently re-reads and authenticates the card.
Stored display labels and slot numbers never authorize a private operation.

| Restored certificate view | Signing | Encryption |
| --- | --- | --- |
| Level 3 v6 | ML-DSA-65 + Ed25519 | ML-KEM-768 + X25519 |
| Level 3 v4 hybrid | Classical Ed25519 | ML-KEM-768 + X25519 |
| Level 3 v4 classical | Classical Ed25519 | Classical X25519 |
| Level 5 ordinary v6 P-384 view | **Classical P-384** | **Classical P-384** |
| Level 5 v4 hybrid compatibility | Classical P-384 | ML-KEM-768 + X25519 |
| Level 5 v4 classical | Classical P-384 | Classical P-384 |
| Optional Level 3 GnuPG / LibrePGP v5 | Classical Ed25519 | LibrePGP ML-KEM-768 + X25519 |
| Level 5 encrypted companion v6 | ML-DSA-87 + Ed448 | ML-KEM-1024 + X448 |
| Level 3 polyfill companion v6 | ML-DSA-65 + Ed25519 | ML-KEM-768 + X25519 |

The ordinary Level 5 P-384 v6 certificate is classical; its packet version does
not make it post-quantum. The Level 5 companion supplies the base RFC hybrid
Ed448/X448 profile. Hardware P-384 compatibility profiles remain distinct from
software P-521 profiles. Compose prefers v6, and prefers hybrid signing within
the same version, while preserving an explicit selection in the current window.
Classical signing/encryption retains the compatibility warnings. v5 requires
v5 certificates at both ends: its packet and combiner rules are separate from
RFC 9580 / RFC 9980.

For a local v5 certificate, select its public file in the optional v5 field
before restoring the ordinary card bundle. WASM accepts it only after its
self-certified email and all operation public keys match the signed Level 3
manifest. Native authorization repeats that comparison. Restore imports an
existing certificate; it does not issue one or write it to the card.

**Restore encrypted on-key companion** is a separate read-only operation. It
keeps the ordinary bundle and its v4 compatibility views intact. The inventory
stores the encrypted companion and authenticated public metadata only, never a
PIN, wrapping share, password, or plaintext `.p12`. For an ultra-compact companion,
select its matching existing public certificate cache; the IWA does not
regenerate missing certificate signatures. Normal compressed companions include
their public certificate.

During a companion operation, native code checks the live hardware and performs
only the required card private operations, including the dedicated wrapping-key
ECDH. A disposable WASM worker authenticates and decrypts the companion,
validates its private/public key correspondence, completes the software component,
and verifies or combines it with the card’s result. There is no saved companion
password and no fallback from a required hardware component to a software key.
The Level 5 companion holds Ed448/X448 software components; the Level 3 polyfill
holds ML-DSA-65/ML-KEM-768 software components. Message algorithms and private-key
storage protection are different properties: plaintext software components exist
in process memory during use and do not have hardware isolation. JavaScript,
JSON and WASM allocation cannot guarantee erasure against swap, crash capture or
an already compromised host.

The local hardware test uses the selected profile and shows its actual component
custody and slots. It compares all PIV public-key and PIN/touch-policy records
before and after. Restore and testing do not generate, erase or move keys, write
card certificates or bundles, or change PIN/touch policies. No message is sent by
the local test.

PIN entry uses a separate native modal dialog. The helper records only fixed
operation stages: dialog requested, PIN received locally, and private worker
started. A dialog timeout or locally rejected input stops before starting the
private worker and reports that no PIN was sent to the YubiKey. Hardware test
reports distinguish a requested operation from a started crypto worker; they
never log the PIN, signature input or recovered secrets. If no PIN dialog is
visible, wait for or cancel that attempt, inspect the result and final public
key/policy audit, then start a fresh test after fixing the presentation problem.
There is no automatic PIN or private-operation retry. A separate display-only
probe can check modal-window visibility with a Close button and no PIN field or
YubiKey operation.

Validation status for this increment: the JavaScript suite passed **281 tests**
with one optional test skipped. Public inventory, revision binding, profile
selection, device discovery, ciphertext-only persistence and transient
wrapping-share cleanup are covered. Three additional Rust tests passed P-384
v4 hybrid, v4 classical and v6 classical signing/encryption/decryption in both
directions against Sequoia’s independent stream implementation, including
wrong-width signature and altered-secret rejection. The full Rust suite passed **60 tests**. Actual browser WASM passed the four
Level 3/Level 5 companion signing/decryption cases and 16 negative checks. A
read-only four-profile preflight on the existing Level 3 YubiKey authenticated
v6, v4 hybrid, v4 classical and the matching local v5 view; all public-key and
PIN/touch-policy records, PIN retries (3/3), and installed backend hashes were
unchanged. After correcting native PIN-window presentation, the installed
**0.19.0 IWA passed its Level 3 v6 hardware test on 2026-11-24**: one signing and
one decryption operation verified the hybrid signature and recovered the exact
text, HTML and attachment. The exported before/after audits were identical for
all 24 slots, key hashes, PIN/touch policies, PIN retries (3/3) and backend hashes.
The test sent no email and requested no card writes. The installed IWA then
passed **v4 hybrid, v4 classical and v5 hybrid** tests on the same Level 3 key.
Each verified its classical Ed25519 signature and recovered the exact text,
HTML and attachment after decryption. v4 hybrid used ML-KEM-768 + X25519; v4
classical used X25519; v5 used the separate LibrePGP hybrid construction. Each
profile performed one signing and one decryption operation. All 24 slot
records, public keys, PIN/touch policies, PIN retries (3/3) and backend hashes
were identical across all four runs. These are installed-IWA local round trips;
they do not replace independent cross-client interoperability tests.

The initial native Python suite passed **121 tests**, with three optional
fixture-dependent skips. Subsequent Level 5 companion hardware validation and
the expanded native regression results are recorded in the validation section
above. Existing 0.18 software behavior remains supported.

The **0.19.1** display update names both signing and encryption algorithms in
identity selectors, so v4 views sharing a primary fingerprint are distinguishable.
Hardware results name the actual algorithms and retain classical warnings;
they no longer call every passing signature or decryption hybrid. Older saved
records without per-certificate component metadata request a fresh public
restore instead of displaying unrelated slots from the entire bundle. Seven
controller regressions cover these cases; the JavaScript suite passed **288
tests**, with one optional skip. This update changes no WASM cryptography,
native backend, extension permissions or app identity. Installed verification
confirmed that v6 remains the default after restart.

## Software creation, portable backup and compatibility profiles (0.18 preview)

**Identities → Software identities** can now create a new identity for the
configured account, restore a password-encrypted identity, and export an
individual password-encrypted backup. Level 3 v6 is the initial selection; v6
remains preferred when choosing a sender. v4/v5 compatibility is explicit and
warns about classical signing. Classical encryption also requires a warning;
the classical component of a hybrid algorithm does not trigger that warning.
The selected sender and recipient show their public version and algorithms.

| Software profile | Signing | Encryption |
| --- | --- | --- |
| Level 3 v6 (default) | ML-DSA-65 + Ed25519 | ML-KEM-768 + X25519 |
| Level 5 v6 | ML-DSA-87 + Ed448 | ML-KEM-1024 + X448 |
| Level 3 v4 hybrid compatibility | Classical Ed25519 | ML-KEM-768 + X25519 |
| Level 3 v4 classical fallback | Classical Ed25519 | Classical X25519 |
| Level 5 v4 hybrid compatibility | Classical P-521 | ML-KEM-768 + X25519 |
| Level 5 v4 classical fallback | Classical P-521 | Classical P-521 |
| Optional GnuPG / LibrePGP v5 | Classical Ed25519 | LibrePGP ML-KEM-768 + X25519 |

Level 5's v4 hybrid encryption is a Level 3 compatibility algorithm. It is not
ML-KEM-1024. The v5 packet/combiner/signature rules are distinct from RFC 9580 /
RFC 9980; v5 and v4/v6 message peers cannot be mixed in one operation. New v6
identities have separate certification, signing and encryption keys. Creation
of each compatibility profile generates its own software keys; it does not
reuse a hybrid component as a standalone classical signing key.

The existing passkey/PIV vault protects every persistent software identity.
Creation chooses an independent random 256-bit storage password and retains
that password only inside authenticated vault ciphertext. Import validates
private/public correspondence, certificate policy and account email before
saving. Creation, import and export stop on lock, cancellation, account change
or a stale vault revision. All private operations run in disposable WASM
workers; no private software key or password is sent to the extension/native
helper. Software memory can still be exposed by a compromised browser/OS or
swap. This is software custody, not hardware-equivalent storage.

**Export encrypted identity** asks for a new backup password of at least 12
characters (at most 1,024 UTF-8 bytes). v4/v6 export produces a standard encrypted OpenPGP secret-key file
(`.pgp`), preserving the public packets, self-signatures and fingerprints.
The optional v5 profile exports an authenticated encrypted **`.pqidentity`**
backup, which this IWA can restore; that private backup is not a standard
OpenPGP secret-key file for direct GnuPG import. Its public certificate is a
normal LibrePGP certificate. Whole-vault export/restore remains available and
includes these entries. Export does not grant recipient trust or change the
source vault entry.

**Import / restore software identity** also accepts PQ Mail's **Level 5 software
OpenPGP `.p12` keyset**. The bounded PFX parser authenticates the complete file
before decrypting its bags, validates all ten expected aliases and seed/public
relationships, and imports its original v6 certificate plus both v4 views
atomically. Certificates and fingerprints are preserved, including the
classical view's already-signed subkey binding. Arbitrary or S/MIME-only `.p12`
files, legacy bag ciphers, unexpected aliases and unauthenticated data are
rejected; this is not a general PKCS#12 converter. See the complete
[software custody, profile and PFX boundaries](wasm/SOFTWARE-KEYS.md).

Automated baseline-worker validation on **2026-11-23** passed all **seven created
profiles and three imported PQ Mail `.p12` certificate views**. It checked
password-encrypted export/restore, wrong-password rejection without a write,
vault restart, signing, decryption, signature verification, and exact text,
HTML and binary attachment recovery. All **2,029 disposable workers** terminated;
there were **zero native-helper calls, card writes or messages sent**. The
`.p12` fixture was generated for the test with disposable keys. All **239
JavaScript regression tests** also passed, including overlapping inventory
refresh, cancellation, changed vault/account context and authenticated PFX
parsing checks. This result
is an automated software matrix, not a new YubiKey hardware test or live Gmail
exchange. Independent OpenSSL-backed Sequoia also decrypted and verified every
v4/v6 profile's outgoing message, and the IWA workers decrypted and verified its
return message: **six profiles in both directions**. Unmodified GnuPG 2.5.24
separately verified the v5 detached signature and decrypted/verified its outgoing
message; the v5 implementation recovered and verified GnuPG's signed MDC and
OCB replies with exact payloads. These v5 checks use the LibrePGP compatibility
policy, not Sequoia's RFC-format verifier.

The signed **0.18.0** update is installed on the Mac. Chrome reported a
successful update, and the installed bundle hash matches the reviewed build.
The installed UI shows all seven profile options, retains v6 Level 3 as the
default, and exposes encrypted restore and PQ Mail `.p12` import. Existing
account/public identities and vault enrollment were preserved; the vault stayed
locked during this UI check. Private software workflows were tested with the
actual worker matrix above, not against the user’s locked vault. All **48 WASM
Rust tests** and **7 independent native-oracle tests** passed. The installed
native helper, hardware authorization files, extension code and extension
permissions are unchanged; no YubiKey operation was performed for this update.

The optional v5 implementation is a bounded Rust compatibility module compiled
into the same WASM package. It is not an embedded GnuPG executable or a separate
LibrePGP service. Existing crypto libraries supply the primitives; the module
implements LibrePGP packet policy and its distinct combiner. The independent
[`v5-gnupg-interop.py`](tests/v5-gnupg-interop.py) harness uses a disposable
software-only GnuPG keyring with smartcard access disabled. Its source documents
how to export synthetic Rust fixtures, run stock GnuPG, and verify the replies.
This new compatibility code remains experimental and has not received an
independent cryptographic audit.

Wide-arithmetic WASM builds, but the available Node 24 runtime rejects
its unsupported wide-arithmetic opcode; software operations use baseline WASM.

To repeat with a new private output directory and, optionally, the separate
OpenSSL-backed Sequoia message oracle:

```sh
IWA_MESSAGE_ORACLE_BIN=/path/to/examples/message_oracle \
  node experiments/mac-iwa/tests/software-profile-interop.mjs \
  /path/to/new-private-results baseline
```

Set `IWA_P12_FIXTURE` to a **disposable** PQ Mail Level 5 test file with the
synthetic password documented in the test harness to include the PFX matrix.
Never point this synthetic-password test at a real identity. Detailed profile,
worker, lifecycle and malformed-PFX regressions are in the adjacent tests.
Hardware identities remain restricted to the independently authorized Level 3
v6 path; this software expansion changes no YubiKey slots, keys or touch policies.

## Vault-protected software identities and production helper (0.17.2)

**Identities → Software identities** imports a password-encrypted `.pgp`, `.asc`
or `.gpg` secret-key file into the existing encrypted PRF/PIV vault. The initial
profile is Level 3 v6: separate ML-DSA-65 + Ed25519 certification and signing keys,
and ML-KEM-768 + X25519 encryption. Import verifies the password, every private
key against its public certificate, current bindings and the configured email.
It does not create keys on a YubiKey or grant recipient trust. PKCS#12 files remain
opaque vault backups; they are not usable software identities in this preview.

Compose lists unlocked software identities alongside live-matched YubiKey
identities, clearly identifying their custody provider. Incoming encrypted
messages match the actual recipient subkey in WASM; matching more than one
provider requires a choice. Software errors never fall back to a native key.
Software identities disappear from selection on vault lock and return after
unlock. Removing an identity removes its encrypted local record, leaving the
original file, recipient trust and hardware keys unchanged.

The vault stores both the encrypted OpenPGP file and its password inside its
authenticated ciphertext. Each private operation uses a new disposable WASM
worker; unlocked long-term keys never enter the extension or native helper.
Lock, cancellation, expiry, account changes and storage revisions invalidate
pending operations. A restarted app must unlock the vault again. **Software
custody is experimental:** the browser/OS can retain memory copies, and the
selected WASM crypto paths have not received an independent side-channel audit.
See the [private-crypto review and limits](wasm/SOFTWARE-KEYS.md).

Each software identity has a **Test signing and decryption — no email** action.
It exercises the normal signing, encryption, recipient-matching, decryption and
verification workers with fresh text, HTML and a binary attachment. Its report
records only public metadata and outcomes. Self-trust is temporary; it is not
saved as a contact. Public certificate export is separate from trust management.

The installed native executable now accepts only production public-card and
component operations. Old whole-message modes and verification fixtures live in
an explicitly built `message_oracle` example. Installers reject that oracle and
older broad workers. No test executable is installed. Native authorization still
independently validates the live signed bundle, serial, public keys and one-use
grants before private hardware operations. See the
[production/test executable boundary](crypto/README.md).

Validation passed **215 JavaScript**, **122 Python**, **18 production-worker
Rust**, **7 test-oracle Rust**, and **24 WASM Rust** tests. The real baseline
worker integration imports an encrypted identity, checks vault persistence and
restart, rejects cancellation and stale contexts, signs/encrypts/decrypts exact
text/HTML/attachment content, then removes the identity without resurrection.
It terminates all 54 workers and makes no native-helper calls. Independent
OpenSSL-backed Sequoia verifies/decrypts the WASM message; the WASM workers
verify/decrypt Sequoia's reply. Wide-arithmetic assets build, but are not runtime
validated on the available Node 20; the production software provider always
uses baseline WASM.

The signed Mac IWA and scoped extension were updated to **0.17.2** with the same
origin, extension identity and permissions. Installed UI checks on **2026-11-23** passed encrypted
software import, explicit software selection, offline Compose signing/encryption,
software round trips before and after a full app restart, and removal of the
disposable identity. Locking removed software choices, and restart required vault
unlock before the saved identity became usable, without reimporting its file or
re-entering its OpenPGP password. The public JSON reports confirm
valid hybrid signatures and exact text, HTML and attachment recovery. No email
was sent, no recipient trust was added, the disposable entry was removed, and the
vault was left locked. Existing vault enrollment and the prior item were kept.

A separate before/after physical audit confirmed all **24 PIV slot records**, ten
existing public keys, PIN/touch policies, **3/3 PIN retries** and eleven protected
configuration/backend files unchanged. The existing hardware wrapper was used
only to unlock the vault; software signing and decryption made no native helper
calls. This is not a new physical signing test of the narrower native worker.

For a disposable encrypted fixture generated as described in
[software test setup](wasm/SOFTWARE-KEYS.md#regression-coverage-and-disposable-browser-fixture):

```sh
IWA_MESSAGE_ORACLE_BIN=/path/to/examples/message_oracle \
  node experiments/mac-iwa/tests/software-identity-interop.mjs \
  /path/to/disposable-fixture baseline
```


## IWA hardware tests and shared public parser (0.16.0)

Hardware-test orchestration now runs in the IWA. **Hardware test** selects a
saved, live-matched Level 3 v6 identity for the configured account. It creates
fresh synthetic text, HTML and a binary attachment, signs through the existing
native component interface, encrypts to that identity, matches the recipient
in WASM, decrypts through the existing component interface and checks the exact
recovered content. It sends no email and never edits a card or contact store.
The test's temporary self-trust is confined to that test; it grants no saved
recipient trust.

The native **`chat-hardware-audit`** route independently authenticates the selected
live bundle and returns a bounded before/after snapshot: all 24 public slot
states, public-key hashes, algorithms, origin, PIN/touch policies, PIN retry
counts and a hash of the installed backend. It reads those slot states twice
and rejects changes or ambiguous failures. The IWA reports **unchanged** only
when complete snapshots match. Cancellation, a PIN/backend failure or a missing
final audit cannot become a green pass, and no private operation is retried.
The downloadable JSON report contains public identity/audit data and controlled
status labels, not PINs, message keys or raw process output.

The browser and native authorization now use the same
[`sequoia-public-bundle` crate](bundle-parser/README.md). The WASM binding is thin;
native authorization separately reads the current physical bank, invokes that
same public parser, and compares every authenticated component and serial before
issuing a private-operation grant. Shared implementation does not make the
browser's saved preview an authority. Re-reading object frames and live keys
continues to reject changing snapshots. The crate has no filesystem, process,
PIN, token or card-write API.

The installed Python helper no longer imports the standalone mail/chat runtime,
launches the legacy PTY/Java test runner, or performs MIME composition. Small
native utilities handle public certificate policy checks and exclusive one-use
grant creation. Fresh installation requires the PKCS#11 backend, ykman, Rust
worker, public enrollment certificate and native PIN prompt; it does not copy a
JDK, Java classes, gws, sq CLI or the standalone software-identity executable.
Historical source-only test oracles remain available outside the installed
allowlist. Existing installed configuration/vault enrollment is preserved;
unused older runtime files are not deleted by an upgrade.

The extension still brokers Google OAuth, PRF and bounded Chat attachments, and
relays the closed native hardware API. Independent external Sequoia/PQ Mail
interoperability tests remain separate: the new browser self-test is not a
substitute for checking another implementation.

Validation for 0.16.0 passed **202 JavaScript**, **116 Python**, **23 native
Rust**, **14 WASM Rust**, and **6 shared-parser** tests. Another **11 actual-worker
checks** cover identity matching and decryption. A complete software-oracle run
uses the shipped signing, recipient-matching and decryption workers to verify
fresh text, HTML and binary attachment bytes with exactly one signing callback
and one decapsulation callback. Native PIN entry and physical key protection
are not simulated as hardware evidence by these software tests.

The live PIN-free preflight read the connected Level 3 card's signed current
bundle and all 24 PIV slots through the new native shared-parser path; all ten
mapped public keys matched and PIN retries remained 3/3. The signed IWA and
extension were updated to 0.16.0 with unchanged origins, permissions and existing
PKCS#11 binaries. The installed **0.16.0 physical test passed** on a Level 3
YubiKey: one hybrid signing operation, exact recipient matching, one hybrid
decryption operation, and exact text/HTML/64-byte attachment verification. Both
complete native audits matched. An independent snapshot also confirmed all 24
slot records, ten occupied public keys, PIN/touch policies, 3/3 PIN retries and
protected PKCS#11/configuration files unchanged. No email or card write occurred.
The JSON report exported successfully from the IWA. This local round trip tests
the new controller; it does not replace the earlier two-way external Sequoia
interoperability tests.

To exercise the new components without a YubiKey, from the repository root
using Rust 1.88 or newer and the previously built WASM assets. These commands
assume no `CARGO_TARGET_DIR` override; otherwise adjust `fixture_bin`:

```sh
cargo test --locked --manifest-path experiments/mac-iwa/bundle-parser/Cargo.toml
node --test experiments/mac-iwa/tests/hardware-test.test.mjs
cargo build --locked --release --example signing_fixture \
  --manifest-path experiments/mac-iwa/crypto/Cargo.toml
# Use a new directory containing only disposable software test keys.
fixture_dir="$(mktemp -d)"
fixture_bin="$PWD/experiments/mac-iwa/crypto/target/release/examples/signing_fixture"
"$fixture_bin" generate "$fixture_dir"
IWA_SIGNING_FIXTURE_BIN="$fixture_bin" \
  node experiments/mac-iwa/tests/hardware-test-interop.mjs "$fixture_dir"
```

## Browser-owned bundle inspection and account startup (0.15.1)

The 0.15.1 implementation moves public compressed-bundle inspection into the
signed IWA and removes native account discovery from startup. This section
describes the current code and local validation; the older numbered sections
retain their historical test results. **The signed 0.15.1 update passed startup,
account persistence, on-key restore and offline bundle-review checks, then a
fresh two-way offline signing/decryption exchange with independent Sequoia.**

### Public bundle parsing and the native transport boundary

The dedicated identity worker calls the baseline WASM `inspect_bundle` export.
It bounds the compressed `PQMZIP01` container and expanded data, parses the
supported public profile, authenticates the envelope signature, validates the
OpenPGP certificate/key bindings, and derives public component hashes and slot
descriptions. Composite bundle signatures require both components to verify.
Unsupported profiles, secret-key packets, ambiguous/trailing data, malformed
compression, oversized inputs and altered signatures fail closed. No browser
parser failure falls back to native bundle decoding.

**Restore certificate bundle from YubiKey…** invokes the new
`chat-identity-bundle-read` public transport. Native code reads only the committed
current object bank, validates the fixed framing, chunk lengths/generation and
transport checksum, and returns at most 64 KiB of opaque compressed bytes plus
the actual public-key hashes for all 24 PIV slots. It re-reads the observed
objects, slot states and serial to reject a changing snapshot. This transport
does not decompress the bundle, parse its certificates or declare its signature
valid. The IWA hashes the exact returned compressed bytes, authenticates them in
WASM, and matches every signed component against the native public snapshot
before showing the review. The separate `chat-identity-key-snapshot` operation
reads only the public slot states and does not read bundle objects. Neither
operation accepts a browser-selected slot, object identifier, executable path,
PIN or private-operation command.

**Import identity from file** now works without an extension, native helper or
connected key. A valid signed bundle may be reviewed and saved with
`bundleSignatureVerified: true` and `liveKeysMatched: false`. Its serial, public
certificates and signed mapping are visible, but it is excluded from Compose and
recipient selection. **Match connected YubiKey…** explicitly obtains a public
key snapshot, compares every mapped component and shows a second review. Saving
that review records the live-match evidence; file generation/freshness remains
unestablished. A raw public certificate import remains unmapped. Saving either
form grants no recipient trust. Inventory revisions prevent an old live-match
operation from resurrecting or replacing a record removed or changed in another
window.

The WASM parser is a constrained mirror of the public format/profile rules in
the pinned `sequoia-pqmail-piv` adapter, with independent RustCrypto verification
and cross-implementation fixtures. The existing adapter combines its decoder
with OpenSSL, process and filesystem dependencies and cannot currently link into
`wasm32`. At this milestone a shared target-independent parser crate had not yet been
extracted. Version 0.16.0 above replaces that duplicated implementation with
one public parser used independently by both targets.
See [the WASM implementation and reproduction command](wasm/README.md#compressed-public-bundle-inspection-0151).

All native private-operation checks remain in place. Selected signing and
decryption independently re-read and authenticate the live signed on-key bundle,
bind the serial, bundle hash, canonical certificate hash, primary fingerprint and
certified mailbox, and derive the supported slots before issuing a one-use grant.
The private backend still checks live keys before the operation. Browser-saved
metadata and a previous successful match never replace those checks. PIN entry,
hardware signing and component decapsulation stay native; existing vault wrappers
retain their fixed enrollment and do not follow the account or Compose selector.

### IWA-owned account configuration and startup

The **Account** tab reviews and saves one normalized Google account email in the
IWA's origin-local public settings. The record contains only its schema version,
revision and email: no token, password, serial, certificate, slot or vault key.
The optional **Review account from existing helper…** action explicitly reads
legacy `chat-state`, extracts only the email and still requires review before
saving. Neither startup nor a restart performs that native read automatically.
Default vault metadata is also read only through its explicit hardware control.

Startup, contact management and ordinary Gmail/Chat operations use IWA state
without a native helper dependency. Gmail and Chat REST calls remain browser
requests; Google authorization and bounded Chat attachment transfers still use
their extension brokers. A missing browser transport is an error, never a native
transport fallback. Google sign-in must authenticate the configured email, and
signing still requires a supported saved identity certifying that same email.
An account change clears Google authorization, readers and pending send/export
reviews. Revision checks also reject stale work before private operations and
each send stage when a cross-window storage notification is delayed.

This is public configuration persistence, not new OAuth persistence. Access
tokens remain in memory and are cleared on lock, expiry or exit. **Restart still
requires Google authorization**, even though the public account email survives.
The encrypted vault database, its existing unlock methods and stable enrollment,
saved own identities and contact trust are not migrated or rewritten by Account
setup. Existing hardware restore, status, signing, decryption and vault controls
remain available.

### Validation and installed UI checks

On 2026-11-23, the current implementation passed **187 JavaScript tests, 102
Python tests, 21 native Rust tests, 20 WASM Rust tests and 11 actual-worker
integration tests**, plus the actual baseline WASM bundle-vector runner. Coverage
includes offline signed-file inspection, both composite signature components,
strict framing/compression bounds, all-slot snapshot matching, unchanged native
private-operation authorization, unmatched-identity exclusion, concurrent
inventory/account changes, startup without native messaging and browser-only
ordinary Gmail/Chat routing. Use the [regression commands below](#reproduce-the-current-regression-tests)
and `node experiments/mac-iwa/wasm/tests/bundle.mjs pkg` for the actual baseline
bundle vectors.

A separate physical public-only check read a **47,538-byte** current compressed
bundle through the new native transport. The actual baseline WASM reader and the
independent native reader agreed on all **three public certificate views and ten
mapped public-key hashes**. This exercised public reads and parsing; it did not
request a PIN, sign/decrypt or send a message. The signed installed 0.15.1
bundle is byte-identical to the verified build, with the existing IWA origin,
extension ID and permissions preserved. The Account UI saved the existing email
and restored it after a full app restart. The installed on-key restore review
recognized the unchanged three-certificate bundle; offline file review correctly
showed that live keys had not been matched and required a separate match before
private use. Both reviews were cancelled without replacing the existing identity.
Saved contacts/trust and vault enrollment remained present. Final read-only
snapshots matched all 24 PIV slot records, ten occupied keys, PIN/touch policies,
PIN retry counts and eleven protected configuration/backend files.

### Two-way offline IWA and Sequoia hardware test (2026-11-23)

The installed **0.15.1** app then passed a fresh exchange using the existing,
bundle-authenticated Level 3 v6 identity and a physical YubiKey:

| Direction | Verified result |
| --- | --- |
| IWA → Sequoia | Compose produced a hybrid signature using ML-DSA-65 in slot `9c` and Ed25519 in `84`, then encrypted and exported a local `.eml`. Independent Sequoia decrypted it and verified the signature, protected headers, plain text, HTML and all 69 attachment bytes. |
| Sequoia → IWA | Sequoia prepared a fresh signed/encrypted reply. The IWA automatically matched its recipient subkey to the saved identity and reviewed ML-KEM-768/X25519 slots `9d`/`85` before PIN entry. It decrypted the reply and displayed **Valid hybrid / Trusted** for the expected sender. Plain text and formatted HTML were checked, and the downloaded 66-byte attachment matched the source bytes and SHA-256. |

The final snapshot was identical to the pre-test snapshot across **all 24 PIV
slot records and all ten existing keys**, including public-key hashes and
PIN/touch policies. PIN retries remained **3/3**. Eleven protected configuration/
backend files and nine runtime/IWA files also retained their hashes. The test
wrote no keys, card certificates, on-key bundles or policies and sent no email.
This verifies the installed offline `.eml` flow; it does not rerun Gmail/Chat
transport tests or establish performance timings. Local account names, device
identifiers and private test reports are not published.

## Selected sending identities and recipient matching (0.14.0 preview)

Compose **Send as** lists saved, bundle-authenticated Level 3 v6 identities whose
currently certified email matches the mail account. Each choice shows the
certificate fingerprint, hybrid algorithms and YubiKey serial. Public certificates
without a verified hardware mapping and the saved v4 views are not outgoing
identities in this preview. Software identities and other hardware profiles remain
outside this selection flow.

Before decryption, a public-only WASM worker matches the named recipient subkey
to the IWA's saved own certificates. The review shows the matching certificate,
serial and decryption slots; if several saved devices match, the user
chooses explicitly. No match stops before PIN entry. Connecting the wrong key
produces an instruction to insert the selected serial, without submitting a PIN.

For both operations the native helper re-reads and authenticates that device's
signed on-key bundle, checks the full canonical certificate hash, primary
fingerprint and certified mailbox, and derives the supported slot mapping itself.
Browser data cannot choose an executable, arbitrary slot or private-operation
backend. A one-use grant binds the selected public context and installed backend;
PKCS#11 still checks the live public keys before its private operation. There is
no silent fallback to the default key. Removing or replacing an own identity,
changing contact trust, locking the vault or cancelling invalidates pending work.
The worker's ciphertext hash is checked independently before requesting hardware
shares, as well as during WASM finalization.

The existing default vault identity and its enrollment are unchanged. The IWA
inventory contains only public material; private keys and PIN entry remain native.
Selected message operations do not rewrite helper configuration, device keys,
card certificates or touch policies.

Validation passes **166 JavaScript tests, 98 Python tests, 14 WASM Rust tests
and 15 native Rust tests**, plus actual-worker interoperability checks. Coverage
includes exact certificate/subkey matching, expiry/revocation and usage flags,
multiple-device selection, changed inventory and trust, wrong ciphertext bindings,
one-use grants, wrong-card rejection before PIN, and preservation of vault routing.
The installed 0.14.0 bundle is signature-verified and byte-identical to the tested
build. Physical public-only preparation passed for signing and decryption.

**Installed 0.14.0 offline interoperability passed in both directions on
2026-11-23.** Compose selected the restored Level 3 v6 identity, signed with its
existing YubiKey components and exported encrypted PGP/MIME. Independent Sequoia
decrypted it and verified the hybrid signature, expected protected headers and
plain text, HTML content and all 66 attachment bytes. Sequoia's fresh encrypted
reply automatically matched the saved identity and displayed its serial,
certificate fingerprint, recipient subkey and slots 9d/85 before PIN entry. The
IWA then displayed **Encrypted (decrypted) / Valid hybrid / Trusted**, the expected
subject and text/HTML; all 63 downloaded attachment bytes matched. An earlier
reply attempt timed out before PIN submission; the successful run was explicitly
restarted by the user. No email was sent and no keys or policies were changed.
The final snapshot matched all 24 PIV slot records, ten occupied keys, PIN/touch
policies and eleven protected configuration/backend files against the original
pre-update baseline. PIN retries remained **3/3**.

### Reproduce the current regression tests

Run from the repository root with the native build prerequisites below, Node 24,
Rust 1.88 and `wasm-bindgen-cli` 0.2.130 installed. The commands generate disposable
software fixtures and use a synthetic public-only card transport. They do not
connect a YubiKey, request credentials or access mail. Generated fixture files
stay outside the repository; the split fixture contains disposable component
shares and must never be replaced with captured real-operation secrets.

```sh
npm ci --ignore-scripts --prefix experiments/mac-iwa
mkdir -p experiments/mac-iwa/app/vendor/postal-mime
cp experiments/mac-iwa/node_modules/postal-mime/dist/esm/*.js \
  experiments/mac-iwa/app/vendor/postal-mime/
mkdir -p /tmp/iwa-public-fixtures
export IWA_PUBLIC_TEST_FIXTURES=/tmp/iwa-public-fixtures
export CARGO_TARGET_DIR=/tmp/iwa-native-test-target
cargo test --locked --manifest-path experiments/mac-iwa/crypto/Cargo.toml
cargo build --release --locked --manifest-path experiments/mac-iwa/crypto/Cargo.toml \
  --bin sequoia-iwa-crypto --example message_oracle
export IWA_CRYPTO_TEST_BIN="$CARGO_TARGET_DIR/release/sequoia-iwa-crypto"
export IWA_CRYPTO_ORACLE_BIN="$CARGO_TARGET_DIR/release/examples/message_oracle"
python3 -m unittest discover -s experiments/mac-iwa/tests -p 'test_*.py'
export IWA_SPLIT_DECAP_FIXTURE=/tmp/iwa-split-decap-fixture.json
CARGO_TARGET_DIR=/tmp/iwa-wasm-host-test-target cargo +1.88.0 test --locked \
  --manifest-path experiments/mac-iwa/wasm/Cargo.toml
# The build script owns separate baseline/wide target directories.
env -u CARGO_TARGET_DIR sh experiments/mac-iwa/wasm/build.sh
node --test experiments/mac-iwa/tests/*.test.mjs experiments/mac-iwa/tests/*.test.cjs
node --test experiments/mac-iwa/tests/identity-worker-interop.mjs \
  experiments/mac-iwa/tests/decryption-worker-interop.mjs
node experiments/mac-iwa/wasm/tests/bundle.mjs pkg
node experiments/mac-iwa/wasm/tests/split-decryption.mjs "$IWA_SPLIT_DECAP_FIXTURE"
```

The production-worker Python integrations use `IWA_CRYPTO_TEST_BIN`. The
public signature/verification integrations use the separate
`IWA_CRYPTO_ORACLE_BIN` and `IWA_PUBLIC_TEST_FIXTURES`, populated by the Rust
tests above. Integrations without their required paths are skipped. The actual
worker tests require freshly built WASM and the generated split fixture. Passing
these software regressions does not substitute for the separately reported
physical-key and installed-UI tests.

## Own identities and reviewed public restore (0.13.0 preview)

**Identities** separates your own public certificates from recipient **Contacts**
and email/fingerprint trust. It displays the helper’s configured certificate,
algorithms, YubiKey serial and PIV roles/slots, plus an independent inventory in
`sequoia-iwa-identities` IndexedDB. No private key, PIN, OAuth credential or `.p12`
password is stored in this inventory.

- **Restore certificate bundle from YubiKey…** reads the signed public bundle
  from the configured Level 3 key, verifies its envelope and OpenPGP bindings,
  and matches every mapped public key against the connected device. It needs no
  PIN and performs no key generation, object writes or touch-policy changes.
- **Import identity from file** accepts one public OpenPGP certificate or a signed
  PQ Mail compressed `.pqmzip`/`.pqkey` bundle. Historical uncompressed bundles
  are rejected. Bundle files require the configured key
  connected for the same serial/public-key checks. Individual `.asc`/`.pgp`/`.gpg`
  certificates are parsed in WASM and carry no verified hardware mapping.
- Both paths show a review before **Save reviewed identity**. Saving does not
  grant contact trust or change vault enrollment. In 0.14.0, a supported saved
  identity becomes available in Compose and recipient matching; private-operation
  authority is rebuilt from its live signed bundle as described above.
- **Forget local identity** removes only its IWA inventory entry. The device,
  recipient contacts/trust and installed helper configuration remain unchanged.

Imported bundle checks describe evidence **at import**, not proof that the key
is currently connected. File imports do not establish the card generation or
freshness; that limitation appears in the review. The inventory survives app restarts but is removed by
clearing the IWA’s browser data. Review tokens are single-use and expire; revision
checks reject concurrent or stale save/removal confirmations. Secret-key packets,
oversized data and tampered bundles are rejected. File data never chooses a native
executable, device or private-operation slot. Bundle authentication reuses the
published Sequoia PIV adapter reader; the native dependency is pinned to commit
`6b99afc20984e16180e5bbfbabb51d8685d247e1`.

The 0.13.0 milestone added public identity management; active selection arrived
in 0.14.0. Those historical milestones did not use software `.p12` identities
or encrypted companions. The current 0.18/0.19 sections above describe their
subsequent software and hardware profile support. S/MIME remains outside this
OpenPGP interface.

Validation for this update: **153 JavaScript tests, 82 Python tests and 14
native Rust tests passed**, plus actual shipped WASM integration for all three
public certificate views and ten slot mappings. The signed installed 0.13.0
preview displayed its configured metadata, reviewed/imported the configured
public certificate, and retained that inventory after a full app restart. The
two existing contact trust bindings remained unchanged. The bundle reader passed
synthetic signed-bundle, tamper and every-component mismatch tests.

**Physical on-key restore passed in installed 0.13.0 on 2026-11-23.** The signed
bundle verified against the connected Level 3 YubiKey, with all ten mapped public
keys matching. The UI reviewed and saved the v6, v4 hybrid and v4 classical
certificate views; all three and their slot mappings persisted after a full app
restart. Independent WASM inspection confirmed that the restored v6 canonical
certificate bytes match the configured identity, while the two v4 views share
their primary fingerprint but retain distinct certified subkey packets. All 24
PIV slot records, public-key hashes, PIN/touch policies and eleven protected
configuration/backend files were unchanged; PIN retries remained **3/3**. No
PIN, private-key operation, card write or message send occurred.

## Browser-owned recipient parsing and hybrid recovery (0.12.0 preview)

The IWA now retains the entire encrypted OpenPGP message in a disposable WASM
worker. WASM selects and validates the named Level 3 v6 recipient packet, checks
the SEIPDv2 AES envelope, combines the ML-KEM-768 and X25519 shared secrets using
the RFC 9980 SHA3-256 combiner, authenticates the AES key unwrap, and recovers the
session key. Full AEAD authentication, decompression, MIME reading, signature
verification and current contact trust checks also run in the IWA. Neither the
full encrypted message nor its recovered session key crosses Native Messaging.

The helper exposes two new operations: `chat-decryption-material` supplies the
fixed public recipient and a short-lived grant; `chat-decapsulate-components`
consumes that grant before PIN entry and performs only the two existing PKCS#11
private operations. Requests cannot choose a device, slot, path or backend. The
helper checks its configured identity and live public keys and returns no partial
result if either component fails. Both shares are bound to the operation ID,
recipient fingerprint, ciphertext hash and exact component inputs. The ciphertext
hash is an opaque binding to the helper; WASM checks it against its retained bytes.

The same split flow unlocks existing hybrid PIV vault wrappers. WASM checks a
separate unsigned vault purpose and the exact vault/wrapper identifiers, so a
vault envelope cannot be accepted as a signed message. Stored wrapper formats,
hardware keys and touch policies do not change. The optional classical PIV ECDH
vault operation remains available. Both old browser routes, `chat-decap` and
`chat-vault-decapsulate`, are rejected by the extension and native schema gate.
Legacy native crypto functions used by standalone diagnostic tests are not an
IWA fallback.

Cancellation, timeout, vault lock and changed reader/trust state destroy the
worker and discard late results; no private operation is automatically retried.
WASM consumes pending state before processing a final reply, including a malformed
one. Component shares remain in memory only for the operation; managed-runtime
and IPC copies cannot be guaranteed erased. Native PIN entry and the installed
PKCS#11 backend remain unchanged.

Validation passes **136 JavaScript tests**, **five actual-worker interoperability
tests**, **74 Python tests**, **10 WASM Rust tests**, **11 native Rust tests**, the
WASM export lifecycle checks and formatting checks. Independent Sequoia-generated
software fixtures cover message and vault round trips, wrong recipients, changed
component shares and bindings, final AEAD-tag tampering, replay, cancellation,
timeouts and trust changes. Baseline and wide WASM builds are both generated; the
message path uses baseline WASM.

**Installed 0.12.0 hardware validation passed on 2026-11-23.** The signed bundle
and extension were updated without changing their identities, permissions or
stored vault. The existing Level 3 YubiKey unlocked its existing PIV vault wrapper
through the new component-only route. Opening a local copy of the previously
Gmail-delivered binary PGP/MIME test then displayed **Encrypted (decrypted)**,
**Valid hybrid** and **Trusted**. Protected subject, plain text and HTML matched;
the downloaded 48-byte attachment matched every byte and SHA-256. This was local
reception of an existing delivery, not a new Gmail or Chat send.

Before/after snapshots matched all 24 public PIV slot records, ten occupied keys,
PIN/touch policies and eleven protected configuration/certificate/backend files.
PIN retries remained **3/3**. No keys, card certificates, policies or trust bindings
were changed. Private hardware reports, message copies and account/device
identifiers remain outside the repository.

## Chat attachment transport correction (0.11.4 preview)

A live 0.11.3 Compose test constructed and verified the hybrid signature in
WASM, but the browser could not read Google's attachment-upload response because
it lacked an `Access-Control-Allow-Origin` header for the IWA. The test stopped
before posting a certificate or encrypted message. That initial attempt did not
complete an end-to-end Chat test; the successful 0.11.4 exchange is recorded below.

The 0.11.4 correction uses extension HTTPS **only for Chat attachment upload and
download**, with the `https://chat.googleapis.com/*` host permission. Installation
requires approving that expanded extension permission. No new OAuth scopes,
refresh-token storage, native Google transport, or browser security switches are
introduced. Ordinary Gmail and Chat message REST calls remain in the IWA.

The broker accepts only the configured IWA's top-level origin. It constructs fixed
Chat API URLs, permits the two named bundle/certificate upload filenames, caps
input and streamed response sizes, rejects redirects, and never retries. The
OAuth access token is supplied for one request in memory, is not logged or saved,
and never reaches the native helper. Vault lock, navigation, timeout or port
closure aborts the request and discards late replies. Certificates, trust, message
construction, encryption and verification remain in the IWA; hardware private
operations remain in the native helper.

Send errors identify the failed stage and preserve uncertain-delivery semantics.
An upload can reach Google even if the browser cannot read its response; this
alone does not create a Chat message. A failed message-creation response must be
investigated before resending.

**Installed 0.11.4 live testing passed in both directions on 2026-11-23.** After
approval of the scoped Chat permission, the installed signed bundle matched the
reviewed build and preserved the IWA origin, extension ID and both existing
certificate/trust records. The exchange sent two synthetic encrypted bundles and
their two linked public-certificate messages in the existing test conversation:

- **IWA to Sequoia:** native YubiKey ML-DSA-65/Ed25519 signing, WASM signature
  construction/verification and encryption, then the corrected Chat upload path.
  Independent Sequoia decrypted the delivered 5,516-byte ciphertext and verified
  the hybrid signature, full signer fingerprint, signed From/To/Subject, exact
  plain text and HTML alternative.
- **Sequoia to IWA:** the existing encrypted software identity produced a fresh
  5,632-byte reply. The IWA downloaded it through the scoped broker, used YubiKey
  ML-KEM-768/X25519 decapsulation, and displayed **Encrypted (decrypted)**,
  **Valid hybrid** and **Trusted** for the selected contact. The protected subject,
  text and HTML matched; all 50 downloaded attachment bytes and SHA-256 matched.
- All 24 public PIV slot records, including ten occupied slots, PIN/touch policies
  and the eleven protected identity/backend files matched the original snapshot.
  An earlier rejected PIN reduced retries to two; the successful resumed unlock
  restored the normal **3/3** count, which remained at completion. No keys,
  certificates, policies or trust bindings were changed.

The software suite passes **123 JavaScript tests plus the formatting test**,
including attachment bounds, fixed endpoints, origin restrictions, cancellation,
late-response rejection and stage-specific failure handling. These checks and the
live exchange are distinct evidence; browser CORS was discovered only live.

## IWA-owned certificates and trust (0.11 preview)

Public OpenPGP certificates and trust now belong to this signed IWA's origin, in
the `sequoia-iwa-certificates` IndexedDB database. **Contacts** shows certificate
version, algorithms, full primary fingerprint and the separately trusted email
addresses. The store contains public certificate bytes and trust decisions; it
contains no YubiKey private keys, PINs or OAuth refresh tokens. Clearing this
IWA's browser data removes the local store, including its migration marker.

**Save certificate without trust** makes a public key available for mathematical
signature verification. **Save and trust selected email** requires independent
fingerprint verification and an explicit choice of email. Trust is the exact
email/full-primary-fingerprint pair, not every address on the certificate or
the sender name supplied by Google. Only currently valid, self-certified email
bindings are offered. **Remove trust** keeps the public certificate;
**Delete saved certificate** removes it and its local trust bindings. Neither
action deletes device keys or changes hardware policies.

An attached certificate can verify a message without being saved or trusted.
The reader offers separate save and trust actions only after a valid signature;
it re-verifies the captured message bytes before applying either action. Public
v4 and v6 certificates can be saved for incoming verification. Outgoing encrypted
messages currently require an explicitly trusted **Level 3 hybrid v6** contact
with ML-DSA-65 + Ed25519 signing and ML-KEM-768 + X25519 encryption. There is no
automatic classical or v4 outgoing fallback in this IWA preview.

### Reviewed migration from the native public store

In **Contacts**, choose **Review migration from native store…**, inspect every
public certificate and existing email/fingerprint trust binding, then explicitly
confirm **Copy reviewed certificates and trust**. The native helper returns a
bounded, read-only public snapshot; WASM inspects the certificates before the
IWA commits the snapshot and its migration marker atomically. No account secrets
are copied, no device operation is required, and native files remain unchanged.

Migration is not run automatically at startup. Repeating the same migration does
not restore a certificate or trust binding subsequently removed in the IWA. A
different native snapshot is rejected after migration; use individual public
certificate imports for later changes. No native-store fallback silently
recreates missing browser records. The retained native files are an explicit
backup, not the active trust source. Clearing all browser data also clears the
one-time marker, so another migration would require a new explicit review.

The browser store rejects private-key material, multiple certificates in a
single import, unsupported versions and oversized inputs. Changing the canonical
bytes of a saved certificate with the same primary fingerprint requires explicit
removal and review; it cannot silently inherit existing trust. Atomic revisions
reject stale writes from another window. Trust changes, deletion, lock and view
changes invalidate pending reader/save results instead of displaying stale trust
or saving a late attached-certificate result.

### Private operations and send review

The native helper still owns the fixed local sending identity, serial/backend
binding, native PIN dialog and YubiKey private signing/decapsulation operations.
The browser cannot select an arbitrary module, slot or private key. Signing
preparation obtains only that fixed own public certificate and a one-use native
grant; recipient selection and trust checks happen in the IWA before any PIN
request. Native digest signing and session-key decapsulation retain their
existing private-operation boundaries. Removing certificate storage does not
remove the extension or native helper.

Compose metadata, ciphertext and send reviews are kept only in browser memory.
WASM constructs and verifies the signature and encrypts the protected MIME. The
browser wraps the exact ciphertext in standard PGP/MIME for Gmail, using a generic
outer subject; Chat retains its encrypted attachment and separate public-sender-
certificate attachment. The native helper no longer stages recipient-bound
message drafts on disk or exports them for sending.

Send reviews expire after ten minutes, are single-use and bind the Google
account, service, destination and exact certificate/trust snapshot. Trust is
checked again before consuming a review. A changed certificate, removed trust,
account/service mismatch, expired review or replay stops the send without an
automatic retry. Locking the vault or leaving the page clears pending reviews.
No email or ciphertext is persisted by this browser draft store.

The **0.11.2** preview adds explicit offline testing. In the Gmail Compose
review, **Save encrypted email…** downloads only the encrypted PGP/MIME `.eml`
and consumes the review; it does not send mail or create a native draft. **Open
local email copy (no upload)** also accepts encrypted PGP/MIME: choose an
existing trusted sender, unlock the vault, and authorize the native YubiKey
decapsulation. WASM verifies the signed inner sender, recipient and message
against the current IWA trust store before displaying plaintext. Google sign-in
is not required. Escape, cancellation, message replacement, trust changes and
vault lock discard the pending local envelope.

### Validation and current limits

Automated validation passes **94 Node tests, 65 Python tests, four Rust public-
certificate inspection tests and eight native Rust tests**. The regressions cover
one-time migration without trust resurrection, per-email trust, stale-window
updates, attached-certificate save without automatic trust, late worker results,
trust revocation before send, service/account binding, expiry and one-use reviews.
Certificate routes are checked against the actual UI functions to ensure they do
not reach the native certificate store.

The actual signing worker's ciphertext also passes through the browser PGP/MIME
wrapper and MIME extraction before independent native Sequoia `sq` decryption
and signature verification. The exact ciphertext, Unicode text, HTML and all
1,024 attachment bytes match. This uses disposable software fixtures and performs
no account or hardware operation. Sources and regressions are in
[the browser store](app/certificates/store.js), [store tests](tests/certificates-store.test.mjs),
[UI routing tests](tests/browser-certificate-routing.test.mjs),
[send-review tests](tests/compose-review.test.mjs) and
[worker interoperability test](tests/signing-worker-interop.mjs).

**Installed 0.11 UI migration and restart checks passed.** The update preserved
the existing IWA origin and extension ID. The reviewed migration copied two
existing public certificates and their two existing email/full-fingerprint trust
bindings unchanged. Contacts displayed both trusted records, and Compose offered
the existing v6 recipient. After closing the empty Compose window and reopening
the IWA, a fresh window still displayed both certificates and trust bindings and
recognized that migration had already completed.

The migration check itself performed no private YubiKey operation, PIN prompt
or message send. A subsequent **0.11.2 physical-key test on 2026-11-23** used the
migrated v6 recipient and sender trust through the actual IWA interface:

- Incoming synthetic Sequoia PGP/MIME decrypted through ML-KEM-768/X25519 in
  slots 9d/85. WASM reported a valid hybrid signature and the expected trusted
  primary fingerprint. Plain text and HTML displayed, and the downloaded
  308-byte attachment matched its expected SHA-256.
- Compose used ML-DSA-65/Ed25519 in slots 9c/84, then verified and encrypted in
  WASM to the migrated recipient. Explicit export saved encrypted PGP/MIME
  without Google sign-in or sending mail. Independent native Sequoia decrypted
  the export and verified its hybrid signature, signed From/To/Subject, plain
  text and formatted HTML against the existing software recipient identity.
- All 24 public slot records, including 10 occupied slots, PIN/touch policies,
  and PIN retry counts matched before and after. The eight installed PKCS#11
  backend files were unchanged. Both migrated certificate/trust entries remained
  in the IWA, and no keys, policies or trust were changed by the test.

### Live Gmail exchange using migrated certificates (2026-11-23)

The installed **0.11.2** IWA passed an actual signed-and-encrypted Gmail exchange
with the standalone gws/Sequoia app, using the previously migrated certificates
and trust bindings. This sent **two synthetic emails**, separately from the
offline tests above.

- **IWA to Sequoia:** Compose signed through the existing YubiKey
  ML-DSA-65/Ed25519 keys, with signature construction, verification and encryption
  in WASM. The IWA sent through Gmail's REST API. Independent Sequoia decrypted
  the delivered message and verified its hybrid signature, pinned sender and
  recipient, protected From/To/Subject, exact text and HTML.
- **Sequoia to IWA:** the existing software identity signed and encrypted a fresh
  reply. The IWA opened it from its Gmail inbox and used native YubiKey
  ML-KEM-768/X25519 decapsulation. WASM displayed **Valid hybrid** and **Trusted**
  for the migrated sender. The protected subject, plain text and HTML matched;
  the downloaded 48-byte attachment matched every prepared byte and its SHA-256.
- All 24 public PIV slot records, including ten occupied slots, PIN/touch policies
  and PIN retry counts were unchanged. The eight installed PKCS#11 backend files
  and both migrated trust entries were unchanged. No provisioning or trust
  changes were requested.

The first delivery exposed Gmail rewriting the unsigned outer `multipart/encrypted`
wrapper to `multipart/mixed`, with a base64 binary ciphertext attachment. The
standalone reader's narrow binary-wrapper fix was installed before successful
verification. Both the standalone and IWA parsers now preserve all decoded
ciphertext bytes while rejecting malformed base64, duplicate structure headers,
nested or extra parts and arbitrary plaintext substitutes. The full IWA suite
passes **94 JavaScript tests**; **16 standalone mail tests** include real Sequoia
decryption/signature checks and ciphertext-tamper rejection.

The return used ASCII armor and the installed IWA's existing reader. The IWA
binary-wrapper fix was not installed during that 0.11.2 run; the subsequent
0.11.3 binary receive test below validates the installed fix. The first pre-upload MIME was not captured; the armored reply's
captured pre-upload and Gmail Sent copies retained the same MIME structure and
identical decoded ciphertext. These observations do not establish where the
first rewrite occurred. See the [investigation report](../../docs/gmail-mime-rewriting.md)
for exact structures, scope and follow-up questions. Private raw messages, account
identifiers and hardware results remain outside the public repository.

### Binary Gmail reception and native PIN dialog (0.11.3)

On **2026-11-23**, the signed **0.11.3** bundle was rebuilt, its signature checked
and the installed bytes compared with the rebuild. The update preserved the
IWA origin, extension ID, build keys and both saved certificate/trust entries.
One additional synthetic email reused the earlier Sequoia reply's signed,
encrypted payload in a new binary/base64 PGP/MIME envelope. This is a receive
and transport regression, not a new signing test.

- The captured pre-upload and Gmail Sent copies used `multipart/encrypted`.
  The independently captured recipient raw used `multipart/mixed`, two base64
  attachment leaves and no root protocol parameter. All **5,626 ciphertext
  bytes** matched across the three copies. Gmail also replaced the unsigned
  outer Message-ID; the exact Sent receipt and observed replacement ID bound
  the captures to this single delivery.
- The unmodified 0.11.2 parser rejects that actual recipient message with
  `Ambiguous rewritten encryption`. The fixed parser accepts the exact same
  ciphertext, proving that this delivery exercises the new binary mixed-wrapper
  path rather than only the already-supported standard envelope or armor path.
- Opening that message in the actual IWA Gmail inbox used native YubiKey
  **ML-KEM-768 + X25519** decapsulation in slots 9d/85. WASM displayed
  **Encrypted (decrypted), Valid hybrid, Trusted**. The protected subject,
  plain text and formatted HTML matched, and the downloaded **48-byte**
  attachment matched every byte and its expected hash.
- All **24 public slot records**, including ten occupied slots, PIN/touch
  policies and retry counts matched before and after; PIN retries remained
  **3/3**. All eleven protected configuration/certificate/backend files,
  including eight PKCS#11 backend files, were unchanged. No hardware writes
  or trust changes were requested.

The first receive attempt stopped after the native PIN dialog was not visible
to the user. The old helper activated before its modal window was ordered;
that lifecycle/focus weakness is a plausible explanation, not a conclusively
observed cause. The helper now presents from `applicationDidFinishLaunching`,
orders a floating window in the active Space, focuses the secure PIN field and
has a temporary Dock/Cmd-Tab entry (`pin-prompt`). An isolated presentation check
showed the focused field and was cancelled without any hardware operation.
The installed helper then completed both the real vault unlock and Gmail
message decryption.

A PIN-dialog timeout or local cancellation/format rejection now has a specific
message explaining that no PIN reached the YubiKey. Unknown cryptographic errors
retain generic guidance and never claim this safe pre-submission state. The host
does not retry automatically, expose captured subprocess output, or send PINs
to Chrome. Four [PIN-boundary regressions](tests/test_pin_prompt_boundary.py)
check timeout, cancellation, invalid local input and sanitized errors; the full
suite passes **65 Python tests**, including both optional public-fixture
integration tests when configured. The existing **94 JavaScript tests** pass.
Swift compilation, bundle signature validation and the installed UI checks
also passed.

See the [expanded MIME investigation](../../docs/gmail-mime-rewriting.md#captured-binary-delivery-in-installed-iwa-0113)
for the captured wrapper differences and limits on attributing Google's internal
rewrite stage. Raw email, accounts, fingerprints, device identifiers, build
keys and local hardware reports remain outside the public repository.

The 0.10.1 results below remain separate historical evidence for that build.

## Browser-owned signing (0.10.1 preview, 2026-11-23)

This milestone describes 0.10.1. Its native contact/review storage was superseded
by the browser-owned 0.11 store and send reviews above; its hardware test results
still apply to the exact 0.10.1 build that was tested.

The Level 3 v6 signing path now constructs its OpenPGP signature inside a fresh
WASM worker. It preserves the exact composed MIME, v6 salt, creation time and
signature template while awaiting the YubiKey. Only a SHA-512 digest, the fixed
configured signing fingerprint and one-use operation identifiers cross the
extension/native bridge for signing. The MIME body and attachment bytes do not
cross that boundary during the signing operation. Existing PKCS#11 operations
perform ML-DSA-65 and Ed25519 signing, with one native PIN prompt for the composite
operation and unchanged hardware touch policies.

The native helper verifies both returned components. WASM verifies them again,
assembles v6 OnePassSig/Literal/Signature packets, verifies the full signed stream
and encrypts it for the selected recipient. The resulting ciphertext then goes
through the existing separate review/export/send flow. Signing does not send a
message or grant certificate trust. The native signer cannot inspect MIME
addresses or subject from a digest: exact composition/metadata binding is now
performed by the trusted signed IWA worker; native routing remains bound to the
selected local contact and certificate hashes.

Preparation is PIN-free. Signing authorization is consumed **before** the PIN
prompt, including cancellation/failure. Worker state is consumed on every
finalization attempt and expires after six minutes; native tickets expire after
ten minutes. Wrong request/digest/key/hash, either altered signature component,
replays and stale responses fail closed without retry or native signing-packet
fallback. A worker timeout retains the UI operation lock until an already-started
native operation settles. A bridge ownership fix prevents delayed cleanup from
an older connection releasing a newer signing operation's lock.

Automated validation used newly generated disposable software keys; the separate
physical-key and real Compose checks are recorded below:

- The actual WASM module's signed stream and detached signature verify with the
  independent native OpenSSL-backed Sequoia implementation. `sq` decrypts and
  verifies its encrypted output with exact MIME recovery.
- The real browser worker/session modules, exercised through a Node Web Worker
  shim, make one digest-only callback and produce output that `sq` decrypts and
  verifies. Unicode subject, plain text, HTML and every attachment byte survive.
- Both components are independently tamper-tested; fresh v6 salt, matching
  one-pass salt, delayed completion, expiry, cancellation and malformed/oversized
  input tests pass. The worker rejects mismatched compose metadata before PIN.
- Publication checks pass 60 Python tests with no skips, eight native Rust tests,
  46 Node tests and the standalone HTML-formatting test, including browser
  coordination, direct-transport routing and extension lock regressions.
  Browser-target WASM signing, verification, encryption, decryption and vault
  interoperability checks also pass with disposable software fixtures.

This is **automated interoperability validation, not a new live YubiKey or mail
send result**. No real private keys, card keys, certificates or touch policies
were accessed or changed for these tests. Hardware component signing and
OpenPGP session-key decapsulation remained native; certificate-store migration
was subsequent work, implemented in 0.11 above. The extension is still required.
Software `.p12` signing is not enabled
by this change. See [WASM signing tests](wasm/README.md#split-phase-signing).

### Physical signing check (2026-11-23)

The updated 0.10.1 IWA and native bridge were installed with the existing app
origin/extension ID and user configuration preserved. A local physical test then
used the actual signing worker in a Node Web Worker shim, its digest-only native
authorization path and the existing Level 3 YubiKey PKCS#11 backend. One native
PIN-authorized ML-DSA-65 + Ed25519 signature passed. Independent native Sequoia
`sq` decrypted the encrypted output using a disposable software recipient and
verified the hardware sender's hybrid signature, plain text, HTML and all binary
attachment bytes. All 24 PIV slot records, full public-key hashes, PIN/touch
policies and backend hashes matched before/after; PIN retries remained full.
No email or card writes occurred, and disposable recipient secrets were removed.

This is a **physical-key test of the real worker/native signing boundary**, not
a Chrome Compose/send test or hardware decryption test. The IWA itself was
reopened successfully with its configured identity after installation. The old
Hardware test button still exercises the earlier native test, so use
`tests/signing_hardware.py` for this new isolated check. PINs remain in the native
masked dialog; the harness has no provisioning/reset/write command.

### Live Compose interface → Sequoia verification (2026-11-23)

The installed **0.10.1** preview then passed the actual **Chrome Canary IWA
Compose** flow with the existing Level 3 YubiKey. A temporary, explicitly trusted
software recipient allowed independent decryption without another hardware
operation. The test entered a subject, plain text, Markdown formatting and a
1,024-byte binary attachment through Compose, then selected **Sign and prepare
Gmail email…** and completed the native PIN prompt.

The IWA reported **“Gmail signature constructed and verified in WASM; encrypted
message ready for review.”** The test checked the recipient and fingerprint in
the Send confirmation and selected **Cancel**. Native Sequoia `sq` independently
decrypted and verified the resulting local PGP/MIME draft:

| Check | Result |
| --- | --- |
| Hardware signature components | ML-DSA-65 in 9c + Ed25519 in 84 |
| WASM signature construction | v6 one-pass/signature packets, SHA-512, matching 32-byte salt |
| Encryption | ML-KEM-768 + X25519; SEIPv2 AES-256/OCB; ZLIB compression |
| Native Sequoia verification | One authenticated hybrid signature from the expected sender |
| Signed From, To, subject, plain text and formatted HTML | Exact match |
| Binary attachment | All 1,024 bytes matched |
| Hardware audit | All 24 slots, including ten occupied slots, public-key hashes and PIN/touch policies unchanged |
| PIN retries / installed PKCS#11 files | 3/3 before and after; all eight backend file hashes unchanged |

This validates the real Compose → WASM → Native Messaging → PKCS#11 path, beyond
the Node worker harness above. The YubiKey still performs the private signing
operations; WASM constructs and verifies the signature packets and encrypts the
message. The recipient decrypted with disposable software keys. This run did
not test Gmail delivery or hardware recipient decryption, and sent no email.

After verification, the temporary recipient/trust and pending send ticket were
removed from the live app, and its disposable recipient secret was deleted.
Existing contacts and trust records retained their original hashes. Device
identifiers, personal certificates, message artifacts, PINs and private test
reports are not published. To reproduce: import a disposable hybrid v6 recipient,
prepare the same kind of Compose message, cancel Send, and independently decrypt
the staged PGP/MIME ciphertext with `sq` using that recipient's secret and the
expected sender's public certificate. Compare exact signed MIME and take public
slot/policy snapshots around the operation; never provision or change policies
as part of this test.

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
cargo build --locked --release --manifest-path experiments/mac-iwa/crypto/Cargo.toml \
  --bin sequoia-iwa-crypto --example message_oracle
export IWA_CRYPTO_TEST_BIN="$CARGO_TARGET_DIR/release/sequoia-iwa-crypto"
export IWA_CRYPTO_ORACLE_BIN="$CARGO_TARGET_DIR/release/examples/message_oracle"
python3 -m unittest discover -s experiments/mac-iwa/tests -p 'test_*.py'
node experiments/mac-iwa/tests/test_format.cjs
```

These fixtures contain temporary public certificates and signatures, not private
keys or user messages. Without `IWA_CRYPTO_ORACLE_BIN` and
`IWA_PUBLIC_TEST_FIXTURES`, the public verification integrations are skipped. The production boundary tests use
`IWA_CRYPTO_TEST_BIN`; neither worker may substitute for the other.

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

## Historical native test scope (initial preview)

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

## Historical native test architecture (initial preview)

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

### Reproduce the initial native-runner installation (historical)

These steps describe the original runner. For the current smaller hardware
service, use the installation steps below.

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

### IWA credential vault (preview 0.9)

The browser stores an AES-256-GCM encrypted vault in IndexedDB. Each vault has a
random 256-bit content key. PIV and FIDO PRF methods independently wrap that same
key; adding another method requires an unlocked vault. PIV becomes the default
when enrolled. Names can be edited, methods removed (except the last), and an
encrypted backup exported/restored into an empty instance. Removal does not
revoke a hardware credential or remove its wrapper from older exported backups.

The configured Level 3 PIV path uses fresh ML-KEM-768 + X25519 OpenPGP envelopes
created in baseline WASM. Only decapsulation runs natively; WASM authenticates an
explicit vault/wrapper-purpose payload. Enrolment verifies an actual unwrap
before saving. No keys, PIN policies or touch policies are provisioned/changed.
An optional classical P-256/P-384 ECDH backend supports older YubiKeys without
FIDO or ML-KEM: the fixed local `vault_piv` configuration supplies `serial`,
`slot` (9d or 82–95), `algorithm` (ECDH-P256/ECDH-P384) and base64 DER SPKI `public`.
The existing PKCS#11 helper checks the token public key before deriving; the
browser applies context-bound HKDF and authenticated wrapping. Classical vault
backups are explicitly **not post-quantum resistant**. This optional configuration
must refer to an existing key; it is not inferred from the currently inserted key.
`configure_vault_piv.py --serial SERIAL --slot SLOT --algorithm ECDH-P384`
performs a PIN-free public-key read; add `--apply` to save that public mapping,
then select the classical PIV option in Vault. It never creates token keys.

Chromium does not offer ordinary WebAuthn from an IWA origin. The experiment's
existing scoped extension therefore opens an extension-owned PRF chooser. Its
stable extension ID is the RP scope, **not** the PQ Mail website RP. Start with
an assertion to discover an existing credential; creation is a separate explicit
choice after that attempt, with a fresh random user handle and required user
verification. PRF on creation is used when available, otherwise an assertion is
needed. Unsupported PRF fails closed. The extension keeps no PRF output; it
returns it only to the requesting IWA for HKDF/AES-GCM wrapping.

Vault item names, .p12 bytes/passwords and secret settings are encrypted at rest.
The current UI stores .p12 backups; it does not yet select software identities
for sending. Existing Google credentials remain in gws's native OS-keyring-backed
store and are **not migrated**. Once a vault exists, account and message operations
through the IWA require unlock. This application gate is not a replacement for
native credential encryption. Public certificates/configuration remain readable.

Lock clears live vault references, input fields and the content-key byte buffer;
a five-minute inactivity timer and page exit also lock it. JavaScript, WebCrypto
and IPC memory copies cannot be guaranteed erased. Vault writes use IndexedDB
compare-and-swap to reject stale concurrent windows. Restored backups must unlock
before persistence. No plaintext exports or automatic private-key retries exist.

Offline tests cover independent PIV/PRF wraps, restart, tampering and wrong-key
rejection, last-method protection, classical P-256/P-384 ECDH agreement, extension
origin/request binding, and native Sequoia decapsulation of a WASM-created vault
envelope followed by WASM unwrap.

Live Mac preview 0.9 testing enrolled PIV and a USB-security-key FIDO PRF
credential on the same vault. Each method unlocked the saved synthetic test item
after independently closing and reopening the IWA; PIV remained the default.
The extension now keeps the bounded passkey ceremony alive across MV3 idle
periods and aborts the popup ceremony if its request disappears. Seven vault and
PRF broker regression tests pass. An earlier PIV decapsulation attempt failed;
the subsequent restart/unlock passed, but the intermittent failure's cause is
not established. This is not yet evidence of reliable repeated PIV operation.
The native helper now records a bounded local diagnostic history containing only
fixed status codes, elapsed time and process exit status. Errors distinguish
ML-KEM, X25519, adapter timeout/input rejection, and unclassified cryptographic
validation; no raw stderr, PIN, session key or vault content is logged. A live
instrumented PIV unlock passed in 969 ms after PIN submission (including any
touch wait), followed by successful browser vault authentication. This single
successful observation does not establish the earlier failure's cause.
No PIV keys or touch policies were changed. Google credentials remain in native
gws storage; these tests used only a synthetic vault item.


The future [provisioning and recovery application](../../docs/provisioning-recovery-design.md)
would reuse the envelope-encryption model with separate provisioning keys/policy, tested backup
devices, per-device administration secrets and authenticated SCP. The proposal
also identifies format-versioning and anti-rollback work beyond the mail preview.


### Single-PIN PIV diagnostic run

`piv_soak.py` is a local Terminal-only diagnostic for the configured Level 3
identity. It checks the connected serial, all 24 PIV slot states and public keys,
and requires `Touch policy: Never` on 9c/84/9d/85 before requesting one hidden PIN.
The PIN remains only in run memory and anonymous subprocess pipes; it is never
saved in the vault, files, arguments or environment. Owned buffers are cleared
on exit, but Python/OS copies cannot be guaranteed erased. No application-wide
PIN caching is enabled.

Five rounds by default (maximum twenty, with a fifteen-minute authorization
window) exercise hybrid ML-DSA-65 + Ed25519 signing, hybrid ML-KEM-768 + X25519
message decryption and signature verification, byte-exact synthetic multipart
MIME/HTML/attachment recovery, and baseline WASM vault envelope wrapping and
unwrapping. Each vault round uses a fresh WASM instance and checks wrong binding,
wrong session-key and unsigned-message rejection. This tests the cryptographic
path without opening or editing the user's real vault or sending messages.
FIDO PRF, browser UI and OAuth flows are not automated by this PIV PIN runner.

Every private operation starts a fresh native process/session. Any failure stops
all further private operations immediately; there is no retry with the cached
PIN. A read-only after snapshot is attempted even on failure. `result.json`
contains operation timings, fixed error codes and the key/policy comparison;
`unchanged: false` or an unavailable snapshot must not be reported as unchanged.
The runner takes the same operation lock as the IWA Chat/Vault helper.

This historical diagnostic uses the explicitly built
[message oracle](crypto/README.md#explicitly-build-the-historical-message-oracle),
not the installed production worker's component interface.

```sh
python3 -I -B experiments/mac-iwa/piv_soak.py \
  --installed "$HOME/Library/Application Support/Sequoia IWA Lab" \
  --oracle /absolute/path/to/examples/message_oracle \
  --serial YOUR_TEST_SERIAL --node /absolute/path/to/node \
  --rounds 5 --out /absolute/path/to/new-result-directory
```

Five control-flow tests verify stop-on-failure, authorization expiry, refusal of
touch-required slots, and redaction of error/timeout data. Hardware execution is
separate from those automated tests and requires the user's local PIN entry.

### Standalone Google transport feasibility (preview 0.9.1)

Open **Hardware test → Standalone Google OAuth / CORS feasibility probe**.
This bundled JavaScript page uses `fetch` directly, without gws, the extension
or the native helper. Only this page permits connections to four exact Google
origins; the main app retains its existing self-only network CSP. Cookies and
Authorization headers are omitted. No remote executable script is loaded.

Live Mac IWA checks on 2026-11-23 returned readable responses:

| Probe | HTTP status | Interpretation |
| --- | --- | --- |
| OpenID discovery | 200 | Public discovery reachable |
| Token endpoint, intentionally invalid grant | 400 | Error response readable |
| Gmail profile without credentials | 401 | Unauthorized response readable |
| Chat spaces without credentials | 401 | Unauthorized response readable |

The redirect probe uses a public client ID, `response_type=code`, S256 PKCE,
a random state and only `openid` scope. Using the existing Desktop client,
Google rejected the `isolated-app://…/oauth-callback.html` redirect before consent
with **400 invalid_request**, naming `redirect_uri` in its error details. This
establishes failure for that client/redirect combination, not every possible
Google authentication architecture. No Cloud registration was changed.

The optional callback page clears query/fragment data and reports only whether
state matched and a code/error was present; it does not exchange or persist a
code. The probe deliberately discards the PKCE verifier, so it cannot become a
production authorization flow accidentally. Its report contains no credentials.

**Decision:** retain working gws authentication. Investigate a supported HTTPS
authorization companion and its secure return channel before replacing it.
Authenticated API CORS, authorization-header preflights, attachment endpoints,
PKCE code exchange, refresh-token availability and restart refresh remain
untested. Anonymous 400/401 responses do not establish those capabilities. A
hosted companion is an additional dependency, not a fully self-contained IWA.
Never bundle a confidential web-client secret or disable browser protections.

References: [Google origin validation](https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow),
[Google code model](https://developers.google.com/identity/oauth2/web/guides/use-code-model),
[IWA CSP](https://developer.chrome.com/docs/iwa/introduction).

### Static Google authorization prototype (2026-11-23)

Mac preview 0.9.2 successfully loaded the GitHub Pages authorization companion
in a credentialless iframe and completed the exact-origin/nonce-bound
`postMessage` handshake. The Google Identity Services library loaded and enabled
its sign-in button. A shared Web OAuth test client was created with
`https://ve7jtb.github.io` as its authorized JavaScript origin.

**Authorization did not complete.** GIS reported failure to open its popup,
although a disconnected Google account chooser appeared. The IWA handled the
error and displayed “Google authorization stopped. No token saved.” No access
token was received and the direct Gmail profile test was not run. No messages
were read or sent; existing gws sessions were unchanged. Two validator tests
passed, but this is not an end-to-end OAuth success.

Chrome documents that popups from a credentialless iframe use `noopener` and
cannot communicate with that iframe:
https://developer.chrome.com/blog/iframe-credentialless/ . This rules out the
current credentialless-iframe GIS popup design. A future prototype needs a
supported return channel (for example, a separately evaluated extension bridge
or an appropriately hosted non-credentialless flow); it must not weaken IWA
isolation or claim that static hosting alone solves OAuth. The baseline gws
transport remains the working implementation.

### Normal iframe with explicit headers (2026-11-23)

Preview 0.9.5 tested a public synthetic HTTPS fixture at
https://sequoia-iwa-header-test.ve7jtb.chatgpt.site . GET response headers were
verified as COEP `require-corp`, COOP `same-origin-allow-popups`, and CORP
`cross-origin`. The normal iframe loaded and completed its nonce-bound message
handshake with `credentialless=false`.

The popup still had `window.opener === null`; the iframe's `window.open()`
returned null and no reply arrived. This popup was **same-origin with the HTTPS
iframe**, but cross-origin with the top-level IWA. Its generic fixture label
“separate-origin” refers to the original local two-port fixture and should not
be interpreted as proof of a separate-origin provider test. Even this simpler
return channel failed, so no Google authorization was attempted.

The diagnostic reported `crossOriginIsolated=false` for the IWA and iframe;
we did not change the existing IWA isolation headers or enable new permissions.
The result establishes that these companion headers alone do not repair the
popup return channel in this preview, not a claim about every possible browser
configuration. No PINs, Google tokens, messages, token keys or policies were
accessed/changed. The working gws transport remains unchanged.

The first localhost HTTP fixture was blocked by the IWA's enforced HTTPS-only
frame CSP before loading. The HTTPS fixture is served by a minimal Worker with
fixed routes and no application storage or credential handling.

### Extension OAuth succeeds (2026-11-23)

Preview/extension 0.9.6 successfully used `chrome.identity.launchWebAuthFlow`
to intercept the fixed `https://bfofmobbkplpofnjjlcikmamjngbmcpp.chromiumapp.org/google`
callback registered on the shared Web test client. Google returned a short-lived
Gmail read-only token; the IWA then fetched `/gmail/v1/users/me/profile` directly
and displayed PASS for the authorized test account. No message was retrieved or
sent, and no gws/native helper handled OAuth or the Gmail API request. PIV vault
unlock still uses the existing native helper.

The extension verifies callback origin/path, OAuth state, bearer type, expiry
and required scope. Its operation accepts no caller-selected URLs or scopes.
The access token is delivered only to the requesting, exact-origin top-level
IWA port, and neither extension nor IWA persists it. Disconnecting during
authorization discards the eventual result. No refresh token or client secret
is used. Google/browser sign-in cookies and prior consent remain outside the
IWA vault; locking clears app access, not the Google browser session.

Live checks confirmed vault lock clears the temporary token and disables the
profile test. After closing/reopening with 0.9.7, the app required vault unlock
before starting authorization. Version 0.9.7 adds clearer locked-vault wording;
the installed extension's OAuth implementation is 0.9.6. Six automated tests
passed across callback validation, disconnect handling, static-message validation
and the existing PRF broker. Expiry is implemented but was not waited out in the
live test. This remains a diagnostic profile-read flow: inbox, Chat, sending and
attachments still use the established gws transport.

### Direct Gmail and Chat transport (0.10 preview, 2026-11-23)

The IWA now has browser-owned REST transport for Gmail and Google Chat. The
main sign-in button uses the extension's `chrome.identity.launchWebAuthFlow`
callback; it requests the fixed `gmail.readonly`, `gmail.send`,
`chat.spaces.readonly`, `chat.messages.readonly`, and `chat.messages.create`
scopes. Account identity must match the configured sending identity. Access
tokens stay in closure memory and clear on vault lock, expiry or page exit.
There is no refresh token, client secret or Google token in Native Messaging.
Reauthentication is required after locking or restarting the IWA.

Gmail supports inbox paging/search, raw MIME retrieval, ordinary and signed
messages, and sending the reviewed encrypted PGP/MIME message. Chat supports
conversation/message paging, bounded media downloads, and the existing linked
public-certificate/encrypted-bundle messages. Requests use only fixed Google
API origins, reject redirects, bound response bytes and never automatically
retry a send. A partial Chat send reports the certificate message reference
so the conversation can be inspected before another attempt.

At the 0.10 milestone, the native helper retained YubiKey operations,
public-certificate management and single-use reviewed ciphertext export.
Attached-key save/trust re-verified the browser-supplied raw message before
changing local trust. **0.11 supersedes that public-store/export boundary**:
the IWA now owns recipient certificates, trust, reader re-verification and
memory-only send reviews as described above; private YubiKey operations remain
native.
Legacy native Google transport entry points are disabled; the IWA installer no
longer requires or copies `gws`, its wrapper, or an OAuth client-secret file.
Existing standalone gws sessions are left untouched. The standalone CLI remains
a separate supported experiment.

Validation: 14 JavaScript OAuth/direct-transport/PRF tests and three offline
native export tests pass, including exact binary upload bytes, account mismatch,
late response after lock, redirect/traversal rejection, single-use export and
changed-trust rejection. These are automated fixtures, **not a live Google
send/receive result** for that historical revision. Subsequent offline and live
two-way Gmail tests passed in IWA 0.11.2, as documented above. Those Gmail results
do not establish a live Google Chat send/receive result for the current browser
transport.

API references: [Gmail send](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/send),
[Chat media upload](https://developers.google.com/workspace/chat/api/reference/rest/v1/media/upload),
[Chat media download](https://developers.google.com/workspace/chat/api/reference/rest/v1/media/download).

## Install the current hardware service (0.16.0)

Build the Rust worker and baseline/wide WASM using the regression commands above,
then build the signed IWA and native PIN prompt. Preserve existing development
signing keys and extension identity when updating an installed preview. For a
fresh helper, copy `config.example.json` to ignored `private/config-input.json`
and supply the existing backend, ykman, public certificate, serial and certified
enrollment email. No hardware keys are created by installation.

```sh
python3 install_native.py --config private/config-input.json \
  --crypto-bin /absolute/path/to/sequoia-iwa-crypto
```

The destination must be new. To update code in an existing helper after backing
it up and closing in-flight operations, the historical upgrade filename remains:

```sh
python3 install_chat.py --installed "/absolute/path/to/Sequoia IWA Lab" \
  --crypto-bin /absolute/path/to/sequoia-iwa-crypto
```

No transport root or standalone CLI is required. Omitting `--email` preserves
the fixed native enrollment exactly. Reload the matching extension and install
the newer signed bundle through Canary's IWA developer UI. Existing origin-local
account, vault, identities and trust remain associated with the stable IWA ID.

### Development installation conversion limitation (2026-11-25)

On the tested Chromebook, fetching the public update manifest offered 0.20.15,
but installing it over the existing development installation returned **App is
already installed**. **Perform update now** opened a local `.swbn` picker; it
did not subscribe the app to the manifest. The existing FIDO PRF vault enrollment
and saved Level 3 v6/v4 public identities remained present. No uninstall or data
clearing was performed, and this is not an automatic-update success claim.

Chromium's `GetUpdateOptionsIfAllowed` explicitly excludes developer-mode apps
from automatic updates. Its `CheckCanBeInstalled` rejects an installation from
the same management source, and both the developer UI and graphical installer
map to `kIwaUserInstalled`. Merely adding an update URL or using the graphical
installer therefore cannot convert this existing installation in place.

The build now embeds `update_manifest_url` for future normal unmanaged installs.
This source change is not retroactive to published 0.20.15 bundles. A future
release needs a new version and the same signing key/package ID.

Do **not** uninstall to convert until a complete migration backup is verified.
The current **Export encrypted vault** contains the sealed vault and its unlock
wrappers, but own identities and contact/trust records reside in separate
IndexedDB databases. Those must also be backed up and validated on restore,
along with account/transport settings. An encrypted vault export alone is not
a complete application backup. Never copy Chrome's internal registration database
or alter its development-mode marker manually.

References: [Chrome version management](https://developer.chrome.com/docs/iwa/version-management),
[update manager](https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/web_applications/isolated_web_apps/update/isolated_web_app_update_manager.cc),
[install command](https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/web_applications/isolated_web_apps/commands/install_isolated_web_app_command.cc),
and [source mapping](https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/web_applications/web_app_install_utils.cc).

### Google Drive encrypted files (0.20.18, local preview)

Select **Google Drive files** in Service, then **Drive files → Connect Google
Drive**. The shared Desktop OAuth registration uses loopback PKCE and requests
only `https://www.googleapis.com/auth/drive.file`. Enable Drive API in that
registration's project. This session is separate from Gmail/Chat. Its access
token remains in memory until expiry, vault lock, exit or disconnect; no new
refresh token is persisted. Select the intended storage account during consent.

In **Compose**, choose a trusted recipient and your software or YubiKey identity,
enter a subject/body, attach files, and prepare the encrypted message. Review,
then choose **Upload encrypted files to Drive**. The standard binary `.pgp`
contains signed multipart MIME: text, optional HTML, and attachments. Original
filenames and subject are encrypted; Drive sees a neutral outer filename, size,
time and account metadata. Upload creates a new file, sends no email, and does
not grant sharing permissions. Select your own recipient certificate for files
you want to decrypt yourself: only the selected recipient receives the file key.

**Refresh encrypted files** lists this app's marked OpenPGP files. **Download,
decrypt and verify** asks for the expected trusted signer, matches the recipient
to a saved software or YubiKey identity, then uses the existing WASM decryption
and signature verification. Nothing is imported or trusted automatically.
**Download encrypted .pgp** saves ciphertext without claiming verification.
Share the public signer certificate separately for Sequoia CLI verification.

Preview limits: 128 KiB total attachments, 256 KiB encrypted packets; MIME
encoding overhead can reduce usable capacity. There is no arbitrary Drive file
browser, large-file resume, overwrite/delete, or automatic retry. A failed POST
may have reached Google; check the file list before uploading again.

Tests cover exact binary transport, neutral metadata, fixed API origin, redirect
rejection, drive.file scope, size limits, expiry/lock, one-use trusted reviews,
and rejection of late UI results. A real software/WASM message passed through
in-memory Drive HTTP upload/download and was decrypted and signature-verified
independently by native Sequoia, including exact text, HTML and attachment bytes.
Sequoia's reply also decrypted and verified in WASM. Live Drive consent, upload, download, software decryption and trusted hybrid
signature verification passed in Chromium IWA Lab with a disposable Level 3
identity. Physical YubiKey Drive operations and independent native Sequoia
verification of that live download remain pending. No hardware keys, certificates or policies were changed.

### Complete authenticator-protected backup (local preview)

**Vault → Complete encrypted backup / restore and Google Drive** captures the
sealed vault, own identities, public certificates/trust and local settings.
It encrypts with the existing random AES-256 vault key, fresh nonce and distinct
associated data; there is no backup password. The recovery header contains the
encrypted vault and existing authenticator wrappers, including public wrapper
names/identifiers. Restore requires the same signed IWA origin and an enrolled
authenticator. The separate restore page currently supports FIDO PRF unlock
through Web Smart Card; other wrapper types are preserved but cannot yet unlock
that page.

Restore refuses conflicting destination data, supports an interrupted identical
restore, and checks all records by readback. A pending marker blocks ordinary
startup until restore completes. Close other app windows before capture. The
Drive backup list is separate from OpenPGP files and accepts only encrypted
backup envelopes. In-memory drafts/tokens are excluded. Automated tests cover
restoration, wrong authenticator, tampering, conflicts and interrupted recovery;
**real second-instance restoration is not yet validated**. Do not uninstall the
Chromebook's existing app until that validation completes.

The live Chromium IWA Lab check found and fixed a Trusted Types bootstrap error;
script loading now accepts only a fixed list of signed-bundle assets. Startup
and navigation were verified in installed 0.20.17. Version 0.20.18 additionally
requires an actually unlocked vault for Drive, including a new empty instance.
The current automated run reports 315 passed, one optional skip, zero failures.

Version 0.20.18 uses file-specific Drive compose, review and result labels, and
hides email import and inbox paging in Drive mode. The signed preview is
available through the update manifest; existing vault and identity storage
remain under the same signed application ID.

Distribution check (0.20.18): Chromium IWA Lab fetched the public HTTPS update
manifest and selected 0.20.18. The downloaded GitHub asset matched the local
signed bundle byte-for-byte. Using Install against the existing developer
installation returned “App is already installed”; this is not evidence of an
automatic update or a conversion to unmanaged installation. Applying that
web-downloaded bundle through Update and checking retained data is pending.

### 0.20.19 backup feedback

Unlock reports **No YubiKey found** with the expected serial when no PC/SC reader
is detected, without retrying a PIN operation. Connected keys proceed directly
to the normal PIN flow. Restore now shows a prominent completion panel and
Return to app link; disabled buttons no longer imply work with a wait cursor.
A separate-profile restore in Chromium IWA Lab reported every record read back
identically. Post-restore signing/decryption validation remains pending.
Validation: 315 automated tests passed, one optional skip.

### 0.20.20 OAuth default

Profiles without a saved Google OAuth choice now default to Direct Sockets
loopback PKCE, rather than Extension. Explicit saved choices remain unchanged.
Drive authorization already used loopback independently. The user confirmed
Gmail/Chat authorization worked after selecting loopback in the restored profile.
Regression tests cover missing settings and persistence of both explicit modes.

### 0.20.30 — discover before enrolling

New-vault FIDO setup checks for an existing credential under the selected RP and serial before offering creation. Only CTAP NO_CREDENTIALS plus explicit confirmation permits creation; cancellation, PIN and transport errors stop. After FIDO protection succeeds, a read-only PIV probe offers a second unlock method when matching existing wrapping material is available. No PIV provisioning is performed by this flow. Four new policy regressions pass.

### 0.20.31 — silent FIDO discovery

Existing-credential discovery first tries getAssertion with UP=false and UV=false and no PIN authentication. Protected/hidden credential responses fall through to authenticated discovery; they never authorize creation. Vault PRF evaluation still uses the existing UV-protected path. Three silent-discovery regressions passed. Existing-credential enrollment passed the live test below; no separate APDU trace was saved to distinguish silent discovery from authenticated fallback.

### 0.20.32 — bounded PIV vault probe

Vault wrapping-key discovery stops at the first usable authenticated EC key rather than continuing through unrelated empty slots. Explicit slot selection reads only that slot. This avoids the observed beta empty-slot un-MACed response without relaxing SCP authentication. Thirteen probe/SCP regressions pass. Hardware enrollment and a fresh PIV unlock passed the live test below.

### FIDO reuse and PIV vault validation (0.20.32)

On 2026-11-26, the installed signed IWA in macOS Chromium completed this sequence
using an existing provisioned beta YubiKey:

1. Discovery-first setup reused the existing discoverable FIDO PRF credential
   under the IWA package RP and saved an unlocked vault. No new-credential
   confirmation or makeCredential operation was performed by the test workflow.
2. After the PIV probe fix, the existing **slot 82 ECDH-P384** key was enrolled
   as a second local vault unlock method. The app reported **“Unlock method
   verified and saved.”** The existing FIDO method remained enrolled.
3. The vault was explicitly locked, the PIV method selected, and a separate
   PIV PIN operation completed. The app reported **“Vault unlocked.”** Both
   methods remained listed, with PIV marked as the default.

SCP11b and the explicitly approved temporary beta SD certificate pin remained
enabled. The PIV probe stops at the first usable authenticated wrapping key;
it does not ignore missing response MACs or fall back to plaintext. The earlier
empty-slot `SW=6a88` failure no longer blocked this enrollment.

The final read-only audit matched both the original FIDO-setup baseline and
the immediate PIV-enrollment baseline: all **24 PIV slots**, public-key hashes,
key metadata, PIN/touch policies and retry counters were unchanged. FIDO
credential storage remained **78 available**, FIDO PIN retries remained **8**,
and PIV PIN retries remained **3/3**. No duplicate discoverable credential was
added, and no hardware keys or policies were generated, deleted or changed.
FIDO assertions may advance signature counters; this is not a claim that every
internal device byte stayed identical. Device-specific audit files stay local.

This test validates classical P-384 vault wrapping, not hybrid PQ vault wrapping.
The new PIV method changes the local encrypted vault's unlock wrappers only.
The beta SD pin does not establish manufacturer-root provenance. Silent
`UP=false, UV=false` discovery is covered by regression tests; the live run
confirms credential reuse but does not separately prove which discovery path
returned the credential. PRF evaluation still used UV.

### 0.20.33 — hybrid YK6 vault enrollment

New PIV vault methods use reported firmware, never serial-number model lists. YK6 restores its signed public bundle, checks every mapped live public key, and requires supported native Level 3 ML-KEM-768/X25519 wrapping; missing/unsupported bundles fail without classical fallback. YK5 can use an existing P-384 key. Existing classical wrappers remain readable for migration; remove them only after a fresh hybrid unlock passes. Vault decryption has its own active-operation guard and purpose-bound, single-use hardware ticket, independent of mail-account selection. Forty-one focused regressions and transport tests passed. Hardware migration testing is pending.
