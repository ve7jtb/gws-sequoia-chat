# gws + Sequoia Mail & Chat

A standalone local browser app and CLI for encrypted Google Chat bundles and OpenPGP email, using [Google Workspace CLI (`gws`)](https://github.com/googleworkspace/cli) for transport and [Sequoia `sq`](https://sequoia-pgp.org/) for OpenPGP. No PQ Mail installation, Java runtime, `.p12` identity, or PQ Mail vault is needed.

This is an experimental integration, not an official Google or Sequoia product. The local browser UI uses a native Python helper with gws and Sequoia. Chat uses Google's documented Chat API; the new mail preview uses Gmail API and standard signed-and-encrypted PGP/MIME. See [Local browser app](#local-browser-app-mac-preview) and [Gmail preview](#gmail-preview).

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

The installer downloads official gws v0.22.5 and verifies its published SHA-256. It copies only the executables; dynamically linked Sequoia libraries must remain installed. The current shell wrapper is tested on macOS Apple Silicon; Linux is intended but untested. Windows binaries exist upstream, but this wrapper currently requires a POSIX environment such as WSL. Native Android/iOS clients are not included. The local browser UI is tested on macOS.

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
an installed/offline PWA. Python 3.9 or newer and the project's installed `gws`
and `sq` binaries are required. Start it outside restricted sandboxes so gws can
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

The combined suite passed **25 tests on macOS**: the 14 CLI tests plus 11 browser
helper tests covering real password-protected Level 3/5 hybrid round trips,
wrong passwords/signers, tampering, MIME path and HTML safety, explicit one-time
send confirmation, trust persistence/removal and loopback access controls.
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
verified inner From/To headers must match the selected identities. Unencrypted
mail can be read with safe formatting and explicit **unverified** status. This
preview does not verify detached `multipart/signed` mail, handle inline PGP,
S/MIME, classical/v4 certificates, or unsigned encrypted messages. Those formats
must not be mistaken for verified hybrid mail.

The complete offline command is:

```sh
python3 -B -m unittest -v test_chat test_webapp test_mail_transport
node --check web/app.js
node --check web/mail.js
```

**35 tests passed on macOS**, including ten new Gmail tests with real protected
Level 3/5 Sequoia keys and mocked Gmail transport. They cover RFC 3156 wrappers,
text/HTML/files, protected subjects, wrong passwords, tampering, forged outer
headers, unverified ordinary mail, search/paging metadata, one-time send review,
account matching and separation of Chat/Gmail credentials. No live Gmail send or
receive is claimed for this new module yet; it needs Gmail API setup and user
consent. The earlier live **Chat** decryption result above remains separate.
