# Gmail MIME rewriting: interoperability observations

This records a transport compatibility issue observed on 2026-11-23 while
sending an encrypted IWA message to the standalone Sequoia app through Gmail.
It is not evidence of an OpenPGP cryptographic failure or a general claim about
every Gmail delivery. The private raw delivery and its hashes are retained with
the local test results; account addresses, message IDs and raw messages are not
published here.

## Expected sender wrapper and observed received wrapper

The IWA's `gmailEnvelope()` source constructs a conventional two-part PGP/MIME
envelope. The received Gmail API `format=raw` message had this structure:

| Element | IWA constructor | Observed Gmail delivery |
| --- | --- | --- |
| Root media type | `multipart/encrypted` | `multipart/mixed` |
| Root protocol parameter | `application/pgp-encrypted` | Absent |
| Number of immediate MIME parts | Two | Two |
| First part media type | `application/pgp-encrypted` | `application/pgp-encrypted` |
| First part transfer encoding | Unencoded ASCII | `base64` |
| Decoded first part | `Version: 1` with CRLF | `Version: 1` with CRLF, 12 bytes |
| First part disposition | Not set | `attachment` |
| Second part media type | `application/octet-stream` | `application/octet-stream` |
| Second part transfer encoding | `base64` | `base64` |
| Second part disposition | `inline` | `attachment` |
| Ciphertext filename | `message.pgp` | `message.pgp` |

The received ciphertext decoded to 5,515 bytes, and the received MIME parser
reported no defects. Both leaves used canonical base64. The original pre-upload
MIME was kept only in IWA memory and its send review was consumed, so this run
does **not** provide a byte-for-byte comparison with an independently captured
pre-upload message. The constructor column describes the reviewed sending code,
not a second captured artifact.

These MIME headers and dispositions belong to the **unsigned outer transport
wrapper**. The signed inner subject, text, HTML and attachments are carried
inside the encrypted OpenPGP payload. A wrapper change may prevent a client
from recognizing the message without invalidating its inner signature. That
distinction does not establish that a particular payload survived intact;
successful authenticated decryption and signature verification must confirm it.

Earlier tests had already observed a different rewrite: a mixed root with an
ASCII-armored ciphertext leaf, sometimes labeled `text/plain`. That motivated
the existing narrow armor fallback. This newer binary/base64 case is a distinct
representation and must not be handled by trimming decoded ciphertext.

## Failure and conservative handling

Both `mail_transport.rewritten_payload()` and the IWA's `envelope()` previously
accepted only the armored variant under `multipart/mixed`. The delivered binary
packet stream therefore stopped at the MIME wrapper check, before any private
decryption operation or signature verification.

The added path accepts exactly two immediate leaves: one
`application/pgp-encrypted` control part that decodes to `Version: 1`, and one
`application/octet-stream` ciphertext part using canonical base64. It rejects
duplicate structure headers, missing or extra parts, nested MIME, arbitrary
plaintext leaves, malformed base64 and noncanonical padding. Only ASCII MIME
whitespace is removed from the encoded base64; decoded ciphertext bytes are
never trimmed or normalized. The existing armored fallback remains separate.

Recognizing this wrapper does **not** mean that its contents are valid,
authenticated or trusted. The normal native/WASM or Sequoia path must still
validate the OpenPGP packets, recipient, authenticated encryption, signature,
signed content and selected sender certificate. No outer Google header or
attachment label grants certificate trust.

## Validation and remaining investigation

Synthetic regressions exercise the exact two-leaf binary shape, including a
base64-encoded control record, leading/trailing whitespace octets in the binary
ciphertext and malformed/ambiguous negative cases. These fixtures contain no
real messages, credentials or hardware identifiers. A separate software-fixture
integration test uses Sequoia to decrypt and verify an actual hybrid message
after the wrapper rewrite, and rejects ciphertext tampering.

The real **IWA-to-standalone Sequoia delivery passed independent hybrid
decryption and signature verification** after the wrapper fix. The test pinned
the sender's full primary fingerprint and the intended recipient, and checked
the protected From, To, Subject, exact plain text and formatted HTML. No message
attachments were expected or found. A separate audit recomputed the retained
raw-message and ciphertext hashes, confirmed that extraction reproduced all
5,515 ciphertext bytes, and compared the verified MIME and displayed bodies
against the prepared expectations.

This establishes successful cryptographic delivery for this message, not a
byte-for-byte comparison against the uncaptured pre-upload wrapper. A separate
**Sequoia-to-IWA return test also passed** through the actual Gmail inbox and
reader in installed IWA 0.11.2. Native YubiKey ML-KEM-768/X25519 decryption
completed; WASM displayed a valid hybrid signature and the expected trusted
primary fingerprint. The protected subject, text and HTML matched, and the
downloaded 48-byte attachment exactly matched the prepared file and its hash.
Both migrated trust entries remained present. Before/after snapshots matched
for all 24 slots, including ten occupied slots, PIN/touch policies, PIN retry
counts and eight installed PKCS#11 backend files. The two-direction run sent
two synthetic messages and requested no hardware or trust changes.

The return used **ASCII-armored** ciphertext. Its captured pre-upload wrapper
and the sender's Gmail Sent `format=raw` copy both retained
`multipart/encrypted` and the same two MIME leaves. The raw messages differed,
but each decoded leaf was byte-identical, and the OpenPGP ciphertext decoded
from armor was the same 5,626 bytes with the same SHA-256. This is a useful
contrast with the first binary/base64 delivery, not proof of the reason for
that rewrite. No independent raw copy of the return message was captured at
the recipient, and these observations do not pinpoint whether the first
rewrite occurred at submission, delivery or API presentation.

The standalone parser fix was installed for the outgoing verification. The
corresponding IWA source change passed regressions, but the installed IWA
remained 0.11.2 for the return test and used its existing armor support. The
private test reports retain the detailed evidence without publishing account
addresses, fingerprints or message contents here.

## Captured binary delivery in installed IWA 0.11.3

A subsequent receive test on **2026-11-23** sent one synthetic email using the
same previously signed/encrypted Sequoia reply payload, now wrapped as binary
PGP/MIME by the real IWA `gmailEnvelope()` constructor. No new signature was
created. Unlike the initial run, this test retained the exact pre-upload bytes,
the sender's Gmail Sent raw and the recipient's Gmail raw.

| Observation | Pre-upload | Gmail Sent raw | Recipient raw |
| --- | --- | --- | --- |
| Root media type | `multipart/encrypted` | `multipart/encrypted` | `multipart/mixed` |
| Root protocol parameter | `application/pgp-encrypted` | Same | Absent |
| Control transfer encoding | Unencoded ASCII | Same | `base64` |
| Control disposition | Absent | Absent | `attachment` |
| Ciphertext transfer encoding | `base64` | `base64` | `base64` |
| Ciphertext disposition | `inline` | `inline` | `attachment` |
| Decoded ciphertext | 5,626 bytes | Identical | Identical |
| Message-ID | Sender supplied | Replaced by Gmail | Same as Gmail Sent |

The exact Gmail send receipt pinned the Sent read; its observed Message-ID then
selected the recipient read. Each capture also checked the sender/recipient and
exact ciphertext. Gmail's replacement Message-ID is another **unsigned outer
header** change; it does not modify the protected inner headers or signature.
The MIME difference is present between the Sent and recipient API observations.
This narrows the evidence but does not establish which internal Google delivery,
storage or API-serialization stage produced it.

The original 0.11.2 parser rejected the actual captured recipient bytes with
`Ambiguous rewritten encryption`. The fixed parser recovered all 5,626 bytes
unchanged, and its source matched the rebuilt preview. The installed **0.11.3**
IWA then opened the delivered email from Gmail and completed native YubiKey
ML-KEM-768/X25519 decryption and WASM hybrid signature verification. The reader
showed **Encrypted (decrypted), Valid hybrid, Trusted**. Protected subject,
plain text, HTML and the downloaded 48-byte attachment matched expectations.
This establishes live coverage of the new binary mixed-wrapper path, not just
a synthetic parser test or an armored-message fallback.

The receive initially stopped after a missed PIN dialog. After the native
window-presentation fix, an isolated Cancel check and the actual vault/message
operations passed. Before/after snapshots matched all 24 slot records, ten
occupied public keys, PIN/touch policies, PIN retry counts (3/3) and eight
installed PKCS#11 backend files. The test changed no keys or policies. The
[0.11.3 README](../experiments/mac-iwa/README.md#binary-gmail-reception-and-native-pin-dialog-0113)
details the PIN fix and its failure-boundary regressions.

Further investigation can compare controlled binary versus armored bodies and
Content-Disposition variants to identify which changes influence Google's
rewrite. Preserve strict receiving checks and synthetic content; these observed
deliveries do not justify generalizing to every Gmail message or weakening
cryptographic verification.

Sources: [standalone receiver](../mail_transport.py),
[IWA receiver](../experiments/mac-iwa/app/message-mime.js),
[IWA sender wrapper](../experiments/mac-iwa/app/compose-review.js),
[standalone regressions](../test_mail_transport.py), and
[IWA regressions](../experiments/mac-iwa/tests/message-mime.test.mjs).
