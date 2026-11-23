# Provisioning and recovery application design

Status: **proposal, not an implemented provisioning product**. Updated 2026-11-22.

The application would create recoverable mail identities in a restricted,
standalone environment, provision them to one or more YubiKeys, and maintain an
encrypted recovery archive. Normal mail clients would consume public certificate
bundles and use the provisioned keys, without receiving recovery private keys or
PIV administration secrets.

This document is not authorization to reset, import, overwrite or change any
connected device. Each destructive operation requires a separate, explicit plan
and confirmation naming the target device and affected slots.

## Objectives and boundaries

- Boot a signed, read-only system image with a small, auditable application.
- Keep durable private material only in an authenticated encrypted keystore on
  separate writable storage; the boot image itself contains no user secrets.
- Require an enrolled hardware key to unlock an existing provisioning keystore.
- Create verified backup devices before declaring an identity recoverable.
- Support older PIV devices for vault protection and software PQ polyfills where
  appropriate, without depending on FIDO availability.
- Manage each device's PUK, management key, supported algorithms and policies.
- Authenticate and encrypt supported smart-card connections using SCP11.
- Resume interrupted provisioning from a journal without blind retries or resets.

The environment must handle private keys in RAM during generation/import. A boot
image does not eliminate a compromised firmware, host, peripheral or supply-chain
threat. Secure boot/image-signature verification, reproducible builds, a pinned
software manifest, disabled plaintext swap/hibernation/core dumps, no telemetry,
and a default-off network are requirements, not current verified properties.
A VM is useful for testing but does not isolate secrets from its host.

## Distinguish identity keys from device unlock keys

| Material | Origin and lifetime | Backup model |
|---|---|---|
| Recoverable signing, certification and encryption private keys | Generated in the provisioning environment; imported where supported | Retained in encrypted archive; may be identical on several devices |
| Non-exportable identity keys | Generated on a YubiKey | Cannot later be cloned; recovery means a new identity/key and updated certificates/trust |
| Device-specific vault-unlock key | Preferably generated on each YubiKey | Unique per device; never needs to be cloned |
| Polyfill PQ private key | Software-generated where hardware lacks the algorithm | Encrypted archive plus device-wrapped client representation |
| Certificates and public bundle | Constructed from the identity keys and metadata | Public, portable; include slot mappings for each target device |
| PUK and PIV management key | Independent values for each device | Encrypted administration records, never public bundles |

Yubico documents that PIV keys generated on-device cannot leave it, and imported
keys cannot receive an attestation asserting on-device generation. Existing
on-device identities therefore cannot be converted into identical recoverable
copies by exporting their certificates. [PIV attestation](https://docs.yubico.com/yesdk/users-manual/application-piv/attestation.html)

PQ import capabilities, private-key encodings, supported sizes, slot policies and
SCP support must be tested for the exact firmware/SDK combination. In particular,
YK6 Beta0 support must not be inferred from production YubiKey 5 documentation.
The application must refuse a plan whose required private-key imports are not
supported; it must not silently substitute a different algorithm or key.

## Reusable vault architecture

Reuse the IWA vault's envelope-encryption model and transport-independent
interfaces, rather than creating a provisioning-only cryptographic scheme:

1. Generate a fresh random 256-bit data-encryption key (DEK) for a vault.
2. Encrypt the private payload with AES-256-GCM and a fresh 96-bit nonce per write.
3. Give each enrolled device its own wrapper around the **same vault DEK**.
4. Obtain wrapping material through PIV decapsulation/ECDH or, where explicitly
   allowed by that vault's policy, FIDO PRF. Apply purpose-bound HKDF-SHA-256.
5. Authenticate the wrapper's vault ID, wrapper ID, algorithm and recipient key
   binding. Match full public-key identifiers, not merely a serial and slot.
6. Authenticate the complete payload before exposing private records.

A shared DEK here means one provisioning vault accessible through several device
wrappers. It should **not** be the daily mail vault's DEK. Use separate random DEKs
and purposes for `mail-credentials` and `provisioning-recovery`, even when the same
physical YubiKey is enrolled in both. Merely hiding recovery functions behind a
UI or deriving an administrative key from an already-exposed mail DEK would not
provide this separation.

Recommended provisioning policy: PIV unlock only by default. The common format
may support PRF, but enabling a PRF or recovery-secret wrapper must be a deliberate
policy change: any such wrapper is another route to the whole recovery archive.
No automatic password fallback should be introduced.

### Current IWA format versus the proposed shared format

The local, not-yet-published preview 0.9 implementation is in
`experiments/mac-iwa/app/vault/core.js`, `app/vault/piv.js`, and the WASM
vault-envelope functions under `experiments/mac-iwa/wasm/src/lib.rs`.
Those implementation changes are not part of this design-document commit.
Its JSON record has `format: sequoia-iwa-vault`, `version: 1`, a vault `id`,
`revision`, `default` wrapper ID, a `wrappers` array and encrypted `body`.
Wrappers have an ID, display name, method type, method-specific public `binding`,
and authenticated encrypted `box`. Names, serials, wrapper identifiers and
encapsulations are public metadata; secrets and stored item contents are encrypted.

Version 1 uses exact JSON-encoded arrays as AES-GCM additional data and HKDF
context, including its binding object. Byte serialization is significant. Do not
reimplement this with differently ordered JSON fields and assume compatibility.
Before independently implementing another client, publish deterministic test
vectors and freeze a canonical encoding or a precisely specified encoding for a
new version. Never silently reinterpret existing version-1 records.

The proposed shared provisioning format must additionally define:

| Field/record | Required semantics |
|---|---|
| Format/version and purpose | Reject unsupported versions and cross-purpose use |
| Vault UUID and revision | Stable identity, concurrent-update detection and migration tracking |
| Payload algorithm, nonce and ciphertext/tag | Exact algorithm suite and authenticated encoding |
| Wrapper type and suite | Explicit KEM/hybrid combiner or ECDH curve, HKDF and wrap algorithms |
| Recipient binding | Full public-key digest/component identities; serial and slot are locators |
| Wrapper policy | Whether PIV, PRF or another recovery route is permitted |
| Authenticated manifest | Protect default/method/policy metadata, including the wrapper set, after unlock |
| Encrypted private payload | Identity secrets, certificates, device records, administration secrets and journal |
| Resource limits | Strict maximum sizes, counts, recursion and decompression bounds |

The current preview does not authenticate every outer metadata field or provide
cryptographic anti-rollback. Its IndexedDB compare-and-swap prevents accidental
stale-window writes, not an attacker restoring an older valid backup. The future
format needs a defined rollback-detection policy: e.g. compare an independently
retained latest manifest hash/revision, with explicit recovery handling. A revision
inside the same replaceable file is insufficient.

For both formats, adding a wrapper requires an already unlocked vault and a
successful test of the new unlock method **before** committing it. Refuse deletion
of the last viable method. Removing a wrapper from today's file cannot revoke it
from an old exported backup. Rotating the DEK protects future snapshots, not
previously obtained private material.

### Transport-independent interfaces

- `inspectDevice`: capabilities, stable public identifiers and occupied slots.
- `establishAuthenticatedChannel`: verified card identity and channel properties.
- `unwrapVaultKey`: fixed recipient/algorithm request, PIN/touch handled locally.
- `generateOrImportIdentity`: provisioning-only, bound to an approved plan.
- `readAndVerifyPublicState`: verify keys, certificates, policies and bundles.
- `changeAdministrationSecret`: journalled per-device PUK/management-key change.

Use PKCS#11/PCSC/native implementations initially. Web Smart Card would replace
the APDU transport, not the vault format. FIDO remains an independent optional
unlock backend, not a prerequisite for PIV. Client secret values must not appear
in command-line arguments, logs, browser URLs, crash reports or public bundles.

## Keystore records

The encrypted payload should include:

- Identity UUID, account names and email SANs, algorithms, full fingerprints,
  certificate revisions and private-key material/seed encoding where recoverable.
- OpenPGP certification/signing/encryption component relationships, v4/v6 public
  certificates and S/MIME certificates; preserve packet creation times and other
  fingerprint-affecting metadata when cloning the same OpenPGP identity.
- Whether each private key was generated externally, generated on a token,
  imported, or held as an encrypted software polyfill.
- Per-device serial/model/firmware, public unlock key, identity slot mappings,
  supported mechanisms, requested and observed PIN/touch policies.
- Separate PUK and management-key records with algorithm, rotation state and
  references to the verified device. Do not store a PIN by default.
- SCP trust anchors, validated card-certificate identity, enrollment evidence and
  policy; public audit exports must omit device identifiers unless explicitly chosen.
- A recoverable provisioning journal and verification results.

Each target device may have different slot mappings and unique administration
secrets while sharing the same imported identity keys and certificates. The
certificate bundle must describe the receiving device accurately; do not blindly
copy another device's serial/mapping metadata.

## First setup and backup enrollment

The requirement for an existing unlock device has one explicit bootstrap
exception: creating the first vault and enrolling its first device.

1. Verify the boot image and select storage for the new encrypted archive.
2. Inspect the target's capabilities and current PIV contents. Display a concrete
   plan; refuse unexpected occupied slots. Reset is a separate explicit action.
3. Establish an authenticated SCP connection where supported and required.
4. Generate a device-specific unlock key in an approved empty slot, or enroll an
   explicitly selected existing key after proving possession. Verify its public key.
5. Create the vault DEK in RAM, wrap it to that device, test unwrap, then atomically
   persist the first encrypted archive. Establish per-device administration secrets
   using the journalled process below; retain necessary bootstrap state until verified.
6. Generate recoverable identity keys in the protected environment and commit an
   encrypted checkpoint before importing them. Create certificates and import the
   supported private components with the approved policies.
7. Verify public keys, perform signature/decryption self-tests, install certificates
   and the public bundle, then read back and validate them.
8. Enroll a second YubiKey with its own unlock key and administration secrets;
   import the intended identity copies from the same archive.
9. Shut down/reboot the environment, unlock from the second device, and verify
   archive contents and key use. Mark the backup complete only after this test.

Two physically separate archive copies and two tested unlock devices are the
recommended minimum. Keep backups apart. An encrypted archive alone is not a
usable recovery mechanism if every enrolled unlock key is lost or reset.

For older YubiKeys, a classical ECDH wrapper can unlock an archive containing
software PQ private keys. This does not make that archive post-quantum resistant:
an adversary who can break the classical wrapper may recover all archived PQ
keys. The UI must report this for **every** enabled unlock route; a strong hybrid
wrapper does not strengthen a weaker alternative wrapper of the same DEK.

## Replacement, loss and compromise

With one surviving authorized key, unlock the archive and provision a replacement
using the normal inspected/approved plan. Add and test its independent vault
wrapper before removing any retired wrapper. Certificate renewal and identity
rotation are separate choices from duplicating existing identity keys.

If no enrolled unlock method survives, a strict hardware-required archive is
unrecoverable. Optional offline recovery or threshold recovery would be a separate
future policy, not an implicit back door.

A lost device holding copied identity private keys is different from a lost
vault-unlock device. Removing its vault wrapper does not invalidate the identity
keys it already holds. If compromise is suspected, rotate the affected signing,
certification and encryption identities, update peer trust/certificates and revoke
old credentials where supported. Other copies of the same key cannot remain
cryptographically distinct from the lost one. Archive deletion cannot undo an
attacker's prior copy of a key or ciphertext.

## PUK and management-key lifecycle

Use independent cryptographically generated administration secrets per device;
never reuse the vault DEK, identity private keys, PIN or another device's secrets.
Choose the strongest supported management-key algorithm according to an explicit
firmware policy, and generate PUKs within that device's supported character/length
constraints. The PUK unblocks the PIN; the management key authorizes provisioning
operations. Neither substitutes for the vault-unlock private key.
[Yubico PIN/PUK/management-key reference](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html)

Journal each rotation as prepared → attempted → verified → committed. Durably
store the encrypted old and proposed values before sending a command that could
change the device. Remove the obsolete value from the active record only after
verification and durable commit. Existing historical backups may still contain it.

An uncertain response after changing a PUK or management key must pause for
reconciliation, not alternate old/new values in a retry loop. Document exactly
which read-only or bounded authentication check is safe for each command and
retry-counter state. No automatic counter exhaustion or reset as recovery.

Recovery of a blocked device must be possible using another enrolled key to read
that device's PUK from the archive. Do not make its blocked PIN the sole route to
its own PUK. Changing retry counters or resetting PIV is outside ordinary repair
and requires a separately approved plan because of its side effects.

## Authenticated SCP11 connections

The target is **authenticated secure messaging**, not merely encrypted APDUs.
Yubico recommends validating the card's Secure Domain certificate against its
full chain; firmware generations and available certificates differ.
[Secure Domain documentation](https://developers.yubico.com/Secure_Domain/Introduction.html)

Before sending PINs, PUKs, management keys or imported private keys:

1. Discover the supported SCP variant and protocol/key parameters without sending
   secrets. Resolve the supported device/application/channel combination.
2. Build and validate the card certificate chain against deliberately installed
   trust anchors. Check signatures, permitted algorithms, validity and certificate
   purpose according to the vendor profile. Define trusted clock and offline
   revocation-data freshness requirements explicitly.
3. Bind the authenticated endpoint to the enrolled device record and verified
   public-key identity. A genuine-device chain alone does not identify which of
   the user's devices is intended; a serial string alone is not cryptographic proof.
4. Complete the selected SCP11 key agreement/confirmation and establish protected
   command/response processing with the protocol's integrity and sequence rules.
5. Keep that verified session through the sensitive operation. Reset state and
   establish a new authenticated channel after disconnect/reconnect; do not reuse
   session keys or counters, or silently fall back to plaintext.

SCP11b card authentication does not replace PIV management-key authentication or
user PIN/touch authorization. Where mutual off-card authentication is required,
choose an appropriate supported SCP variant and manage its credentials separately.
Use a reviewed SDK/protocol implementation; do not create a custom secure channel.

PCSC and Web Smart Card carry APDUs; encryption/authentication belongs in the SCP
layer above that transport. With PKCS#11, the provider/module must support the
required authenticated SCP policy or expose an appropriate integration point.
An IWA cannot independently wrap APDUs that an opaque PKCS#11 module constructs
and transmits on a separate session. Provisioning may therefore need a direct
PIV/SCP adapter even when routine signing uses PKCS#11.

An `--enc` flag is not sufficient evidence of authenticated transport. Yubico's
PIV tool documentation describes SCP11b encryption that does not validate the
on-card certificate. Test the exact chosen SDK/module and configuration, not just
whether traffic is encrypted. [PIV tool options and SCP11 notes](https://docs.yubico.com/software/yubikey/tools/pivtool/piv-tool-command.html)

Default secure provisioning must refuse secret import when authenticated SCP is
required but unavailable. A legacy compatibility mode, if offered, needs a
separate explicit decision and local-only workflow; never describe it as an
SCP-protected operation. SCP11 also does not protect private keys from the host
that is generating/importing them, and its conventional key agreement must not be
advertised as post-quantum transport protection.

## Interrupted operations and audit

Treat provisioning as a journalled sequence, not an atomic multi-slot operation.
Before each mutation, record the expected before-state, target key identity,
approved after-state and operation ID in the encrypted archive. Afterward read
back the public state and compare it before advancing. A failed import may have
completed despite a transport error: do not overwrite a slot just because a
response was lost. Secret-changing commands need their own bounded reconciliation
rules rather than a generic retry function.

Persist archive updates with atomic replacement, durability checks and a retained
last-known-good encrypted snapshot. Refuse stale concurrent writers. On restart,
show which steps are verified, pending or ambiguous and permit resuming only after
matching the device to the journal. Public logs contain stage/result codes and
redacted identifiers, never private key bytes, PINs, PUKs, management keys, wrapping
secrets or session keys.

## Validation and delivery stages

1. Freeze a versioned shared vault specification and cross-runtime test vectors.
2. Implement the archive library and synthetic provisioning journal without hardware.
3. Test native PIV adapters against disposable keys and a capability matrix.
4. Add authenticated SCP with negative certificate/handshake/session tests.
5. Build and verify the restricted boot image and offline update process.
6. Conduct restore drills with two real devices before enabling recovery claims.

Required tests include multi-wrapper unlock and restart; wrong device/key/PIN;
body/header/wrapper tampering; mixed-up vault purposes; unsupported algorithms;
quota/disk-full and stale writes; old-backup rollback detection; partial import
and administration-key rotation; last-unlock-method protection; second-device
recovery after simulated primary loss; independent per-device PUK/management keys;
public bundle readback; and invalid, untrusted, expired or substituted SCP card
certificates, altered responses, dropped sessions and downgrade refusal.

Current status: local IWA preview 0.9 has experimental PIV/PRF envelope code and
software tests, but its first live PIV vault attempt stopped before saving and
live FIDO PRF testing is pending. It does not yet implement this provisioning
application, administration-secret lifecycle, authenticated SCP, recovery image,
private-key cloning, or automatic migration of gws credentials. Do not interpret
existing mail interoperability tests as validation of these proposed features.
