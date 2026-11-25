# ARKG previewSign / OpenPGP interoperability report

Validation recorded 2026-11-25 for Sequoia Chat Lab IWA 0.20.11.

## Hardware run

The IWA reused its existing experimental previewSign master credential on a
Beta0 YubiKey through CTAP2 over Web Smart Card. It derived ten distinct
ARKG-P256 public keys and produced ten self-certified OpenPGP v4 ECDSA/P-256
certificates and ten individual signed synthetic messages. The run completed
all twenty certificate/message signing operations. The UI reported successful
Sequoia WASM verification for every certificate and message and rejection of
all altered-message checks.

The downloaded public JSON report contains the exact exported certificate,
message, payload and detached-signature bytes. No replacement software signers
were used for the CLI check below.

## Independent native Sequoia CLI check

A separate native `sq` executable verified every exported hardware-generated
message using its corresponding certificate, in an isolated local Sequoia home:

```sh
sq --home isolated-sq-home verify --message \
  --signer-file arkg-1-certificate.pgp arkg-1-message.pgp
```

The same procedure was applied to indices 1 through 10.

| Check | Result |
| --- | --- |
| Message signature with matching certificate | 10/10 passed |
| Recovered content equals the original payload byte for byte | 10/10 passed |
| Altered literal data with original signature | 10/10 rejected |
| Original message with a different derived-key certificate | 10/10 rejected |
| Distinct primary-key fingerprints | 10 |

`--signer-file` explicitly supplies the test trust anchor; this verifies
cryptographic signatures and certificate usability, not an external identity
claim or a certification chain to a trusted root. These certificates are
self-certified. No third-party root certification was added.

Message packets use a v3 one-pass signature packet, literal data and a v4
signature packet. ARKG derivation and previewSign are experimental; exported
OpenPGP public keys and ECDSA signatures use the conventional P-256 format.
This is classical cryptography, not post-quantum signing.

## Evidence and boundaries

- Downloaded hardware report SHA-256:
  `1f4c5a991c352d76c885b7ea05f856f2f3168e33e92abad89c05913456253efb`.
- Native `sq` executable SHA-256:
  `e63cc1d3a75e84e2c7f512a0782add340d741acbbb00688f3c44de90a80bca1b`.
- Published IWA bundle SHA-256:
  `239c8c8ce481d5ccc412c87e9581da98a9f0cb86187de1192b9f9f7cd31834a3`.
- The prior software regression run passed 31 targeted tests.
- Native verification used public files only: no card access, PIN, private-key
  operation, network request or user keyring modification was required.
- The hardware batch reused an existing FIDO credential and issued no PIV
  writes. No independent before/after PIV policy audit was performed for this
  diagnostic; this report does not claim such an audit.
- Local artifacts, per-key logs and the JSON results were retained privately.
  PINs, private material and user vault data are not included in this report.

All checks above passed. Root certification is a possible future test, not an
implemented part of this run.
