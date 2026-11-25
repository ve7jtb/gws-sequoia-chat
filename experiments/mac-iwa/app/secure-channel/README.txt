Reusable SCP11b connection module
================================
API: openSecureConnection(rawConnection, {trust, onStatus}) returns an object
with transmit(Uint8Array), authenticatedDevice, and close(). The raw connection
needs only an asynchronous transmit method. Its owner must hold an exclusive
card transaction for the entire lifetime and disconnect in finally. Call close
before disconnect. Only one command may be outstanding. An applet SELECT
establishes a fresh authenticated SCP11b session; no PIN should be requested
until it succeeds. Existing short-APDU PIV and CTAP callers can use the wrapper.

The module is independent of Sequoia, mail, DOM, storage and Web Smart Card.
Copy certificates.js and scp11.js into another IWA, then supply its pinned trust
configuration. secure-channel-ui.js is this application's policy/UI adapter.

Trust input: root DER bytes, rootSha256 hex, untrusted intermediate DER array,
and optional requiredPolicyOids (DER OID value hex). This application pins
Yubico Attestation Root 1:
62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8
Public source: https://developers.yubico.com/Secure_Domain/Introduction.html
Root: https://developers.yubico.com/PKI/yubico-ca-1.pem
Intermediate source: https://developers.yubico.com/PKI/yubico-intermediate.pem
Retrieved 2026-11-25. Only the A/B parent and SD A/B/B2 intermediates are bundled.
No runtime network lookup, OS roots, trust-on-first-use or card-provided anchor.
Beta firmware using a different manufacturer chain fails closed, not auto-pinned.

This narrow X.509 profile supports RSA SHA-256/384/512 and ECDSA SHA-256/384
issuers, P-256 device ECKA keys, time validity, CA/key usage/path length, exact
issuer names and recognized Yubico SD policy intersections. Unknown critical
extensions and policy qualifiers fail closed. Revocation is not fetched online;
root/intermediate changes require a reviewed signed application update.
No FIPS certification claim is inferred from a policy OID or successful handshake.

The initial certificate discovery, applet SELECT and handshake are public.
Subsequent application APDUs are encrypted and MACed. Card serial and expected
identity public keys must still be checked inside the authenticated session.
The secure channel authenticates the device, not the user's email certificate.
SCP11b does not authenticate the host to the card or replace PIN/touch policy.
It uses classical P-256/AES-128, not a post-quantum transport. It cannot protect
secrets from a compromised application endpoint. JavaScript zeroization is
best effort and is not a guarantee against GC copies or swap.

Protocol reference implementation:
https://github.com/Yubico/yubikey-manager/blob/main/yubikit/core/smartcard/scp.py
GlobalPlatform Card Specification Amendment F (SCP11), key agreement/receipt;
SCP03-style AES-CBC/CMAC secure messaging as implemented by YubiKit.

The module performs only certificate discovery and channel establishment by
itself. It does not provision or change Security Domain, PIV or FIDO keys.
The caller remains responsible for allowing only authorized application commands.
No automatic retry, no plaintext downgrade, no retry on a different reader
following an authenticated/private-operation failure.

Tests: node --test tests/secure-channel.test.mjs
Set OPENSSL to an OpenSSL 3 executable (default openssl on PATH).
Software tests do not constitute physical YubiKey validation. Secure PIV and
CTAP GetInfo must pass on each supported firmware before PIN/private testing.
