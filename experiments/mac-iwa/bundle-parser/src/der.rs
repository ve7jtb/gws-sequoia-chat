// SPDX-License-Identifier: LGPL-2.0-or-later
// Adapted from Sequoia piv-adapter/src/restore/der.rs at 6b99afc20984e16180e5bbfbabb51d8685d247e1.
//! A bounded DER reader for extracting public SPKIs, not an X.509 trust engine.
//! Unsupported algorithms/parameters fail closed. No BER indefinite lengths,
//! nonminimal lengths, trailing bytes, or non-byte-aligned public keys pass.
use anyhow::{ensure, Result};

pub(super) fn item<'a>(input: &mut &'a [u8], tag: u8) -> Result<(&'a [u8], &'a [u8])> {
    let original = *input;
    ensure!(input.len() >= 2 && input[0] == tag, "Unexpected DER tag");
    let first = input[1];
    let (head, n) = if first < 128 {
        (2, first as usize)
    } else {
        let count = (first & 127) as usize;
        ensure!(
            (1..=3).contains(&count) && input.len() >= 2 + count && input[2] != 0,
            "Invalid DER length"
        );
        let n = input[2..2 + count]
            .iter()
            .fold(0usize, |n, b| (n << 8) | *b as usize);
        ensure!(n >= 128, "Nonminimal DER length");
        (2 + count, n)
    };
    ensure!(head + n <= input.len(), "Truncated DER");
    *input = &original[head + n..];
    Ok((&original[..head + n], &original[head..head + n]))
}

pub(super) fn whole(bytes: &[u8], tag: u8) -> Result<&[u8]> {
    let mut r = bytes;
    let (_, body) = item(&mut r, tag)?;
    ensure!(r.is_empty(), "Trailing DER data");
    Ok(body)
}

/// The certificate is retained as public backup data only. Native must match
/// its SPKI to the live device; this function does not establish S/MIME certificate trust.
pub(super) fn certificate_spki(cert: &[u8]) -> Result<Vec<u8>> {
    let mut outer = whole(cert, 0x30)?;
    let (_, mut tbs) = item(&mut outer, 0x30)?;
    item(&mut outer, 0x30)?;
    item(&mut outer, 0x03)?;
    ensure!(outer.is_empty(), "Trailing certificate fields");
    if tbs.first() == Some(&0xa0) {
        item(&mut tbs, 0xa0)?;
    }
    item(&mut tbs, 0x02)?; // serial
    for _ in 0..4 {
        item(&mut tbs, 0x30)?;
    } // signature, issuer, validity, subject
    let (spki, _) = item(&mut tbs, 0x30)?;
    // Remaining optional X.509 fields are not interpreted or imported as trust.
    Ok(spki.to_vec())
}

/// Returns the complete AlgorithmIdentifier and the raw public-key octets.
pub(super) fn spki(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut r = whole(bytes, 0x30)?;
    let (algorithm, _) = item(&mut r, 0x30)?;
    let (_, bits) = item(&mut r, 0x03)?;
    ensure!(
        r.is_empty() && bits.first() == Some(&0),
        "Invalid SPKI bit string"
    );
    Ok((algorithm, &bits[1..]))
}

pub(super) const MLDSA65: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 0x12,
];
pub(super) const MLKEM768: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 4, 2,
];
pub(super) const COMPOSITE_SIGN: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2b, 6, 1, 5, 5, 7, 6, 46];
pub(super) const COMPOSITE_KEM: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2b, 6, 1, 5, 5, 7, 6, 60];
// LAMPS Level 5 identifiers are distinct from Level 3; accepting only lengths
// would let a mislabeled algorithm cross the hardware authorization boundary.
pub(super) const MLDSA87: &[u8] = &[0x30,0x0b,0x06,0x09,0x60,0x86,0x48,1,0x65,3,4,3,0x13];
pub(super) const MLKEM1024: &[u8] = &[0x30,0x0b,0x06,0x09,0x60,0x86,0x48,1,0x65,3,4,4,3];
pub(super) const COMPOSITE_SIGN_87: &[u8] = &[0x30,0x0a,0x06,0x08,0x2b,6,1,5,5,7,6,49];
pub(super) const COMPOSITE_KEM_1024: &[u8] = &[0x30,0x0a,0x06,0x08,0x2b,6,1,5,5,7,6,63];
pub(super) const P384: &[u8] = &[
    0x30, 0x10, 0x06, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1, 0x06, 5, 0x2b, 0x81, 4, 0, 0x22,
];

pub(super) fn p384(raw: &[u8]) -> Result<Vec<u8>> {
    ensure!(raw.len() == 97 && raw[0] == 4, "Invalid P-384 public key");
    p384::PublicKey::from_sec1_bytes(raw)?;
    let mut bits = vec![0];
    bits.extend(raw);
    let mut body = P384.to_vec();
    body.extend(encode(3, &bits));
    Ok(encode(0x30, &body))
}

/// Minimal DER for bounded, fixed public SPKIs only.
pub(super) fn encode(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if body.len() < 128 {
        result.push(body.len() as u8);
    } else if body.len() <= 255 {
        result.extend([0x81, body.len() as u8]);
    } else {
        result.extend([0x82, (body.len() >> 8) as u8, body.len() as u8]);
    }
    result.extend_from_slice(body);
    result
}
