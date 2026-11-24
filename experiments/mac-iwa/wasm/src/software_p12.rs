//! Narrow PQ Mail PKCS#12 import. The browser worker authenticates/decrypts the
//! PFX bags, then this layer reconstructs the exact existing OpenPGP packets.
//! No X.509 certificate is promoted to an OpenPGP identity or newly signed.
use super::*;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// PKCS#12 Appendix B password derivation for the MAC diversifier (3). SHA-1
/// here is legacy PFX password integrity, never an OpenPGP signature algorithm.
fn mac_key(password: &str, salt: &[u8], iterations: u64, sha1: bool) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        password.len() <= 1024
            && (8..=64).contains(&salt.len())
            && (1..=1_000_000).contains(&iterations),
        "PKCS12 KDF limits"
    );
    let hash = |bytes: &[u8]| -> Vec<u8> {
        if sha1 {
            Sha1::digest(bytes).to_vec()
        } else {
            Sha256::digest(bytes).to_vec()
        }
    };
    // Password BMPString includes its terminating two zero bytes. encode_utf16
    // preserves non-BMP surrogate pairs rather than truncating UTF-8 bytes.
    let mut pw = Zeroizing::new(Vec::new());
    for c in password.encode_utf16() {
        pw.extend(c.to_be_bytes());
    }
    pw.extend([0, 0]);
    let mut input = Zeroizing::new(vec![3; 64]);
    for source in [salt, pw.as_slice()] {
        let n = 64 * ((source.len() + 63) / 64);
        for i in 0..n {
            input.push(source[i % source.len()]);
        }
    }
    let mut a = Zeroizing::new(hash(&input));
    for _ in 1..iterations {
        let next = hash(&a);
        a.zeroize();
        *a = next;
    }
    // SHA-1/SHA-256 MAC key is exactly one digest, so no second PKCS12 block
    // or I_j addition is needed. Do not reuse this routine for cipher keys.
    Ok(a)
}
pub(super) fn verify_mac(v: serde_json::Value) -> Result<serde_json::Value> {
    fields(
        &v,
        &["data", "salt", "iterations", "mac", "password", "hash"],
    )?;
    let data = B64.decode(text(&v, "data")?)?;
    let salt = B64.decode(text(&v, "salt")?)?;
    let mac = B64.decode(text(&v, "mac")?)?;
    ensure!(
        data.len() <= 1_000_000
            && B64.encode(&data) == text(&v, "data")?
            && B64.encode(&salt) == text(&v, "salt")?
            && B64.encode(&mac) == text(&v, "mac")?,
        "Canonical bounded PFX MAC"
    );
    let is_sha1 = match text(&v, "hash")? {
        "SHA-1" => true,
        "SHA-256" => false,
        _ => bail!("Unsupported PFX MAC"),
    };
    ensure!(mac.len() == if is_sha1 { 20 } else { 32 }, "PFX MAC length");
    let key = mac_key(
        text(&v, "password")?,
        &salt,
        v["iterations"].as_u64().context("Iterations")?,
        is_sha1,
    )?;
    if is_sha1 {
        let mut h = <Hmac<Sha1> as Mac>::new_from_slice(&key)?;
        h.update(&data);
        h.verify_slice(&mac)
            .map_err(|_| anyhow::anyhow!("PFX MAC"))?;
    } else {
        let mut h = <Hmac<Sha256> as Mac>::new_from_slice(&key)?;
        h.update(&data);
        h.verify_slice(&mac)
            .map_err(|_| anyhow::anyhow!("PFX MAC"))?;
    }
    Ok(serde_json::json!({"verified":true}))
}

/// Only bounded definite-length DER is allowed inside PKCS#8. BER PFX framing
/// is handled by the browser decoder, never by this small seed extractor.
fn tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    ensure!(input.len() >= 2, "Truncated DER");
    let tag = input[0];
    let first = input[1];
    let (mut n, mut offset) = (first as usize, 2);
    if first & 0x80 != 0 {
        let count = (first & 0x7f) as usize;
        ensure!(
            (1..=3).contains(&count) && input.len() >= 2 + count && input[2] != 0,
            "DER length"
        );
        n = 0;
        for b in &input[2..2 + count] {
            n = (n << 8) | *b as usize;
        }
        ensure!(n >= 128, "Nonminimal DER length");
        offset += count;
    }
    ensure!(offset + n <= input.len(), "Truncated DER value");
    Ok((tag, &input[offset..offset + n], &input[offset + n..]))
}
fn value(input: &[u8], tag: u8) -> Result<&[u8]> {
    let (t, v, r) = tlv(input)?;
    ensure!(t == tag && r.is_empty(), "DER type/trailing data");
    Ok(v)
}
fn children(mut input: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        ensure!(out.len() < 32, "DER field limit");
        let (t, v, r) = tlv(input)?;
        out.push((t, v));
        input = r;
    }
    Ok(out)
}
fn oid(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// Extract only the seed forms emitted by PQ Mail/Bouncy Castle. If the file
/// includes both a seed and an expanded PQ private key, regenerate and compare
/// the expanded representation too; never ignore a contradictory private copy.
#[allow(deprecated)] // Compare the optional legacy expanded encoding; never use it as key material.
fn seed(pkcs8: &[u8], algorithm: &str) -> Result<Zeroizing<Vec<u8>>> {
    let fields = children(value(pkcs8, 0x30)?)?;
    ensure!(
        (3..=4).contains(&fields.len())
            && fields[0].0 == 2
            && matches!(fields[0].1, &[0] | &[1])
            && fields[1].0 == 0x30
            && fields[2].0 == 4,
        "PKCS8 structure"
    );
    let alg = children(fields[1].1)?;
    ensure!(!alg.is_empty() && alg[0].0 == 6, "PKCS8 algorithm");
    let (expected, size) = match algorithm {
        "MLDSA87" => ("608648016503040313", 32),
        "MLKEM1024" => ("608648016503040403", 64),
        "MLKEM768" => ("608648016503040402", 64),
        "Ed448" => ("2b6571", 57),
        "X448" => ("2b656f", 56),
        "X25519" => ("2b656e", 32),
        "P521" => ("2a8648ce3d0201", 66),
        _ => bail!("Unsupported PKCS8 key"),
    };
    ensure!(alg[0].1 == oid(expected), "PKCS8 algorithm mismatch");
    if algorithm == "P521" {
        ensure!(
            alg.len() == 2 && alg[1].0 == 6 && alg[1].1 == oid("2b81040023"),
            "P521 parameters"
        );
    } else {
        ensure!(alg.len() == 1, "Unexpected algorithm parameters");
    }
    let mut embedded_public = Vec::new();
    if fields.len() == 4 {
        // RFC 5958's optional publicKey is IMPLICIT BIT STRING [1]. Treat it
        // as another binding to validate, not advisory data to ignore.
        ensure!(
            fields[0].1 == [1] && fields[3].0 == 0x81 && fields[3].1.first() == Some(&0),
            "PKCS8 public field"
        );
        embedded_public.push(&fields[3].1[1..]);
    } else {
        ensure!(fields[0].1 == [0], "PKCS8 version/public mismatch");
    }
    let (raw, expanded) = if algorithm.starts_with("ML") {
        let (t, v, r) = tlv(fields[2].1)?;
        ensure!(r.is_empty(), "PQ key trailing data");
        if t == 0x30 {
            let parts = children(v)?;
            ensure!(
                parts.len() == 2 && parts[0].0 == 4 && parts[1].0 == 4,
                "PQ seed pair"
            );
            (parts[0].1, Some(parts[1].1))
        } else {
            ensure!(t == 0x80 || t == 4, "PQ seed form");
            (v, None)
        }
    } else if algorithm == "P521" {
        let ec = children(value(fields[2].1, 0x30)?)?;
        ensure!(
            ec.len() >= 2 && ec.len() <= 4 && ec[0] == (2, &[1]) && ec[1].0 == 4,
            "SEC1 key"
        );
        let mut last_tag = 0x9f;
        for (tag, body) in &ec[2..] {
            ensure!(*tag > last_tag, "Duplicate SEC1 field");
            last_tag = *tag;
            match tag {
                0xa0 => ensure!(value(body, 6)? == oid("2b81040023"), "SEC1 curve mismatch"),
                0xa1 => {
                    let point = value(body, 3)?;
                    ensure!(point.first() == Some(&0), "SEC1 bit padding");
                    embedded_public.push(&point[1..]);
                }
                _ => bail!("Unexpected SEC1 field"),
            }
        }
        (ec[1].1, None)
    } else {
        (value(fields[2].1, 4)?, None)
    };
    ensure!(raw.len() == size, "Private seed length");
    if let Some(expanded) = expanded {
        let correct = match algorithm {
            "MLDSA87" => {
                let key = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(raw.try_into()?);
                key.expanded_key().to_expanded().to_vec()
            }
            "MLKEM1024" => {
                use ml_kem::ExpandedKeyEncoding;
                ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::from_seed(raw.try_into()?)
                    .to_expanded_bytes()
                    .to_vec()
            }
            "MLKEM768" => {
                use ml_kem::ExpandedKeyEncoding;
                ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(raw.try_into()?)
                    .to_expanded_bytes()
                    .to_vec()
            }
            _ => bail!("Unexpected expanded key"),
        };
        let correct = Zeroizing::new(correct);
        ensure!(
            correct.as_slice() == expanded,
            "Seed/expanded private-key mismatch"
        );
    }
    if !embedded_public.is_empty() {
        use ml_dsa::Keypair;
        use ml_kem::kem::KeyExport;
        use p521::elliptic_curve::sec1::ToEncodedPoint;
        let public = match algorithm {
            "MLDSA87" => ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(raw.try_into()?)
                .verifying_key()
                .encode()
                .to_vec(),
            "MLKEM1024" => {
                ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::from_seed(raw.try_into()?)
                    .encapsulation_key()
                    .to_bytes()
                    .to_vec()
            }
            "MLKEM768" => ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(raw.try_into()?)
                .encapsulation_key()
                .to_bytes()
                .to_vec(),
            "Ed448" => cx448::SigningKey::from(cx448::SecretKey::from_slice(raw))
                .verifying_key()
                .to_bytes()
                .to_vec(),
            "X448" => {
                // cx448's X448 scalar has no Drop implementation, so the
                // import-time public-key proof also needs a wiping owner.
                let secret = Zeroizing::new(cx448::x448::Secret::from(<[u8; 56]>::try_from(raw)?));
                cx448::x448::PublicKey::from(&*secret).as_bytes().to_vec()
            }
            "X25519" => x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
                <[u8; 32]>::try_from(raw)?,
            ))
            .as_bytes()
            .to_vec(),
            "P521" => p521::SecretKey::from_slice(raw)?
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            _ => bail!("Unsupported public binding"),
        };
        ensure!(
            embedded_public.iter().all(|p| *p == public),
            "Embedded PKCS8 public-key mismatch"
        );
    }
    Ok(Zeroizing::new(raw.to_vec()))
}
fn component(
    keys: &BTreeMap<String, Zeroizing<Vec<u8>>>,
    alias: &str,
) -> Result<pgp::crypto::mem::Protected> {
    Ok(keys
        .get(alias)
        .context("Missing PQ Mail key alias")?
        .as_slice()
        .into())
}
fn attach(cert: &pgp::Cert, keys: &BTreeMap<String, Zeroizing<Vec<u8>>>) -> Result<pgp::Cert> {
    ensure!(!cert.is_tsk(), "Public metadata only");
    let pile = pgp::PacketPile::from_bytes(&cert.to_vec()?)?;
    let mut packets = Vec::new();
    for packet in pile.children().cloned() {
        packets.push(match packet {
            pgp::Packet::PublicKey(key) => {
                let secret = match key.pk_algo() {
                    A::MLDSA87_Ed448 => mpi::SecretKeyMaterial::MLDSA87_Ed448 {
                        eddsa: component(keys, "cert-ed")?,
                        mldsa: component(keys, "cert-ml")?,
                    },
                    A::ECDSA => mpi::SecretKeyMaterial::ECDSA {
                        scalar: mpi::ProtectedMPI::from(
                            keys.get("v4-sign").context("v4 signer")?.as_slice(),
                        ),
                    },
                    _ => bail!("Unexpected PQ Mail primary"),
                };
                pgp::Packet::SecretKey(key.add_secret(secret.into()).0)
            }
            pgp::Packet::PublicSubkey(key) => {
                let secret = match key.pk_algo() {
                    A::MLDSA87_Ed448 => mpi::SecretKeyMaterial::MLDSA87_Ed448 {
                        eddsa: component(keys, "sign-ed")?,
                        mldsa: component(keys, "sign-ml")?,
                    },
                    A::MLKEM1024_X448 => mpi::SecretKeyMaterial::MLKEM1024_X448 {
                        ecdh: component(keys, "kem-x")?,
                        mlkem: component(keys, "kem-ml")?,
                    },
                    A::MLKEM768_X25519 => mpi::SecretKeyMaterial::MLKEM768_X25519 {
                        ecdh: component(keys, "v4-x")?,
                        mlkem: component(keys, "v4-ml")?,
                    },
                    A::ECDH => mpi::SecretKeyMaterial::ECDH {
                        scalar: mpi::ProtectedMPI::from(
                            keys.get("v4-ec").context("v4 EC")?.as_slice(),
                        ),
                    },
                    _ => bail!("Unexpected PQ Mail subkey"),
                };
                pgp::Packet::SecretSubkey(key.add_secret(secret.into()).0)
            }
            other => other,
        });
    }
    pgp::Cert::from_packets(packets.into_iter())
}
pub(super) fn import(mut v: serde_json::Value) -> Result<serde_json::Value> {
    fields(&v, &["keys", "modern", "compatibility", "password"])?;
    let list = v["keys"].as_array().context("PKCS12 keys")?;
    ensure!(list.len() == 10, "Complete PQ Mail Level 5 keyset required");
    let expected = [
        ("cert-ml", "MLDSA87"),
        ("cert-ed", "Ed448"),
        ("sign-ml", "MLDSA87"),
        ("sign-ed", "Ed448"),
        ("kem-ml", "MLKEM1024"),
        ("kem-x", "X448"),
        ("v4-sign", "P521"),
        ("v4-ml", "MLKEM768"),
        ("v4-x", "X25519"),
        ("v4-ec", "P521"),
    ];
    let mut keys = BTreeMap::new();
    for item in list {
        fields(item, &["alias", "pkcs8", "certificate"])?;
        let alias = text(item, "alias")?
            .strip_prefix("pgp5-")
            .context("PQ Mail key alias")?;
        let algorithm = expected
            .iter()
            .find(|(a, _)| *a == alias)
            .context("Unexpected key alias")?
            .1;
        let der = Zeroizing::new(B64.decode(text(item, "pkcs8")?)?);
        ensure!(der.len() <= 16384, "Private key size");
        let parsed = seed(&der, algorithm)?;
        ensure!(
            keys.insert(alias.to_owned(), parsed).is_none(),
            "Duplicate alias"
        );
    }
    let modern = pgp::Cert::from_bytes(&B64.decode(text(&v, "modern")?)?)?;
    let compatibility = pgp::Cert::from_bytes(&B64.decode(text(&v, "compatibility")?)?)?;
    let modern = attach(&modern, &keys)?;
    let compatibility = attach(&compatibility, &keys)?;
    let hybrid = compatibility
        .clone()
        .retain_subkeys(|ka| ka.key().pk_algo() == A::MLKEM768_X25519);
    let classical = compatibility.retain_subkeys(|ka| ka.key().pk_algo() == A::ECDH);
    let mut pw = v["password"].take();
    let result = (|| -> Result<_> {
        let password = pw.as_str().context("Import vault password")?;
        let mut result = encrypted_result(&modern, password)?;
        result["compatibility"] = serde_json::json!([
            encrypted_result(&hybrid, password)?,
            encrypted_result(&classical, password)?
        ]);
        Ok(result)
    })();
    if let serde_json::Value::String(p) = &mut pw {
        p.zeroize();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pfx_mac_matches_independent_kdf_vectors_and_rejects_limits() {
        // Independent expected values are generated by Python hashlib for these
        // public, synthetic password/salt vectors, not by the import implementation.
        let sha1 = mac_key("test-password", b"0123456789abcdef", 1, true).unwrap();
        let sha256 = mac_key("test-password", b"0123456789abcdef", 1, false).unwrap();
        assert_eq!(&*sha1, &oid("d02bbf952d3f4b772b529411e0dfb87278b4c787"));
        assert_eq!(
            &*sha256,
            &oid("3fa636c09ee644731db8b82fa7a912f7346471021747c97f5eeed480e8e4b87c")
        );
        assert_ne!(&sha1[..], &sha256[..20]);
        assert!(mac_key("x", b"short", 1, true).is_err());
        assert!(mac_key("x", b"0123456789abcdef", 1_000_001, false).is_err());
        let base = serde_json::json!({"data":B64.encode(b"authenticated fixture"),"salt":B64.encode(b"0123456789abcdef"),"iterations":1,"mac":B64.encode([0u8;20]),"password":"test-password","hash":"SHA-1"});
        assert!(verify_mac(base).is_err());
    }
    #[test]
    fn optional_actual_pqmail_p12_import_preserves_all_three_public_views() {
        let Ok(path) = std::env::var("IWA_P12_DECODED_FIXTURE") else {
            return;
        };
        let input: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let modern =
            pgp::Cert::from_bytes(&B64.decode(input["modern"].as_str().unwrap()).unwrap()).unwrap();
        let old = pgp::Cert::from_bytes(
            &B64.decode(input["compatibility"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let result = import(input.clone()).unwrap();
        assert_eq!(
            result["public"]["fingerprint"],
            modern.fingerprint().to_hex()
        );
        assert_eq!(result["compatibility"].as_array().unwrap().len(), 2);
        for profile in result["compatibility"].as_array().unwrap() {
            assert_eq!(profile["public"]["fingerprint"], old.fingerprint().to_hex());
        }
        assert_ne!(
            result["compatibility"][0]["public"]["certificateHash"],
            result["compatibility"][1]["public"]["certificateHash"]
        );
        // BC includes the public key in its Ed448 OneAsymmetricKey encoding.
        // Authentication of the PFX does not excuse inconsistent key objects:
        // a corrupted embedded public value must fail seed reconstruction.
        let ed = input["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["alias"] == "pgp5-cert-ed")
            .unwrap();
        let mut inconsistent = B64.decode(ed["pkcs8"].as_str().unwrap()).unwrap();
        let last = inconsistent.len() - 1;
        inconsistent[last] ^= 1;
        assert!(seed(&inconsistent, "Ed448").is_err());
        // Likewise, a supplied expanded PQ private key must agree with its
        // seed, not simply be ignored while the seed is trusted in isolation.
        let pq = input["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["alias"] == "pgp5-cert-ml")
            .unwrap();
        let mut inconsistent = B64.decode(pq["pkcs8"].as_str().unwrap()).unwrap();
        let last = inconsistent.len() - 1;
        inconsistent[last] ^= 1;
        assert!(seed(&inconsistent, "MLDSA87").is_err());
        let mut wrong = input;
        wrong["keys"][0]["alias"] = "pgp5-unknown".into();
        assert!(import(wrong).is_err());
    }
}
