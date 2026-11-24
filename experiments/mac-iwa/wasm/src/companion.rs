//! One-operation opening of an encrypted on-card companion.
//!
//! Native code supplies only the fresh signed ciphertext, checked public map,
//! P384 shared secret and one hardware component. This module derives the AEAD
//! key, opens the empty-password P12, verifies every private/public binding and
//! completes the missing component. It never exports a private key or plaintext
//! P12. Its caller must terminate the worker on every outcome, including cancel.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sequoia_openpgp::{
    cert::amalgamation::key::PrimaryKey, parse::Parse, policy::StandardPolicy,
    serialize::SerializeInto, Cert,
};
use sequoia_public_bundle::companion::{public_bytes, spki, verify_ml, VerifiedCompanion};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};
const MAX: usize = 65536;
fn text<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    v[key].as_str().context("Missing companion field")
}
fn bytes(v: &serde_json::Value, key: &str) -> Result<Vec<u8>> {
    let s = text(v, key)?;
    ensure!(s.len() <= 90000, "Companion field limit");
    let out = B64.decode(s)?;
    ensure!(
        out.len() <= MAX && B64.encode(&out) == s,
        "Canonical bounded companion bytes required"
    );
    Ok(out)
}
fn inspect(v: &serde_json::Value) -> Result<VerifiedCompanion> {
    let object = v.as_object().context("Companion object required")?;
    ensure!(
        object
            .keys()
            .all(|k| ["encoded", "serial", "publicKeys", "certificate"].contains(&k.as_str())),
        "Unknown companion descriptor fields"
    );
    let serial = if let Some(n) = v["serial"].as_u64() {
        n
    } else {
        text(v, "serial")?.parse::<u64>()?
    };
    ensure!(
        serial > 0 && serial <= i32::MAX as u64,
        "Companion serial limit"
    );
    let mut expected = BTreeMap::new();
    let keys = v["publicKeys"]
        .as_object()
        .context("Live public keys required")?;
    ensure!(
        keys.len() == 4,
        "Exactly four companion hardware keys required"
    );
    for (slot, value) in keys {
        ensure!(
            slot.len() == 2
                && slot
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "Canonical slot required"
        );
        let s = value.as_str().context("SPKI encoding required")?;
        ensure!(s.len() < 4000, "SPKI limit");
        let raw = B64.decode(s)?;
        ensure!(B64.encode(&raw) == s, "Canonical SPKI required");
        expected.insert(slot.clone(), raw);
    }
    let certificate = if v
        .get("certificate")
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.is_empty())
    {
        Some(bytes(v, "certificate")?)
    } else {
        None
    };
    VerifiedCompanion::parse(
        &bytes(v, "encoded")?,
        serial as u32,
        &expected,
        certificate.as_deref(),
    )
}

/// Public inspection is safe in the same public-only import worker as ordinary
/// bundles. Validity establishes key binding, never contact/email trust.
#[wasm_bindgen]
pub fn companion_inspect(input: &str) -> Result<String, JsValue> {
    let run = || -> Result<String> {
        ensure!(input.len() < 200000, "Companion request limit");
        let v = serde_json::from_str(input)?;
        Ok(inspect(&v)?.preview().to_string())
    };
    run().map_err(|e| JsValue::from_str(&format!("Companion inspection rejected: {e}")))
}

/// Small bounded BER reader for Bouncy Castle's unencrypted PFX containers.
/// Indefinite lengths are accepted only for constructed outer containers;
/// PKCS8 and seed fields below are required to use their exact fixed shape.
struct Node<'a> {
    tag: u8,
    body: &'a [u8],
    encoded: &'a [u8],
}
fn node<'a>(input: &mut &'a [u8], depth: usize) -> Result<Node<'a>> {
    ensure!(
        depth < 16 && input.len() >= 2,
        "P12 nesting/truncation limit"
    );
    let all = *input;
    let tag = all[0];
    ensure!(tag & 31 != 31 && tag != 0, "Unsupported ASN1 tag");
    let first = all[1];
    let (head, n, end) = if first == 128 {
        ensure!(tag & 32 != 0, "Primitive indefinite ASN1 rejected");
        let mut tail = &all[2..];
        while !tail.starts_with(&[0, 0]) {
            node(&mut tail, depth + 1)?;
        }
        let bodylen = all.len() - 2 - tail.len();
        (2, bodylen, 2 + bodylen + 2)
    } else {
        let (h, n) = if first < 128 {
            (2, first as usize)
        } else {
            let count = (first & 127) as usize;
            ensure!(
                (1..=3).contains(&count) && all.len() >= 2 + count && all[2] != 0,
                "P12 length encoding"
            );
            let n = all[2..2 + count]
                .iter()
                .fold(0usize, |n, b| (n << 8) | *b as usize);
            ensure!(n >= 128, "Nonminimal P12 length");
            (2 + count, n)
        };
        (h, n, h + n)
    };
    ensure!(n <= MAX && end <= all.len(), "P12 object length limit");
    *input = &all[end..];
    Ok(Node {
        tag,
        body: &all[head..head + n],
        encoded: &all[..end],
    })
}
fn one(input: &[u8], tag: u8) -> Result<Node<'_>> {
    let mut r = input;
    let n = node(&mut r, 0)?;
    ensure!(n.tag == tag && r.is_empty(), "P12 type/trailing bytes");
    Ok(n)
}
fn children(input: &[u8]) -> Result<Vec<Node<'_>>> {
    let mut r = input;
    let mut v = Vec::new();
    while !r.is_empty() {
        ensure!(v.len() < 32, "P12 field limit");
        v.push(node(&mut r, 0)?);
    }
    Ok(v)
}
fn octets(n: &Node) -> Result<Zeroizing<Vec<u8>>> {
    if n.tag == 4 {
        return Ok(Zeroizing::new(n.body.to_vec()));
    }
    ensure!(n.tag == 0x24, "Expected P12 OCTET STRING");
    let mut out = Zeroizing::new(Vec::new());
    for c in children(n.body)? {
        ensure!(c.tag == 4, "Nested OCTET fragments rejected");
        out.extend(c.body);
        ensure!(out.len() <= MAX, "P12 octet limit");
    }
    Ok(out)
}
const DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1];
const KEY: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 12, 10, 1, 1];
const CERT: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 12, 10, 1, 3];
const NAME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 20];
const LOCAL_ID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 21];
fn content(n: &Node) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(n.tag == 0x30, "P12 ContentInfo required");
    let fields = children(n.body)?;
    ensure!(
        fields.len() == 2 && fields[0].tag == 6 && fields[0].body == DATA && fields[1].tag == 0xa0,
        "Only unencrypted P12 data permitted"
    );
    let explicit = children(fields[1].body)?;
    ensure!(explicit.len() == 1, "P12 explicit content");
    octets(&explicit[0])
}
fn oid(algorithm: &str) -> Result<Vec<u8>> {
    let size = match algorithm {
        "Ed448" => 57,
        "X448" => 56,
        "ML-DSA-65" => 1952,
        "ML-KEM-768" => 1184,
        _ => bail!("Unknown seed algorithm"),
    };
    let spki = spki(algorithm, &vec![0; size])?;
    let fields = children(one(&spki, 0x30)?.body)?;
    let alg = children(fields[0].body)?;
    Ok(alg[0].body.to_vec())
}
/// Bag aliases identify the intended role, but acceptance also requires deriving
/// every public key from the seed and comparing with the authenticated envelope.
fn private_seed(encoded: &[u8], algorithm: &str) -> Result<Zeroizing<Vec<u8>>> {
    let top = one(encoded, 0x30)?;
    ensure!(top.encoded[1] != 0x80, "DER PKCS8 required");
    let fields = children(top.body)?;
    ensure!(
        (fields.len() == 3 || fields.len() == 4)
            && fields[0].tag == 2
            && fields[1].tag == 0x30
            && fields[2].tag == 4,
        "Expected seed PKCS8"
    );
    ensure!(
        if fields.len() == 3 {
            fields[0].body == [0]
        } else {
            !algorithm.starts_with("ML")
                && fields[0].body == [1]
                && fields[3].tag == 0x81
                && fields[3].body.first() == Some(&0)
        },
        "PKCS8 version/public mismatch"
    );
    let alg = children(fields[1].body)?;
    ensure!(
        alg.len() == 1 && alg[0].tag == 6 && alg[0].body == oid(algorithm)?,
        "PKCS8 algorithm mismatch"
    );
    let (tag, size) = match algorithm {
        "Ed448" => (4, 57),
        "X448" => (4, 56),
        "ML-DSA-65" => (0x80, 32),
        "ML-KEM-768" => (0x80, 64),
        _ => bail!("Unsupported private seed"),
    };
    let seed = one(fields[2].body, tag)?;
    ensure!(seed.body.len() == size, "Seed length mismatch");
    if fields.len() == 4 {
        let derived = seed_public(algorithm, seed.body)?;
        ensure!(
            public_bytes(algorithm, &derived)? == &fields[3].body[1..],
            "PKCS8 embedded public mismatch"
        );
    }
    Ok(Zeroizing::new(seed.body.to_vec()))
}
fn certificate_spki(encoded: &[u8]) -> Result<Vec<u8>> {
    let cert = children(one(encoded, 0x30)?.body)?;
    ensure!(
        cert.len() == 3 && cert[0].tag == 0x30,
        "P12 certificate shape"
    );
    let tbs = children(cert[0].body)?;
    let offset = usize::from(tbs.first().is_some_and(|n| n.tag == 0xa0));
    ensure!(
        tbs.len() >= offset + 6 && tbs[offset + 5].tag == 0x30,
        "P12 certificate SPKI"
    );
    Ok(tbs[offset + 5].encoded.to_vec())
}
fn seed_public(algorithm: &str, seed: &[u8]) -> Result<Vec<u8>> {
    use ml_dsa::Keypair;
    use ml_kem::kem::KeyExport;
    let raw = match algorithm {
        "Ed448" => cx448::SigningKey::from(cx448::SecretKey::from_slice(seed))
            .verifying_key()
            .to_bytes()
            .to_vec(),
        "X448" => {
            // cx448 provides Zeroize but its X448 Secret is Copy and has no
            // Drop. An explicit owner is required even for public derivation.
            let secret = Zeroizing::new(cx448::x448::Secret::from(<[u8; 56]>::try_from(seed)?));
            cx448::x448::PublicKey::from(&*secret).as_bytes().to_vec()
        }
        "ML-DSA-65" => ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(seed.try_into()?)
            .verifying_key()
            .encode()
            .to_vec(),
        "ML-KEM-768" => ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed.try_into()?)
            .encapsulation_key()
            .to_bytes()
            .to_vec(),
        _ => bail!("Unknown seed algorithm"),
    };
    spki(algorithm, &raw)
}
fn parse_p12(p12: &[u8], env: &VerifiedCompanion) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>> {
    ensure!(p12.len() <= 16384, "Companion P12 limit");
    let root = one(p12, 0x30)?;
    let fields = children(root.body)?;
    // No password/MAC may be supplied: signed AES-GCM is the sole protection.
    ensure!(
        fields.len() == 2 && fields[0].tag == 2 && fields[0].body == [3],
        "Expected empty-password PFX without MAC"
    );
    let authenticated = content(&fields[1])?;
    let infos = children(one(&authenticated, 0x30)?.body)?;
    let l3 = env.profile() == "LEVEL3_POLYFILL";
    let aliases = if l3 {
        ["cert-pq", "sign-pq", "kem-pq"]
    } else {
        ["cert-ed", "sign-ed", "kem-x"]
    };
    let mut keys = BTreeMap::new();
    let mut certificates = BTreeMap::new();
    for info in infos {
        let safe = content(&info)?;
        for bag in children(one(&safe, 0x30)?.body)? {
            ensure!(bag.tag == 0x30, "Expected SafeBag");
            let fields = children(bag.body)?;
            ensure!(
                fields.len() == 3
                    && fields[0].tag == 6
                    && fields[1].tag == 0xa0
                    && fields[2].tag == 0x31,
                "SafeBag shape"
            );
            let mut role = None;
            let mut seen = BTreeSet::new();
            for attr in children(fields[2].body)? {
                ensure!(attr.tag == 0x30, "Bag attribute shape");
                let a = children(attr.body)?;
                ensure!(
                    a.len() == 2
                        && a[0].tag == 6
                        && a[1].tag == 0x31
                        && seen.insert(a[0].body.to_vec()),
                    "Duplicate bag attribute"
                );
                let value = children(a[1].body)?;
                ensure!(value.len() == 1, "Bag attribute singleton required");
                if a[0].body == NAME {
                    ensure!(
                        value[0].tag == 0x1e
                            && value[0].body.len() % 2 == 0
                            && value[0]
                                .body
                                .chunks_exact(2)
                                .all(|v| v[0] == 0 && v[1].is_ascii()),
                        "Invalid bag name"
                    );
                    role = Some(String::from_utf8(
                        value[0].body.chunks_exact(2).map(|v| v[1]).collect(),
                    )?);
                } else {
                    ensure!(
                        !l3 && a[0].body == LOCAL_ID
                            && value[0].tag == 4
                            && value[0].body.len() <= 64,
                        "Unsupported bag attribute"
                    );
                }
            }
            let role = role.context("Missing bag role")?;
            let index = aliases
                .iter()
                .position(|a| *a == role)
                .context("Unknown private role")?;
            let component = &env.components()[4 + index];
            if fields[0].body == KEY {
                let seed = private_seed(fields[1].body, &component.algorithm)?;
                ensure!(
                    seed_public(&component.algorithm, &seed)? == component.public_key,
                    "Companion private/public mismatch"
                );
                ensure!(keys.insert(role, seed).is_none(), "Duplicate private role");
            } else {
                ensure!(!l3 && fields[0].body == CERT, "Unexpected companion bag");
                let certbag = children(one(fields[1].body, 0x30)?.body)?;
                ensure!(
                    certbag.len() == 2
                        && certbag[0].tag == 6
                        && certbag[0].body == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 22, 1]
                        && certbag[1].tag == 0xa0,
                    "Expected X509 certBag"
                );
                let cert = one(certbag[1].body, 4)?;
                ensure!(
                    certificate_spki(cert.body)? == component.public_key,
                    "P12 carrier public mismatch"
                );
                ensure!(
                    certificates.insert(role, ()).is_none(),
                    "Duplicate carrier role"
                );
            }
        }
    }
    ensure!(
        keys.len() == 3 && certificates.len() == if l3 { 0 } else { 3 },
        "Incomplete companion key set"
    );
    Ok(keys)
}

/// The original shared secret, HKDF PRK/key, tentative plaintext and seed copies
/// use wiping owners. Ciphertext and signed public metadata may remain cached.
fn open(env: &VerifiedCompanion, secret: &[u8]) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>> {
    use aes_gcm::{
        aead::{AeadInPlace, KeyInit},
        Aes256Gcm,
    };
    use hmac::{Hmac, Mac};
    ensure!(
        secret.len() == 48 && secret.iter().any(|b| *b != 0),
        "Invalid wrapping shared secret"
    );
    let hmac = |key: &[u8], data: &[u8]| -> Result<Zeroizing<Vec<u8>>> {
        let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key)?;
        h.update(data);
        Ok(Zeroizing::new(h.finalize().into_bytes().to_vec()))
    };
    let prk = hmac(env.salt(), secret)?;
    let mut info = if env.profile() == "LEVEL3_POLYFILL" {
        b"PQMail companion L3 P384 v1".to_vec()
    } else {
        b"PQMail companion P384 v1".to_vec()
    };
    info.extend(Sha256::digest(env.aad()));
    info.push(1);
    let key = hmac(&prk, &info)?;
    let n = env.ciphertext().len() - 16;
    let mut plain = Zeroizing::new(env.ciphertext()[..n].to_vec());
    Aes256Gcm::new_from_slice(&key)?
        .decrypt_in_place_detached(
            env.nonce().into(),
            env.aad(),
            &mut *plain,
            env.ciphertext()[n..].into(),
        )
        .map_err(|_| anyhow::anyhow!("Companion authentication failed"))?;
    ensure!(
        plain.len() >= 4 && u32::from_be_bytes(plain[..4].try_into()?) as usize == plain.len() - 4,
        "Companion private framing mismatch"
    );
    parse_p12(&plain[4..], env)
}

fn complete(v: &serde_json::Value) -> Result<serde_json::Value> {
    let operation = text(v, "operation")?;
    ensure!(
        ["sign", "decapsulate"].contains(&operation),
        "Unsupported companion operation"
    );
    let request = &v["request"];
    let response = &v["response"];
    let bindings: &[&str] = if operation == "sign" {
        &["requestId", "signingFingerprint", "hashAlgorithm", "digest"]
    } else {
        &[
            "requestId",
            "cipherHash",
            "recipientKey",
            "mlkemCiphertext",
            "x25519Ephemeral",
        ]
    };
    ensure!(
        request
            .as_object()
            .is_some_and(|r| r.len() == bindings.len())
            && bindings
                .iter()
                .all(|k| request.get(*k).is_some() && request[*k] == response[*k]),
        "Companion operation binding mismatch"
    );
    let env = inspect(&response["companion"])?;
    let cert = Cert::from_bytes(env.certificate_bytes())?;
    let selected = Cert::from_bytes(&bytes(v, "certificate")?)?;
    // Packet framing can be normalized by native serialization. Compare every
    // public packet after the same canonical serialization, never only a
    // fingerprint (which would ignore changed bindings or revocations).
    ensure!(
        !selected.is_tsk() && selected.to_vec()? == cert.to_vec()?,
        "Selected certificate does not match companion"
    );
    let policy = StandardPolicy::new();
    let l3 = env.profile() == "LEVEL3_POLYFILL";
    // Preserve and validate the hardware part; a malformed partial result must
    // never be silently overwritten with software output or a different key.
    let (result_field, alias) = if operation == "sign" {
        let signer = cert
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_signing()
            .find(|k| !k.primary())
            .context("Missing signing key")?;
        ensure!(
            text(request, "signingFingerprint")? == signer.key().fingerprint().to_hex()
                && request["hashAlgorithm"].as_u64() == Some(10),
            "Signing identity/hash mismatch"
        );
        let digest = bytes(request, "digest")?;
        ensure!(digest.len() == 64, "SHA512 digest required");
        if l3 {
            let raw = public_bytes("Ed25519", &env.components()[1].public_key)?;
            ed25519_dalek::VerifyingKey::from_bytes(raw.try_into()?)?.verify_strict(
                &digest,
                &ed25519_dalek::Signature::from_slice(&bytes(response, "ed25519")?)?,
            )?;
            ("mldsa65", "sign-pq")
        } else {
            verify_ml(
                "ML-DSA-87",
                public_bytes("ML-DSA-87", &env.components()[1].public_key)?,
                &digest,
                &bytes(response, "mldsa65")?,
            )?;
            ("ed25519", "sign-ed")
        }
    } else {
        let recipient = cert
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .next()
            .context("Missing recipient")?;
        ensure!(
            text(request, "recipientKey")? == recipient.key().fingerprint().to_hex(),
            "Recipient key mismatch"
        );
        let existing = Zeroizing::new(bytes(
            response,
            if l3 { "x25519Secret" } else { "mlkemSecret" },
        )?);
        ensure!(
            existing.len() == 32 && existing.iter().any(|b| *b != 0),
            "Invalid hardware decapsulation component"
        );
        (
            if l3 { "mlkemSecret" } else { "x25519Secret" },
            if l3 { "kem-pq" } else { "kem-x" },
        )
    };
    ensure!(
        response
            .get(result_field)
            .is_none_or(|v| v.as_str() == Some("")),
        "Software component already supplied"
    );
    let mut secret = Zeroizing::new(bytes(response, "companionShared")?);
    let keys = open(&env, &secret)?;
    secret.zeroize();
    let seed = &keys[alias];
    let generated = Zeroizing::new(if operation == "sign" {
        let digest = bytes(request, "digest")?;
        if l3 {
            ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(seed.as_slice().try_into()?)
                .expanded_key()
                .sign_deterministic(&digest, b"")
                .map_err(|_| anyhow::anyhow!("ML-DSA signing failed"))?
                .encode()
                .to_vec()
        } else {
            cx448::SigningKey::from(cx448::SecretKey::from_slice(seed))
                .sign_raw(&digest)
                .to_bytes()
                .to_vec()
        }
    } else if l3 {
        use ml_kem::kem::Decapsulate;
        let ct = bytes(request, "mlkemCiphertext")?;
        ensure!(
            ct.len() == 1088 && bytes(request, "x25519Ephemeral")?.len() == 32,
            "Level3 ciphertext shape"
        );
        ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed.as_slice().try_into()?)
            .decapsulate(ct.as_slice().try_into()?)
            .to_vec()
    } else {
        let peer = bytes(request, "x25519Ephemeral")?;
        ensure!(
            bytes(request, "mlkemCiphertext")?.len() == 1568 && peer.len() == 56,
            "Level5 ciphertext shape"
        );
        let key = Zeroizing::new(cx448::x448::Secret::from(<[u8; 56]>::try_from(
            seed.as_slice(),
        )?));
        let peer = cx448::x448::PublicKey::from_bytes(&peer).context("Invalid X448 peer")?;
        let shared = Zeroizing::new(
            key.as_diffie_hellman(&peer)
                .context("Invalid X448 shared secret")?,
        );
        shared.as_bytes().to_vec()
    });
    let mut out = request.clone();
    for name in if operation == "sign" {
        ["ed25519", "mldsa65"]
    } else {
        ["mlkemSecret", "x25519Secret"]
    } {
        out[name] = if name == result_field {
            B64.encode(&generated).into()
        } else {
            response[name].clone()
        };
    }
    Ok(out)
}

/// The wrapper receives only public descriptors and transient native operation
/// output. Error strings never include private bytes, PINs or ciphertext dumps.
#[wasm_bindgen]
pub fn companion_complete(input: &str) -> Result<String, JsValue> {
    let run = || -> Result<String> {
        ensure!(input.len() < 400000, "Companion operation limit");
        let v: serde_json::Value = serde_json::from_str(input)?;
        Ok(complete(&v)?.to_string())
    };
    run().map_err(|e| JsValue::from_str(&format!("Companion operation rejected: {e}")))
}

#[cfg(test)]
#[path = "companion_tests.rs"]
mod tests;
