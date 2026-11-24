// SPDX-License-Identifier: LGPL-2.0-or-later
//! Public-only authentication of PQ Mail encrypted companion envelopes.
//!
//! The card's certificate, exact live public keys and signed manifest determine
//! routing. This module never decrypts the P12, prompts for a PIN, creates keys,
//! writes a card object or reconstructs a certificate. Native and WASM callers
//! share this parser so an untrusted browser descriptor cannot select a slot.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use flate2::{Decompress, FlushDecompress, Status};
use pgp::{
    cert::amalgamation::key::PrimaryKey, crypto::mpi, parse::Parse, policy::StandardPolicy,
    types::RevocationStatus, Cert,
};
use sequoia_openpgp as pgp;
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
mod ultra;
const MAX: usize = 65536;

/// Authenticated public component, including software components whose private
/// material will be unwrapped only inside the one-operation browser worker.
#[derive(Clone, Debug)]
pub struct Component {
    pub role: String,
    pub algorithm: String,
    pub storage: String,
    pub slot: String,
    pub public_key: Vec<u8>,
}
impl Component {
    fn new(role: &str, algorithm: &str, storage: &str, slot: &str, public_key: Vec<u8>) -> Self {
        Self {
            role: role.into(),
            algorithm: algorithm.into(),
            storage: storage.into(),
            slot: slot.into(),
            public_key,
        }
    }
}

/// Fully authenticated public data. Private fields prevent callers constructing
/// a forged AAD, salt or ciphertext and bypassing signature or key-map checks.
pub struct VerifiedCompanion {
    serial: u32,
    profile: &'static str,
    encoded_hash: String,
    certificate: Vec<u8>,
    components: Vec<Component>,
    ephemeral: Vec<u8>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// A bounded u32-length reader; the same exact envelope bytes become AEAD AAD.
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.0.len(), "Truncated companion");
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn number(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?) as usize)
    }
    fn field(&mut self) -> Result<&'a [u8]> {
        let n = self.number()?;
        ensure!(n <= MAX, "Companion field limit");
        self.take(n)
    }
    fn end(&self) -> Result<()> {
        ensure!(self.0.is_empty(), "Trailing companion bytes");
        Ok(())
    }
}
fn expand(stored: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !stored.is_empty() && stored.len() <= MAX,
        "Companion size limit"
    );
    if !stored.starts_with(b"PQMCZ001") {
        return Ok(stored.to_vec());
    }
    ensure!(stored.len() >= 12, "Truncated companion compression header");
    let n = u32::from_be_bytes(stored[8..12].try_into()?) as usize;
    ensure!((1..=MAX).contains(&n), "Expanded companion limit");
    // One spare byte distinguishes an overlong stream from a valid exact fit.
    let mut out = vec![0; n + 1];
    let mut d = Decompress::new(true);
    ensure!(
        d.decompress(&stored[12..], &mut out, FlushDecompress::Finish)? == Status::StreamEnd
            && d.total_out() == n as u64
            && d.total_in() == (stored.len() - 12) as u64,
        "Invalid compressed companion boundary"
    );
    out.truncate(n);
    ensure!(!out.starts_with(b"PQMCZ001"), "Nested compression rejected");
    Ok(out)
}
fn hash(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Fixed algorithm identifiers have absent parameters. Canonical byte equality
/// prevents algorithm substitution through alternate SPKI parameter encodings.
pub fn spki(algorithm: &str, raw: &[u8]) -> Result<Vec<u8>> {
    let (oid, size): (&[u8], usize) = match algorithm {
        "ML-DSA-65" => (&[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 0x12], 1952),
        "ML-DSA-87" => (&[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 0x13], 2592),
        "ML-KEM-768" => (&[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 4, 2], 1184),
        "ML-KEM-1024" => (&[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 4, 3], 1568),
        "Ed25519" => (&[0x2b, 0x65, 0x70], 32),
        "Ed448" => (&[0x2b, 0x65, 0x71], 57),
        "X25519" => (&[0x2b, 0x65, 0x6e], 32),
        "X448" => (&[0x2b, 0x65, 0x6f], 56),
        _ => bail!("Unsupported companion algorithm"),
    };
    ensure!(raw.len() == size, "Wrong component public size");
    let alg = crate::der::encode(0x30, &crate::der::encode(6, oid));
    let mut bits = vec![0];
    bits.extend(raw);
    let mut body = alg;
    body.extend(crate::der::encode(3, &bits));
    Ok(crate::der::encode(0x30, &body))
}
pub fn public_bytes<'a>(algorithm: &str, value: &'a [u8]) -> Result<&'a [u8]> {
    let size = match algorithm {
        "ML-DSA-65" => 1952,
        "ML-DSA-87" => 2592,
        "ML-KEM-768" => 1184,
        "ML-KEM-1024" => 1568,
        "Ed25519" | "X25519" => 32,
        "Ed448" => 57,
        "X448" => 56,
        _ => bail!("Unsupported component"),
    };
    ensure!(value.len() > size, "Truncated SPKI");
    let raw = &value[value.len() - size..];
    ensure!(
        spki(algorithm, raw)? == value,
        "Noncanonical component SPKI"
    );
    Ok(raw)
}
fn p384(point: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        point.len() == 97 && point[0] == 4,
        "Uncompressed P384 point required"
    );
    p384::PublicKey::from_sec1_bytes(point).context("Invalid P384 point")?;
    let alg = crate::der::encode(
        0x30,
        &[
            crate::der::encode(6, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1]),
            crate::der::encode(6, &[0x2b, 0x81, 4, 0, 0x22]),
        ]
        .concat(),
    );
    Ok(crate::der::encode(
        0x30,
        &[alg, crate::der::encode(3, &[&[0][..], point].concat())].concat(),
    ))
}
/// Pure FIPS 204 (empty context), used for the outer storage signature and
/// RFC9980 ML-DSA components. No prehashed/external-mu interpretation is guessed.
pub fn verify_ml(algorithm: &str, public: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    macro_rules! verify {
        ($p:ty,$pk:expr,$sig:expr) => {{
            let pk: &[u8; $pk] = public.try_into()?;
            let sig: &[u8; $sig] = signature.try_into()?;
            let key = ml_dsa::VerifyingKey::<$p>::decode(pk.into());
            let signature = ml_dsa::Signature::<$p>::decode(sig.into())
                .context("Malformed ML-DSA signature")?;
            ensure!(
                key.verify_with_context(message, b"", &signature),
                "ML-DSA signature rejected"
            );
        }};
    }
    match algorithm {
        "ML-DSA-65" => verify!(ml_dsa::MlDsa65, 1952, 3309),
        "ML-DSA-87" => verify!(ml_dsa::MlDsa87, 2592, 4627),
        _ => bail!("Wrong signature algorithm"),
    };
    Ok(())
}
pub(super) fn verify_ed448(public: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let key = cx448::VerifyingKey::from_bytes(public.try_into()?).context("Invalid Ed448 key")?;
    let sig = cx448::Signature::from_bytes(signature.try_into()?)
        .map_err(|_| anyhow::anyhow!("Invalid Ed448 signature"))?;
    key.verify_raw(&sig, message)
        .context("Ed448 signature rejected")
}
impl VerifiedCompanion {
    /// An ultra template is not usable without its exact verified public cache.
    /// This read-only API never makes new self-signatures or changes fingerprints.
    pub fn parse(
        encoded: &[u8],
        serial: u32,
        expected: &BTreeMap<String, Vec<u8>>,
        cached: Option<&[u8]>,
    ) -> Result<Self> {
        ensure!(
            (1..=i32::MAX as u32).contains(&serial) && expected.len() == 4,
            "Invalid companion serial/mapping"
        );
        let expanded = expand(encoded)?;
        let mut outer = Reader(&expanded);
        let body = outer.field()?;
        let signature = outer.field()?;
        outer.end()?;
        let mut r = Reader(body);
        let magic = r.take(8)?;
        let l3 = magic == b"PQMCP003";
        ensure!(
            l3 || magic == b"PQMCP001" || magic == b"PQMCP002",
            "Unsupported companion format"
        );
        ensure!(r.number()? == serial as usize, "Companion serial mismatch");
        let slots = if l3 {
            ["82", "9c", "9d", "83"]
        } else {
            ["86", "9c", "9d", "82"]
        };
        let algs = if l3 {
            ["Ed25519", "Ed25519", "X25519", "P-384"]
        } else {
            ["ML-DSA-87", "ML-DSA-87", "ML-KEM-1024", "P-384"]
        };
        let roles = if l3 {
            [
                "certification-classical",
                "signing-classical",
                "decryption-classical",
                "companion-wrap",
            ]
        } else {
            [
                "certification-pq",
                "signing-pq",
                "decryption-pq",
                "companion-wrap",
            ]
        };
        let mut components = Vec::new();
        for i in 0..4 {
            let key = r.field()?;
            ensure!(
                expected.get(slots[i]).map(Vec::as_slice) == Some(key),
                "Live companion key mismatch in {}",
                slots[i]
            );
            if i == 3 {
                ensure!(
                    key.len() > 97 && p384(&key[key.len() - 97..])? == key,
                    "Invalid wrapping key"
                );
            } else {
                public_bytes(algs[i], key)?;
            }
            components.push(Component::new(
                roles[i],
                algs[i],
                "piv",
                slots[i],
                key.to_vec(),
            ));
        }
        ensure!(
            components[0].public_key != components[1].public_key,
            "Certification/signing keys must differ"
        );
        let stored_cert = r.field()?;
        // The Level3 S/MIME catalog anchors are authenticated opaque baggage.
        // They are neither returned nor granted any trust by this OpenPGP API.
        if l3 {
            r.field()?;
            r.field()?;
        }
        let manifest = r.field()?;
        let ephemeral = p384(r.take(97)?)?;
        let salt = r.take(32)?.to_vec();
        let nonce = r.take(12)?.to_vec();
        let aad = body[..body.len() - r.0.len()].to_vec();
        let ciphertext = r.field()?.to_vec();
        r.end()?;
        ensure!(ciphertext.len() >= 16, "Truncated AES-GCM payload");
        let full = if magic == b"PQMCP002" {
            let full =
                cached.context("Ultra companion needs its verified public certificate cache")?;
            ultra::Template::parse(stored_cert)?.verify_cache(full)?;
            full
        } else {
            stored_cert
        };
        ensure!(full.len() <= MAX, "Companion certificate limit");
        let cert = Cert::from_bytes(full)?;
        ensure!(!cert.is_tsk(), "Public certificate required");
        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, None)?;
        valid.alive()?;
        ensure!(
            matches!(
                valid.revocation_status(),
                RevocationStatus::NotAsFarAsWeKnow
            ),
            "Revoked companion certificate"
        );
        ensure!(
            cert.keys().count() == 3 && cert.keys().all(|k| k.key().version() == 6),
            "Separated v6 companion profile required"
        );
        let signers: Vec<_> = valid.keys().alive().revoked(false).for_signing().collect();
        let recipients: Vec<_> = valid
            .keys()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .collect();
        ensure!(
            signers.len() == 1
                && !signers[0].primary()
                && recipients.len() == 1
                && !recipients[0].primary(),
            "Unique separate message subkeys required"
        );
        let primary = cert.primary_key();
        let mpis = [
            primary.key().mpis(),
            signers[0].key().mpis(),
            recipients[0].key().mpis(),
        ];
        let softroles = if l3 {
            ["certification-pq", "signing-pq", "decryption-pq"]
        } else {
            [
                "certification-classical",
                "signing-classical",
                "decryption-classical",
            ]
        };
        for (i, mpis) in mpis.iter().enumerate() {
            let (hardware, software) = match (l3, i, mpis) {
                (true, 0 | 1, mpi::PublicKey::MLDSA65_Ed25519 { mldsa, eddsa }) => (
                    spki("Ed25519", eddsa.as_ref())?,
                    ("ML-DSA-65", spki("ML-DSA-65", mldsa.as_ref())?),
                ),
                (true, 2, mpi::PublicKey::MLKEM768_X25519 { mlkem, ecdh }) => (
                    spki("X25519", ecdh.as_ref())?,
                    ("ML-KEM-768", spki("ML-KEM-768", mlkem.as_ref())?),
                ),
                (false, 0 | 1, mpi::PublicKey::MLDSA87_Ed448 { mldsa, eddsa }) => (
                    spki("ML-DSA-87", mldsa.as_ref())?,
                    ("Ed448", spki("Ed448", eddsa.as_ref())?),
                ),
                (false, 2, mpi::PublicKey::MLKEM1024_X448 { mlkem, ecdh }) => (
                    spki("ML-KEM-1024", mlkem.as_ref())?,
                    ("X448", spki("X448", ecdh.as_ref())?),
                ),
                _ => bail!("Unexpected companion certificate component"),
            };
            ensure!(
                hardware == components[i].public_key,
                "Companion certificate/live binding mismatch"
            );
            components.push(Component::new(
                softroles[i],
                software.0,
                "companion",
                "",
                software.1,
            ));
        }
        ensure!(
            components[4].public_key != components[5].public_key,
            "Software certification/signing keys must differ"
        );
        let profile = if l3 {
            "LEVEL3_POLYFILL"
        } else {
            "LEVEL5_COMPANION"
        };
        let entries=components.iter().map(|c|format!("{{\"role\":\"{}\",\"algorithm\":\"{}\",\"storage\":\"{}\",\"slot\":\"{}\",\"sha256\":\"{}\"}}",c.role,c.algorithm,c.storage,c.slot,hash(&c.public_key))).collect::<Vec<_>>().join(",");
        ensure!(manifest==format!("{{\"version\":1,\"serial\":{serial},\"profile\":\"{profile}\",\"components\":[{entries}]}}").as_bytes(),"Noncanonical companion manifest");
        if l3 {
            ensure!(
                signature.len() == 3373,
                "Wrong Level3 envelope signature size"
            );
            let digest =
                Sha512::digest([b"PQMail Level3 companion signature v1".as_slice(), body].concat());
            let key = ed25519_dalek::VerifyingKey::from_bytes(
                public_bytes("Ed25519", &components[0].public_key)?.try_into()?,
            )?;
            key.verify_strict(
                &digest,
                &ed25519_dalek::Signature::from_slice(&signature[..64])?,
            )?;
            verify_ml(
                "ML-DSA-65",
                public_bytes("ML-DSA-65", &components[4].public_key)?,
                &digest,
                &signature[64..],
            )?;
        } else {
            verify_ml(
                "ML-DSA-87",
                public_bytes("ML-DSA-87", &components[0].public_key)?,
                body,
                signature,
            )?;
        }
        Ok(Self {
            serial,
            profile,
            encoded_hash: hash(encoded),
            certificate: full.to_vec(),
            components,
            ephemeral,
            salt,
            nonce,
            aad,
            ciphertext,
        })
    }
    pub fn profile(&self) -> &str {
        self.profile
    }
    pub fn certificate_bytes(&self) -> &[u8] {
        &self.certificate
    }
    pub fn components(&self) -> &[Component] {
        &self.components
    }
    pub fn wrapping_peer(&self) -> &[u8] {
        &self.ephemeral
    }
    pub fn wrapping_slot(&self) -> &str {
        &self.components[3].slot
    }
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn preview(&self) -> serde_json::Value {
        serde_json::json!({"format":"sequoia-iwa-companion","version":1,"serial":self.serial.to_string(),"profile":self.profile,"companionHash":self.encoded_hash,"certificate":B64.encode(&self.certificate),"components":self.components.iter().map(|c|serde_json::json!({"role":c.role,"algorithm":c.algorithm,"storage":c.storage,"slot":c.slot,"publicKey":B64.encode(&c.public_key)})).collect::<Vec<_>>(),"wrapping":{"slot":self.wrapping_slot(),"publicKey":B64.encode(&self.components[3].public_key),"peer":B64.encode(&self.ephemeral)}})
    }
}
