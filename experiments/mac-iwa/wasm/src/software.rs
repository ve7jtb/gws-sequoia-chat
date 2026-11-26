//! Experimental, one-operation software custody for encrypted OpenPGP identities.
//!
//! The caller must use a fresh dedicated worker and destroy it on completion,
//! cancellation and vault lock. No unlocked key, password, static handle, PIN,
//! native bridge or persistence API is retained here. Strings created by JSON,
//! wasm-bindgen and JavaScript cannot promise complete erasure; the worker
//! lifetime is part of the boundary, not a substitute for a constant-time audit.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pgp::{
    cert::CertParser,
    crypto::{mpi, Password, Signer, S2K},
    packet::key,
    parse::Parse,
    policy::StandardPolicy,
    serialize::SerializeInto,
    types::{HashAlgorithm as H, PublicKeyAlgorithm as A, SymmetricAlgorithm as S},
};
use sequoia_openpgp as pgp;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

#[path = "software_envelope.rs"]
mod envelope;
#[path = "software_p12.rs"]
mod p12;

const SECRET_LIMIT: usize = 262144;
const SIGN_FIELDS: [&str; 4] = ["requestId", "signingFingerprint", "hashAlgorithm", "digest"];
const DECAP_FIELDS: [&str; 5] = [
    "requestId",
    "cipherHash",
    "recipientKey",
    "mlkemCiphertext",
    "x25519Ephemeral",
];

fn fields(v: &serde_json::Value, expected: &[&str]) -> Result<()> {
    let object = v.as_object().context("Object required")?;
    ensure!(
        object.len() == expected.len() && expected.iter().all(|k| object.contains_key(*k)),
        "Unexpected fields"
    );
    Ok(())
}
fn text<'a>(v: &'a serde_json::Value, name: &str) -> Result<&'a str> {
    v[name].as_str().context("Text required")
}
fn hex(v: &str, upper: bool) -> bool {
    (v.len() == 64 || (upper && v.len() == 40))
        && v.bytes().all(|b| {
            b.is_ascii_digit()
                || if upper {
                    (b'A'..=b'F').contains(&b)
                } else {
                    (b'a'..=b'f').contains(&b)
                }
        })
}
fn octets(v: &serde_json::Value, name: &str, size: usize) -> Result<Vec<u8>> {
    let encoded = text(v, name)?;
    ensure!(
        encoded.len() == 4 * ((size + 2) / 3),
        "Component encoding limit"
    );
    let bytes = B64.decode(encoded)?;
    ensure!(
        bytes.len() == size && B64.encode(&bytes) == encoded,
        "Canonical component required"
    );
    Ok(bytes)
}

/// Reject excessive KDF work before invoking any password derivation. AES and
/// bounded modern iterated/Argon2 protection cover the standalone Sequoia
/// identity files; unsupported protection is rejected, never silently weakened.
fn protection(value: &key::SecretKeyMaterial) -> Result<()> {
    let key::SecretKeyMaterial::Encrypted(encrypted) = value else {
        bail!("Every secret packet must be encrypted")
    };
    ensure!(
        matches!(encrypted.algo(), S::AES128 | S::AES192 | S::AES256),
        "AES secret protection required"
    );
    match encrypted.s2k() {
        S2K::Iterated {
            hash, hash_bytes, ..
        } => ensure!(
            matches!(hash, H::SHA256 | H::SHA384 | H::SHA512)
                && (1024..=0x3e00000).contains(hash_bytes),
            "Bounded modern iterated S2K required"
        ),
        S2K::Argon2 { t, p, m, .. } => ensure!(
            (1..=4).contains(t) && (1..=4).contains(p) && (10..=16).contains(m),
            "Argon2 work limit"
        ),
        _ => bail!("Unsupported secret protection"),
    }
    Ok(())
}

/// Do not accept a valid public certificate carrying unrelated encrypted secret
/// bytes. Derive each public component from its decrypted seed and compare all
/// public bytes before permitting a signing or decapsulation operation.
fn check_components(pair: &pgp::crypto::KeyPair) -> Result<()> {
    use ml_dsa::Keypair;
    use ml_kem::kem::KeyExport;
    pair.secret().map(|secret| -> Result<()> {
        match (pair.public().mpis(), secret) {
            (
                mpi::PublicKey::MLDSA65_Ed25519 {
                    eddsa: ep,
                    mldsa: mp,
                },
                mpi::SecretKeyMaterial::MLDSA65_Ed25519 { eddsa, mldsa },
            ) => {
                let ed = ed25519_dalek::SigningKey::from_bytes(eddsa.as_ref().try_into()?);
                let ml = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed((&mldsa[..]).try_into()?);
                ensure!(
                    ed.verifying_key().as_bytes().as_slice() == ep.as_ref()
                        && ml.verifying_key().encode().as_slice() == mp.as_ref(),
                    "Private/public signing mismatch"
                );
            }
            (
                mpi::PublicKey::MLKEM768_X25519 {
                    ecdh: ep,
                    mlkem: mp,
                },
                mpi::SecretKeyMaterial::MLKEM768_X25519 { ecdh, mlkem },
            ) => {
                let ec = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(ecdh.as_ref())?);
                let ml = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(
                    (&mlkem[..]).try_into()?,
                );
                ensure!(
                    x25519_dalek::PublicKey::from(&ec).as_bytes().as_slice() == ep.as_ref()
                        && ml.encapsulation_key().to_bytes().as_slice() == mp.as_ref(),
                    "Private/public encryption mismatch"
                );
            }
            (
                mpi::PublicKey::MLDSA87_Ed448 {
                    eddsa: ep,
                    mldsa: mp,
                },
                mpi::SecretKeyMaterial::MLDSA87_Ed448 { eddsa, mldsa },
            ) => {
                let ed = cx448::SigningKey::from(cx448::SecretKey::from_slice(eddsa));
                let ml = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed((&mldsa[..]).try_into()?);
                ensure!(
                    ed.verifying_key().to_bytes().as_slice() == ep.as_ref()
                        && ml.verifying_key().encode().as_slice() == mp.as_ref(),
                    "Private/public Level 5 signing mismatch"
                );
            }
            (
                mpi::PublicKey::MLKEM1024_X448 {
                    ecdh: ep,
                    mlkem: mp,
                },
                mpi::SecretKeyMaterial::MLKEM1024_X448 { ecdh, mlkem },
            ) => {
                // X448 implements Zeroize but not Drop; own it explicitly so
                // success and error exits clear the transient scalar copy.
                let ec = Zeroizing::new(cx448::x448::Secret::from(<[u8; 56]>::try_from(
                    ecdh.as_ref(),
                )?));
                let ml = ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::from_seed(
                    (&mlkem[..]).try_into()?,
                );
                ensure!(
                    cx448::x448::PublicKey::from(&*ec).as_bytes().as_slice() == ep.as_ref()
                        && ml.encapsulation_key().to_bytes().as_slice() == mp.as_ref(),
                    "Private/public Level 5 encryption mismatch"
                );
            }
            // Legacy Ed25519 and P-521 signing use MPI encodings. A fresh
            // signature proof verifies the seed/scalar against the full public
            // point without making assumptions about MPI leading zeroes.
            (
                mpi::PublicKey::EdDSA {
                    curve: pgp::types::Curve::Ed25519,
                    ..
                },
                mpi::SecretKeyMaterial::EdDSA { .. },
            )
            | (mpi::PublicKey::Ed25519 { .. }, mpi::SecretKeyMaterial::Ed25519 { .. })
            | (
                mpi::PublicKey::ECDSA {
                    curve: pgp::types::Curve::NistP521,
                    ..
                },
                mpi::SecretKeyMaterial::ECDSA { .. },
            ) => {
                let mut proof = pair.clone();
                let signature = proof.sign(H::SHA512, &[0x73; 64])?;
                pair.public().verify(&signature, H::SHA512, &[0x73; 64])?;
            }
            (
                mpi::PublicKey::ECDH {
                    curve: pgp::types::Curve::Cv25519,
                    q,
                    ..
                },
                mpi::SecretKeyMaterial::ECDH { scalar },
            ) => {
                let mut raw = [0u8; 32];
                ensure!(scalar.value().len() <= raw.len(), "X25519 scalar length");
                raw[32 - scalar.value().len()..].copy_from_slice(scalar.value());
                raw.reverse();
                let private = x25519_dalek::StaticSecret::from(raw);
                raw.zeroize();
                ensure!(
                    q.value().first() == Some(&0x40)
                        && q.value().get(1..)
                            == Some(
                                x25519_dalek::PublicKey::from(&private)
                                    .as_bytes()
                                    .as_slice()
                            ),
                    "Private/public X25519 mismatch"
                );
            }
            (
                mpi::PublicKey::ECDH {
                    curve: pgp::types::Curve::NistP521,
                    q,
                    ..
                },
                mpi::SecretKeyMaterial::ECDH { scalar },
            ) => {
                use p521::elliptic_curve::sec1::ToEncodedPoint;
                let private = p521::SecretKey::from_slice(scalar.value())?;
                ensure!(
                    private.public_key().to_encoded_point(false).as_bytes() == q.value(),
                    "Private/public P521 mismatch"
                );
            }
            _ => bail!("Unsupported software private algorithm"),
        }
        Ok(())
    })
}

struct Loaded {
    cert: pgp::Cert,
    info: serde_json::Value,
    pairs: Vec<pgp::crypto::KeyPair>,
}
impl Loaded {
    fn pair(&mut self, fingerprint: &str) -> Result<pgp::crypto::KeyPair> {
        let index = self
            .pairs
            .iter()
            .position(|p| p.public().fingerprint().to_hex() == fingerprint)
            .context("Selected private key missing")?;
        Ok(self.pairs.remove(index))
    }
}

/// Validate the entire encrypted identity on each call. The public certificate
/// must contain exactly certification/signing/encryption keys with current
/// self-certified mailboxes and valid bindings. Missing, expired, revoked,
/// ambiguous, classical and partially encrypted identities fail closed.
fn load(v: &mut serde_json::Value) -> Result<Loaded> {
    let encoded = text(v, "encryptedSecret")?;
    ensure!(encoded.len() <= 349528, "Encrypted identity limit");
    let raw = Zeroizing::new(B64.decode(encoded)?);
    ensure!(
        !raw.is_empty() && raw.len() <= SECRET_LIMIT && B64.encode(&*raw) == encoded,
        "Canonical encrypted identity required"
    );
    let armor = String::from_utf8_lossy(&raw);
    ensure!(
        armor.matches("-----BEGIN PGP").count() <= 1,
        "One identity required"
    );
    let mut parser = CertParser::from_bytes(&raw)?;
    let cert = parser.next().context("One identity required")??;
    ensure!(parser.next().is_none(), "One identity required");
    ensure!(
        cert.is_tsk()
            && matches!(cert.keys().count(), 2 | 3)
            && cert.keys().secret().count() == cert.keys().count(),
        "Complete supported secret identity required"
    );
    let p = StandardPolicy::new();
    let valid = cert.with_policy(&p, None)?;
    valid.alive()?;
    ensure!(
        !matches!(
            valid.revocation_status(),
            pgp::types::RevocationStatus::Revoked(_)
        ),
        "Revoked identity"
    );
    let primary = valid.primary_key();
    let flags = primary.key_flags().context("Primary key flags required")?;
    let modern = primary.key().version() == 6;
    ensure!(
        flags.for_certification()
            && !flags.for_transport_encryption()
            && !flags.for_storage_encryption()
            && if modern {
                !flags.for_signing()
                    && matches!(
                        primary.key().pk_algo(),
                        A::MLDSA65_Ed25519 | A::MLDSA87_Ed448
                    )
            } else {
                primary.key().version() == 4
                    && flags.for_signing()
                    && matches!(primary.key().pk_algo(), A::EdDSA | A::Ed25519 | A::ECDSA)
            },
        "Separate modern certification or explicit classical compatibility primary required"
    );
    ensure!(
        cert.keys().count() == if modern { 3 } else { 2 },
        "Profile key count"
    );
    for ka in cert.keys() {
        ensure!(
            ka.key().version() == primary.key().version()
                && matches!(
                    ka.key().pk_algo(),
                    A::MLDSA65_Ed25519
                        | A::MLDSA87_Ed448
                        | A::MLKEM768_X25519
                        | A::MLKEM1024_X448
                        | A::EdDSA
                        | A::Ed25519
                        | A::ECDSA
                        | A::ECDH
                ),
            "Unsupported private algorithm/version"
        );
    }
    let public = cert.clone().strip_secret_key_material().to_vec()?;
    let info = super::certificates::inspect_identity_value(&B64.encode(public))?;
    ensure!(
        info["supported"] == true && (!modern || info["signingFingerprint"] != info["fingerprint"]),
        "Current unambiguous message keys required"
    );
    // Validate every encrypted KDF before deriving even the first one. A file
    // cannot hide excessive work or a plaintext packet behind a valid first key.
    for ka in cert.keys().secret() {
        protection(ka.key().secret())?;
    }
    let mut password = v["password"].take();
    let value = password.as_str().context("Password required")?;
    ensure!(!value.is_empty() && value.len() <= 1024, "Password limit");
    let password_protected = Password::from(value.as_bytes());
    if let serde_json::Value::String(value) = &mut password {
        value.zeroize();
    }
    let mut pairs = Vec::new();
    for ka in cert.keys().secret() {
        // AEAD secret-key protection binds the packet tag (primary/subkey).
        // Preserve that role through decryption; erasing it before the KDF/AEAD
        // check would reject valid Sequoia-generated v6 secret certificates.
        let pair = if ka.key().fingerprint() == cert.fingerprint() {
            ka.key()
                .clone()
                .role_into_primary()
                .decrypt_secret(&password_protected)?
                .into_keypair()?
        } else {
            ka.key()
                .clone()
                .role_into_subordinate()
                .decrypt_secret(&password_protected)?
                .into_keypair()?
        };
        check_components(&pair)?;
        pairs.push(pair);
    }
    Ok(Loaded { cert, info, pairs })
}

fn inspect(mut v: serde_json::Value) -> Result<serde_json::Value> {
    fields(&v, &["encryptedSecret", "password"])?;
    if envelope::is_envelope(&v) {
        return Ok(envelope::open(&mut v)?.2);
    }
    Ok(load(&mut v)?.info)
}
pub(super) fn sign(mut v: serde_json::Value) -> Result<serde_json::Value> {
    fields(&v, &["encryptedSecret", "password", "request"])?;
    if envelope::is_envelope(&v) {
        let (cert, secret, _) = envelope::open(&mut v)?;
        return super::libre::sign(&cert, &secret, &v["request"]);
    }
    fields(&v["request"], &SIGN_FIELDS)?;
    // Reject malformed requests before password/KDF work. Identity fingerprints
    // are checked again against the decrypted, publicly bound message subkey.
    let request = &v["request"];
    ensure!(
        text(request, "requestId")?.len() == 64
            && hex(text(request, "requestId")?, true)
            && hex(text(request, "signingFingerprint")?, true),
        "Signing identifiers"
    );
    ensure!(
        request["hashAlgorithm"].as_u64() == Some(10),
        "SHA-512 required"
    );
    let digest = octets(request, "digest", 64)?;
    let mut loaded = load(&mut v)?;
    let request = &v["request"];
    ensure!(
        request["signingFingerprint"] == loaded.info["signingFingerprint"],
        "Wrong signing key"
    );
    let mut pair = loaded.pair(text(request, "signingFingerprint")?)?;
    let signature = pair.sign(H::SHA512, &digest)?;
    pair.public().verify(&signature, H::SHA512, &digest)?;
    let (ed, ml) = match signature {
        mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa } => {
            (eddsa.as_ref().to_vec(), mldsa.as_ref().to_vec())
        }
        mpi::Signature::MLDSA87_Ed448 { eddsa, mldsa } => {
            (eddsa.as_ref().to_vec(), mldsa.as_ref().to_vec())
        }
        mpi::Signature::Ed25519 { s } => (s.to_vec(), Vec::new()),
        mpi::Signature::EdDSA { r, s } => {
            let mut bytes = Vec::new();
            for mpi in [r, s] {
                ensure!(mpi.value().len() <= 32, "Ed25519 MPI");
                bytes.extend(vec![0; 32 - mpi.value().len()]);
                bytes.extend(mpi.value());
            }
            (bytes, Vec::new())
        }
        mpi::Signature::ECDSA { r, s } => {
            let mut bytes = Vec::new();
            for mpi in [r, s] {
                ensure!(mpi.value().len() <= 66, "P521 MPI");
                bytes.extend(vec![0; 66 - mpi.value().len()]);
                bytes.extend(mpi.value());
            }
            (bytes, Vec::new())
        }
        _ => bail!("Wrong signature algorithm"),
    };
    // These historical field names are the fixed split-signing protocol. The
    // recipient's authenticated algorithm determines component sizes; an empty
    // PQ component is permitted only for explicit v4 classical signing.
    Ok(
        serde_json::json!({"requestId":request["requestId"],"hashAlgorithm":10,"signingFingerprint":request["signingFingerprint"],"digest":request["digest"],"ed25519":B64.encode(ed),"mldsa65":B64.encode(ml)}),
    )
}

pub(super) fn decapsulate(mut v: serde_json::Value) -> Result<serde_json::Value> {
    use ml_kem::{kem::Decapsulate, DecapsulationKey, MlKem1024, MlKem768};
    fields(&v, &["encryptedSecret", "password", "request"])?;
    if envelope::is_envelope(&v) {
        let (cert, secret, _) = envelope::open(&mut v)?;
        return super::libre::decapsulate(&cert, &secret, &v["request"]);
    }
    fields(&v["request"], &DECAP_FIELDS)?;
    let request = &v["request"];
    ensure!(
        text(request, "requestId")?.len() == 64
            && hex(text(request, "requestId")?, true)
            && hex(text(request, "cipherHash")?, false)
            && hex(text(request, "recipientKey")?, true),
        "Decryption identifiers"
    );
    // Parse only the finite component sizes used by the supported profiles.
    // The actual profile is authenticated from the decrypted certificate below.
    let ciphertext = B64.decode(text(request, "mlkemCiphertext")?)?;
    let ephemeral = B64.decode(text(request, "x25519Ephemeral")?)?;
    ensure!(
        matches!(
            (ciphertext.len(), ephemeral.len()),
            (1088, 32) | (1568, 56) | (0, 33) | (0, 133)
        ) && B64.encode(&ciphertext) == text(request, "mlkemCiphertext")?
            && B64.encode(&ephemeral) == text(request, "x25519Ephemeral")?,
        "Canonical component input"
    );
    let mut loaded = load(&mut v)?;
    let request = &v["request"];
    ensure!(
        request["recipientKey"] == loaded.info["recipientKey"],
        "Wrong encryption key"
    );
    let pair = loaded.pair(text(request, "recipientKey")?)?;
    let mut result = request.clone();
    pair.secret().map(|secret| -> Result<()> {
        let (ml_shared, ec_shared): (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) = match secret {
            mpi::SecretKeyMaterial::MLKEM768_X25519 { ecdh, mlkem } => {
                let ct: &[u8; 1088] = ciphertext.as_slice().try_into()?;
                let ep: [u8; 32] = ephemeral.as_slice().try_into()?;
                let ec = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(ecdh.as_ref())?);
                let shared = ec.diffie_hellman(&x25519_dalek::PublicKey::from(ep));
                ensure!(shared.was_contributory(), "Noncontributory X25519");
                let ml = DecapsulationKey::<MlKem768>::from_seed((&mlkem[..]).try_into()?);
                (
                    Zeroizing::new(ml.decapsulate(ct.into()).to_vec()),
                    Zeroizing::new(shared.as_bytes().to_vec()),
                )
            }
            mpi::SecretKeyMaterial::MLKEM1024_X448 { ecdh, mlkem } => {
                let ct: &[u8; 1568] = ciphertext.as_slice().try_into()?;
                let ep: &[u8; 56] = ephemeral.as_slice().try_into()?;
                // X448 implements Zeroize but not Drop; own it explicitly so
                // success and error exits clear the transient scalar copy.
                let ec = Zeroizing::new(cx448::x448::Secret::from(<[u8; 56]>::try_from(
                    ecdh.as_ref(),
                )?));
                let public = cx448::x448::PublicKey::from_bytes(ep).context("X448 point")?;
                let shared = Zeroizing::new(
                    ec.as_diffie_hellman(&public)
                        .context("Noncontributory X448")?,
                );
                let ml = DecapsulationKey::<MlKem1024>::from_seed((&mlkem[..]).try_into()?);
                (
                    Zeroizing::new(ml.decapsulate(ct.into()).to_vec()),
                    Zeroizing::new(shared.as_bytes().to_vec()),
                )
            }
            mpi::SecretKeyMaterial::ECDH { scalar } => {
                ensure!(ciphertext.is_empty(), "Classical component binding");
                match pair.public().mpis() {
                    mpi::PublicKey::ECDH {
                        curve: pgp::types::Curve::Cv25519,
                        ..
                    } => {
                        ensure!(
                            ephemeral.len() == 33 && ephemeral[0] == 0x40,
                            "Legacy X25519 point"
                        );
                        let mut raw = [0u8; 32];
                        ensure!(scalar.value().len() <= 32, "Scalar limit");
                        raw[32 - scalar.value().len()..].copy_from_slice(scalar.value());
                        raw.reverse();
                        let ec = x25519_dalek::StaticSecret::from(raw);
                        raw.zeroize();
                        let shared = ec.diffie_hellman(&x25519_dalek::PublicKey::from(
                            <[u8; 32]>::try_from(&ephemeral[1..])?,
                        ));
                        ensure!(shared.was_contributory(), "Noncontributory X25519");
                        (
                            Zeroizing::new(Vec::new()),
                            Zeroizing::new(shared.as_bytes().to_vec()),
                        )
                    }
                    mpi::PublicKey::ECDH {
                        curve: pgp::types::Curve::NistP521,
                        ..
                    } => {
                        let ec = p521::SecretKey::from_slice(scalar.value())?;
                        let public = p521::PublicKey::from_sec1_bytes(&ephemeral)?;
                        let shared =
                            p521::ecdh::diffie_hellman(ec.to_nonzero_scalar(), public.as_affine());
                        (
                            Zeroizing::new(Vec::new()),
                            Zeroizing::new(shared.raw_secret_bytes().to_vec()),
                        )
                    }
                    _ => bail!("Unsupported classical recipient"),
                }
            }
            _ => bail!("Unsupported decryption key"),
        };
        // Component shares are released together, only to the matching live
        // worker operation. The message worker owns combiner/session-key/AEAD
        // checks; ML-KEM implicit rejection is never converted into an oracle.
        result["mlkemSecret"] = serde_json::json!(B64.encode(&*ml_shared));
        result["x25519Secret"] = serde_json::json!(B64.encode(&*ec_shared));
        Ok(())
    })?;
    Ok(result)
}

/// Encrypt every private packet while preserving packet roles and all public
/// bytes/self-signatures. Exporting with a new password never changes a public
/// fingerprint or silently substitutes freshly generated keys.
fn protect(cert: &pgp::Cert, password: &str) -> Result<pgp::Cert> {
    ensure!(
        (12..=1024).contains(&password.len()),
        "Use at least 12 password bytes"
    );
    let pw = Password::from(password);
    let pile = pgp::PacketPile::from_bytes(&cert.as_tsk().to_vec()?)?;
    let mut packets = Vec::new();
    for packet in pile.children().cloned() {
        packets.push(match packet {
            pgp::Packet::SecretKey(key) => pgp::Packet::SecretKey(key.encrypt_secret(&pw)?),
            pgp::Packet::SecretSubkey(key) => pgp::Packet::SecretSubkey(key.encrypt_secret(&pw)?),
            other => other,
        });
    }
    pgp::Cert::from_packets(packets.into_iter())
}
fn encrypted_result(cert: &pgp::Cert, password: &str) -> Result<serde_json::Value> {
    let encrypted = protect(cert, password)?;
    let encoded = B64.encode(encrypted.as_tsk().to_vec()?);
    let mut check = serde_json::json!({"encryptedSecret":encoded,"password":password});
    let public = load(&mut check)?.info;
    Ok(serde_json::json!({"encryptedSecret":encoded,"public":public}))
}
pub(super) fn generate(mut v: serde_json::Value) -> Result<serde_json::Value> {
    // Take the optional single-credential contribution before strict field
    // validation. The RAII scope wipes DRBG state even on generation errors.
    let mut contribution = zeroize::Zeroizing::new(Vec::new());
    if let Some(value) = v.as_object_mut().and_then(|m|m.remove("hardwareEntropy")) {
        contribution.extend_from_slice(&B64.decode(value.as_str().context("Entropy encoding")?)?);
        ensure!(contribution.len()==32,"One 32-byte entropy output required");
    }
    #[cfg(target_arch="wasm32")]
    let _entropy_scope = if contribution.is_empty(){None}else{Some(super::entropy::start(&contribution)?)};
    #[cfg(not(target_arch="wasm32"))]
    ensure!(contribution.is_empty(),"Hardware entropy generation is browser-only");
    let result=generate_inner(v);
    #[cfg(target_arch="wasm32")]
    if result.is_ok(){if let Some(scope)=&_entropy_scope{scope.assert_used()?;}}
    result
}
fn generate_inner(mut v:serde_json::Value)->Result<serde_json::Value>{
    use pgp::cert::{CertBuilder, CipherSuite};
    use pgp::types::{KeyFlags, PublicKeyAlgorithmSpecification as Spec};
    fields(&v, &["profile", "email", "name", "password"])?;
    let profile = text(&v, "profile")?.to_string();
    let email = text(&v, "email")?;
    ensure!(
        email.is_ascii()
            && email.len() <= 254
            && !email
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || "<>".contains(c))
            && email.matches('@').count() == 1
            && !email.starts_with('@')
            && !email.ends_with('@'),
        "Mailbox required"
    );
    let name = text(&v, "name")?;
    ensure!(
        name.len() <= 100 && !name.chars().any(|c| c.is_control() || "<>".contains(c)),
        "Display name limit"
    );
    let uid = if name.is_empty() {
        email.to_owned()
    } else {
        format!("{name} <{email}>")
    };
    if profile == "level3-v5-hybrid" {
        let (certificate, secret) = super::libre::generate(email)?;
        return envelope::seal(&certificate, &secret, text(&v, "password")?);
    }
    let modern = matches!(profile.as_str(), "level3" | "level5");
    ensure!(
        modern
            || matches!(
                profile.as_str(),
                "level3-v4-hybrid"
                    | "level3-v4-classical"
                    | "level5-v4-hybrid"
                    | "level5-v4-classical"
            ),
        "Unsupported profile"
    );
    let mut builder = CertBuilder::new().add_userid(uid);
    builder = if modern {
        builder
            .set_profile(pgp::Profile::RFC9580)?
            .set_cipher_suite(if profile == "level5" {
                CipherSuite::MLDSA87_Ed448
            } else {
                CipherSuite::MLDSA65_Ed25519
            })
            .set_primary_key_flags(KeyFlags::empty().set_certification())
            .add_signing_subkey()
    } else {
        // Compatibility identities intentionally use dedicated classical
        // certification/signing keys; they never reuse a composite component.
        builder
            .set_profile(pgp::Profile::RFC4880)?
            .set_cipher_suite(if profile.starts_with("level5") {
                CipherSuite::P521
            } else {
                CipherSuite::Cv25519
            })
            .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
    };
    if profile.ends_with("-hybrid") {
        builder = builder.set_encryption_algorithm(Spec::mlkem768_x25519());
    }
    let (cert, _revocation) = builder.add_transport_encryption_subkey().generate()?;
    let mut password = v["password"].take();
    let value = password.as_str().context("Password required")?;
    let result = encrypted_result(&cert, value);
    if let serde_json::Value::String(value) = &mut password {
        value.zeroize();
    }
    result
}
fn export(mut v: serde_json::Value) -> Result<serde_json::Value> {
    fields(&v, &["encryptedSecret", "password", "newPassword"])?;
    if envelope::is_envelope(&v) {
        let (cert, secret, _) = envelope::open(&mut v)?;
        return envelope::seal(&cert, &secret, text(&v, "newPassword")?);
    }
    let mut loaded = load(&mut v)?;
    let pile = pgp::PacketPile::from_bytes(&loaded.cert.as_tsk().to_vec()?)?;
    let mut packets = Vec::new();
    for packet in pile.children().cloned() {
        packets.push(match packet {
            pgp::Packet::SecretKey(key) => {
                let pair = loaded.pair(&key.fingerprint().to_hex())?;
                pgp::Packet::SecretKey(key.add_secret(pair.secret().clone().into()).0)
            }
            pgp::Packet::SecretSubkey(key) => {
                let pair = loaded.pair(&key.fingerprint().to_hex())?;
                pgp::Packet::SecretSubkey(key.add_secret(pair.secret().clone().into()).0)
            }
            other => other,
        });
    }
    let cert = pgp::Cert::from_packets(packets.into_iter())?;
    let mut password = v["newPassword"].take();
    let result = encrypted_result(
        &cert,
        password.as_str().context("Export password required")?,
    );
    if let serde_json::Value::String(value) = &mut password {
        value.zeroize();
    }
    result
}
/// Export validated Level 3 seeds only for an explicitly reviewed card import.
/// This operation runs in a disposable worker. It is never used for downloads,
/// normal signing, or persistence; the caller wipes mutable seed buffers after
/// the SCP-protected import and keeps the encrypted source on every failure.
fn backup_material(mut v: serde_json::Value) -> Result<serde_json::Value> {
    fields(&v, &["encryptedSecret", "password"])?;
    let loaded = load(&mut v)?;
    ensure!(loaded.info["profile"] == "level3", "Native Level 3 backup required");
    ensure!(loaded.pairs.len() == 3, "Exactly three logical keys required");
    let primary = loaded.cert.fingerprint().to_hex();
    let mut keys = Vec::new();
    for pair in &loaded.pairs {
        let fp = pair.public().fingerprint().to_hex();
        pair.secret().map(|secret| -> Result<()> {
            let mut add = |slot: &str, algorithm: &str, seed: &[u8], public: &[u8]| {
                keys.push(serde_json::json!({"slot":slot,"algorithm":algorithm,"seed":B64.encode(seed),"publicKey":B64.encode(public)}));
            };
            match (pair.public().mpis(), secret) {
                (mpi::PublicKey::MLDSA65_Ed25519 { mldsa: mp, eddsa: ep }, mpi::SecretKeyMaterial::MLDSA65_Ed25519 { mldsa, eddsa }) => {
                    let certification = fp == primary;
                    ensure!(certification || loaded.info["signingFingerprint"] == fp, "Unexpected signing role");
                    add(if certification {"86"} else {"9c"}, "ML-DSA-65", mldsa.as_ref(), mp.as_ref());
                    add(if certification {"87"} else {"84"}, "Ed25519", eddsa.as_ref(), ep.as_ref());
                },
                (mpi::PublicKey::MLKEM768_X25519 { mlkem: mp, ecdh: ep }, mpi::SecretKeyMaterial::MLKEM768_X25519 { mlkem, ecdh }) => {
                    ensure!(loaded.info["recipientKey"] == fp, "Unexpected encryption role");
                    add("9d", "ML-KEM-768", mlkem.as_ref(), mp.as_ref());
                    add("85", "X25519", ecdh.as_ref(), ep.as_ref());
                },
                _ => bail!("Unsupported card backup algorithm"),
            }
            Ok(())
        })?;
    }
    ensure!(keys.len()==6, "Incomplete backup");
    Ok(serde_json::json!({"keys":keys,"certificateHash":loaded.info["certificateHash"]}))
}
#[wasm_bindgen]
pub fn software_backup_material(input: &str) -> Result<String, JsValue> {
    call(input, backup_material).map_err(|_| JsValue::from_str("Hardware backup material rejected"))
}

/// Generate only software keys using the browser's CSPRNG-backed Rust backend.
#[wasm_bindgen]
pub fn software_generate(input: &str) -> Result<String, JsValue> {
    call(input, generate).map_err(|_| JsValue::from_str("Software identity generation rejected"))
}
/// Produce portable, password-encrypted OpenPGP secret packets; no plaintext key
/// export exists, and the source vault record is never mutated by this call.
#[wasm_bindgen]
pub fn software_export(input: &str) -> Result<String, JsValue> {
    call(input, export)
        .map_err(|_| JsValue::from_str("Encrypted software identity export rejected"))
}

/// Authenticate legacy/current PQ Mail PFX MACs inside bounded Rust work. This
/// never returns the derived password key or permits an unauthenticated import.
#[wasm_bindgen]
pub fn software_p12_verify_mac(input: &str) -> Result<String, JsValue> {
    let run = || -> Result<String> {
        ensure!(input.len() <= 1_500_000, "PFX request limit");
        Ok(serde_json::to_string(&p12::verify_mac(
            serde_json::from_str(input)?,
        )?)?)
    };
    run().map_err(|_| JsValue::from_str("PKCS12 authentication rejected"))
}
/// Reconstruct existing public certificate fingerprints from authenticated,
/// decrypted PQ Mail PKCS8 bags. All private/public components are rechecked.
#[wasm_bindgen]
pub fn software_import_p12(input: &str) -> Result<String, JsValue> {
    let run = || -> Result<String> {
        ensure!(input.len() <= 1_500_000, "PFX request limit");
        Ok(serde_json::to_string(&p12::import(serde_json::from_str(
            input,
        )?)?)?)
    };
    run().map_err(|_| JsValue::from_str("PQ Mail software PKCS12 import rejected"))
}

fn call(input: &str, op: fn(serde_json::Value) -> Result<serde_json::Value>) -> Result<String> {
    ensure!(input.len() <= 400000, "Software request limit");
    Ok(serde_json::to_string(&op(serde_json::from_str(input)?)?)?)
}
/// Inspect an encrypted software identity; return only canonical public data.
#[wasm_bindgen]
pub fn software_inspect(input: &str) -> Result<String, JsValue> {
    call(input, inspect).map_err(|_| JsValue::from_str("Software identity inspection rejected"))
}
/// Sign exactly one prepared digest using the selected software message subkey.
#[wasm_bindgen]
pub fn software_sign(input: &str) -> Result<String, JsValue> {
    call(input, sign).map_err(|_| JsValue::from_str("Software signing rejected"))
}
/// Recover exactly two bound component shares; packet recovery stays separate.
#[wasm_bindgen]
pub fn software_decapsulate(input: &str) -> Result<String, JsValue> {
    call(input, decapsulate).map_err(|_| JsValue::from_str("Software decryption rejected"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::{
        cert::{CertBuilder, CipherSuite},
        types::{AEADAlgorithm, KeyFlags},
        Cert, Packet,
    };
    use std::{
        sync::OnceLock,
        time::{Duration, SystemTime},
    };
    const PASSWORD: &str = "Disposable software regression password";
    struct Fixture {
        plain: Cert,
        encrypted: Cert,
        revocation: pgp::packet::Signature,
    }
    fn builder(email: &str) -> CertBuilder<'_> {
        CertBuilder::new()
            .set_profile(pgp::Profile::RFC9580)
            .unwrap()
            .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
            .set_primary_key_flags(KeyFlags::empty().set_certification())
            .add_userid(email)
            .add_signing_subkey()
            .add_transport_encryption_subkey()
    }
    // Fixture keys exist only in tests. Fast, valid S2K parameters keep negative
    // tests cheap; the optional exported fixture separately exercises Sequoia's
    // normal production encryption defaults, not these reduced work factors.
    fn encrypt(cert: &Cert, password: &str, normal: bool) -> Cert {
        let packets = pgp::PacketPile::from_bytes(&cert.as_tsk().to_vec().unwrap()).unwrap();
        let pw = Password::from(password);
        let packets = packets.children().cloned().map(|packet| match packet {
            Packet::SecretKey(key) => {
                let encrypted = if normal {
                    key.encrypt_secret(&pw).unwrap()
                } else {
                    let secret = key
                        .secret()
                        .clone()
                        .encrypt_with(
                            &key,
                            S2K::new_iterated(H::SHA256, 1024).unwrap(),
                            S::AES256,
                            Some(AEADAlgorithm::OCB),
                            &pw,
                        )
                        .unwrap();
                    key.add_secret(secret).0
                };
                Packet::SecretKey(encrypted)
            }
            Packet::SecretSubkey(key) => {
                let encrypted = if normal {
                    key.encrypt_secret(&pw).unwrap()
                } else {
                    let secret = key
                        .secret()
                        .clone()
                        .encrypt_with(
                            &key,
                            S2K::new_iterated(H::SHA256, 1024).unwrap(),
                            S::AES256,
                            Some(AEADAlgorithm::OCB),
                            &pw,
                        )
                        .unwrap();
                    key.add_secret(secret).0
                };
                Packet::SecretSubkey(encrypted)
            }
            other => other,
        });
        Cert::from_packets(packets).unwrap()
    }
    fn fixture() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| {
            let (plain, revocation) = builder("fixture@example.invalid").generate().unwrap();
            let encrypted = encrypt(&plain, PASSWORD, false);
            Fixture {
                plain,
                encrypted,
                revocation,
            }
        })
    }
    fn request(cert: &Cert) -> serde_json::Value {
        serde_json::json!({"encryptedSecret":B64.encode(cert.as_tsk().to_vec().unwrap()),"password":PASSWORD})
    }
    fn signing_request(info: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({"requestId":"A".repeat(64),"signingFingerprint":info["signingFingerprint"],"hashAlgorithm":10,"digest":B64.encode([7;64])})
    }
    #[test]
    fn generated_profiles_encrypt_all_secrets_and_export_preserves_identity() {
        // These generated identities remain in process memory. Export must
        // change only password protection, including for compatibility views.
        for profile in [
            "level3",
            "level5",
            "level3-v4-hybrid",
            "level3-v4-classical",
            "level5-v4-hybrid",
            "level5-v4-classical",
        ] {
            let generated=generate(serde_json::json!({"profile":profile,"email":"generation@example.invalid","name":"Software fixture","password":PASSWORD})).unwrap();
            let inspected=inspect(serde_json::json!({"encryptedSecret":generated["encryptedSecret"],"password":PASSWORD})).unwrap();
            assert_eq!(inspected, generated["public"]);
            let cert = Cert::from_bytes(
                &B64.decode(generated["encryptedSecret"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert!(cert
                .keys()
                .secret()
                .all(|k| matches!(k.key().secret(), key::SecretKeyMaterial::Encrypted(_))));
            assert_eq!(
                cert.primary_key().key().version(),
                if profile.contains("-v4-") { 4 } else { 6 }
            );
            let new_password = "A different disposable export password";
            let reencrypted=export(serde_json::json!({"encryptedSecret":generated["encryptedSecret"],"password":PASSWORD,"newPassword":new_password})).unwrap();
            assert_eq!(reencrypted["public"], generated["public"]);
            assert_ne!(reencrypted["encryptedSecret"], generated["encryptedSecret"]);
            assert!(inspect(serde_json::json!({"encryptedSecret":reencrypted["encryptedSecret"],"password":PASSWORD})).is_err());
            assert_eq!(inspect(serde_json::json!({"encryptedSecret":reencrypted["encryptedSecret"],"password":new_password})).unwrap(),generated["public"]);
        }
    }
    #[test]
    fn generation_rejects_unsupported_profiles_and_unsafe_mailboxes() {
        let base = serde_json::json!({"profile":"level3","email":"fixture@example.invalid","name":"","password":PASSWORD});
        for (field, value) in [
            ("profile", "RSA"),
            ("email", "a@example.invalid\r\nBcc: x@invalid"),
            ("email", "missing-at"),
            ("name", "Bad <display>"),
            ("password", "short"),
        ] {
            let mut request = base.clone();
            request[field] = value.into();
            assert!(generate(request).is_err());
        }
    }
    #[test]
    fn v5_encrypted_backup_authenticates_and_preserves_fingerprint() {
        let generated=generate(serde_json::json!({"profile":"level3-v5-hybrid","email":"v5@example.invalid","name":"","password":PASSWORD})).unwrap();
        let request =
            serde_json::json!({"encryptedSecret":generated["encryptedSecret"],"password":PASSWORD});
        assert_eq!(inspect(request.clone()).unwrap()["version"], 5);
        let mut wrong = request.clone();
        wrong["password"] = "wrong".into();
        assert!(inspect(wrong).is_err());
        let mut envelope: serde_json::Value = serde_json::from_slice(
            &B64.decode(generated["encryptedSecret"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut bytes = B64
            .decode(envelope["ciphertext"].as_str().unwrap())
            .unwrap();
        bytes[0] ^= 1;
        envelope["ciphertext"] = B64.encode(bytes).into();
        let mut tampered = request.clone();
        tampered["encryptedSecret"] = B64.encode(serde_json::to_vec(&envelope).unwrap()).into();
        assert!(inspect(tampered).is_err());
        let mut export_request = request;
        export_request["newPassword"] = "Fresh encrypted v5 export password".into();
        let fresh = export(export_request).unwrap();
        assert_eq!(fresh["public"], generated["public"]);
    }
    #[test]
    fn encrypted_binary_and_armored_import_returns_only_public_metadata() {
        let f = fixture();
        let info = inspect(request(&f.encrypted)).unwrap();
        assert!(info["supported"].as_bool().unwrap());
        assert_eq!(info["version"], 6);
        assert_ne!(info["signingFingerprint"], info["fingerprint"]);
        let public =
            Cert::from_bytes(&B64.decode(info["certificate"].as_str().unwrap()).unwrap()).unwrap();
        assert!(!public.is_tsk());
        assert_eq!(public.fingerprint(), f.plain.fingerprint());
        assert_eq!(
            info["emails"],
            serde_json::json!(["fixture@example.invalid"])
        );
        let mut arm = request(&f.encrypted);
        arm["encryptedSecret"] = B64
            .encode(f.encrypted.as_tsk().armored().to_vec().unwrap())
            .into();
        assert_eq!(inspect(arm).unwrap(), info);
        for forbidden in ["password", "secret", "encryptedSecret", "privateKey"] {
            assert!(info.get(forbidden).is_none());
        }
    }
    #[test]
    fn wrong_password_plaintext_public_only_mixed_and_incomplete_are_rejected() {
        let f = fixture();
        let mut wrong = request(&f.encrypted);
        wrong["password"] = "Wrong password".into();
        assert!(inspect(wrong).is_err());
        assert!(inspect(request(&f.plain)).is_err());
        assert!(inspect(request(&f.encrypted.clone().strip_secret_key_material())).is_err());
        let primary = f
            .plain
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap();
        let mixed = f
            .encrypted
            .clone()
            .insert_packets(Some(Packet::SecretKey(primary)))
            .unwrap()
            .0;
        assert!(inspect(request(&mixed)).is_err());
        let incomplete = f.encrypted.clone().retain_subkeys(|_| false);
        assert!(inspect(request(&incomplete)).is_err());
        let mut multi = request(&f.encrypted);
        let mut bytes = f.encrypted.as_tsk().to_vec().unwrap();
        bytes.extend(f.encrypted.as_tsk().to_vec().unwrap());
        multi["encryptedSecret"] = B64.encode(bytes).into();
        assert!(inspect(multi).is_err());
    }
    #[test]
    fn expired_revoked_and_wrong_profile_are_rejected() {
        let f = fixture();
        let revoked = f
            .encrypted
            .clone()
            .insert_packets(Some(f.revocation.clone()))
            .unwrap()
            .0;
        assert!(inspect(request(&revoked)).is_err());
        let (expired, _) = builder("expired@example.invalid")
            .set_creation_time(SystemTime::now() - Duration::from_secs(7200))
            .set_validity_period(Duration::from_secs(60))
            .generate()
            .unwrap();
        assert!(inspect(request(&encrypt(&expired, PASSWORD, false))).is_err());
        let (classic, _) = CertBuilder::new()
            .add_userid("classic@example.invalid")
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();
        assert!(inspect(request(&encrypt(&classic, PASSWORD, false))).is_err());
        let (wrong_role, _) = builder("wrong-role@example.invalid")
            .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
            .generate()
            .unwrap();
        assert!(inspect(request(&encrypt(&wrong_role, PASSWORD, false))).is_err());
    }
    #[test]
    fn encrypted_secret_tampering_and_public_private_mismatch_are_rejected() {
        let f = fixture();
        let mut bytes = f.encrypted.as_tsk().to_vec().unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 1;
        let mut tampered = request(&f.encrypted);
        tampered["encryptedSecret"] = B64.encode(bytes).into();
        assert!(inspect(tampered).is_err());
        let (other, _) = builder("other@example.invalid").generate().unwrap();
        let key = f
            .plain
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap();
        let foreign = other
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .secret()
            .clone();
        let mismatch = f
            .plain
            .clone()
            .insert_packets(Some(Packet::SecretKey(key.add_secret(foreign).0)))
            .unwrap()
            .0;
        assert!(inspect(request(&encrypt(&mismatch, PASSWORD, false))).is_err());
    }
    #[test]
    fn exact_json_encoding_password_and_resource_limits_are_enforced() {
        let f = fixture();
        let good = request(&f.encrypted);
        for password in ["".to_string(), "é".repeat(513)] {
            let mut bad = good.clone();
            bad["password"] = password.into();
            assert!(inspect(bad).is_err());
        }
        let mut extra = good.clone();
        extra["slot"] = "9c".into();
        assert!(inspect(extra).is_err());
        let mut huge = good.clone();
        huge["encryptedSecret"] = B64.encode(vec![0; SECRET_LIMIT + 1]).into();
        assert!(inspect(huge).is_err());
        let mut noncanonical = good;
        noncanonical["encryptedSecret"] =
            format!("{}\n", noncanonical["encryptedSecret"].as_str().unwrap()).into();
        assert!(inspect(noncanonical).is_err());
        assert!(call(&" ".repeat(400001), inspect).is_err());
        // No attacker-selected work factor is derived by these checks.
        let key = fixture()
            .encrypted
            .primary_key()
            .key()
            .parts_as_secret()
            .unwrap();
        assert!(protection(key.secret()).is_ok());
    }
    #[test]
    #[allow(deprecated)] // Explicitly prove obsolete import protection is rejected.
    fn unsupported_ciphers_and_unbounded_kdf_parameters_are_rejected_before_derivation() {
        // Construct metadata only: no expensive KDF, encryption or malformed
        // plaintext parsing is necessary to exercise every work-factor gate.
        let protected = |s2k, algorithm| {
            key::SecretKeyMaterial::Encrypted(key::Encrypted::new(
                s2k,
                algorithm,
                None,
                vec![0; 32].into_boxed_slice(),
            ))
        };
        let iterated = |hash, hash_bytes| S2K::Iterated {
            hash,
            salt: [0; 8],
            hash_bytes,
        };
        for s2k in [
            S2K::Simple { hash: H::SHA256 },
            iterated(H::SHA1, 1024),
            iterated(H::SHA256, 0),
            iterated(H::SHA512, 0x3e00001),
            S2K::Argon2 {
                salt: [0; 16],
                t: 5,
                p: 1,
                m: 16,
            },
            S2K::Argon2 {
                salt: [0; 16],
                t: 1,
                p: 5,
                m: 16,
            },
            S2K::Argon2 {
                salt: [0; 16],
                t: 1,
                p: 1,
                m: 17,
            },
            S2K::Argon2 {
                salt: [0; 16],
                t: 0,
                p: 1,
                m: 16,
            },
        ] {
            assert!(protection(&protected(s2k, S::AES256)).is_err());
        }
        assert!(protection(&protected(iterated(H::SHA256, 1024), S::TripleDES)).is_err());
        assert!(protection(&protected(
            S2K::Argon2 {
                salt: [0; 16],
                t: 3,
                p: 1,
                m: 16
            },
            S::AES256
        ))
        .is_ok());
    }
    #[test]
    fn software_signature_uses_only_selected_subkey_and_closed_digest_schema() {
        let f = fixture();
        let info = inspect(request(&f.encrypted)).unwrap();
        let mut q = request(&f.encrypted);
        q["request"] = signing_request(&info);
        let result = sign(q.clone()).unwrap();
        assert_eq!(result.as_object().unwrap().len(), 6);
        assert_eq!(
            B64.decode(result["ed25519"].as_str().unwrap())
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            B64.decode(result["mldsa65"].as_str().unwrap())
                .unwrap()
                .len(),
            3309
        );
        for (field, value) in [
            ("hashAlgorithm", serde_json::json!(8)),
            ("requestId", serde_json::json!("a".repeat(64))),
            ("signingFingerprint", info["fingerprint"].clone()),
            ("digest", serde_json::json!(B64.encode([0; 63]))),
        ] {
            let mut bad = q.clone();
            bad["request"][field] = value;
            assert!(sign(bad).is_err(), "{field}");
        }
        let mut extra = q;
        extra["request"]["slot"] = "9c".into();
        assert!(sign(extra).is_err());
    }
    /// Exercise the same split-signing and split-decryption exports as the IWA,
    /// with Sequoia independently validating signatures and producing the AEAD
    /// encryption envelope. Only freshly generated disposable software keys run.
    fn roundtrip(cert: &Cert, password: &str, email: &str) -> serde_json::Value {
        let mut base = request(cert);
        base["password"] = password.into();
        let info = inspect(base.clone()).unwrap();
        let payload=B64.encode(b"From: fixture@example.invalid\r\nSubject: Software custody test\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSynthetic software round trip.\r\n");
        let signing = serde_json::json!({"requestId":"B".repeat(64),"senderCertificate":info["certificate"],"senderEmail":email,"payload":payload});
        let sign_req: serde_json::Value =
            serde_json::from_str(&super::super::prepare_signing(&signing.to_string()).unwrap())
                .unwrap();
        let mut sign_input = base.clone();
        sign_input["request"] = sign_req;
        let reply = sign(sign_input.clone()).unwrap();
        let signed: serde_json::Value =
            serde_json::from_str(&super::super::finalize_signing(&reply.to_string()).unwrap())
                .unwrap();
        let encrypted=super::super::encrypt_public(&serde_json::json!({"senderCertificate":info["certificate"],"recipientCertificate":info["certificate"],"recipientFingerprint":info["fingerprint"],"recipientEmail":email,"signed":signed["signed"],"payload":payload})).unwrap();
        let decryption = serde_json::json!({"requestId":"C".repeat(64),"cipher":encrypted["cipher"],"recipientCertificate":info["certificate"],"recipientKey":info["recipientKey"],"purpose":"message"});
        let decap_req: serde_json::Value = serde_json::from_str(
            &super::super::prepare_decryption(&decryption.to_string()).unwrap(),
        )
        .unwrap();
        let mut decap_input = base;
        decap_input["request"] = decap_req;
        let shares = decapsulate(decap_input.clone()).unwrap();
        let decrypted: serde_json::Value =
            serde_json::from_str(&super::super::finalize_decryption(&shares.to_string()).unwrap())
                .unwrap();
        assert_eq!(decrypted["raw"], payload);
        let verified=super::super::verify_public(&serde_json::json!({"payload":decrypted["raw"],"signature":decrypted["signature"],"certificates":[info["certificate"]]})).unwrap();
        assert_eq!(verified["signatures"][0]["status"], "valid");
        serde_json::json!({"identity":info,"signing":signing,"decryption":decryption,"signInput":sign_input,"decapInput":decap_input,"shares":shares,"payload":payload})
    }
    #[test]
    fn software_signing_and_decryption_round_trip_with_sequoia() {
        let f = fixture();
        roundtrip(&f.encrypted, PASSWORD, "fixture@example.invalid");
    }
    #[test]
    fn decryption_rejects_wrong_key_malformed_components_and_low_order_ecdh() {
        let f = fixture();
        let data = roundtrip(&f.encrypted, PASSWORD, "fixture@example.invalid");
        let good = data["decapInput"].clone();
        for (field, value) in [
            (
                "recipientKey",
                data["identity"]["signingFingerprint"].clone(),
            ),
            ("requestId", serde_json::json!("a".repeat(64))),
            ("cipherHash", serde_json::json!("A".repeat(64))),
            ("mlkemCiphertext", serde_json::json!(B64.encode([0; 1087]))),
            ("x25519Ephemeral", serde_json::json!(B64.encode([0; 32]))),
        ] {
            let mut bad = good.clone();
            bad["request"][field] = value;
            assert!(decapsulate(bad).is_err(), "{field}");
        }
        let mut low_order = good.clone();
        let mut one = [0; 32];
        one[0] = 1;
        low_order["request"]["x25519Ephemeral"] = B64.encode(one).into();
        assert!(decapsulate(low_order).is_err());
        let mut tampered = good;
        let mut ct = B64
            .decode(tampered["request"]["mlkemCiphertext"].as_str().unwrap())
            .unwrap();
        ct[0] ^= 1;
        tampered["request"]["mlkemCiphertext"] = B64.encode(ct).into();
        // ML-KEM must retain implicit rejection; the final authenticated envelope
        // check (covered by decryption.rs) rejects this different shared secret.
        assert_ne!(
            decapsulate(tampered).unwrap()["mlkemSecret"],
            data["shares"]["mlkemSecret"]
        );
    }
    #[test]
    fn export_disposable_encrypted_software_fixture() {
        let Ok(directory) = std::env::var("IWA_SOFTWARE_FIXTURE_DIR") else {
            return;
        };
        let email = std::env::var("IWA_SOFTWARE_FIXTURE_EMAIL")
            .unwrap_or_else(|_| "fixture@example.invalid".into());
        assert!(email.len() <= 254 && email.contains('@') && !email.contains(['\r', '\n']));
        let password =
            std::env::var("IWA_SOFTWARE_FIXTURE_PASSWORD").unwrap_or_else(|_| PASSWORD.into());
        assert!(!password.is_empty() && password.len() <= 1024);
        let (plain, _) = builder(&email).generate().unwrap();
        let encrypted = encrypt(&plain, &password, true);
        let data = roundtrip(&encrypted, &password, &email);
        let path = std::path::Path::new(&directory);
        std::fs::create_dir(path).expect("Use a new private fixture directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (name, bytes) in [
            ("encrypted-secret.pgp", encrypted.as_tsk().to_vec().unwrap()),
            (
                "public.pgp",
                plain.strip_secret_key_material().to_vec().unwrap(),
            ),
            ("fixture.json", serde_json::to_vec(&data).unwrap()),
        ] {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(path.join(name))
                .unwrap()
                .write_all(&bytes)
                .unwrap();
        }
        println!("Created disposable encrypted software fixture; no existing identity read");
    }
}
