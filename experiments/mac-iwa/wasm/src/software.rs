//! Experimental, one-operation software custody for an encrypted Level 3 TSK.
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
    v.len() == 64
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
            _ => bail!("Only Level 3 hybrid private primitives are allowed"),
        }
        Ok(())
    })
}

struct Loaded {
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
        cert.is_tsk() && cert.keys().count() == 3 && cert.keys().secret().count() == 3,
        "Complete three-key secret identity required"
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
    ensure!(
        primary.key().version() == 6
            && primary.key().pk_algo() == A::MLDSA65_Ed25519
            && flags.for_certification()
            && !flags.for_signing()
            && !flags.for_transport_encryption()
            && !flags.for_storage_encryption(),
        "Separate certification primary required"
    );
    for ka in cert.keys() {
        ensure!(
            ka.key().version() == 6
                && matches!(ka.key().pk_algo(), A::MLDSA65_Ed25519 | A::MLKEM768_X25519),
            "Only Level 3 v6 private algorithms allowed"
        );
    }
    let public = cert.clone().strip_secret_key_material().to_vec()?;
    let info = super::certificates::inspect_identity_value(&B64.encode(public))?;
    ensure!(
        info["supported"] == true && info["signingFingerprint"] != info["fingerprint"],
        "Current separate message subkeys required"
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
    Ok(Loaded { info, pairs })
}

fn inspect(mut v: serde_json::Value) -> Result<serde_json::Value> {
    fields(&v, &["encryptedSecret", "password"])?;
    Ok(load(&mut v)?.info)
}
fn sign(mut v: serde_json::Value) -> Result<serde_json::Value> {
    fields(&v, &["encryptedSecret", "password", "request"])?;
    fields(&v["request"], &SIGN_FIELDS)?;
    // Reject malformed requests before password/KDF work. Identity fingerprints
    // are checked again against the decrypted, publicly bound message subkey.
    let request = &v["request"];
    ensure!(
        hex(text(request, "requestId")?, true) && hex(text(request, "signingFingerprint")?, true),
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
    let mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa } = signature else {
        bail!("Wrong signature algorithm")
    };
    Ok(
        serde_json::json!({"requestId":request["requestId"],"hashAlgorithm":10,"signingFingerprint":request["signingFingerprint"],"digest":request["digest"],"ed25519":B64.encode(eddsa.as_ref()),"mldsa65":B64.encode(mldsa.as_ref())}),
    )
}
fn decapsulate(mut v: serde_json::Value) -> Result<serde_json::Value> {
    use ml_kem::{kem::Decapsulate, DecapsulationKey, MlKem768};
    fields(&v, &["encryptedSecret", "password", "request"])?;
    fields(&v["request"], &DECAP_FIELDS)?;
    let request = &v["request"];
    ensure!(
        hex(text(request, "requestId")?, true)
            && hex(text(request, "cipherHash")?, false)
            && hex(text(request, "recipientKey")?, true),
        "Decryption identifiers"
    );
    let ciphertext: [u8; 1088] = octets(request, "mlkemCiphertext", 1088)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("ML-KEM input"))?;
    let ephemeral: [u8; 32] = octets(request, "x25519Ephemeral", 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("X25519 input"))?;
    ensure!(ephemeral.iter().any(|b| *b != 0), "Zero X25519 input");
    let mut loaded = load(&mut v)?;
    let request = &v["request"];
    ensure!(
        request["recipientKey"] == loaded.info["recipientKey"],
        "Wrong encryption key"
    );
    let pair = loaded.pair(text(request, "recipientKey")?)?;
    let mut result = request.clone();
    pair.secret().map(|secret| -> Result<()> {
        let mpi::SecretKeyMaterial::MLKEM768_X25519 { ecdh, mlkem } = secret else {
            bail!("Wrong private algorithm")
        };
        let ec = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(ecdh.as_ref())?);
        let shared = ec.diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral));
        ensure!(shared.was_contributory(), "Noncontributory X25519 input");
        let ml = DecapsulationKey::<MlKem768>::from_seed((&mlkem[..]).try_into()?);
        let ml_shared = Zeroizing::new(ml.decapsulate((&ciphertext).into()).to_vec());
        // No partial reply escapes. ML-KEM implicit rejection is deliberately
        // left intact; the existing WASM AEAD/session-key recovery rejects a bad
        // ciphertext. The worker must never persist either shared component.
        result["mlkemSecret"] = serde_json::json!(B64.encode(&*ml_shared));
        result["x25519Secret"] = serde_json::json!(B64.encode(shared.as_bytes()));
        Ok(())
    })?;
    Ok(result)
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
