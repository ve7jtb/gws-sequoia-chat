//! Password-encrypted envelope for the explicitly optional LibrePGP v5 profile.
//!
//! This is a PQ Mail identity backup, not an OpenPGP secret-key packet. The
//! public v5 certificate remains standard LibrePGP and is authenticated together
//! with the three private seeds. No decrypted seed or derived key is exported.
use super::*;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
const DOMAIN: &[u8] = b"Sequoia IWA v5 encrypted identity v1";
const ITERATIONS: u32 = 600_000;

/// A single-block PBKDF2-HMAC-SHA256 derives the 256-bit envelope key. A strict
/// iteration window prevents both weak newly exported files and imported files
/// choosing unbounded CPU work. All intermediate PRF blocks are wiped on drop.
fn derive(password: &str, salt: &[u8], iterations: u32) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        !password.is_empty()
            && password.len() <= 1024
            && salt.len() == 16
            && (100_000..=1_000_000).contains(&iterations),
        "Bounded identity KDF required"
    );
    let base = <Hmac<Sha256> as Mac>::new_from_slice(password.as_bytes())?;
    let mut mac = base.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
    let mut out = Zeroizing::new(*u);
    for _ in 1..iterations {
        let mut mac = base.clone();
        mac.update(&*u);
        u.copy_from_slice(&mac.finalize().into_bytes());
        for (a, b) in out.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
    }
    Ok(out)
}
pub(super) fn is_envelope(v: &serde_json::Value) -> bool {
    v["encryptedSecret"]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .map(|b| b.first() == Some(&b'{'))
        .unwrap_or(false)
}
pub(super) fn open(
    v: &mut serde_json::Value,
) -> Result<(Vec<u8>, serde_json::Value, serde_json::Value)> {
    let encoded = text(v, "encryptedSecret")?;
    ensure!(encoded.len() <= 349528, "Encrypted identity size");
    let raw = B64.decode(encoded)?;
    ensure!(B64.encode(&raw) == encoded, "Canonical identity encoding");
    let envelope: serde_json::Value = serde_json::from_slice(&raw)?;
    fields(
        &envelope,
        &[
            "format",
            "version",
            "kdf",
            "iterations",
            "salt",
            "nonce",
            "ciphertext",
        ],
    )?;
    ensure!(
        envelope["format"] == "sequoia-iwa-v5-secret"
            && envelope["version"] == 1
            && envelope["kdf"] == "PBKDF2-HMAC-SHA256",
        "Identity envelope format"
    );
    let salt = octets(&envelope, "salt", 16)?;
    let nonce = octets(&envelope, "nonce", 12)?;
    let iterations = envelope["iterations"].as_u64().context("Iteration count")?;
    ensure!(iterations <= 1_000_000, "KDF limit");
    let cipher = B64.decode(text(&envelope, "ciphertext")?)?;
    ensure!(
        cipher.len() <= SECRET_LIMIT
            && cipher.len() >= 16
            && B64.encode(&cipher) == text(&envelope, "ciphertext")?,
        "Ciphertext bound"
    );
    let mut pw = v["password"].take();
    let result = (|| -> Result<_> {
        let key = derive(
            pw.as_str().context("Password required")?,
            &salt,
            iterations as u32,
        )?;
        let plaintext = Zeroizing::new(
            Aes256Gcm::new_from_slice(&*key)
                .map_err(|_| anyhow::anyhow!("Cipher"))?
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &cipher,
                        aad: DOMAIN,
                    },
                )
                .map_err(|_| anyhow::anyhow!("Authentication failed"))?,
        );
        let inner: serde_json::Value = serde_json::from_slice(&plaintext)?;
        fields(&inner, &["certificate", "secret"])?;
        let certificate = B64.decode(text(&inner, "certificate")?)?;
        super::super::libre::validate_secret(&certificate, &inner["secret"])?;
        let info = super::super::libre::inspect(&certificate)?;
        Ok((certificate, inner["secret"].clone(), info))
    })();
    if let serde_json::Value::String(p) = &mut pw {
        p.zeroize();
    }
    result
}
pub(super) fn seal(
    certificate: &[u8],
    secret: &serde_json::Value,
    password: &str,
) -> Result<serde_json::Value> {
    ensure!(
        (12..=1024).contains(&password.len()),
        "Export password length"
    );
    super::super::libre::validate_secret(certificate, secret)?;
    let public = super::super::libre::inspect(certificate)?;
    let mut salt = [0; 16];
    let mut nonce = [0; 12];
    pgp::crypto::random(&mut salt)?;
    pgp::crypto::random(&mut nonce)?;
    let key = derive(password, &salt, ITERATIONS)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(
        &serde_json::json!({"certificate":B64.encode(certificate),"secret":secret}),
    )?);
    let ciphertext = Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| anyhow::anyhow!("Cipher"))?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: DOMAIN,
            },
        )
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
    let envelope = serde_json::json!({"format":"sequoia-iwa-v5-secret","version":1,"kdf":"PBKDF2-HMAC-SHA256","iterations":ITERATIONS,"salt":B64.encode(salt),"nonce":B64.encode(nonce),"ciphertext":B64.encode(ciphertext)});
    Ok(
        serde_json::json!({"encryptedSecret":B64.encode(serde_json::to_vec(&envelope)?),"public":public}),
    )
}
