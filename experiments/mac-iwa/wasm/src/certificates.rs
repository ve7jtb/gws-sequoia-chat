//! Public-only certificate inspection for the IWA's local contact store.
//!
//! Parsing and self-certification policy are cryptographic questions; JavaScript
//! never infers a mailbox from an unverified User ID or a caller-supplied key ID.
//! This module reports capabilities but makes no trust decision and has no native
//! bridge, filesystem, network, private-key or hardware-operation access.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sequoia_openpgp as pgp;
use pgp::{cert::CertParser, parse::Parse, policy::StandardPolicy,
          serialize::SerializeInto, types::PublicKeyAlgorithm as A};
use wasm_bindgen::prelude::*;

fn inspect(input: &str) -> Result<String> {
    ensure!(input.len() <= 360000, "Certificate request limit");
    let request: serde_json::Value = serde_json::from_str(input)?;
    let object = request.as_object().context("Object required")?;
    ensure!(object.len() == 1 && object.contains_key("certificate"), "Unexpected fields");
    let raw = B64.decode(request["certificate"].as_str().context("Certificate required")?)?;
    ensure!(!raw.is_empty() && raw.len() <= 262144, "Certificate size limit");

    // A certificate file is one identity, not a keyring. Reject a second armor
    // block explicitly as some armor readers stop after the first block; the
    // packet parser below independently rejects multiple binary certificates.
    let armor = String::from_utf8_lossy(&raw);
    ensure!(armor.matches("-----BEGIN PGP").count() <= 1, "One certificate required");
    ensure!(!armor.contains("-----BEGIN PGP PRIVATE KEY"), "Public certificate only");
    let mut parser = CertParser::from_bytes(&raw)?;
    let cert = parser.next().context("One certificate required")??;
    ensure!(parser.next().is_none(), "One certificate required");
    ensure!(!cert.is_tsk(), "Public certificate only");
    ensure!(matches!(cert.primary_key().key().version(), 4 | 6), "Supported certificate version required");

    // Stable canonical packet bytes identify certificate updates separately
    // from the primary fingerprint. A newly added/revoked UID or changed subkey
    // binding cannot inherit trust merely by retaining the same primary key.
    let canonical = cert.to_vec()?;
    ensure!(canonical.len() <= 262144, "Canonical certificate limit");
    let mut emails = super::current_emails(&cert);
    emails.sort(); emails.dedup();
    let mut algorithms = Vec::new();
    for key in cert.keys() {
        let name = key.key().pk_algo().to_string();
        if !algorithms.contains(&name) { algorithms.push(name); }
    }
    let p = StandardPolicy::new();
    // The current composer supports exactly one Level 3 signing and transport
    // key. Classical v4 certificates remain useful for incoming verification;
    // they are not silently promoted to hybrid outgoing contacts.
    let signing = cert.keys().with_policy(&p, None).alive().revoked(false)
        .for_signing().filter(|k| k.key().pk_algo() == A::MLDSA65_Ed25519).count();
    let encryption = cert.keys().with_policy(&p, None).alive().revoked(false)
        .for_transport_encryption().filter(|k| k.key().pk_algo() == A::MLKEM768_X25519).count();
    let hybrid = cert.primary_key().key().version() == 6 && !emails.is_empty()
        && signing == 1 && encryption == 1;
    Ok(serde_json::to_string(&serde_json::json!({
        "certificate": B64.encode(canonical), "fingerprint": cert.fingerprint().to_hex(),
        "version": cert.primary_key().key().version(), "algorithms": algorithms,
        "emails": emails, "hybridContact": hybrid
    }))?)
}

/// Inspect one public certificate without reading or changing saved trust.
/// Fixed errors avoid returning packet contents from malformed input.
#[wasm_bindgen]
pub fn inspect_public(input: &str) -> Result<String, JsValue> {
    inspect(input).map_err(|_| JsValue::from_str("Public certificate inspection rejected"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::cert::{CertBuilder, CipherSuite};
    use std::time::{Duration, SystemTime};

    // These software-only keys exist in test process memory. No native helper,
    // application identity, token, account or persistent trust is accessed.
    fn identity() -> (pgp::Cert, pgp::packet::Signature) {
        CertBuilder::new().set_profile(pgp::Profile::RFC9580).unwrap()
            .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
            .add_userid("alice@example.invalid").add_signing_subkey()
            .add_transport_encryption_subkey().generate().unwrap()
    }
    fn inspect_bytes(bytes: &[u8]) -> Result<serde_json::Value> {
        Ok(serde_json::from_str(&inspect(&serde_json::json!({"certificate":B64.encode(bytes)}).to_string())?)?)
    }
    #[test]
    fn public_only_single_certificate_and_canonical_fingerprint() {
        let (secret, _) = identity();
        let cert = secret.clone().strip_secret_key_material();
        let public = cert.to_vec().unwrap();
        let result = inspect_bytes(&public).unwrap();
        assert_eq!(result["fingerprint"], cert.fingerprint().to_hex());
        assert_eq!(result["certificate"], B64.encode(&public));
        assert_eq!(result["hybridContact"], true);
        assert!(inspect_bytes(&secret.as_tsk().to_vec().unwrap()).is_err());
        let mut keyring = public.clone(); keyring.extend(identity().0.strip_secret_key_material().to_vec().unwrap());
        assert!(inspect_bytes(&keyring).is_err());
        assert!(inspect_bytes(&[]).is_err());
        assert!(inspect_bytes(&vec![0;262145]).is_err());
        assert!(inspect("{\"certificate\":\"YQ==\",\"trusted\":true}").is_err());
    }
    #[test]
    fn unbound_user_id_is_not_a_trustable_email() {
        let (cert, _) = identity();
        let cert = cert.strip_secret_key_material().insert_packets(Some(
            pgp::packet::UserID::from("mallory@example.invalid"))).unwrap().0;
        let result=inspect_bytes(&cert.to_vec().unwrap()).unwrap();
        assert_eq!(result["emails"],serde_json::json!(["alice@example.invalid"]));
    }
    #[test]
    fn expired_and_revoked_certificates_cannot_supply_current_trust() {
        let (cert, revocation)=identity();
        let revoked=cert.strip_secret_key_material().insert_packets(Some(revocation)).unwrap().0;
        let value=inspect_bytes(&revoked.to_vec().unwrap()).unwrap();
        assert_eq!(value["emails"],serde_json::json!([]));
        assert_eq!(value["hybridContact"],false);
        let (expired,_)=CertBuilder::new()
            .set_creation_time(SystemTime::now()-Duration::from_secs(7200))
            .set_validity_period(Duration::from_secs(60))
            .add_userid("expired@example.invalid").add_signing_subkey().generate().unwrap();
        let value=inspect_bytes(&expired.strip_secret_key_material().to_vec().unwrap()).unwrap();
        assert_eq!(value["emails"],serde_json::json!([]));
        assert_eq!(value["hybridContact"],false);
    }
    #[test]
    fn classical_public_certificates_are_verification_only() {
        let (cert,_)=CertBuilder::new().add_userid("classical@example.invalid")
            .add_signing_subkey().add_transport_encryption_subkey().generate().unwrap();
        let value=inspect_bytes(&cert.strip_secret_key_material().to_vec().unwrap()).unwrap();
        assert_eq!(value["version"],4);
        assert_eq!(value["emails"],serde_json::json!(["classical@example.invalid"]));
        assert_eq!(value["hybridContact"],false);
    }
}
