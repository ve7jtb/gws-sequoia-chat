//! Independent role-cardinality and cross-certificate authorization tests.
//! These tests exercise private constructors only under cfg(test); production
//! callers cannot manufacture a VerifiedBundle or override its authenticated map.
use super::*;
use pgp::{
    cert::{CertBuilder, CipherSuite},
    packet::signature::SignatureBuilder,
    types::{KeyFlags, SignatureType},
    Packet,
};
use std::time::{Duration, SystemTime};

#[test]
fn level5_rejects_two_classical_bindings_in_place_of_hybrid_role() -> Result<()> {
    let created = SystemTime::now() - Duration::from_secs(7200);
    let build = |version| -> Result<Cert> {
        Ok(CertBuilder::new()
            .set_profile(version)?
            .set_creation_time(created)
            .set_cipher_suite(CipherSuite::P384)
            .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
            .add_userid("Role fixture <roles@example.invalid>")
            .add_transport_encryption_subkey()
            .generate()?
            .0)
    };
    let normal = build(pgp::Profile::RFC9580)?;
    let compatibility = build(pgp::Profile::RFC4880)?;
    let policy = StandardPolicy::new();
    let original = compatibility
        .keys()
        .with_policy(&policy, None)
        .for_transport_encryption()
        .next()
        .context("Fixture recipient")?
        .key()
        .clone()
        .role_into_subordinate();
    let mut duplicate = original.clone();
    // Same public point, different packet creation timestamp: this is a distinct
    // valid OpenPGP subkey. A map's `add(equal)` alone does not detect the role
    // duplication, even though both bindings are genuinely self-signed.
    duplicate.set_creation_time(created + Duration::from_secs(1))?;
    assert_ne!(original.fingerprint(), duplicate.fingerprint());
    assert_eq!(original.mpis(), duplicate.mpis());
    let mut signer = compatibility
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;
    let sig = duplicate.bind(
        &mut signer,
        &compatibility,
        SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_key_flags(KeyFlags::empty().set_transport_encryption())?
            .set_signature_creation_time(created + Duration::from_secs(2))?,
    )?;
    let invalid = compatibility
        .insert_packets(vec![
            Packet::PublicSubkey(duplicate.parts_into_public()),
            sig.into(),
        ])?
        .0;
    assert_eq!(
        invalid
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .count(),
        2
    );
    assert_eq!(invalid.keys().count(), 3);
    let mut keys = BTreeMap::new();
    keys.insert(0x9c, companion::spki("ML-DSA-87", &vec![1; 2592])?);
    keys.insert(0x9d, companion::spki("ML-KEM-1024", &vec![1; 1568])?);
    let error = level5_bindings(&normal, Some(&invalid), &mut keys).unwrap_err();
    assert!(error.to_string().contains("Duplicate"), "{error}");
    Ok(())
}

/// Optional read-only checks using host-local public interoperability artifacts.
/// Fixture paths and the account address are never embedded in the repository.
#[test]
fn saved_v5_view_rejects_wrong_mailbox_and_component_if_requested() -> Result<()> {
    let (Ok(bundle_path), Ok(v5_path)) = (
        std::env::var("IWA_REVIEW_BUNDLE"),
        std::env::var("IWA_REVIEW_V5"),
    ) else {
        return Ok(());
    };
    let bytes = std::fs::read(bundle_path)?;
    let v5 = std::fs::read(v5_path)?;
    let now = current_time()?;
    let bundle = verify(&bytes)?;
    let view = bundle.v5_view(&v5, now)?;
    assert_eq!(view["profile"], "level3-v5-hybrid");
    assert_eq!(
        view["components"].as_array().context("Components")?.len(),
        3
    );
    for slot in [0x88, 0x9d, 0x85] {
        let mut wrong = verify(&bytes)?;
        // A different live/authenticated public component cannot be authorized
        // simply because its slot and algorithm match the imported v5 profile.
        *wrong
            .keys
            .get_mut(&slot)
            .context("Slot")?
            .last_mut()
            .unwrap() ^= 1;
        assert!(wrong.v5_view(&v5, now).is_err());
    }
    let mut wrong = verify(&bytes)?;
    wrong.cert = CertBuilder::new()
        .set_profile(pgp::Profile::RFC9580)?
        .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
        .add_userid("different-mailbox@example.invalid")
        .generate()?
        .0
        .strip_secret_key_material();
    assert!(wrong.v5_view(&v5, now).is_err());
    Ok(())
}
