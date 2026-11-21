//! Validate mailbox bindings before the browser can offer a trust decision.
//! A raw User ID packet is an unauthenticated claim: only a live, policy-valid
//! self-certification on an unrevoked certificate may contribute an address.
use anyhow::{ensure, Result};
use sequoia_openpgp as pgp;
use pgp::{cert::prelude::*, parse::Parse, policy::StandardPolicy,
          types::{PublicKeyAlgorithm, RevocationStatus}, Cert};
use std::{collections::BTreeSet, fs::File, io::Read, path::Path, time::SystemTime};

/// Use one reference time for the primary key and every UID. This validates
/// control of a mailbox *claim*, not ownership of the mailbox: out-of-band
/// fingerprint verification and the user's explicit trust decision still apply.
fn bound_emails(cert: &Cert, at: SystemTime) -> Result<Vec<String>> {
    let policy = StandardPolicy::new();
    ensure!(cert.primary_key().key().version() == 6
        && matches!(cert.primary_key().key().pk_algo(),
            PublicKeyAlgorithm::MLDSA65_Ed25519 | PublicKeyAlgorithm::MLDSA87_Ed448),
        "Expected a v6 hybrid primary key");
    let valid = cert.with_policy(&policy, at)?;
    valid.alive()?;
    // Treat uncertain revocation conservatively too. ValidCert/ValidUserID
    // policy checks alone do not automatically exclude revoked components.
    ensure!(matches!(valid.revocation_status(), RevocationStatus::NotAsFarAsWeKnow),
        "Certificate is revoked or has an unresolved revocation");
    let mut addresses = BTreeSet::new();
    for uid in valid.userids() {
        if !matches!(uid.revocation_status(), RevocationStatus::NotAsFarAsWeKnow) {
            continue;
        }
        // Sequoia parses one mailbox from the certified UID; permissive address
        // list parsing could otherwise turn extra text into additional claims.
        if let Ok(Some(address)) = uid.userid().email_normalized() {
            addresses.insert(address.to_lowercase());
        }
    }
    ensure!(!addresses.is_empty(), "No current self-certified email address");
    Ok(addresses.into_iter().collect())
}

/// Read public input with the same 1 MiB cap as Python. No persistent cache is
/// used: expiration and revocation are checked again on every trust/use path.
pub fn inspect(path: &Path) -> Result<()> {
    let mut raw = Vec::new();
    File::open(path)?.take(1024 * 1024 + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 1024 * 1024, "Public certificate exceeds size limit");
    let cert = Cert::from_bytes(&raw)?;
    ensure!(!cert.is_tsk(), "Secret packets are not public certificates");
    let emails = bound_emails(&cert, SystemTime::now())?;
    println!("{}", serde_json::json!({"fingerprint": cert.fingerprint().to_hex(), "emails": emails}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::{packet::{signature::SignatureBuilder, UserID},
              types::{ReasonForRevocation, SignatureType}};
    use std::time::Duration;

    fn fixture() -> Result<(Cert, SystemTime)> {
        // A fixed reference point avoids sleeps and makes expiry assertions
        // deterministic. Every key here is disposable, generated in memory.
        let at = SystemTime::now() - Duration::from_secs(3600);
        let (cert, _) = CertBuilder::new().set_profile(pgp::Profile::RFC9580)?
            .set_cipher_suite(CipherSuite::MLDSA65_Ed25519).set_creation_time(at)
            .add_userid("Alice <alice@example.test>")
            .add_userid("Other <other@example.test>").generate()?;
        Ok((cert, at))
    }

    #[test]
    fn accepts_only_live_self_certified_addresses() -> Result<()> {
        let (cert, at) = fixture()?;
        let mut signer = cert.primary_key().key().clone().parts_into_secret()?.into_keypair()?;
        // Appending an unsigned UID must not make it available for trust.
        let unsigned = UserID::from("unsigned@example.test");
        let expired = UserID::from("expired@example.test");
        let sig = SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_signature_creation_time(at)?
            .set_signature_validity_period(Duration::from_secs(10))?
            .sign_userid_binding(&mut signer, cert.primary_key().key(), &expired)?;
        let cert = cert.insert_packets(vec![pgp::Packet::from(unsigned), expired.into(), sig.into()])?.0;
        assert_eq!(bound_emails(&cert, at + Duration::from_secs(60))?,
            vec!["alice@example.test", "other@example.test"]);
        Ok(())
    }

    #[test]
    fn excludes_revoked_uid_and_rejects_revoked_primary() -> Result<()> {
        let (cert, at) = fixture()?;
        let mut signer = cert.primary_key().key().clone().parts_into_secret()?.into_keypair()?;
        let uid = cert.userids().find(|u| u.userid().email().ok().flatten() == Some("other@example.test")).unwrap();
        let revocation = UserIDRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"test")?
            .build(&mut signer, &cert, uid.userid(), None)?;
        let cert = cert.insert_packets(revocation)?.0;
        assert_eq!(bound_emails(&cert, SystemTime::now())?, vec!["alice@example.test"]);
        let revocation = cert.revoke(&mut signer, ReasonForRevocation::KeyCompromised, b"test")?;
        let revoked = cert.insert_packets(revocation)?.0;
        assert!(bound_emails(&revoked, at + Duration::from_secs(7200)).is_err());
        Ok(())
    }

    #[test]
    fn rejects_expired_primary() -> Result<()> {
        let at = SystemTime::now() - Duration::from_secs(3600);
        let (cert, _) = CertBuilder::new().set_profile(pgp::Profile::RFC9580)?
            .set_cipher_suite(CipherSuite::MLDSA65_Ed25519).set_creation_time(at)
            .set_validity_period(Duration::from_secs(30))
            .add_userid("alice@example.test").generate()?;
        assert!(bound_emails(&cert, at + Duration::from_secs(60)).is_err());
        Ok(())
    }
}
