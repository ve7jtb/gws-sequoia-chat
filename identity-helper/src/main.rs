//! Generate an exportable Level 3 identity without accessing any token or account.
//! Only password-encrypted secret packets reach disk. Component slots are a
//! future import plan, not a claim that keys have been installed on a device.
use anyhow::{ensure, Result};
use sequoia_openpgp as pgp;
use pgp::{cert::prelude::*, crypto::Password, packet::key::{self, Key4}, policy::StandardPolicy,
          serialize::Serialize, types::{KeyFlags, PublicKeyAlgorithm}, Cert, Packet};
use std::{fs::{self, OpenOptions}, io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::Path, time::Duration};
use zeroize::Zeroizing;
mod public_policy;

/// Preserve every private component, but replace each secret packet with its
/// password-encrypted equivalent before serialization. Do not write a temporary
/// plaintext secret key. Public certificate serialization omits secret packets.
fn protect(cert: Cert, password: &Password) -> Result<Cert> {
    let mut packets: Vec<Packet> = Vec::new();
    for ka in cert.keys().secret() {
        let k = ka.key().clone().encrypt_secret(password)?;
        ensure!(!k.has_unencrypted_secret(), "Secret protection failed");
        packets.push(if ka.primary() { k.role_into_primary().into() }
                     else { k.role_into_subordinate().into() });
    }
    Ok(cert.insert_packets(packets)?.0)
}
fn file(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(dir.join(name))?;
    f.write_all(bytes)?; f.sync_all()?; Ok(())
}
fn save(dir: &Path, name: &str, cert: Cert, password: &Password) -> Result<()> {
    let encrypted = protect(cert, password)?;
    let mut bytes = Vec::new(); encrypted.as_tsk().serialize(&mut bytes)?;
    file(dir, &format!("{name}secret.pgp"), &bytes)?;
    bytes.clear(); encrypted.serialize(&mut bytes)?;
    file(dir, &format!("{name}public.pgp"), &bytes)
}

/// Eight components are generated independently: two certification components,
/// two hybrid signing components, two hybrid KEM components, and dedicated
/// classical Ed25519/X25519 keys. The two v4 certificate views share a primary;
/// their hybrid KEM view reuses the v6 KEM, never a classical standalone key.
fn create(dir: &Path, email: &str, password: &Password) -> Result<()> {
    ensure!(!dir.exists(), "Output already exists; refusing to replace an identity");
    ensure!(email.contains('@') && !email.chars().any(|c| c.is_whitespace() || "<>\r\n".contains(c)), "Invalid email");
    let p = StandardPolicy::new();
    let (modern, modern_rev) = CertBuilder::new()
        .set_profile(pgp::Profile::RFC9580)?
        .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
        .set_primary_key_flags(KeyFlags::empty().set_certification())
        .set_validity_period(Duration::from_secs(365*86400))
        .add_userid(email).add_signing_subkey().add_transport_encryption_subkey().generate()?;
    // RFC 4880 uses the legacy EdDSA encoding, which is understood by v4 clients.
    let (classical, classical_rev) = CertBuilder::new()
        .set_profile(pgp::Profile::RFC4880)?
        .set_cipher_suite(CipherSuite::Cv25519)
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        .set_validity_period(Duration::from_secs(365*86400))
        .add_userid(email).add_transport_encryption_subkey().generate()?;
    let kem = modern.keys().secret().find(|k| k.key().pk_algo() == PublicKeyAlgorithm::MLKEM768_X25519)
        .ok_or_else(|| anyhow::anyhow!("Missing hybrid KEM"))?;
    // Reframe the same KEM public/private components as a v4 subkey. Its v4
    // fingerprint differs, but the underlying components and future slots do not.
    let v4kem: Key4<key::SecretParts, key::SubordinateRole> = Key4::with_secret(
        kem.key().creation_time(), kem.key().pk_algo(), kem.key().mpis().clone(), kem.key().secret().clone())?;
    let hybrid = SubkeyBuilder::new(classical.with_policy(&p, None)?, v4kem.into(),
        KeyFlags::empty().set_transport_encryption())?.attach_cert()?
        .retain_subkeys(|k| k.key().pk_algo() == PublicKeyAlgorithm::MLKEM768_X25519);
    ensure!(modern.keys().count()==3 && classical.keys().count()==2 && hybrid.keys().count()==2,
        "Unexpected certificate layout");
    // Record only public fingerprints and slot plans. Never emit seeds in logs
    // or separate unprotected component files; encrypted TSKs retain them.
    let mut plan = format!("Level 3 software identity: {email}\nNo token provisioned. Future empty-device PIV import plan:\n");
    for ka in modern.keys() {
        let slots = if ka.primary() { "86 ML-DSA-65 / 87 Ed25519 (certification)" }
            else if ka.key().pk_algo()==PublicKeyAlgorithm::MLDSA65_Ed25519 { "9c ML-DSA-65 / 84 Ed25519 (hybrid signing)" }
            else { "9d ML-KEM-768 / 85 X25519 (hybrid encryption)" };
        plan += &format!("{} -> {slots}\n",ka.key().fingerprint());
    }
    for ka in classical.keys() { plan += &format!("{} -> {}\n",ka.key().fingerprint(),
        if ka.primary() { "88 Ed25519 (v4 certification/signing)" } else { "89 X25519 (classical decryption)" }); }
    plan += "Importing the SAME private components and retaining these certificate packets preserves fingerprints.\nHardware import support and public-key equality must be checked before any future provisioning.\nSoftware backups continue to contain private keys after an import. No hardware-only origin is claimed.\n";
    fs::create_dir(dir)?; fs::set_permissions(dir,fs::Permissions::from_mode(0o700))?;
    save(dir,"",modern,password)?; save(dir,"v4-hybrid-",hybrid,password)?; save(dir,"v4-classical-",classical,password)?;
    let mut bytes=Vec::new(); Packet::Signature(modern_rev).serialize(&mut bytes)?;
    file(dir,"revocation.pgp",&bytes)?;bytes.clear();Packet::Signature(classical_rev).serialize(&mut bytes)?;
    file(dir,"v4-revocation.pgp",&bytes)?;file(dir,"migration-plan.txt",plan.as_bytes())?;
    println!("Created three certificates with encrypted private keys. {}",dir.display()); Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_>=std::env::args().collect();
    // Public inspection is deliberately dispatched before any identity creation
    // or password prompt. It validates certificate claims without using secrets,
    // accounts, key stores, or hardware, and returns only bounded public JSON.
    if args.get(1).map(String::as_str) == Some("inspect-public") {
        ensure!(args.len() == 3, "Usage: chat-software-identity inspect-public CERTIFICATE");
        return public_policy::inspect(Path::new(&args[2]));
    }
    ensure!(args.len()==3,"Usage: chat-software-identity EMAIL NEW-DIRECTORY");
    ensure!(!Path::new(&args[2]).exists(),"Output already exists");
    let pass=Zeroizing::new(rpassword::prompt_password("New OpenPGP backup password (12+ characters; not Google password or YubiKey PIN): ")?);
    ensure!(pass.chars().count()>=12,"Use at least 12 characters");
    let confirm=Zeroizing::new(rpassword::prompt_password("Confirm OpenPGP backup password: ")?);
    ensure!(*pass==*confirm,"Passwords differ; no keys created");
    create(Path::new(&args[2]),&args[1],&Password::from(pass.as_bytes()))
}

#[cfg(test)] mod tests {
    use super::*;use pgp::parse::Parse;
    #[test] fn encrypted_layout_and_shared_components()->Result<()> {
        let temp=tempfile::tempdir()?;let dir=temp.path().join("identity");let pw: Password="synthetic test password".into();
        create(&dir,"alice@example.test",&pw)?;
        let mut certs=Vec::new();
        for prefix in ["","v4-hybrid-","v4-classical-"] {
            let c=Cert::from_file(dir.join(format!("{prefix}secret.pgp")))?;
            let public=Cert::from_file(dir.join(format!("{prefix}public.pgp")))?;
            ensure!(!public.is_tsk(),"Public file contains private material");
            for k in c.keys().secret() {ensure!(!k.key().has_unencrypted_secret(),"Unencrypted secret");
                ensure!(k.key().clone().decrypt_secret(&"incorrect".into()).is_err(),"Wrong password accepted");
                k.key().clone().decrypt_secret(&pw)?;}
            certs.push(c);
        }
        // YubiKit imports ML-DSA/ML-KEM seeds, not expanded private-key blobs.
        // Confirm that the encrypted OpenPGP backup retains those exact seed
        // sizes along with raw Ed25519/X25519 components for later conversion.
        for k in certs[0].keys().secret() {
            let clear=k.key().clone().decrypt_secret(&pw)?;
            let key::SecretKeyMaterial::Unencrypted(material)=clear.secret() else {anyhow::bail!("Not decrypted")};
            material.map(|m| -> Result<()> {
                use pgp::crypto::mpi::SecretKeyMaterial as M;
                match m {
                    M::MLDSA65_Ed25519{eddsa,mldsa}=>ensure!(eddsa.len()==32 && mldsa.len()==32,"Unexpected signing seed size"),
                    M::MLKEM768_X25519{ecdh,mlkem}=>ensure!(ecdh.len()==32 && mlkem.len()==64,"Unexpected KEM seed size"),
                    _=>anyhow::bail!("Unexpected modern private component"),
                } Ok(())
            })?;
        }
        // Exercise every certificate view through the independently built sq CLI.
        // Only disposable test fixtures are decrypted to this temporary directory.
        if let Ok(sq)=std::env::var("TEST_SQ") {
            for (index, c) in certs.iter().enumerate() {
                let mut packets: Vec<Packet>=Vec::new();
                for ka in c.keys().secret() {
                    let k=ka.key().clone().decrypt_secret(&pw)?;
                    packets.push(if ka.primary(){k.role_into_primary().into()}else{k.role_into_subordinate().into()});
                }
                let clear=c.clone().insert_packets(packets)?.0;
                let secret=temp.path().join(format!("test-{index}.key"));
                let public=temp.path().join(format!("test-{index}.pub"));
                let mut bytes=Vec::new();clear.as_tsk().serialize(&mut bytes)?;fs::write(&secret,bytes)?;
                let mut bytes=Vec::new();clear.serialize(&mut bytes)?;fs::write(&public,bytes)?;
                let input=temp.path().join(format!("input-{index}"));fs::write(&input,b"synthetic round trip")?;
                let encrypted=temp.path().join(format!("encrypted-{index}"));let output=temp.path().join(format!("output-{index}"));
                let run=|args: Vec<&std::ffi::OsStr>| -> Result<()> {
                    let r=std::process::Command::new(&sq).args(["--home=none","--cert-store=none","--key-store=none","--batch"]).args(args).output()?;
                    ensure!(r.status.success(),"sq test {index}: {}",String::from_utf8_lossy(&r.stderr));Ok(())
                };
                run(vec!["encrypt".as_ref(),"--for-file".as_ref(),public.as_os_str(),"--signer-file".as_ref(),secret.as_os_str(),"--binary".as_ref(),"--output".as_ref(),encrypted.as_os_str(),input.as_os_str()])?;
                run(vec!["decrypt".as_ref(),"--recipient-file".as_ref(),secret.as_os_str(),"--signer-file".as_ref(),public.as_os_str(),"--signatures".as_ref(),"1".as_ref(),"--output".as_ref(),output.as_os_str(),encrypted.as_os_str()])?;
                ensure!(fs::read(output)?==b"synthetic round trip","Plaintext changed");
            }
        }
        ensure!(certs[1].fingerprint()==certs[2].fingerprint(),"v4 primaries differ");
        ensure!(certs[0].keys().last().unwrap().key().mpis()==certs[1].keys().last().unwrap().key().mpis(),"Hybrid KEM not shared");
        ensure!(create(&dir,"alice@example.test",&pw).is_err(),"Overwrite allowed");Ok(())
    }
}
