//! Public-only FIPS 204 external-mu preparation for the direct PIV transport.
//! The card signs mu, not the OpenPGP digest. Bind the public key to the selected
//! Sequoia signing subkey; no PIN or private key enters this worker.
use super::{field, public, B64};
use anyhow::{ensure, Context, Result};
use base64::Engine;
use sequoia_openpgp::{crypto::mpi, policy::StandardPolicy};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use wasm_bindgen::prelude::*;
fn mu(public: &[u8], digest: &[u8]) -> [u8;64] {
    let mut tr=[0;64];
    let mut h=Shake256::default();h.update(public);h.finalize_xof().read(&mut tr);
    let mut h=Shake256::default();h.update(&tr);h.update(&[0,0]);h.update(digest);
    let mut out=[0;64];h.finalize_xof().read(&mut out);out
}
fn input(raw: &str) -> Result<String> {
    ensure!(raw.len()<360000,"Input too large");
    let v:serde_json::Value=serde_json::from_str(raw)?;
    let cert=public(field(&v,"certificate")?)?;
    let digest=B64.decode(field(&v,"digest")?)?;
    ensure!(digest.len()==64,"SHA-512 digest required");
    let p=StandardPolicy::new();
    let key=cert.keys().with_policy(&p,None).supported().alive().revoked(false).for_signing()
        .find(|k| k.key().fingerprint().to_hex()==field(&v,"signingFingerprint").unwrap_or(""))
        .context("Current signing key required")?;
    let mpi::PublicKey::MLDSA65_Ed25519{mldsa,..}=key.key().mpis() else {anyhow::bail!("Native Level 3 hybrid required")};
    Ok(serde_json::json!({"mu":B64.encode(mu(mldsa.as_ref(),&digest))}).to_string())
}
#[wasm_bindgen]
pub fn smartcard_signing_input(raw:&str)->std::result::Result<String,String>{input(raw).map_err(|_|"Invalid direct-card signing input".into())}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn fips204_empty_context_known_vector(){
  // Independent Python hashlib SHAKE-256 vector: tr=H(pk), mu=H(tr||0||0||M).
  let out=mu(&vec![0x42;1952],&vec![0x17;64]);
  assert_eq!(B64.encode(out), "xcZrUsXJTNnrdy/Muy+CRDB7gUkWxu8PQJhGE+iWdr/2t3mZcuMnMKm4bk8GaEGN9NJfszIPIIgJhAfHKyZpOQ==");
  assert_ne!(out,mu(&vec![0x43;1952],&vec![0x17;64]));
  assert_ne!(out,mu(&vec![0x42;1952],&vec![0x18;64]));
 }
}
