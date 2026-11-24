//! Digest-only hardware boundary for browser-constructed OpenPGP signatures.
//!
//! The browser owns packet layout, salt and message hashing. Native code cannot
//! infer or attest to MIME headers from a digest; its authority is deliberately
//! limited to one SHA-512 digest under the configured message-signing subkey.
use super::*;
use pgp::crypto::{Signer as CryptoSigner,mpi};
use pgp::types::HashAlgorithm;

/// Reject malformed or substituted identifiers before invoking any signer.
/// Request IDs bind the response to the worker's retained state; the Python
/// host separately enforces one-use authorization, routing and expiry.
pub(crate) fn validate_request(v:&serde_json::Value,key:&PublicKey)->Result<Vec<u8>> {
 let request=field(v,"requestId")?;
 ensure!(request.len()==64 && request.bytes().all(|c|c.is_ascii_digit() || (b'A'..=b'F').contains(&c)),"Invalid signing request ID");
 ensure!(v["hashAlgorithm"].as_u64()==Some(10),"SHA-512 required");
 ensure!(field(v,"signingFingerprint")?==key.fingerprint().to_hex(),"Wrong configured signing key");
 let digest=B64.decode(field(v,"digest")?)?;
 ensure!(digest.len()==64&&B64.encode(&digest)==field(v,"digest")?,"Exactly one canonical SHA-512 digest required");
 Ok(digest)
}

/// Return raw hybrid components, never a native-created signature packet.
/// Independently verify both components even when the selected signer already
/// verifies its hardware result. This is also the independent OpenSSL oracle
/// used by the browser-target regression tests with disposable software keys.
pub(crate) fn sign<S:CryptoSigner>(mut signer:S,v:&serde_json::Value)->Result<serde_json::Value> {
 let key=signer.public().clone();
 ensure!(key.version()==6 && key.pk_algo()==A::MLDSA65_Ed25519,"Level 3 v6 signing key required");
 let digest=validate_request(v,&key)?;
 let signature=signer.sign(HashAlgorithm::SHA512,&digest)?;
 key.verify(&signature,HashAlgorithm::SHA512,&digest)?;
 let mpi::Signature::MLDSA65_Ed25519{eddsa,mldsa}=signature else {bail!("Wrong signature algorithm")};
 Ok(serde_json::json!({"requestId":v["requestId"],"hashAlgorithm":10,
  "signingFingerprint":key.fingerprint().to_hex(),"digest":v["digest"],
  "ed25519":B64.encode(eddsa.as_ref()),"mldsa65":B64.encode(mldsa.as_ref())}))
}

#[cfg(test)]
mod tests {
 use super::*;
 use std::sync::{Arc,atomic::{AtomicUsize,Ordering}};
 struct Counted {key:pgp::crypto::KeyPair,calls:Arc<AtomicUsize>,damage:bool}
 impl CryptoSigner for Counted {
  fn public(&self)->&PublicKey{self.key.public()}
  fn sign(&mut self,hash:HashAlgorithm,digest:&[u8])->Result<mpi::Signature>{
   self.calls.fetch_add(1,Ordering::SeqCst);
   let mut sig=self.key.sign(hash,digest)?;
   if self.damage {if let mpi::Signature::MLDSA65_Ed25519{eddsa,..}=&mut sig {eddsa[0]^=1;}}
   Ok(sig)
  }
 }
 #[test]
 fn digest_gate_precedes_signing_and_verifies_both_components() {
  use pgp::cert::{CertBuilder,CipherSuite};
  let (cert,_)=CertBuilder::new().set_profile(pgp::Profile::RFC9580).unwrap().set_cipher_suite(CipherSuite::MLDSA65_Ed25519).add_signing_subkey().generate().unwrap();
  let policy=StandardPolicy::new();let public=cert.keys().with_policy(&policy,None).alive().revoked(false).for_signing().next().unwrap().key().clone().role_into_unspecified();
  let key=cert.keys().secret().find(|k|k.key().fingerprint()==public.fingerprint()).unwrap().key().clone().role_into_unspecified().into_keypair().unwrap();
  let v=serde_json::json!({"requestId":"A".repeat(64),"hashAlgorithm":10,"signingFingerprint":public.fingerprint().to_hex(),"digest":B64.encode([7;64])});
  for (field,value) in [("requestId",serde_json::json!("bad")),("hashAlgorithm",serde_json::json!(9)),("signingFingerprint",serde_json::json!("0".repeat(64))),("digest",serde_json::json!(B64.encode([7;63])))] {
   let mut bad=v.clone();bad[field]=value;let calls=Arc::new(AtomicUsize::new(0));
   assert!(sign(Counted{key:key.clone(),calls:calls.clone(),damage:false},&bad).is_err());
   assert_eq!(calls.load(Ordering::SeqCst),0,"Rejected input must not reach a private operation");
  }
  let calls=Arc::new(AtomicUsize::new(0));let response=sign(Counted{key:key.clone(),calls:calls.clone(),damage:false},&v).unwrap();
  assert_eq!(calls.load(Ordering::SeqCst),1);assert_eq!(response["requestId"],v["requestId"]);
  assert_eq!(B64.decode(response["ed25519"].as_str().unwrap()).unwrap().len(),64);
  assert_eq!(B64.decode(response["mldsa65"].as_str().unwrap()).unwrap().len(),3309);
  assert!(sign(Counted{key,calls,damage:true},&v).is_err(),"Never release a signature with either invalid component");
 }
}
