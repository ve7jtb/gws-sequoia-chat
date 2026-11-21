//! Bounded, pipe-only cryptographic worker. No network, provisioning or files
//! containing plaintext. The native host owns account/contact authorization.
use anyhow::{ensure,bail,Context,Result};
use base64::{Engine,engine::general_purpose::STANDARD as B64};
use sequoia_openpgp as pgp;
use pgp::serialize::SerializeInto;
use pgp::cert::amalgamation::ValidAmalgamation;
use pgp::{Cert,KeyHandle,crypto::{SessionKey,Decryptor},packet::{PKESK,SKESK},
 parse::{Parse,stream::{DecryptionHelper,VerificationHelper,DecryptorBuilder,VerifierBuilder,MessageStructure,MessageLayer}},
 policy::StandardPolicy,types::{PublicKeyAlgorithm as A,SymmetricAlgorithm,CompressionAlgorithm},
 serialize::stream::{Message,Signer,Encryptor,Compressor,LiteralWriter}};
use sequoia_pqmail_piv::{PublicKey,Level3Signer,Level3Decryptor,process::{Config,Pkcs11Operation}};
use std::{io::{self,Read,Write},path::PathBuf};
use zeroize::Zeroizing;
const LIMIT:usize=262144;
fn field<'a>(v:&'a serde_json::Value,k:&str)->Result<&'a str>{v[k].as_str().context("Missing field")}
fn public(raw:&str)->Result<Cert>{let cert=Cert::from_bytes(&B64.decode(raw)?)?;ensure!(!cert.is_tsk(),"Public certificate only");Ok(cert)}
fn selected(cert:&Cert,sign:bool)->Result<PublicKey>{
 let p=StandardPolicy::new();let mut found=Vec::new();
 for k in cert.keys().with_policy(&p,None).alive().revoked(false){
  let flags=k.key_flags();let eligible=flags.as_ref().map(|f|if sign{f.for_signing()}else{f.for_transport_encryption()}).unwrap_or(false);
  if eligible && k.key().pk_algo()==if sign{A::MLDSA65_Ed25519}else{A::MLKEM768_X25519}{found.push(k.key().clone().role_into_unspecified());}
 }
 ensure!(found.len()==1 && found[0].version()==6,"One valid Level 3 v6 key required");Ok(found.remove(0))
}
struct Verify { cert:Cert, expected:pgp::Fingerprint, encryption_required:bool }
impl VerificationHelper for Verify {
 fn get_certs(&mut self,_:&[KeyHandle])->Result<Vec<Cert>>{Ok(vec![self.cert.clone()])}
 fn check(&mut self,s:MessageStructure)->Result<()>{
  let(mut good,mut encrypted)=(0,false);
  for layer in s.iter(){match layer{
   MessageLayer::SignatureGroup{results}=>for r in results {let valid=r.as_ref().map_err(|_|anyhow::anyhow!("Invalid signature"))?;ensure!(valid.ka.key().fingerprint()==self.expected,"Wrong signing key");good+=1;},
   MessageLayer::Encryption{aead_algo,..}=>{ensure!(aead_algo.is_some(),"AEAD required");encrypted=true;},
   MessageLayer::Compression{..}=>{}
  }}
  ensure!(good==1 && (!self.encryption_required || encrypted),"One valid hybrid signature and encryption required");Ok(())
 }
}
struct Open<D:Decryptor> { verify:Verify, own:Cert, key:D }
impl<D:Decryptor> VerificationHelper for Open<D>{
 fn get_certs(&mut self,k:&[KeyHandle])->Result<Vec<Cert>>{self.verify.get_certs(k)}
 fn check(&mut self,s:MessageStructure)->Result<()>{self.verify.check(s)}
}
impl<D:Decryptor> DecryptionHelper for Open<D>{
 fn decrypt(&mut self,pk:&[PKESK],sk:&[SKESK],hint:Option<SymmetricAlgorithm>,decrypt:&mut dyn FnMut(Option<SymmetricAlgorithm>,&SessionKey)->bool)->Result<Option<Cert>>{
  ensure!(pk.len()==1&&sk.is_empty(),"Exactly one hybrid recipient required");
  ensure!(matches!(&pk[0],PKESK::V6(_))&&pk[0].recipient()==Some(self.key.public().fingerprint().into()),"Recipient mismatch");
  let(alg,key)=pk[0].decrypt(&mut self.key,hint).context("Hybrid decapsulation failed; no retry")?;
  ensure!(decrypt(alg,&key),"Authentication failed");Ok(Some(self.own.clone()))
 }
}
fn sealed_payload<S:pgp::crypto::Signer+Send+Sync>(signer:S,own:Cert,peer:Cert,payload:&[u8])->Result<Vec<u8>> {
 let sign=selected(&own,true)?;let kem=selected(&peer,false)?;let p=StandardPolicy::new();
  let mut signed=Zeroizing::new(Vec::new());{
   let s=Signer::new(Message::new(&mut *signed),signer)?.build()?;
   let mut literal=LiteralWriter::new(s).build()?;literal.write_all(payload)?;literal.finalize()?;
  }
  // Verify the actual hardware signature before encrypting or returning output.
  let helper=Verify{cert:own,expected:sign.fingerprint(),encryption_required:false};
  let mut reader=VerifierBuilder::from_bytes(&signed)?.with_policy(&p,None,helper)?;
  let mut recovered=Zeroizing::new(Vec::new());reader.by_ref().take((LIMIT+1)as u64).read_to_end(&mut recovered)?;
  ensure!(recovered.as_slice()==payload,"Signed content mismatch");
  let recipients=peer.keys().with_policy(&p,None).alive().revoked(false).for_transport_encryption().filter(|k|k.key().fingerprint()==kem.fingerprint());
  let mut out=Vec::new();{
   let e=Encryptor::for_recipients(Message::new(&mut out),recipients).build()?;
   let mut c=Compressor::new(e).algo(CompressionAlgorithm::Zlib).build()?;
   // Signed already contains literal and signature packets, so do not wrap
   // those packets in another LiteralWriter when inserting compression.
   c.write_all(&signed)?;c.finalize()?;
  }Ok(out)
}
// Public verification is deliberately independent of token configuration and PINs.
// Sequoia checks cryptographic validity, certificate bindings and policy; the
// native host separately decides whether the primary fingerprint is trusted.
// Only current, policy-valid, non-revoked self-certified mailboxes may acquire
// local trust. A valid historical message does not revive an expired identity.
fn current_emails(cert:&Cert)->Vec<String> {
 let p=StandardPolicy::new();
 if let Ok(valid)=cert.with_policy(&p,None) {
  if valid.alive().is_ok() && !matches!(valid.revocation_status(),pgp::types::RevocationStatus::Revoked(_)) {
   return valid.userids().filter(|u|!matches!(u.revocation_status(),pgp::types::RevocationStatus::Revoked(_))).filter_map(|u|u.userid().email_normalized().ok().flatten()).collect();
  }
 }
 Vec::new()
}
struct PublicVerify { certs:Vec<Cert>, results:Vec<serde_json::Value> }
impl VerificationHelper for PublicVerify {
 fn get_certs(&mut self,_:&[KeyHandle])->Result<Vec<Cert>> {Ok(self.certs.clone())}
 fn check(&mut self,structure:MessageStructure)->Result<()> {
  for layer in structure.iter() {
   if let MessageLayer::SignatureGroup{results}=layer { for result in results {
    self.results.push(match result {
     Ok(good)=>serde_json::json!({"status":"valid","fingerprint":good.ka.cert().fingerprint().to_hex(),"signingFingerprint":good.ka.key().fingerprint().to_hex(),"algorithm":format!("{}",good.ka.key().pk_algo()),"certificate":B64.encode(good.ka.cert().to_vec()?),"emails":current_emails(good.ka.cert())}),
     // A bad signature can still identify a candidate certificate whose local
     // trust is meaningful. This is NOT proof that this key authored the message.
     // Never infer identity merely from From or an unverified issuer string.
     Err(pgp::parse::stream::VerificationError::BadSignature{ka,..})=>serde_json::json!({"status":"invalid","fingerprint":ka.cert().fingerprint().to_hex(),"signingFingerprint":ka.key().fingerprint().to_hex(),"algorithm":format!("{}",ka.key().pk_algo()),"candidateOnly":true}),
     Err(pgp::parse::stream::VerificationError::MissingKey{..})=>serde_json::json!({"status":"unknown-key"}),
     Err(_)=>serde_json::json!({"status":"invalid"})
    });
   }}
  }
  Ok(())
 }
}
fn verify_public(v:&serde_json::Value)->Result<serde_json::Value> {
 let encoded=v["certificates"].as_array().context("Certificates required")?;
 ensure!(encoded.len()<=32,"Too many certificates");
 // Unusable attachments are not trusted and must not prevent trying saved keys.
 let certs=encoded.iter().filter_map(|x|x.as_str().and_then(|s|public(s).ok())).collect();
 let payload=B64.decode(field(v,"payload")?)?;ensure!(payload.len()<=LIMIT,"Payload too large");
 let signature=B64.decode(field(v,"signature")?)?;ensure!(signature.len()<=65536,"Signature too large");
 let p=StandardPolicy::new();
 let helper=PublicVerify{certs,results:Vec::new()};
 let mut verifier=pgp::parse::stream::DetachedVerifierBuilder::from_bytes(&signature)?.with_policy(&p,None,helper)?;
 verifier.verify_bytes(&payload)?;
 let results=verifier.into_helper().results;
 ensure!(!results.is_empty() && results.len()<=16,"No supported signatures");
 Ok(serde_json::json!({"signatures":results}))
}
fn execute()->Result<()> {
 let mut input=Zeroizing::new(Vec::new());io::stdin().take((LIMIT*4+1) as u64).read_to_end(&mut input)?;ensure!(input.len()<=LIMIT*4,"Input too large");
 let mut v:serde_json::Value=serde_json::from_slice(&input)?;input.clear();
 if field(&v,"op")?=="inspect-public" {
  let cert=public(field(&v,"certificate")?)?;
  println!("{}",serde_json::json!({"fingerprint":cert.fingerprint().to_hex(),"version":cert.primary_key().key().version(),"algorithms":cert.keys().map(|k|format!("{}",k.key().pk_algo())).collect::<Vec<_>>(),"emails":current_emails(&cert)}));return Ok(());
 }
 if field(&v,"op")?=="verify-detached" {
  // Malformed or unsupported signatures get an explicit failure, never a
  // successful result inherited from an earlier message. No hardware is used.
  let result=verify_public(&v).unwrap_or_else(|_|serde_json::json!({"signatures":[{"status":"invalid"}]}));
  println!("{}",result);return Ok(());
 }
 let pin=Zeroizing::new(v["pin"].take().as_str().context("PIN required")?.as_bytes().to_vec());
 let cfg=&v["config"];let path=|n|->Result<PathBuf>{Ok(PathBuf::from(field(cfg,n)?))};
 let config=Config{python:path("python")?,adapters:path("adapters")?,openssl:path("openssl")?,provider:path("provider")?,module:path("module")?,serial:field(cfg,"serial")?.into()};
 let own=public(field(&v,"own")?)?;let peer=public(field(&v,"peer")?)?;
 let payload=Zeroizing::new(B64.decode(field(&v,"payload")?)?);ensure!(payload.len()<=LIMIT,"Payload too large");
 let p=StandardPolicy::new();
 let result=match field(&v,"op")?{
 "seal"=>{
  let sign=selected(&own,true)?;
  let signer=Level3Signer::new(sign.clone(),Pkcs11Operation::new(config,pin)?)?;
  sealed_payload(signer,own,peer,&payload)?
 },
 "open"=>{
  let sign=selected(&peer,true)?;let kem=selected(&own,false)?;
  let helper=Open{verify:Verify{cert:peer,expected:sign.fingerprint(),encryption_required:true},own,key:Level3Decryptor::new(kem,Pkcs11Operation::new(config,pin)?)?};
  let mut reader=DecryptorBuilder::from_bytes(&payload)?.with_policy(&p,None,helper)?;
  let mut clear=Zeroizing::new(Vec::new());reader.by_ref().take((LIMIT+1)as u64).read_to_end(&mut clear)?;
  ensure!(clear.len()<=LIMIT,"Plaintext too large");clear.to_vec()
 },_=>bail!("Unknown operation")};
 ensure!(result.len()<=LIMIT,"Result too large");
 println!("{}",serde_json::json!({"data":B64.encode(result)}));Ok(())
}
fn main(){if execute().is_err(){eprintln!("Cryptographic operation failed; no plaintext released and no automatic retry");std::process::exit(1)}}

#[cfg(test)]
mod tests {
 use super::*;
 use pgp::cert::{CertBuilder,CipherSuite};
 fn identity()->Cert {CertBuilder::new().set_profile(pgp::Profile::RFC9580).unwrap().set_cipher_suite(CipherSuite::MLDSA65_Ed25519).add_userid("test@example.invalid").add_signing_subkey().add_transport_encryption_subkey().generate().unwrap().0}
 fn key(cert:&Cert,sign:bool)->pgp::crypto::KeyPair {let wanted=selected(cert,sign).unwrap().fingerprint();cert.keys().secret().find(|k|k.key().fingerprint()==wanted).unwrap().key().clone().role_into_unspecified().into_keypair().unwrap()}
 fn decrypt(own:&Cert,peer:&Cert,blob:&[u8])->Result<Vec<u8>> {
  let helper=Open{verify:Verify{cert:peer.clone(),expected:selected(peer,true)?.fingerprint(),encryption_required:true},own:own.clone(),key:key(own,false)};
  let p=StandardPolicy::new();let mut reader=DecryptorBuilder::from_bytes(blob)?.with_policy(&p,None,helper)?;let mut out=Vec::new();reader.read_to_end(&mut out)?;Ok(out)
 }
 #[test] fn detached_public_verification_v4_v6_and_tampering(){
  use pgp::serialize::SerializeInto;
  for hybrid in [false,true] {
   let cert=if hybrid {identity()} else {CertBuilder::new().add_userid("sender@example.invalid").add_signing_subkey().generate().unwrap().0};
   let p=StandardPolicy::new();let kp=cert.keys().secret().with_policy(&p,None).for_signing().next().unwrap().key().clone().into_keypair().unwrap();
   let public=cert.clone().strip_secret_key_material().to_vec().unwrap();
   let payload=format!("Content-Type: multipart/mixed; boundary=inside\r\n\r\n--inside\r\nContent-Type: text/plain\r\n\r\nSigned test body.\r\n--inside\r\nContent-Type: application/pgp-keys\r\nContent-Disposition: attachment; filename=public.pgp\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--inside--\r\n",B64.encode(&public)).into_bytes();
   let mut signature=Vec::new();{
    let mut signer=Signer::new(Message::new(&mut signature),kp).unwrap().detached().build().unwrap();signer.write_all(&payload).unwrap();signer.finalize().unwrap();
   }
   let public=cert.strip_secret_key_material().to_vec().unwrap();
   let mut request=serde_json::json!({"payload":B64.encode(&payload),"signature":B64.encode(&signature),"certificates":[B64.encode(&public)]});
   let result=verify_public(&request).unwrap();assert_eq!(result["signatures"][0]["status"],"valid");
   if let Ok(folder)=std::env::var("IWA_PUBLIC_TEST_FIXTURES") {
    // Test-only public fixtures, never production account or secret material.
    std::fs::write(std::path::Path::new(&folder).join(if hybrid{"v6.json"}else{"v4.json"}),serde_json::to_vec(&request).unwrap()).unwrap();
   }
   request["payload"]=serde_json::json!(B64.encode(b"tampered"));
   let bad=verify_public(&request).unwrap();
   assert_eq!(bad["signatures"][0]["status"],"invalid");
   assert_eq!(bad["signatures"][0]["fingerprint"],result["signatures"][0]["fingerprint"]);
   assert_eq!(bad["signatures"][0]["candidateOnly"],true);
   assert!(bad["signatures"][0].get("certificate").is_none());
   request["certificates"]=serde_json::json!([]);
   assert_eq!(verify_public(&request).unwrap()["signatures"][0]["status"],"unknown-key");
  }
 }
 #[test] fn signed_compressed_encrypted_roundtrip_and_rejections(){
  let alice=identity();let bob=identity();let mallory=identity();let payload=include_bytes!("../../tests/multipart-fixture.mime");
  let sealed=sealed_payload(key(&alice,true),alice.clone(),bob.clone(),payload).unwrap();
  assert_eq!(decrypt(&bob,&alice,&sealed).unwrap(),payload);
  assert!(decrypt(&bob,&mallory,&sealed).is_err());
  assert!(decrypt(&mallory,&alice,&sealed).is_err());
  let mut bad=sealed;let n=bad.len();bad[n-8]^=1;assert!(decrypt(&bob,&alice,&bad).is_err());
 }
}
