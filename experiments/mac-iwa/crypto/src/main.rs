//! Bounded, pipe-only cryptographic worker. No network, provisioning or files
//! containing plaintext. The native host owns account/contact authorization.
use anyhow::{ensure,bail,Context,Result};
use base64::{Engine,engine::general_purpose::STANDARD as B64};
use sequoia_openpgp as pgp;
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
fn execute()->Result<()> {
 let mut input=Zeroizing::new(Vec::new());io::stdin().take((LIMIT*4+1) as u64).read_to_end(&mut input)?;ensure!(input.len()<=LIMIT*4,"Input too large");
 let mut v:serde_json::Value=serde_json::from_slice(&input)?;input.clear();
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
 #[test] fn signed_compressed_encrypted_roundtrip_and_rejections(){
  let alice=identity();let bob=identity();let mallory=identity();let payload=include_bytes!("../../tests/multipart-fixture.mime");
  let sealed=sealed_payload(key(&alice,true),alice.clone(),bob.clone(),payload).unwrap();
  assert_eq!(decrypt(&bob,&alice,&sealed).unwrap(),payload);
  assert!(decrypt(&bob,&mallory,&sealed).is_err());
  assert!(decrypt(&mallory,&alice,&sealed).is_err());
  let mut bad=sealed;let n=bad.len();bad[n-8]^=1;assert!(decrypt(&bob,&alice,&bad).is_err());
 }
}
