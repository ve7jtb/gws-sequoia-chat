//! Disposable OpenSSL-backed oracle for WASM signing regressions.
//!
//! This example is never installed or called by the native host. It uses newly
//! generated software secrets only; real hardware certificates/PINs must never
//! be supplied to fixture generation. Output files belong in a private test dir.
use anyhow::{ensure,bail,Context,Result};
use base64::{Engine,engine::general_purpose::STANDARD as B64};
use sequoia_openpgp as pgp;
use pgp::{Cert,KeyHandle,parse::{Parse,stream::{MessageLayer,MessageStructure,VerificationHelper}},policy::StandardPolicy,types::PublicKeyAlgorithm as A};
use pgp::serialize::SerializeInto;
use sequoia_pqmail_piv::PublicKey;
use std::{io::{self,Read,Write},path::Path};
#[path="../src/digest_sign.rs"] mod digest_sign;
fn field<'a>(v:&'a serde_json::Value,k:&str)->Result<&'a str>{v[k].as_str().context("Missing field")}
fn selected(cert:&Cert)->Result<PublicKey> {
 let p=StandardPolicy::new();let keys:Vec<_>=cert.keys().with_policy(&p,None).alive().revoked(false).for_signing().filter(|k|k.key().pk_algo()==A::MLDSA65_Ed25519).collect();
 ensure!(keys.len()==1,"One signing key required");Ok(keys[0].key().clone().role_into_unspecified())
}
struct Verify{cert:Cert}
impl VerificationHelper for Verify {
 fn get_certs(&mut self,_:&[KeyHandle])->Result<Vec<Cert>>{Ok(vec![self.cert.clone()])}
 fn check(&mut self,s:MessageStructure)->Result<()> {
  let expected=selected(&self.cert)?.fingerprint();let mut count=0;
  for l in s.iter(){if let MessageLayer::SignatureGroup{results}=l {for r in results{
   let good=r.as_ref().map_err(|_|anyhow::anyhow!("Invalid signature"))?;
   ensure!(good.ka.key().fingerprint()==expected,"Wrong signing key");count+=1;
  }}}
  ensure!(count==1,"One signature required");Ok(())
 }
}
fn main()->Result<()> {
 let args:Vec<_>=std::env::args().collect();ensure!(args.len()==3,"generate directory | sign secret | verify public");
 if args[1]=="generate" {
  use pgp::cert::{CertBuilder,CipherSuite};
  let directory=Path::new(&args[2]);std::fs::create_dir_all(directory)?;
  #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(directory,std::fs::Permissions::from_mode(0o700))?;}
  let mut certs=Vec::new();
  for (name,email) in [("sender","test@example.invalid"),("recipient","recipient@example.invalid")] {
   let (cert,_)=CertBuilder::new().set_profile(pgp::Profile::RFC9580)?.set_cipher_suite(CipherSuite::MLDSA65_Ed25519).add_userid(email).add_signing_subkey().add_transport_encryption_subkey().generate()?;
   std::fs::write(directory.join(format!("{name}-secret.pgp")),cert.as_tsk().to_vec()?)?;
   std::fs::write(directory.join(format!("{name}-public.pgp")),cert.clone().strip_secret_key_material().to_vec()?)?;
   certs.push(cert.strip_secret_key_material());
  }
  // Exact MIME/attachment bytes are compared by the Node runner after native
  // signature verification, so a packet-layout success cannot mask data loss.
  let payload=include_bytes!("../../tests/multipart-fixture.mime");
  let request=serde_json::json!({"requestId":"A".repeat(64),"senderEmail":"test@example.invalid",
   "senderCertificate":B64.encode(certs[0].to_vec()?),"payload":B64.encode(payload),
   "recipientCertificate":B64.encode(certs[1].to_vec()?),"recipientEmail":"recipient@example.invalid",
   "recipientFingerprint":certs[1].fingerprint().to_hex()});
  std::fs::write(directory.join("request.json"),serde_json::to_vec(&request)?)?;return Ok(());
 }
 let cert=Cert::from_file(&args[2])?;
 let mut bytes=Vec::new();io::stdin().take(800001).read_to_end(&mut bytes)?;ensure!(bytes.len()<=800000,"Test input limit");
 let request:serde_json::Value=serde_json::from_slice(&bytes)?;
 if args[1]=="sign" {
  let wanted=selected(&cert)?.fingerprint();
  let key=cert.keys().secret().find(|k|k.key().fingerprint()==wanted).context("Secret signing key required")?.key().clone().role_into_unspecified().into_keypair()?;
  println!("{}",digest_sign::sign(key,&request)?);return Ok(());
 }
 if args[1]=="verify" {
  let signed=B64.decode(field(&request,"signed")?)?;let p=StandardPolicy::new();
  let mut verifier=pgp::parse::stream::VerifierBuilder::from_bytes(&signed)?.with_policy(&p,None,Verify{cert:cert.clone()})?;
  let mut clear=Vec::new();verifier.by_ref().take(262145).read_to_end(&mut clear)?;ensure!(clear.len()<=262144,"Payload limit");
  if let Some(sig)=request["signature"].as_str(){
   let detached=B64.decode(sig)?;let mut v=pgp::parse::stream::DetachedVerifierBuilder::from_bytes(&detached)?.with_policy(&p,None,Verify{cert})?;v.verify_bytes(&clear)?;
  }
  io::stdout().write_all(&clear)?;return Ok(());
 }
 bail!("Unknown test operation")
}
