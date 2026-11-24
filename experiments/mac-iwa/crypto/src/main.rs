//! Production, pipe-only YubiKey component worker.
//!
//! Only identity/card reads and the two bounded private-component operations
//! are compiled into this executable. MIME/OpenPGP message construction,
//! packet decryption, verification oracles and fixture generation live in the
//! separately built `message_oracle` example, never in Native Messaging.
use anyhow::{ensure,bail,Context,Result};
use base64::{Engine,engine::general_purpose::STANDARD as B64};
use sequoia_openpgp as pgp;
use pgp::serialize::SerializeInto;
use pgp::cert::amalgamation::ValidAmalgamation;
use pgp::{Cert,parse::Parse,policy::StandardPolicy,types::PublicKeyAlgorithm as A};
use sequoia_pqmail_piv::{PublicKey,Level3Signer,process::{Config,Pkcs11Operation}};
use std::{io::{self,Read},path::PathBuf};
use zeroize::Zeroizing;
mod digest_sign;
mod component_decap;
mod identity_restore;
mod public_snapshot;

/// An explicit production capability contract is also checked by installers.
/// Retired message modes cannot be revived by supplying their old JSON shape.
const OPERATIONS:[&str;10]=["identity-current","identity-canonical","identity-restore",
 "identity-bundle-read","identity-key-snapshot","decryption-material",
 "signing-material","inspect-public","decapsulate-components","sign-digest"];
fn production_operation(v:&serde_json::Value)->Result<&str>{
 let op=field(v,"op")?;
 ensure!(OPERATIONS.contains(&op),"Unsupported production operation");Ok(op)
}
fn capabilities()->serde_json::Value {
 serde_json::json!({"service":"sequoia-iwa-hardware","version":1,
  "operations":OPERATIONS,"testOracle":false})
}
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
fn current_emails(cert:&Cert)->Vec<String> {
 let p=StandardPolicy::new();
 if let Ok(valid)=cert.with_policy(&p,None) {
  if valid.alive().is_ok() && !matches!(valid.revocation_status(),pgp::types::RevocationStatus::Revoked(_)) {
   return valid.userids().filter(|u|!matches!(u.revocation_status(),pgp::types::RevocationStatus::Revoked(_))).filter_map(|u|u.userid().email_normalized().ok().flatten()).collect();
  }
 }
 Vec::new()
}
/// Canonical public identity material used only after authenticated restore.
/// Reject keyrings and secret packets explicitly; the reviewed hash binds the
/// whole certification/subkey view, not merely its primary fingerprint.
fn canonical_identity(encoded:&str)->Result<serde_json::Value> {
 ensure!(encoded.len()<=174764,"Encoded certificate limit");
 let raw=B64.decode(encoded)?;ensure!(!raw.is_empty()&&raw.len()<=131072,"Certificate limit");
 let armor=String::from_utf8_lossy(&raw);ensure!(armor.matches("-----BEGIN PGP").count()<=1,"One certificate required");
 let mut parser=pgp::cert::CertParser::from_bytes(&raw)?;
 let cert=parser.next().context("One certificate required")??;
 ensure!(parser.next().is_none()&&!cert.is_tsk(),"One public certificate required");
 ensure!(cert.primary_key().key().version()==6,"v6 certificate required");
 let sign=selected(&cert,true)?;let recipient=selected(&cert,false)?;
 let emails=current_emails(&cert);ensure!(!emails.is_empty(),"Current certified email required");
 let bytes=cert.to_vec()?;ensure!(bytes.len()<=65536,"Certificate limit");
 use sha2::{Digest,Sha256};
 Ok(serde_json::json!({"certificate":B64.encode(&bytes),
  "certificateHash":Sha256::digest(&bytes).iter().map(|b|format!("{b:02x}")).collect::<String>(),
  "fingerprint":cert.fingerprint().to_hex(),"emails":emails,
  "signingFingerprint":sign.fingerprint().to_hex(),"recipientKey":recipient.fingerprint().to_hex()}))
}

fn execute()->Result<()> {
 let mut input=Zeroizing::new(Vec::new());io::stdin().take((LIMIT*4+1) as u64).read_to_end(&mut input)?;ensure!(input.len()<=LIMIT*4,"Input too large");
 let mut v:serde_json::Value=serde_json::from_slice(&input)?;input.clear();
 // Reject the operation before parsing a PIN, configuration or token input.
 // This is defense in depth independent of the Python/extension schema gates.
 production_operation(&v)?;
 if field(&v,"op")?=="identity-current" {
  // This display route proves the configured public certificate is supported,
  // without pretending that a physical key is present or selecting new slots.
  let encoded=field(&v,"certificate")?;let cert=public(encoded)?;
  selected(&cert,true)?;selected(&cert,false)?;
  println!("{}",serde_json::json!({"certificate":encoded,"fingerprint":cert.fingerprint().to_hex(),"slots":[
   {"role":"OpenPGP signing","slot":"9c","algorithm":"ML-DSA-65"},
   {"role":"OpenPGP signing","slot":"84","algorithm":"Ed25519"},
   {"role":"OpenPGP decryption","slot":"9d","algorithm":"ML-KEM-768"},
   {"role":"OpenPGP decryption","slot":"85","algorithm":"X25519"}]}));return Ok(());
 }
 if field(&v,"op")?=="identity-canonical" {
  // Public-only selection binding, evaluated before PIN/private configuration.
  println!("{}",canonical_identity(field(&v,"certificate")?)?);return Ok(());
 }
 if field(&v,"op")?=="identity-restore" {
  // Public-only route: no PIN extraction or private-operation config exists.
  println!("{}",identity_restore::preview(&v)?);return Ok(());
 }
 if matches!(field(&v,"op")?,"identity-bundle-read"|"identity-key-snapshot") {
  // Raw public transport only: no bundle/certificate decoder or PIN access.
  println!("{}",public_snapshot::snapshot(&v)?);return Ok(());
 }
 if field(&v,"op")?=="decryption-material" {
  let own=public(field(&v,"own")?)?;let key=selected(&own,false)?;
  println!("{}",serde_json::json!({"recipientKey":key.fingerprint().to_hex()}));return Ok(());
 }
 if field(&v,"op")?=="signing-material" {
  let own=public(field(&v,"own")?)?;let key=selected(&own,true)?;
  println!("{}",serde_json::json!({"signingFingerprint":key.fingerprint().to_hex()}));return Ok(());
 }
 if field(&v,"op")?=="inspect-public" {
  let cert=public(field(&v,"certificate")?)?;
  println!("{}",serde_json::json!({"fingerprint":cert.fingerprint().to_hex(),"version":cert.primary_key().key().version(),"algorithms":cert.keys().map(|k|format!("{}",k.key().pk_algo())).collect::<Vec<_>>(),"emails":current_emails(&cert)}));return Ok(());
 }
 let pin=Zeroizing::new(v["pin"].take().as_str().context("PIN required")?.as_bytes().to_vec());
 let cfg=&v["config"];let path=|n|->Result<PathBuf>{Ok(PathBuf::from(field(cfg,n)?))};
 let config=Config{python:path("python")?,adapters:path("adapters")?,openssl:path("openssl")?,provider:path("provider")?,module:path("module")?,serial:field(cfg,"serial")?.into()};
 let own=public(field(&v,"own")?)?;
 if field(&v,"op")?=="decapsulate-components" {
  // Only fixed-key component inputs cross this boundary. Recipient packet
  // parsing, hybrid combining and session-key unwrap now belong to WASM.
  let key=selected(&own,false)?;component_decap::validate_request(&v,&key)?;
  let result=component_decap::decapsulate(&key,Pkcs11Operation::new(config,pin)?,&v)?;
  println!("{}",result);return Ok(());
 }
 if field(&v,"op")?=="sign-digest" {
  // Validate the digest and fixed public key before the operation-scoped PIN is
  // passed to PKCS#11. No MIME, arbitrary slot, or supplied key is accepted.
  let key=selected(&own,true)?;digest_sign::validate_request(&v,&key)?;
  let signer=Level3Signer::new(key,Pkcs11Operation::new(config,pin)?)?;
  println!("{}",digest_sign::sign(signer,&v)?);return Ok(());
 }
 // Every accepted private operation returned above. Keep this hard stop if
 // the capability list changes without a matching reviewed implementation.
 bail!("Unsupported production operation")
}
// PIV_UNLOCK_DIAGNOSTICS: safe component status protocol for investigating the
// intermittent vault failure, separate from Python's optional on-disk history.
// If retiring this protocol, replace main's status emission with a fixed generic
// error and keep exit(1). Update native/chat_bridge.py, native/host.py, piv_soak.py
// and diagnostics tests together. Never replace it with Debug/Display of the
// full error chain, and never remove failure propagation or add a retry.
// Map errors to a closed vocabulary. Never print the error chain: provider
// diagnostics can contain input bytes. Component identification is sufficient
// to distinguish a token failure from later packet/session-key validation.
fn diagnostic_code(error: &anyhow::Error) -> &'static str {
 for cause in error.chain() {
  let message=cause.to_string();
  if message.starts_with("PKCS#11 ML-KEM-768 failed (exit ") {return "MLKEM_FAILED";}
  if message.starts_with("PKCS#11 X25519 failed (exit ") {return "X25519_FAILED";}
  if message=="PKCS#11 adapter timed out or rejected input; no retry" {return "ADAPTER_TIMEOUT_OR_INPUT";}
  if message.starts_with("Incorrect ML-KEM-768 response size") {return "MLKEM_RESPONSE_SIZE";}
  if message.starts_with("Incorrect X25519 response size") {return "X25519_RESPONSE_SIZE";}
 }
 "CRYPTO_FAILED"
}
fn main(){
 // Capabilities are public constants; this path never reads stdin, config,
 // files, credentials or a card. Refuse every other command-line argument.
 let args:Vec<_>=std::env::args().skip(1).collect();
 if args==["--capabilities"] {println!("{}",capabilities());return;}
 if !args.is_empty(){eprintln!("IWA_CRYPTO_STATUS=CRYPTO_FAILED");std::process::exit(1);}
 if let Err(error)=execute(){eprintln!("IWA_CRYPTO_STATUS={}",diagnostic_code(&error));std::process::exit(1)}
}

#[test]
fn diagnostics_do_not_echo_error_data() {
 assert_eq!(diagnostic_code(&anyhow::anyhow!("private data")),"CRYPTO_FAILED");
 for (component,code) in [("ML-KEM-768","MLKEM_FAILED"),("X25519","X25519_FAILED")] {
  let e=anyhow::anyhow!("PKCS#11 {} failed (exit Some(1)); no retry",component).context("Decapsulation failed; no retry");
  assert_eq!(diagnostic_code(&e),code);
 }
}

#[cfg(test)]
mod tests {
 use super::*;
 use pgp::cert::{CertBuilder,CipherSuite};
 fn identity()->Cert {CertBuilder::new().set_profile(pgp::Profile::RFC9580).unwrap().set_cipher_suite(CipherSuite::MLDSA65_Ed25519).add_userid("test@example.invalid").add_signing_subkey().add_transport_encryption_subkey().generate().unwrap().0}
 #[test]
 fn selected_identity_is_canonical_public_only_and_one_certificate() {
  let secret=identity();let public=secret.clone().strip_secret_key_material();
  let bytes=public.to_vec().unwrap();let info=canonical_identity(&B64.encode(&bytes)).unwrap();
  assert_eq!(info["certificate"],B64.encode(&bytes));
  assert_eq!(info["fingerprint"],public.fingerprint().to_hex());
  assert_eq!(info["emails"],serde_json::json!(["test@example.invalid"]));
  assert_eq!(info["signingFingerprint"],selected(&public,true).unwrap().fingerprint().to_hex());
  assert_eq!(info["recipientKey"],selected(&public,false).unwrap().fingerprint().to_hex());
  assert!(canonical_identity(&B64.encode(secret.as_tsk().to_vec().unwrap())).is_err());
  let mut ring=bytes.clone();ring.extend(identity().strip_secret_key_material().to_vec().unwrap());
  assert!(canonical_identity(&B64.encode(ring)).is_err());
  assert!(canonical_identity("").is_err());
 }

 #[test]
 fn production_rejects_message_modes_before_private_inputs() {
  // Deliberately omit PIN/configuration: dispatch must reject these modes
  // without touching any key, executing a process or accepting test payloads.
  for op in ["seal","open","sign-browser","open-browser","decapsulate-browser",
             "verify-detached","check-ciphertext","generate","unknown"] {
   let error=production_operation(&serde_json::json!({"op":op})).unwrap_err();
   assert_eq!(error.to_string(),"Unsupported production operation");
  }
  for op in OPERATIONS {assert_eq!(production_operation(&serde_json::json!({"op":op})).unwrap(),op);}
  assert_eq!(capabilities()["testOracle"],false);
 }
}
