//! Verification, split-phase signing, public-key encryption and message decryption.
//! No network, token, PIN, filesystem or trust-store mutation is exposed.
//! Public/hardware workers remain public-only; the separate opt-in software
//! provider decrypts bounded encrypted identities for one operation per worker.
use anyhow::{ensure,Context,Result};
use base64::{Engine,engine::general_purpose::STANDARD as B64};
use sequoia_openpgp as pgp;
use pgp::{Cert,KeyHandle,parse::{Parse,stream::{VerificationHelper,MessageStructure,MessageLayer}},policy::StandardPolicy};
use pgp::serialize::SerializeInto;
use pgp::cert::amalgamation::ValidAmalgamation;
use wasm_bindgen::prelude::*;
mod libre;
mod signing;
pub use signing::{prepare_signing, finalize_signing, cancel_signing};
mod decryption;
pub use decryption::{prepare_decryption, finalize_decryption, cancel_decryption, match_recipients};
mod certificates;
pub use certificates::{inspect_public, inspect_identity};
mod bundle;
pub use bundle::inspect_bundle;
// Software custody is a separate, opt-in, one-shot worker API. Hardware paths
// continue accepting public material only; no native fallback handles secrets.
mod companion;
pub use companion::{companion_inspect, companion_complete};
mod software;
pub use software::{software_inspect, software_sign, software_decapsulate, software_generate, software_export, software_backup_material, software_import_p12, software_p12_verify_mac};
const LIMIT:usize=262144;
fn field<'a>(v:&'a serde_json::Value,k:&str)->Result<&'a str>{v[k].as_str().context("Missing field")}
fn public(raw:&str)->Result<Cert>{let cert=Cert::from_bytes(&B64.decode(raw)?)?;ensure!(!cert.is_tsk(),"Public certificate only");Ok(cert)}
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
     Ok(good)=>serde_json::json!({"status":"valid","fingerprint":good.ka.cert().fingerprint().to_hex(),"signingFingerprint":good.ka.key().fingerprint().to_hex(),"algorithm":format!("{}",good.ka.key().pk_algo()),"pqSigning":matches!(good.ka.key().pk_algo(),pgp::types::PublicKeyAlgorithm::MLDSA65_Ed25519|pgp::types::PublicKeyAlgorithm::MLDSA87_Ed448),"certificate":B64.encode(good.ka.cert().to_vec()?),"emails":current_emails(good.ka.cert())}),
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
 let signature=B64.decode(field(v,"signature")?)?;
 if libre::is_signature(&signature){return libre::verify_detached(v);}
 // Literal metadata is meaningful only to the explicitly selected v5 parser.
 // A normal RFC signature cannot opt into an alternate digest transcript.
 ensure!(v.get("literalMetadata").is_none(),"Unexpected literal metadata");
 let encoded=v["certificates"].as_array().context("Certificates required")?;
 ensure!(encoded.len()<=32,"Too many certificates");
 // Unusable attachments are not trusted and must not prevent trying saved keys.
 let total:usize=encoded.iter().map(|x|x.as_str().map(str::len).unwrap_or(usize::MAX/64)).sum();
 ensure!(total<=280000,"Certificates too large");
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

/// The caller supplies exact signed bytes extracted by the IWA MIME parser or
/// authenticated native decryption. Trust is deliberately absent: a valid signature does not grant trust.
/// A bad signature may name a candidate certificate, never an authenticated sender.
#[wasm_bindgen]
pub fn verify_detached(input:&str)->Result<String,JsValue>{
 let run=||->Result<String>{
  ensure!(input.len()<=800000,"Request too large");
  let request:serde_json::Value=serde_json::from_str(input)?;
  Ok(serde_json::to_string(&verify_public(&request)?)?)
 };
 run().map_err(|_|JsValue::from_str("Verification request rejected"))
}

// Encryption accepts only public certificates and already-signed packets. The
// recipient fingerprint and mailbox must match the native trusted selection.
// Reverify the signature here before wrapping the unchanged packet stream.
fn encrypt_public(v:&serde_json::Value)->Result<serde_json::Value> {
 use std::io::{Read,Write};
 use pgp::serialize::stream::{Message,Encryptor,Compressor};
 use pgp::types::{PublicKeyAlgorithm as A,CompressionAlgorithm};
 let own_raw=B64.decode(field(v,"senderCertificate")?)?;
 let peer_raw=B64.decode(field(v,"recipientCertificate")?)?;
 if libre::is_certificate(&own_raw)||libre::is_certificate(&peer_raw){return libre::encrypt_signed(v);}
 let own=public(field(v,"senderCertificate")?)?;
 let peer=public(field(v,"recipientCertificate")?)?;
 ensure!(matches!(peer.primary_key().key().version(),4|6)&&matches!(own.primary_key().key().version(),4|6),"Supported OpenPGP version required");
 ensure!(peer.fingerprint().to_hex()==field(v,"recipientFingerprint")?,"Recipient mismatch");
 ensure!(current_emails(&peer).iter().any(|e|e==field(v,"recipientEmail").unwrap_or("")),"Recipient mailbox mismatch");
 let signed=B64.decode(field(v,"signed")?)?;
 ensure!(!signed.is_empty() && signed.len()<=LIMIT,"Signed packet limit");
 let payload=B64.decode(field(v,"payload")?)?;
 ensure!(payload.len()<=LIMIT,"Payload limit");
 let p=StandardPolicy::new();
 let helper=PublicVerify{certs:vec![own.clone()],results:Vec::new()};
 let mut verifier=pgp::parse::stream::VerifierBuilder::from_bytes(&signed)?.with_policy(&p,None,helper)?;
 let mut clear=Vec::new();verifier.by_ref().take((LIMIT+1) as u64).read_to_end(&mut clear)?;
 ensure!(clear==payload,"Signed payload mismatch");
 let results=verifier.into_helper().results;
 ensure!(results.len()==1 && results[0]["status"]=="valid" && results[0]["fingerprint"]==own.fingerprint().to_hex(),"One valid message signature required");
 // Selection is derived from current certified usages. Prefer hybrid keys
 // within either certificate version; a classical-only contact is explicitly
 // warned about by the UI before any software signing operation.
 let all:Vec<_>=peer.keys().with_policy(&p,None).alive().revoked(false).for_transport_encryption().filter(|k|certificates::encryption_supported(k.key())).collect();
 let has_hybrid=all.iter().any(|k|matches!(k.key().pk_algo(),A::MLKEM768_X25519|A::MLKEM1024_X448));
 let recipients:Vec<_>=all.into_iter().filter(|k|!has_hybrid||matches!(k.key().pk_algo(),A::MLKEM768_X25519|A::MLKEM1024_X448)).collect();
 ensure!(recipients.len()==1,"Exactly one supported recipient required");
 // RustCrypto obtains fresh randomness through getrandom's wasm_js backend;
 // no session key or random seed is supplied by JavaScript or the native host.
 let mut cipher=Vec::new();
 {
  let encrypted=Encryptor::for_recipients(Message::new(&mut cipher),recipients).build()?;
  let mut compressed=Compressor::new(encrypted).algo(CompressionAlgorithm::Zlib).build()?;
  compressed.write_all(&signed)?;compressed.finalize()?;
 }
 ensure!(cipher.len()<=LIMIT,"Ciphertext limit");
 Ok(serde_json::json!({"cipher":B64.encode(cipher)}))
}

#[wasm_bindgen]
pub fn encrypt_signed(input:&str)->Result<String,JsValue>{
 let run=||->Result<String>{
  ensure!(input.len()<=800000,"Request too large");
  let request:serde_json::Value=serde_json::from_str(input)?;
  Ok(serde_json::to_string(&encrypt_public(&request)?)?)
 };
 run().map_err(|_|JsValue::from_str("Encryption request rejected"))
}

// The session key is released by native PIV decapsulation for one ciphertext.
// This helper never requests hardware operations and does not retry a bad key.
struct SessionOpen {
 key:pgp::crypto::SessionKey, algorithm:pgp::types::SymmetricAlgorithm,
 recipient:pgp::Fingerprint, signatures:Vec<u8>, vault:bool,
}
impl VerificationHelper for SessionOpen {
 fn get_certs(&mut self,_:&[KeyHandle])->Result<Vec<Cert>> {Ok(Vec::new())}
 fn check(&mut self,structure:MessageStructure)->Result<()> {
  let mut encrypted=false;let mut count=0;
  for layer in structure.iter(){match layer {
   // Message compatibility permits authenticated SEIPDv1/MDC; the packet
   // preflight below rejects unauthenticated Symmetrically Encrypted Data.
   // Existing vault wrappers remain v6/AEAD only.
   MessageLayer::Encryption{aead_algo,..}=>{if self.vault{ensure!(aead_algo.is_some(),"Vault AEAD required");}encrypted=true;},
   MessageLayer::Compression{..}=>{},
   MessageLayer::SignatureGroup{results}=>for result in results {
    let sig=match result {Err(pgp::parse::stream::VerificationError::MissingKey{sig})=>sig,_=>anyhow::bail!("Unsupported signature structure")};
    self.signatures.extend(pgp::Packet::Signature((*sig).clone()).to_vec()?);count+=1;
   }
  }}
  ensure!(encrypted && count==if self.vault {0}else{1} && self.signatures.len()<=65536,"Unexpected signature structure");Ok(())
 }
}
impl pgp::parse::stream::DecryptionHelper for SessionOpen {
 fn decrypt(&mut self,pk:&[pgp::packet::PKESK],sk:&[pgp::packet::SKESK],hint:Option<pgp::types::SymmetricAlgorithm>,decrypt:&mut dyn FnMut(Option<pgp::types::SymmetricAlgorithm>,&pgp::crypto::SessionKey)->bool)->Result<Option<Cert>> {
  ensure!(pk.len()==1&&sk.is_empty()&&pk[0].recipient().map(|r|r.aliases(pgp::KeyHandle::from(self.recipient.clone()))).unwrap_or(false),"Recipient mismatch");
  if self.vault{ensure!(pk[0].version()==6,"Vault recipient version");}
  ensure!(hint.map(|a|a==self.algorithm).unwrap_or(true)&&decrypt(Some(self.algorithm),&self.key),"Authentication failed");Ok(None)
 }
}
fn decrypt_session_mode(v:&serde_json::Value,vault:bool)->Result<serde_json::Value> {
 use std::io::Read;
 use sha2::{Digest,Sha256};
 use pgp::types::SymmetricAlgorithm as S;
 let cipher=B64.decode(field(v,"cipher")?)?;
 ensure!(!cipher.is_empty() && cipher.len()<=LIMIT,"Ciphertext limit");
 ensure!(format!("{:x}",Sha256::digest(&cipher))==field(v,"cipherHash")?,"Ciphertext binding mismatch");
 // This public export can be called directly, so require authenticated data
 // here too rather than relying only on the split-phase recipient parser.
 let pile=pgp::PacketPile::from_bytes(&cipher)?;let packets:Vec<_>=pile.children().collect();
 ensure!(packets.len()==2&&matches!(packets[0],pgp::Packet::PKESK(_))&&matches!(packets[1],pgp::Packet::SEIP(_)),"One PKESK and authenticated SEIPD required");
 let code=v["algorithm"].as_u64().context("Algorithm required")?;ensure!(code<=255,"Invalid algorithm");
 let algorithm=S::from(code as u8);ensure!(matches!(algorithm,S::AES128|S::AES192|S::AES256),"AES required");
 let key:pgp::crypto::SessionKey=B64.decode(field(v,"sessionKey")?)?.into();
 ensure!(key.len()==algorithm.key_size()?,"Session key length mismatch");
 let recipient:pgp::Fingerprint=field(v,"recipientKey")?.parse()?;
 let helper=SessionOpen{key,algorithm,recipient,signatures:Vec::new(),vault};
 let p=StandardPolicy::new();
 let mut reader=pgp::parse::stream::DecryptorBuilder::from_bytes(&cipher)?.with_policy(&p,None,helper)?;
 let mut clear=Vec::new();reader.by_ref().take((LIMIT+1) as u64).read_to_end(&mut clear)?;
 ensure!(clear.len()<=LIMIT,"Plaintext limit");
 // read_to_end must authenticate the final AEAD tag before any plaintext result
 // is returned. The worker then verifies the signature and trusted addresses.
 let helper=reader.into_helper();
 Ok(serde_json::json!({"raw":B64.encode(clear),"signature":B64.encode(helper.signatures),"encrypted":true}))
}
#[wasm_bindgen]
pub fn decrypt_with_session_key(input:&str)->Result<String,JsValue>{
 let run=||->Result<String>{
  ensure!(input.len()<=400000,"Request too large");
  let request:serde_json::Value=serde_json::from_str(input)?;
  Ok(serde_json::to_string(&decrypt_session_mode(&request,false)?)?)
 };
 run().map_err(|_|JsValue::from_str("Decryption request rejected"))
}

// Vault envelopes are deliberately unsigned, with an explicit purpose and
// vault/wrapper identifiers inside authenticated encryption. This separate API
// cannot relax the signed-message reader's signature requirement.
#[wasm_bindgen]
pub fn wrap_vault_key(input:&str)->Result<String,JsValue>{
 let run=||->Result<String>{
  use std::io::Write;
  use pgp::serialize::stream::{Message,Encryptor,LiteralWriter};
  ensure!(input.len()<100000,"Request too large");
  let v:serde_json::Value=serde_json::from_str(input)?;
  let cert=public(field(&v,"certificate")?)?;let p=StandardPolicy::new();
  ensure!(cert.primary_key().key().version()==6,"v6 required");
  let keys:Vec<_>=cert.keys().with_policy(&p,None).alive().revoked(false).for_transport_encryption().filter(|k|k.key().pk_algo()==pgp::types::PublicKeyAlgorithm::MLKEM768_X25519).collect();
  ensure!(keys.len()==1,"One supported PIV hybrid key required");
  let fingerprint=keys[0].key().fingerprint().to_hex();
  let secret=B64.decode(field(&v,"secret")?)?;ensure!(secret.len()==32,"32-byte wrapping secret required");
  ensure!(field(&v,"vaultId")?.len()==36 && field(&v,"wrapperId")?.len()==36,"Invalid identifiers");
  let payload=serde_json::json!({"purpose":"sequoia-iwa-vault-wrap-v1","vaultId":v["vaultId"],"wrapperId":v["wrapperId"],"secret":v["secret"]});
  let mut out=Vec::new();{
   let encrypted=Encryptor::for_recipients(Message::new(&mut out),keys).build()?;
   let mut writer=LiteralWriter::new(encrypted).build()?;writer.write_all(&serde_json::to_vec(&payload)?)?;writer.finalize()?;
  }
  Ok(serde_json::json!({"cipher":B64.encode(out),"recipientKey":fingerprint}).to_string())
 };
 run().map_err(|_|JsValue::from_str("Vault wrapping rejected"))
}
#[wasm_bindgen]
pub fn unwrap_vault_key(input:&str)->Result<String,JsValue>{
 let run=||->Result<String>{
  ensure!(input.len()<100000,"Request too large");let v:serde_json::Value=serde_json::from_str(input)?;
  let result=decrypt_session_mode(&v,true)?;
  let raw=B64.decode(field(&result,"raw")?)?;ensure!(raw.len()<1024,"Vault payload limit");
  let value:serde_json::Value=serde_json::from_slice(&raw)?;
  ensure!(value["purpose"]=="sequoia-iwa-vault-wrap-v1" && value["vaultId"]==v["vaultId"] && value["wrapperId"]==v["wrapperId"],"Vault binding mismatch");
  ensure!(B64.decode(field(&value,"secret")?)?.len()==32,"Invalid wrapping secret");
  Ok(serde_json::json!({"secret":value["secret"]}).to_string())
 };
 run().map_err(|_|JsValue::from_str("Vault unwrapping rejected"))
}

#[cfg(test)]
mod profile_tests;

mod smartcard;
pub use smartcard::smartcard_signing_input;

mod entropy;
