//! Experimental public-only verifier. No MIME parser, network, token, PIN,
//! private-key operation, filesystem or trust-store mutation is exposed.
use anyhow::{ensure,Context,Result};
use base64::{Engine,engine::general_purpose::STANDARD as B64};
use sequoia_openpgp as pgp;
use pgp::{Cert,KeyHandle,parse::{Parse,stream::{VerificationHelper,MessageStructure,MessageLayer}},policy::StandardPolicy};
use pgp::serialize::SerializeInto;
use pgp::cert::amalgamation::ValidAmalgamation;
use wasm_bindgen::prelude::*;
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

/// The caller supplies exact signed bytes extracted by the existing native MIME
/// parser. Trust is deliberately absent: a valid signature does not grant trust.
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
