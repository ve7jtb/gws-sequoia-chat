//! Fixed-key private component operations for browser-owned OpenPGP recovery.
//!
//! This module deliberately accepts no PKESK, full ciphertext, wrapped session
//! key, symmetric algorithm or browser-supplied hardware slot. WASM retains and
//! validates those structures. Native code checks the configured recipient and
//! live component public keys, executes exactly two existing PKCS#11 operations,
//! then returns their shares bound to the opaque browser operation identifiers.
use super::*;
use pgp::crypto::mpi;
use sequoia_pqmail_piv::{Backend,Operation,public_spki};

const BINDINGS:[&str;5]=["requestId","cipherHash","recipientKey","mlkemCiphertext","x25519Ephemeral"];

fn hex(value:&str,upper:bool)->bool {
 value.len()==64 && value.bytes().all(|b|b.is_ascii_digit() ||
  if upper {(b'A'..=b'F').contains(&b)} else {(b'a'..=b'f').contains(&b)})
}

fn octets(v:&serde_json::Value,name:&str,size:usize)->Result<Vec<u8>> {
 let encoded=field(v,name)?;
 ensure!(encoded.len()==4*((size+2)/3),"Invalid component encoding");
 let bytes=B64.decode(encoded)?;
 // Canonical base64 binds a single representation, avoiding equivalent but
 // unequal encodings between the native response and retained WASM request.
 ensure!(bytes.len()==size && B64.encode(&bytes)==encoded,"Invalid component encoding");
 Ok(bytes)
}

/// Validate public inputs before any backend call, including an all-zero X25519
/// input. Invalid/non-contributory points which survive this cheap input check
/// are still rejected by the backend or the all-zero shared-secret check below.
pub(crate) fn validate_request(v:&serde_json::Value,key:&PublicKey)->Result<(Vec<u8>,Vec<u8>)> {
 ensure!(key.version()==6 && key.pk_algo()==A::MLKEM768_X25519,"Level 3 v6 encryption key required");
 ensure!(hex(field(v,"requestId")?,true) && hex(field(v,"cipherHash")?,false),"Invalid decryption binding");
 ensure!(field(v,"recipientKey")?==key.fingerprint().to_hex(),"Wrong configured encryption key");
 let ml=octets(v,"mlkemCiphertext",1088)?;
 let ec=octets(v,"x25519Ephemeral",32)?;
 ensure!(ec.iter().any(|b|*b!=0),"Invalid X25519 public input");
 Ok((ml,ec))
}

/// Release shares only after BOTH operations succeed. The backend's finish is
/// invoked on every success/error path to erase its operation-scoped PIN. There
/// is no retry, classical fallback, combiner, session-key unwrap or partial print.
pub(crate) fn decapsulate<B:Backend>(key:&PublicKey,mut backend:B,v:&serde_json::Value)->Result<serde_json::Value> {
 let result=(|| {
  let (cipher,ephemeral)=validate_request(v,key)?;
  let mpi::PublicKey::MLKEM768_X25519{ecdh,mlkem}=key.mpis() else {bail!("Wrong encryption algorithm")};
  let ml=backend.execute(Operation::MlKem768,&public_spki(Operation::MlKem768,mlkem.as_ref())?,&cipher)?;
  ensure!(ml.len()==32,"Incorrect ML-KEM-768 response size");
  let ec=backend.execute(Operation::X25519,&public_spki(Operation::X25519,ecdh.as_ref())?,
                         &public_spki(Operation::X25519,&ephemeral)?)?;
  ensure!(ec.len()==32,"Incorrect X25519 response size");
  ensure!(ec.iter().any(|b|*b!=0),"Rejected all-zero X25519 shared secret");
  let mut reply=serde_json::Map::new();
  for name in BINDINGS {reply.insert(name.into(),v[name].clone());}
  reply.insert("mlkemSecret".into(),serde_json::Value::String(B64.encode(&*ml)));
  reply.insert("x25519Secret".into(),serde_json::Value::String(B64.encode(&*ec)));
  // The response is serialized once to the parent pipe, then the short-lived
  // worker exits. The Zeroizing backend outputs are dropped before this return;
  // JSON/base64 copies cannot promise zeroization and are never logged/stored.
  Ok(serde_json::Value::Object(reply))
 })();
 backend.finish();
 result
}

#[cfg(test)]
mod tests {
 use super::*;
 use std::sync::{Arc,Mutex};
 #[derive(Default)] struct State { calls:Vec<Operation>,finished:usize }
 struct Fake {state:Arc<Mutex<State>>,fail:Option<Operation>,bad_length:bool,zero_ec:bool}
 impl Backend for Fake {
  fn execute(&mut self,op:Operation,spki:&[u8],input:&[u8])->Result<Zeroizing<Vec<u8>>> {
   self.state.lock().unwrap().calls.push(op);
   // The backend receives only expected SPKI and narrow algorithm-specific
   // inputs. In particular, no OpenPGP packet or browser path reaches it.
   ensure!(spki.starts_with(&[0x30]),"Expected SPKI");
   ensure!(input.len()==if op==Operation::MlKem768{1088}else{44},"Wrong input shape");
   ensure!(self.fail!=Some(op),"Synthetic backend failure");
   Ok(Zeroizing::new(vec![if op==Operation::X25519&&self.zero_ec{0}else{7};if self.bad_length{31}else{32}]))
  }
  fn finish(&mut self){self.state.lock().unwrap().finished+=1;}
 }
 fn material()->(PublicKey,serde_json::Value) {
  use pgp::cert::{CertBuilder,CipherSuite};
  let(cert,_)=CertBuilder::new().set_profile(pgp::Profile::RFC9580).unwrap()
   .set_cipher_suite(CipherSuite::MLDSA65_Ed25519).add_transport_encryption_subkey().generate().unwrap();
  let key=selected(&cert,false).unwrap();
  let v=serde_json::json!({"requestId":"A".repeat(64),"cipherHash":"b".repeat(64),
   "recipientKey":key.fingerprint().to_hex(),"mlkemCiphertext":B64.encode([3;1088]),"x25519Ephemeral":B64.encode([9;32])});
  (key,v)
 }
 fn fake(state:&Arc<Mutex<State>>)->Fake{Fake{state:state.clone(),fail:None,bad_length:false,zero_ec:false}}
 #[test] fn rejects_bad_binding_before_either_private_operation() {
  let(key,request)=material();
  for(name,value) in [("requestId",serde_json::json!("x".repeat(64))),("cipherHash",serde_json::json!("A".repeat(64))),
   ("recipientKey",serde_json::json!("0".repeat(64))),("mlkemCiphertext",serde_json::json!(B64.encode([0;1087]))),
   ("x25519Ephemeral",serde_json::json!(B64.encode([0;32])))] {
   let mut v=request.clone();v[name]=value;let state=Arc::new(Mutex::new(State::default()));
   assert!(decapsulate(&key,fake(&state),&v).is_err());
   let s=state.lock().unwrap();assert!(s.calls.is_empty());assert_eq!(s.finished,1);
  }
 }
 #[test] fn complete_result_contains_only_bound_component_shares() {
  let(key,v)=material();let state=Arc::new(Mutex::new(State::default()));
  let r=decapsulate(&key,fake(&state),&v).unwrap();
  assert_eq!(r.as_object().unwrap().len(),7);
  for name in BINDINGS {assert_eq!(r[name],v[name]);}
  for name in ["mlkemSecret","x25519Secret"] {assert_eq!(B64.decode(r[name].as_str().unwrap()).unwrap(),vec![7;32]);}
  let s=state.lock().unwrap();assert_eq!(s.calls,vec![Operation::MlKem768,Operation::X25519]);assert_eq!(s.finished,1);
 }
 #[test] fn component_failure_is_not_retried_and_never_returns_partial_secrets() {
  let(key,v)=material();
  for op in [Operation::MlKem768,Operation::X25519] {
   let state=Arc::new(Mutex::new(State::default()));let mut b=fake(&state);b.fail=Some(op);
   assert!(decapsulate(&key,b,&v).is_err());
   let s=state.lock().unwrap();assert_eq!(s.calls.len(),if op==Operation::MlKem768{1}else{2});assert_eq!(s.finished,1);
  }
  for zero in [false,true] {
   let state=Arc::new(Mutex::new(State::default()));let mut b=fake(&state);
   if zero {b.zero_ec=true;} else {b.bad_length=true;}
   assert!(decapsulate(&key,b,&v).is_err());assert_eq!(state.lock().unwrap().finished,1);
  }
 }
}
