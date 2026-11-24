//! Explicit, authenticated component routing for restored hardware identities.
//!
//! The outer host constructs `hardware` from an independently verified live
//! bundle. This worker additionally compares each mapped SPKI with the selected
//! OpenPGP public key. A mapping can narrow an operation; it can never substitute
//! another key. PINs exist only for this process and are reused across components.
use super::*;
use pgp::crypto::mpi;
use pgp::types::{Curve,HashAlgorithm};
use sequoia_pqmail_piv::{external_mu,public_spki,Operation};
use std::{io::{Read,Write},process::{Command,Stdio},time::{Duration,Instant}};
use std::os::unix::process::CommandExt;
use openssl::{ec::{EcGroup,EcKey,EcPoint},nid::Nid,pkey::PKey,ecdsa::EcdsaSig};

/// Typed diagnostic boundaries carry no provider text or operation bytes.
/// The outer worker emits only code(), never the underlying error chain.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Failure {AdapterStart,AdapterInput,AdapterWait,AdapterTimeout,AdapterExit,
 AdapterOutputLimit,AdapterEncoding,SignatureLength,SignatureDecode,ComponentVerify,CompositeVerify,
 HelperPublicKey,HelperPrivateKey,HelperSign,HelperVerify,HelperInitialize,HelperParameters,HelperInput,HelperOutput}
impl Failure {
 pub fn code(self)->&'static str {match self {
  Self::AdapterStart=>"ADAPTER_START_FAILED",Self::AdapterInput=>"ADAPTER_INPUT_FAILED",
  Self::AdapterWait=>"ADAPTER_WAIT_FAILED",Self::AdapterTimeout=>"ADAPTER_TIMEOUT",
  Self::AdapterExit=>"ADAPTER_EXIT_FAILED",Self::AdapterOutputLimit=>"ADAPTER_OUTPUT_LIMIT",
  Self::AdapterEncoding=>"ADAPTER_OUTPUT_ENCODING",Self::SignatureLength=>"SIGNATURE_LENGTH_FAILED",
  Self::SignatureDecode=>"SIGNATURE_DECODE_FAILED",Self::ComponentVerify=>"SIGNATURE_COMPONENT_VERIFY_FAILED",
  Self::CompositeVerify=>"SIGNATURE_COMPOSITE_VERIFY_FAILED",Self::HelperPublicKey=>"PKCS11_HELPER_PUBLIC_KEY_FAILED",
  Self::HelperPrivateKey=>"PKCS11_HELPER_PRIVATE_KEY_FAILED",Self::HelperSign=>"PKCS11_HELPER_SIGN_FAILED",
  Self::HelperVerify=>"PKCS11_HELPER_VERIFY_FAILED",Self::HelperInitialize=>"PKCS11_HELPER_INITIALIZE_FAILED",
  Self::HelperParameters=>"PKCS11_HELPER_PARAMETERS_FAILED",
  Self::HelperInput=>"PKCS11_HELPER_INPUT_FAILED",Self::HelperOutput=>"PKCS11_HELPER_OUTPUT_FAILED",
 }}
}
impl std::fmt::Display for Failure {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str(self.code())}}
impl std::error::Error for Failure {}

/// Public numeric diagnostics, parsed only from the adapter's fixed markers.
/// No reason string, URI, path, PIN or provider error-data string is retained.
/// Display deliberately does not serialize even these safe fields; only main's
/// reviewed fixed-line protocol may publish the bounded numeric values.
#[derive(Debug,Default)]
pub struct AdapterEvidence {pub codes:Vec<u64>,pub callbacks:Option<u16>,pub pkcs11:Vec<(&'static str,u64)>,pub pcsc:Vec<PcscEvidence>}
#[derive(Debug)]
pub struct PcscEvidence{pub method:&'static str,pub rv:u32,pub elapsed:u32,pub length:Option<u32>,pub sw:Option<u16>}
fn public_hex(value:&[u8],width:usize)->Option<u32>{if value.len()!=width||!value.iter().all(|b|b.is_ascii_digit()||(b'A'..=b'F').contains(b)){return None;}u32::from_str_radix(std::str::from_utf8(value).ok()?,16).ok()}
fn public_decimal(value:&[u8],maximum:u32)->Option<u32>{if value.is_empty()||value.len()>6||!value.iter().all(u8::is_ascii_digit){return None;}let n=std::str::from_utf8(value).ok()?.parse::<u32>().ok()?;(n<=maximum).then_some(n)}
fn pcsc_evidence(value:&[u8])->Option<PcscEvidence>{
 let mut fields=value.split(|b|*b==b' ');let method=match fields.next()?{b"SCardTransmit"=>"SCardTransmit",b"SCardBeginTransaction"=>"SCardBeginTransaction",b"SCardEndTransaction"=>"SCardEndTransaction",b"SCardReconnect"=>"SCardReconnect",_=>return None};
 let rv=public_hex(fields.next()?.strip_prefix(b"RV=")?,8)?;let elapsed=public_decimal(fields.next()?.strip_prefix(b"MS=")?,120000)?;
 let mut result=PcscEvidence{method,rv,elapsed,length:None,sw:None};
 if let Some(length)=fields.next(){
  if rv!=0||method!="SCardTransmit"{return None;}
  let length=public_decimal(length.strip_prefix(b"LEN=")?,65536)?;result.length=Some(length);
  if let Some(sw)=fields.next(){if length<2{return None;}result.sw=Some(public_hex(sw.strip_prefix(b"SW=")?,4)? as u16);}
 }
 if fields.next().is_some(){return None;}Some(result)
}
impl std::fmt::Display for AdapterEvidence {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("PKCS11_ADAPTER_EVIDENCE")}}
impl std::error::Error for AdapterEvidence {}
fn adapter_evidence(stderr:&[u8])->AdapterEvidence {
 let mut evidence=AdapterEvidence::default();let mut callback_seen=false;
 for line in stderr.split(|b|*b==b'\n') {
  // Python renders the helper's filtered lines as semicolon-separated fields
  // on this one known failure line. Unrelated process output is ignored.
  if !line.starts_with(b"PQ Mail: Single-process PKCS#11 signing failed")&&!line.starts_with(b"PQ Mail: Single-process PKCS#11 signing diagnostics;"){continue;}
  for field in line.split(|b|*b==b';').skip(1) {
   let field=field.strip_prefix(b" ").unwrap_or(field);
   if let Some(rest)=field.strip_prefix(b"PQMAIL_ERROR ") {
    let token=rest.split(|b|*b==b' ').next().unwrap_or(&[]);
    if (8..=16).contains(&token.len())&&token.iter().all(|b|b.is_ascii_digit()||(b'A'..=b'F').contains(b))&&evidence.codes.len()<8 {
     if let Ok(code)=u64::from_str_radix(std::str::from_utf8(token).unwrap_or(""),16){if !evidence.codes.contains(&code){evidence.codes.push(code);}}
    }
   }else if let Some(rest)=field.strip_prefix(b"PQMAIL_PCSC ") {
    // A trace may describe only the numeric trailing SW of a successful
    // response. Command bytes and all response body bytes remain native-only.
    if evidence.pcsc.len()<96{if let Some(row)=pcsc_evidence(rest){evidence.pcsc.push(row);}}
   }else if let Some(rest)=field.strip_prefix(b"PQMAIL_PKCS11 ") {
    // Only method names chosen in the forwarding shim and numeric CK_RV values
    // are eligible. Parameters, handles and module error strings are excluded.
    let mut parts=rest.split(|b|*b==b' ');let method=match parts.next(){Some(b"C_Login")=>"C_Login",Some(b"C_SignInit")=>"C_SignInit",Some(b"C_Sign")=>"C_Sign",_=>continue};
    let Some(token)=parts.next().and_then(|p|p.strip_prefix(b"RV=")) else{continue};
    if parts.next().is_none()&&(8..=16).contains(&token.len())&&token.iter().all(|b|b.is_ascii_digit()||(b'A'..=b'F').contains(b))&&evidence.pkcs11.len()<16 {
     if let Ok(rv)=u64::from_str_radix(std::str::from_utf8(token).unwrap_or(""),16){evidence.pkcs11.push((method,rv));}
    }
   }else if let Some(token)=field.strip_prefix(b"PQMAIL_PIN_CALLBACKS ") {
    // Duplicate or malformed counts are ambiguous; retain no count. A marker
    // cannot smuggle a suffix or arbitrary decimal string into diagnostics.
    if callback_seen {evidence.callbacks=None;continue;}callback_seen=true;
    if !token.is_empty()&&token.len()<=4&&token.iter().all(u8::is_ascii_digit){evidence.callbacks=std::str::from_utf8(token).ok().and_then(|v|v.parse().ok());}
   }
  }
 }
 evidence
}

/// Only known adapter-generated stage names may refine a nonzero exit. Raw
/// This stage parser ignores OpenSSL reasons, numbers and arbitrary suffixes;
/// the separate bounded evidence parser permits numeric identifiers only.
/// Unknown or truncated diagnostics retain the generic exit failure.
fn adapter_failure(stderr:&[u8])->Failure {
 const PREFIX:&[u8]=b"PQ Mail: Single-process PKCS#11 signing failed at ";
 for line in stderr.split(|b|*b==b'\n') {
  let Some(rest)=line.strip_prefix(PREFIX) else {continue};
  let Some(end)=rest.windows(10).position(|w|w==b"; no retry") else {continue};
  return match &rest[..end] {
   b"public key check"=>Failure::HelperPublicKey,b"private key check"=>Failure::HelperPrivateKey,
   b"sign"=>Failure::HelperSign,b"verify"=>Failure::HelperVerify,
   b"sign initialization"|b"providers"|b"PIN callback setup"=>Failure::HelperInitialize,
   b"sign parameters"=>Failure::HelperParameters,
   b"input"|b"PIN input"|b"arguments"=>Failure::HelperInput,b"output"=>Failure::HelperOutput,
   _=>Failure::AdapterExit,
  };
 }
 Failure::AdapterExit
}

/// Drain stderr concurrently so diagnostic output cannot block a signer. Keep
/// at most 16 KiB in a wiping buffer; overflow is a fixed failure, never an
/// excuse to log more. The worker's existing deadline bounds waiting for EOF.
fn bounded_stderr(mut input:impl Read)->Result<Zeroizing<Vec<u8>>> {
 let mut saved=Zeroizing::new(Vec::new());let mut chunk=Zeroizing::new([0u8;1024]);let mut overflow=false;
 loop {let n=input.read(&mut *chunk).context(Failure::AdapterWait)?;if n==0{break;}
  let keep=n.min(16384usize.saturating_sub(saved.len()));saved.extend_from_slice(&chunk[..keep]);overflow|=keep<n;
 }
 if overflow{return Err(Failure::AdapterOutputLimit.into());}Ok(saved)
}

fn signature_length(algorithm:&str,length:usize)->Result<()> {
 let valid=match algorithm {"ML-DSA-65"=>length==3309,"ML-DSA-87"=>length==4627,
  "Ed25519"=>length==64,"Ed448"=>length==114,"P-384"=> (8..=104).contains(&length),_=>false};
 if !valid{return Err(Failure::SignatureLength.into());}Ok(())
}

/// Public component authority. Storage locations are fixed by the signed
/// manifest, independently of the browser's message/request identifiers.
#[derive(Clone)]
pub struct Component {pub role:String,pub algorithm:String,pub storage:String,pub slot:String,pub public:Vec<u8>}
pub fn components(v:&serde_json::Value)->Result<Vec<Component>> {
 let rows=v["hardware"]["components"].as_array().context("Verified hardware mapping required")?;
 ensure!((2..=8).contains(&rows.len()),"Component count");
 let mut result=Vec::new();
 for row in rows {
  ensure!(row.as_object().map(|r|r.len())==Some(5),"Component schema");
  let c=Component{role:field(row,"role")?.into(),algorithm:field(row,"algorithm")?.into(),storage:field(row,"storage")?.into(),slot:field(row,"slot")?.into(),public:B64.decode(field(row,"publicKey")?)?};
  ensure!(!result.iter().any(|old:&Component|old.role==c.role),"Duplicate role");
  ensure!(c.public.len()<=4096,"Public key limit");result.push(c);
 }
 Ok(result)
}
fn row<'a>(rows:&'a[Component],role:&str,algorithm:&str,public:&[u8])->Result<&'a Component>{
 let c=rows.iter().find(|c|c.role==role).context("Required mapped component absent")?;
 ensure!((c.algorithm==algorithm||(algorithm=="P-384"&&matches!(c.algorithm.as_str(),"ECDSA-P384"|"ECDH-P384")))&&c.public==public,"Mapped key does not match certificate");Ok(c)
}
/// Re-encode classical EC keys from their curve and uncompressed point. OpenSSL
/// validates point membership before any private operation is requested.
fn ec_spki(curve:&Curve,q:&[u8])->Result<Vec<u8>> {
 let nid=match curve {Curve::NistP384=>Nid::SECP384R1,Curve::NistP521=>Nid::SECP521R1,_=>bail!("Unsupported EC curve")};
 let g=EcGroup::from_curve_name(nid)?;let mut ctx=openssl::bn::BigNumContext::new()?;
 let point=EcPoint::from_bytes(&g,q,&mut ctx)?;let key=EcKey::from_public_key(&g,&point)?;key.check_key()?;
 Ok(PKey::from_ec_key(key)?.public_key_to_der()?)
}
fn classical(curve:&Curve,q:&[u8],sign:bool)->Result<(String,Vec<u8>)>{
 if curve==&Curve::Ed25519&&sign {ensure!(q.len()==33&&q[0]==0x40,"Ed25519 point");return Ok(("Ed25519".into(),public_spki(Operation::Ed25519,&q[1..])?));}
 if curve==&Curve::Cv25519&&!sign {ensure!(q.len()==33&&q[0]==0x40,"X25519 point");return Ok(("X25519".into(),public_spki(Operation::X25519,&q[1..])?));}
 Ok((match curve {Curve::NistP384=>"P-384",Curve::NistP521=>"P-521",_=>bail!("Unsupported classical curve")}.into(),ec_spki(curve,q)?))
}

/// Fail before the first private component if the installed transport cannot
/// perform *all* native components. A Goldilocks-capable manifest does not
/// imply that this particular installed provider exposes Goldilocks.
pub fn supported(rows:&[Component],sign:bool)->Result<()> {
 for c in rows.iter().filter(|c|c.role.starts_with(if sign{"signing-"}else{"decryption-"})||c.role=="companion-wrap") {
  if c.storage=="companion" {continue;}
  ensure!(matches!(c.algorithm.as_str(),"ML-DSA-65"|"ML-DSA-87"|"ML-KEM-768"|"ML-KEM-1024"|"Ed25519"|"X25519"|"P-384"|"ECDSA-P384"|"ECDH-P384"),"Installed PKCS11 backend does not support this native component");
 }
 Ok(())
}

/// Existing PKCS#11 adapters retain live public-key verification, explicit
/// serial selection, PIN callbacks and UP enforcement. The closed routing table
/// prevents a general environment/slot execution service from crossing IPC.
pub struct Session {config:Config,pin:Zeroizing<Vec<u8>>}
pub trait Executor {fn execute(&mut self,c:&Component,input:&[u8],sign:bool)->Result<Zeroizing<Vec<u8>>>;}
impl Session {
 pub fn new(config:Config,pin:Zeroizing<Vec<u8>>)->Result<Self>{config.validate()?;ensure!((6..=8).contains(&pin.len())&&pin.iter().all(|b|(32..=126).contains(b)),"Invalid PIN");Ok(Self{config,pin})}
}
impl Executor for Session {
 fn execute(&mut self,c:&Component,input:&[u8],sign:bool)->Result<Zeroizing<Vec<u8>>>{
  ensure!(c.storage=="piv","Software component must remain in WASM");
  let logical=match c.algorithm.as_str(){"ECDSA-P384"|"ECDH-P384"=>"P-384",a=>a};
  let alg=match logical{"P-384"=>if sign{"ECDSA-P384-SHA384"}else{"ECDH-P384"},"ML-DSA-65"|"ML-DSA-87"|"Ed25519"|"ML-KEM-768"|"ML-KEM-1024"|"X25519"=>&c.algorithm,_=>bail!("Installed PKCS11 backend does not support this native component")};
  let script=self.config.adapters.join(if sign{"pkcs11-mu.py"}else{"pkcs11-kem.py"});
  let mut cmd=Command::new(&self.config.python);cmd.args(["-I","-B"]).arg(script).env_clear();
  for n in ["PATH","TMPDIR","TMP","TEMP","SystemRoot","WINDIR"]{if let Some(v)=std::env::var_os(n){cmd.env(n,v);}}
  cmd.env("OPENSSL_BIN",&self.config.openssl).env("PKCS11_PROVIDER",&self.config.provider).env("PKCS11_MODULE",&self.config.module).env("PKCS11_SERIAL",&self.config.serial)
   .env("HYBRID_MAIL_PIN_STDIN","1").env("PQMAIL_SUPERVISED_PROCESS_GROUP","1")
   .env("PKCS11_TRADITIONAL_SLOT",&c.slot).env("PKCS11_KEM_SLOT",&c.slot).env("PKCS11_ECDH_SLOT",&c.slot);
  match (logical,c.slot.as_str(),sign) {
   ("ML-DSA-65"|"ML-DSA-87","9c",true)|("Ed25519","84",true)|("P-384","83",true)|("X25519","85",false)|("ML-KEM-768"|"ML-KEM-1024","9d",false)|("P-384","82",false)=>{},
   ("Ed25519","88",true)|("X25519","89",false)=>{cmd.env("PQMAIL_COMPATIBILITY_SLOT",&c.slot);},
   ("P-384","88",true)|("ML-KEM-768","84",false)|("P-384","89",false)=>{cmd.env("PQMAIL_LEVEL5_COMPATIBILITY","1");},
   ("Ed25519","9c",true)|("X25519","9d",false)|("P-384","83",false)=>{cmd.env("PQMAIL_LEVEL3_POLYFILL","1");},
   _=>bail!("Unsupported authenticated slot mapping"),
  }
  // P-384 ECDSA consumes the leftmost 384 digest bits; the signature is still
  // verified over SHA-512 by OpenPGP below. Never rehash the supplied digest.
  let data=if sign&&logical=="P-384" {ensure!(input.len()==64,"ECDSA digest size");&input[..48]}else{input};
  let mut wire=Zeroizing::new(format!("{}\n{}\n{}\n",alg,B64.encode(&c.public),B64.encode(data)).into_bytes());wire.extend_from_slice(&self.pin);wire.push(b'\n');
  cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
  let mut child=cmd.spawn().context(Failure::AdapterStart)?;let id=child.id();let started=Instant::now();
  // Stderr is inspected only on a failed exit. A bounded reader drains it
  // independently; raw diagnostic bytes are never written or forwarded. Only
  // the closed stage and separately bounded numeric evidence can leave here.
  let stderr=child.stderr.take().context(Failure::AdapterWait)?;
  let(send,receive)=std::sync::mpsc::sync_channel(1);
  std::thread::spawn(move||{let _=send.send(bounded_stderr(stderr));});
  let written=child.stdin.take().context("Adapter stdin")?.write_all(&wire);wire.clear();
  if written.is_err(){unsafe{libc::kill(-(id as i32),libc::SIGKILL);};let _=child.wait();return Err(Failure::AdapterInput.into());}
  loop {if child.try_wait().context(Failure::AdapterWait)?.is_some(){break;}if started.elapsed()>Duration::from_secs(120){unsafe{libc::kill(-(id as i32),libc::SIGKILL);};let _=child.wait();return Err(Failure::AdapterTimeout.into());}std::thread::sleep(Duration::from_millis(10));}
  let output=child.wait_with_output().context(Failure::AdapterWait)?;
  let stderr=receive.recv_timeout(Duration::from_secs(120).saturating_sub(started.elapsed())).context(Failure::AdapterWait)??;
  if !output.status.success(){return Err(anyhow::Error::new(adapter_failure(&stderr)).context(adapter_evidence(&stderr)));}
  // Successful diagnostic runs also need transport evidence. Publish only the
  // parsed numeric schema, not the raw adapter stderr or operation result.
  super::emit_adapter_evidence(&adapter_evidence(&stderr));
  if output.stdout.len()>8192{return Err(Failure::AdapterOutputLimit.into());}
  let raw=if sign {B64.decode(std::str::from_utf8(&output.stdout).context(Failure::AdapterEncoding)?.trim()).context(Failure::AdapterEncoding)?}else{output.stdout};
  if sign{signature_length(logical,raw.len())?;}
  ensure!(!raw.is_empty(),"Empty component response");Ok(Zeroizing::new(raw))
 }
}

/// Component results are verified before release. Companion operations return
/// only the hardware half plus the separately derived wrapping share; WASM must
/// authenticate/decrypt the companion and verify the completed composite.
pub fn sign(key:&PublicKey,rows:&[Component],session:&mut impl Executor,v:&serde_json::Value)->Result<serde_json::Value>{
 let digest=crate::digest_sign::validate_request(v,key)?;
 ensure!(rows.iter().filter(|c|c.role.starts_with("signing-")).all(|c|c.storage=="piv")||v["hardware"].get("companion").is_some(),"Companion authority required");
 let (ed,ml,signature)=match key.mpis(){
  mpi::PublicKey::MLDSA65_Ed25519{eddsa,mldsa}=>{
   let pq=row(rows,"signing-pq","ML-DSA-65",&public_spki(Operation::MlDsa65,mldsa.as_ref())?)?;
   let ec=row(rows,"signing-classical","Ed25519",&public_spki(Operation::Ed25519,eddsa.as_ref())?)?;
   let ml=if pq.storage=="piv"{session.execute(pq,&external_mu(mldsa.as_ref(),&digest),true)?.to_vec()}else{vec![]};
   let ed=if ec.storage=="piv"{session.execute(ec,&digest,true)?.to_vec()}else{vec![]};
   let sig=if ml.len()==3309&&ed.len()==64{Some(mpi::Signature::MLDSA65_Ed25519{eddsa:Box::new(ed.as_slice().try_into()?),mldsa:Box::new(ml.as_slice().try_into()?)})}else{None};(ed,ml,sig)
  },
  mpi::PublicKey::MLDSA87_Ed448{eddsa,mldsa}=>{
   let pq=row(rows,"signing-pq","ML-DSA-87",&public_spki(Operation::MlDsa87,mldsa.as_ref())?)?;
   let ec=row(rows,"signing-classical","Ed448",&public_spki(Operation::Ed448,eddsa.as_ref())?)?;
   let ml=if pq.storage=="piv"{session.execute(pq,&external_mu(mldsa.as_ref(),&digest),true)?.to_vec()}else{vec![]};
   let ed=if ec.storage=="piv"{session.execute(ec,&digest,true)?.to_vec()}else{vec![]};
   let sig=if ml.len()==4627&&ed.len()==114{Some(mpi::Signature::MLDSA87_Ed448{eddsa:Box::new(ed.as_slice().try_into()?),mldsa:Box::new(ml.as_slice().try_into()?)})}else{None};(ed,ml,sig)
  },
  mpi::PublicKey::EdDSA{curve,q}=>{
   let(alg,spki)=classical(curve,q.value(),true)?;let ec=row(rows,"signing-classical",&alg,&spki)?;
   let ed=session.execute(ec,&digest,true)?.to_vec();ensure!(ed.len()==64,"Ed25519 response size");
   let sig=mpi::Signature::EdDSA{r:mpi::MPI::new(&ed[..32]),s:mpi::MPI::new(&ed[32..])};(ed,vec![],Some(sig))
  },
  mpi::PublicKey::ECDSA{curve,q}=>{
   let(alg,spki)=classical(curve,q.value(),true)?;let ec=row(rows,"signing-classical",&alg,&spki)?;
   let der=session.execute(ec,&digest,true)?;let sig=EcdsaSig::from_der(&der).context(Failure::SignatureDecode)?;
   let size=if curve==&Curve::NistP384{48}else{66};let mut ed=sig.r().to_vec_padded(size)?;ed.extend(sig.s().to_vec_padded(size)?);
   let sig=mpi::Signature::ECDSA{r:mpi::MPI::new(&sig.r().to_vec()),s:mpi::MPI::new(&sig.s().to_vec())};(ed,vec![],Some(sig))
  },_=>bail!("Unsupported signing profile")
 };
 // A companion leaves one software component for WASM, but native still
 // verifies every completed ML-DSA/EdDSA hardware signature independently.
 // Pure ML-DSA verification consumes the original digest message, matching
 // external_mu's empty-context FIPS 204 construction; it never verifies μ as
 // if it were the message. The final composite remains WASM's responsibility.
 for (role,raw) in [("signing-pq",&ml),("signing-classical",&ed)] {
  if !raw.is_empty(){let c=rows.iter().find(|c|c.role==role).context("Signing role")?;
   if matches!(c.algorithm.as_str(),"ML-DSA-65"|"ML-DSA-87"|"Ed25519"|"Ed448"){
    signature_length(&c.algorithm,raw.len())?;
    let public=PKey::public_key_from_der(&c.public).context(Failure::ComponentVerify)?;
    let valid=openssl::sign::Verifier::new_without_digest(&public).context(Failure::ComponentVerify)?.verify_oneshot(raw,&digest).context(Failure::ComponentVerify)?;
    if !valid{return Err(Failure::ComponentVerify.into());}
   }
  }
 }
 if let Some(signature)=signature {key.verify(&signature,HashAlgorithm::SHA512,&digest).context(Failure::CompositeVerify)?;}else{ensure!(v["hardware"].get("companion").is_some(),"Incomplete hardware signature");}
 Ok(serde_json::json!({"requestId":v["requestId"],"hashAlgorithm":10,"signingFingerprint":key.fingerprint().to_hex(),"digest":v["digest"],"ed25519":B64.encode(ed),"mldsa65":B64.encode(ml)}))
}

pub fn decapsulate(key:&PublicKey,rows:&[Component],session:&mut impl Executor,v:&serde_json::Value)->Result<serde_json::Value>{
 ensure!(rows.iter().filter(|c|c.role.starts_with("decryption-")).all(|c|c.storage=="piv")||v["hardware"].get("companion").is_some(),"Companion authority required");
 ensure!(field(v,"recipientKey")?==key.fingerprint().to_hex(),"Wrong selected recipient");
 opaque_id(v,"requestId",true)?;opaque_id(v,"cipherHash",false)?;
 let cipher=B64.decode(field(v,"mlkemCiphertext")?)?;let ephemeral=B64.decode(field(v,"x25519Ephemeral")?)?;
 let (pq,ec,peer)=match key.mpis(){
  mpi::PublicKey::MLKEM768_X25519{ecdh,mlkem}=>{ensure!(cipher.len()==1088&&ephemeral.len()==32,"Level3 component lengths");(Some(row(rows,"decryption-pq","ML-KEM-768",&public_spki(Operation::MlKem768,mlkem.as_ref())?)?),row(rows,"decryption-classical","X25519",&public_spki(Operation::X25519,ecdh.as_ref())?)?,public_spki(Operation::X25519,&ephemeral)?)},
  mpi::PublicKey::MLKEM1024_X448{ecdh,mlkem}=>{ensure!(cipher.len()==1568&&ephemeral.len()==56,"Level5 component lengths");(Some(row(rows,"decryption-pq","ML-KEM-1024",&public_spki(Operation::MlKem1024,mlkem.as_ref())?)?),row(rows,"decryption-classical","X448",&public_spki(Operation::X448,ecdh.as_ref())?)?,public_spki(Operation::X448,&ephemeral)?)},
  mpi::PublicKey::ECDH{curve,q,..}=>{ensure!(cipher.is_empty(),"Classical key cannot accept MLKEM input");let(alg,spki)=classical(curve,q.value(),false)?;let peer=if curve==&Curve::Cv25519{ensure!(ephemeral.len()==33&&ephemeral[0]==0x40,"X25519 ephemeral");public_spki(Operation::X25519,&ephemeral[1..])?}else{ec_spki(curve,&ephemeral)?};(None,row(rows,"decryption-classical",&alg,&spki)?,peer)},
  _=>bail!("Unsupported encryption profile")
 };
 ensure!(ephemeral.iter().any(|b|*b!=0),"Noncontributory peer");
 let ml=if let Some(c)=pq {if c.storage=="piv"{let x=session.execute(c,&cipher,false)?;ensure!(x.len()==32,"MLKEM shared size");x.to_vec()}else{vec![]}}else{vec![]};
 let shared=if ec.storage=="piv"{let x=session.execute(ec,&peer,false)?;let size=match ec.algorithm.as_str(){"P-384"|"ECDH-P384"=>48,"P-521"=>66,"X448"=>56,_=>32};ensure!(x.len()==size&&x.iter().any(|b|*b!=0),"ECDH shared size");x.to_vec()}else{vec![]};
 ensure!((pq.map(|c|c.storage=="piv").unwrap_or(true)&&ec.storage=="piv")||v["hardware"].get("companion").is_some(),"Incomplete hardware decryption");
 let mut reply=serde_json::Map::new();for name in ["requestId","cipherHash","recipientKey","mlkemCiphertext","x25519Ephemeral"]{reply.insert(name.into(),v[name].clone());}
 reply.insert("mlkemSecret".into(),B64.encode(ml).into());reply.insert("x25519Secret".into(),B64.encode(shared).into());Ok(reply.into())
}

fn opaque_id(v:&serde_json::Value,name:&str,upper:bool)->Result<()> {
 let text=field(v,name)?;ensure!(text.len()==64&&text.bytes().all(|b|b.is_ascii_digit()||if upper{(b'A'..=b'F').contains(&b)}else{(b'a'..=b'f').contains(&b)}),"Invalid operation identifier");Ok(())
}
fn v5_digests(v:&serde_json::Value)->Result<[Vec<u8>;2]> {
 opaque_id(v,"requestId",true)?;
 let decode=|name|->Result<Vec<u8>>{let text=field(v,name)?;let bytes=B64.decode(text)?;ensure!(bytes.len()==64&&B64.encode(&bytes)==text,"V5 digest length/encoding");Ok(bytes)};
 // Validate the second digest before authorizing even the first signature.
 // A direct pipe caller must not consume UP for half of a malformed request.
 Ok([decode("digest")?,decode("inlineDigest")?])
}

/// LibrePGP v5 is deliberately handled by the shared public verifier rather
/// than coercing its packets through Sequoia's RFC 9580 parser. Only raw
/// component operations remain native; its distinct combiner stays in WASM.
pub fn v5(rows:&[Component],session:&mut impl Executor,v:&serde_json::Value)->Result<serde_json::Value>{
 let raw=B64.decode(field(v,"own")?)?;let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs().try_into()?;
 let info=sequoia_public_bundle::v5::inspect(&raw,now)?;
 for expected in info["components"].as_array().context("V5 public components")? {
  row(rows,field(expected,"role")?,field(expected,"algorithm")?,&B64.decode(field(expected,"publicKey")?)?)?;
 }
 if field(v,"op")?=="sign-digest" {
  let digests=v5_digests(v)?;
  ensure!(v["signingFingerprint"]==info["signingFingerprint"]&&v["hashAlgorithm"]==10,"V5 signing binding");
  let c=rows.iter().find(|c|c.role=="signing-classical").context("V5 signing role")?;
  let mut out=serde_json::json!({"requestId":v["requestId"],"signingFingerprint":v["signingFingerprint"],"hashAlgorithm":10,"digest":v["digest"],"inlineDigest":v["inlineDigest"],"mldsa65":""});
  for (digest,output) in digests.iter().zip(["ed25519","inlineEd25519"]) {
   let signed=session.execute(c,&digest,true)?;ensure!(signed.len()==64,"Ed25519 signature length");
   let key=PKey::public_key_from_der(&c.public)?;ensure!(openssl::sign::Verifier::new_without_digest(&key)?.verify_oneshot(&signed,&digest)?,"V5 signature verification");
   out[output]=B64.encode(&*signed).into();
  }
  Ok(out)
 }else{
  opaque_id(v,"requestId",true)?;opaque_id(v,"cipherHash",false)?;
  ensure!(field(v,"op")?=="decapsulate-components"&&v["recipientKey"]==info["recipientKey"],"V5 recipient binding");
  let cipher=B64.decode(field(v,"mlkemCiphertext")?)?;let ephemeral=B64.decode(field(v,"x25519Ephemeral")?)?;
  ensure!(cipher.len()==1088&&ephemeral.len()==32&&ephemeral.iter().any(|b|*b!=0),"V5 component size");
  let pq=rows.iter().find(|c|c.role=="decryption-pq").context("V5 PQ role")?;let ec=rows.iter().find(|c|c.role=="decryption-classical").context("V5 ECDH role")?;
  let ml=session.execute(pq,&cipher,false)?;let x=session.execute(ec,&public_spki(Operation::X25519,&ephemeral)?,false)?;
  ensure!(ml.len()==32&&x.len()==32&&x.iter().any(|b|*b!=0),"V5 component response");
  let mut out=serde_json::Map::new();for name in ["requestId","cipherHash","recipientKey","mlkemCiphertext","x25519Ephemeral"]{out.insert(name.into(),v[name].clone());}
  out.insert("mlkemSecret".into(),B64.encode(&*ml).into());out.insert("x25519Secret".into(),B64.encode(&*x).into());Ok(out.into())
 }
}

#[cfg(test)]
mod tests {
 use super::*;use pgp::{cert::{CertBuilder,CipherSuite},crypto::Signer};
 /// Test responses come from genuine Sequoia software signatures, while this
 /// fake refuses an incorrect algorithm, SPKI or private-operation input. It
 /// cannot spawn processes or access a device and exposes no software secret.
 struct Prepared {operations:Vec<(Component,Vec<u8>,Vec<u8>)>,calls:usize}
 impl Executor for Prepared {
  fn execute(&mut self,c:&Component,input:&[u8],sign:bool)->Result<Zeroizing<Vec<u8>>>{
   ensure!(sign&&self.calls<self.operations.len(),"Unexpected private operation");let(expected,data,result)=&self.operations[self.calls];
   ensure!(c.role==expected.role&&c.algorithm==expected.algorithm&&c.public==expected.public&&data==input,"Wrong private component input");self.calls+=1;Ok(Zeroizing::new(result.clone()))
  }
 }
 fn c(role:&str,alg:&str,public:Vec<u8>)->Component{Component{role:role.into(),algorithm:alg.into(),storage:"piv".into(),slot:"9c".into(),public}}
 #[test]fn helper_stages_are_closed_and_stderr_is_bounded()->Result<()> {
  for(stage,expected)in [("sign",Failure::HelperSign),("verify",Failure::HelperVerify),("public key check",Failure::HelperPublicKey),("private key check",Failure::HelperPrivateKey),("sign initialization",Failure::HelperInitialize),("sign parameters",Failure::HelperParameters)] {
   let raw=format!("PQ Mail: Single-process PKCS#11 signing failed at {stage}; no retry; sensitive-example\n");
   assert_eq!(adapter_failure(raw.as_bytes()),expected);
   assert!(!expected.to_string().contains("sensitive-example"));
  }
  for raw in [b"sensitive-example".as_slice(),b"PQ Mail: Single-process PKCS#11 signing failed at sign sensitive-example; no retry"] {assert_eq!(adapter_failure(raw),Failure::AdapterExit);}
  assert_eq!(&*bounded_stderr(&b"public diagnostic"[..])?,b"public diagnostic");
  let error=bounded_stderr(&vec![42;16385][..]).unwrap_err();assert_eq!(error.downcast_ref::<Failure>(),Some(&Failure::AdapterOutputLimit));
  Ok(())
 }
 #[test]fn numeric_helper_evidence_excludes_reason_text_and_ambiguous_counts(){
  let raw=b"PQ Mail: Single-process PKCS#11 signing failed at sign; no retry; PQMAIL_ERROR 40800005 sensitive-example; PQMAIL_ERROR 030000EA another reason; PQMAIL_PIN_CALLBACKS 2; PQMAIL_PKCS11 C_Login RV=00000000; PQMAIL_PKCS11 C_Sign RV=00000030\n";
  let evidence=adapter_evidence(raw);assert_eq!(evidence.codes,vec![0x40800005,0x030000EA]);assert_eq!(evidence.callbacks,Some(2));
  assert_eq!(evidence.pkcs11,vec![("C_Login",0),("C_Sign",0x30)]);
  let error=anyhow::Error::new(adapter_failure(raw)).context(evidence).context("IWA_HARDWARE_SIGN");
  assert_eq!(super::super::diagnostic_code(&error),"PKCS11_HELPER_SIGN_FAILED");
  assert_eq!(error.downcast_ref::<AdapterEvidence>().unwrap().callbacks,Some(2));
  assert!(!format!("{error:#}").contains("sensitive-example"));
  // Marker-like text outside the adapter's fixed failure line, malformed hex,
  // possible PIN-sized counts and duplicate counters are never copied out.
  let bad=adapter_evidence(b"PQMAIL_ERROR 40800005 sensitive-example\nPQ Mail: Single-process PKCS#11 signing failed at sign; no retry; PQMAIL_ERROR 030000ea hidden; PQMAIL_ERROR 654321 hidden; PQMAIL_PIN_CALLBACKS 654321\n");
  assert!(bad.codes.is_empty());assert_eq!(bad.callbacks,None);
  let duplicate=adapter_evidence(b"PQ Mail: Single-process PKCS#11 signing failed at sign; no retry; PQMAIL_PIN_CALLBACKS 2; PQMAIL_PIN_CALLBACKS 2\n");
  assert_eq!(duplicate.callbacks,None);
  let bad=adapter_evidence(b"PQ Mail: Single-process PKCS#11 signing failed; no retry; PQMAIL_PKCS11 C_Reset RV=00000030; PQMAIL_PKCS11 C_Sign RV=00000030 secret; PQMAIL_PKCS11 C_Sign RV=abcdefab\n");assert!(bad.pkcs11.is_empty());
 }
 #[test]fn pcsc_metadata_requires_success_before_a_status_word(){
  let evidence=adapter_evidence(b"PQ Mail: Single-process PKCS#11 signing diagnostics; PQMAIL_PCSC SCardTransmit RV=00000000 MS=17 LEN=2 SW=6985; PQMAIL_PCSC SCardTransmit RV=80100016 MS=6500\n");
  assert_eq!(evidence.pcsc.len(),2);assert_eq!(evidence.pcsc[0].sw,Some(0x6985));assert_eq!(evidence.pcsc[1].rv,0x80100016);assert_eq!(evidence.pcsc[1].length,None);
  for bad in [b"SCardTransmit RV=80100016 MS=10 LEN=2 SW=9000".as_slice(),b"SCardTransmit RV=00000000 MS=10 LEN=1 SW=9000",b"SCardTransmit RV=00000000 MS=120001",b"SCardTransmit RV=00000000 MS=10 LEN=65537",b"SCardTransmit RV=00000000 MS=10 LEN=2 SW=9000 secret",b"arbitrary RV=00000000 MS=10"]{assert!(pcsc_evidence(bad).is_none());}
 }
 #[test]fn synthetic_adapter_distinguishes_exit_encoding_and_length_without_retry()->Result<()> {
  // This isolated fake only reads protocol lines and returns fixed bytes. Its
  // backend paths are /usr/bin/true, so it cannot open a token/provider even if
  // a regression accidentally invokes them. It never stores the dummy PIN.
  struct Folder(PathBuf);impl Drop for Folder{fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
  let dir=Folder(std::env::temp_dir().join(format!("iwa-adapter-diagnostic-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos())));
  std::fs::create_dir(&dir.0)?;
  for name in ["pkcs11-kem.py","ykman-mu.py"]{std::fs::write(dir.0.join(name),b"# unused synthetic helper\n")?;}
  let component=c("signing-pq","ML-DSA-87",vec![1;2614]);
  for(output,stderr,exit,expected)in [
   (B64.encode(vec![7;4627]),String::new(),0,None),
   ("%%%".into(),String::new(),0,Some(Failure::AdapterEncoding)),
   (B64.encode(vec![7;4626]),String::new(),0,Some(Failure::SignatureLength)),
   (String::new(),"PQ Mail: Single-process PKCS#11 signing failed at sign; no retry; sensitive-example\n".into(),1,Some(Failure::HelperSign)),
   (String::new(),"PQ Mail: Single-process PKCS#11 signing failed at verify; no retry\n".into(),1,Some(Failure::HelperVerify)),
   (String::new(),"sensitive-example".into(),1,Some(Failure::AdapterExit)),
   (String::new(),"x".repeat(16385),1,Some(Failure::AdapterOutputLimit)),
  ] {
   let script=format!("import sys,base64,pathlib\nlines=[sys.stdin.buffer.readline() for _ in range(4)]\nassert lines[0]==b'ML-DSA-87\\n' and len(base64.b64decode(lines[2]))==64\np=pathlib.Path(__file__).with_name('calls');p.write_text(str(int(p.read_text())+1) if p.exists() else '1')\nsys.stdout.write({});sys.stderr.write({});sys.exit({exit})\n",serde_json::to_string(&output)?,serde_json::to_string(&stderr)?);
   std::fs::write(dir.0.join("pkcs11-mu.py"),script)?;
   let config=Config{python:"/usr/bin/python3".into(),adapters:dir.0.clone(),openssl:"/usr/bin/true".into(),provider:"/usr/bin/true".into(),module:"/usr/bin/true".into(),serial:"123".into()};
   let mut session=Session::new(config,Zeroizing::new(b"123456".to_vec()))?;
   let before=std::fs::read_to_string(dir.0.join("calls")).unwrap_or("0".into()).parse::<usize>()?;
   let result=session.execute(&component,&[7;64],true);
   match expected {None=>assert_eq!(result?.len(),4627),Some(boundary)=>{let e=result.unwrap_err();assert_eq!(e.downcast_ref::<Failure>(),Some(&boundary));assert!(!e.to_string().contains("sensitive-example"));}}
   assert_eq!(std::fs::read_to_string(dir.0.join("calls"))?.parse::<usize>()?,before+1,"A failed adapter must never retry");
  }
  Ok(())
 }
 #[test]fn all_supported_signatures_verify_and_mapping_substitution_precedes_private_operation()->Result<()> {
  for (suite,profile) in [(CipherSuite::MLDSA65_Ed25519,pgp::Profile::RFC9580),(CipherSuite::MLDSA87_Ed448,pgp::Profile::RFC9580),(CipherSuite::Cv25519,pgp::Profile::RFC4880),(CipherSuite::P384,pgp::Profile::RFC4880),(CipherSuite::P384,pgp::Profile::RFC9580)] {
   let(cert,_)=CertBuilder::new().set_profile(profile)?.set_cipher_suite(suite).add_userid("test@example.invalid").add_signing_subkey().generate()?;
   let key=selected(&cert,true)?;let mut pair=cert.keys().secret().find(|k|k.key().fingerprint()==key.fingerprint()).context("Secret fixture")?.key().clone().role_into_unspecified().into_keypair()?;
   let digest=vec![7;64];let signature=pair.sign(HashAlgorithm::SHA512,&digest)?;
   let mut operations=Vec::new();
   match(key.mpis(),signature){
    (mpi::PublicKey::MLDSA65_Ed25519{eddsa,mldsa},mpi::Signature::MLDSA65_Ed25519{eddsa:ed,mldsa:ml})=>{
     operations.push((c("signing-pq","ML-DSA-65",public_spki(Operation::MlDsa65,mldsa.as_ref())?),external_mu(mldsa.as_ref(),&digest).to_vec(),ml.to_vec()));
     operations.push((c("signing-classical","Ed25519",public_spki(Operation::Ed25519,eddsa.as_ref())?),digest.clone(),ed.to_vec()));
    },
    (mpi::PublicKey::MLDSA87_Ed448{eddsa,mldsa},mpi::Signature::MLDSA87_Ed448{eddsa:ed,mldsa:ml})=>{
     operations.push((c("signing-pq","ML-DSA-87",public_spki(Operation::MlDsa87,mldsa.as_ref())?),external_mu(mldsa.as_ref(),&digest).to_vec(),ml.to_vec()));
     operations.push((c("signing-classical","Ed448",public_spki(Operation::Ed448,eddsa.as_ref())?),digest.clone(),ed.to_vec()));
    },
    (mpi::PublicKey::EdDSA{curve,q},mpi::Signature::EdDSA{r,s})=>{let(alg,spki)=classical(curve,q.value(),true)?;let mut raw=r.value_padded(32)?.to_vec();raw.extend(s.value_padded(32)?.as_ref());operations.push((c("signing-classical",&alg,spki),digest.clone(),raw));},
    (mpi::PublicKey::ECDSA{curve,q},mpi::Signature::ECDSA{r,s})=>{let(alg,spki)=classical(curve,q.value(),true)?;let der=EcdsaSig::from_private_components(openssl::bn::BigNum::from_slice(r.value())?,openssl::bn::BigNum::from_slice(s.value())?)?.to_der()?;operations.push((c("signing-classical",&alg,spki),digest.clone(),der));},
    _=>bail!("Unexpected generated signature")
   }
   let rows=operations.iter().map(|x|x.0.clone()).collect::<Vec<_>>();
   let request=serde_json::json!({"requestId":"A".repeat(64),"hashAlgorithm":10,"signingFingerprint":key.fingerprint().to_hex(),"digest":B64.encode(&digest)});
   let mut backend=Prepared{operations,calls:0};
   // Reject a substituted expected SPKI before the first hardware operation,
   // even when all remaining roles/algorithms and the certificate are valid.
   let mut bad=rows.clone();bad[0].public[0]^=1;assert!(sign(&key,&bad,&mut backend,&request).is_err());assert_eq!(backend.calls,0);
   let result=sign(&key,&rows,&mut backend,&request)?;assert_eq!(result["signingFingerprint"],key.fingerprint().to_hex());assert_eq!(backend.calls,rows.len());
   if matches!(key.mpis(),mpi::PublicKey::MLDSA87_Ed448{..}) {
    // A valid-length but damaged ML-DSA-87 result is a verification failure,
    // distinct from a provider exit or transport/base64/length failure.
    backend.operations[0].2[0]^=1;backend.calls=0;
    let error=sign(&key,&rows,&mut backend,&request).unwrap_err();
    assert_eq!(error.downcast_ref::<Failure>(),Some(&Failure::ComponentVerify));
    assert_eq!(backend.calls,2);
    backend.operations[0].2.pop();backend.calls=0;
    let error=sign(&key,&rows,&mut backend,&request).unwrap_err();
    assert_eq!(error.downcast_ref::<Failure>(),Some(&Failure::SignatureLength));
    assert_eq!(backend.calls,2);
   }
  }Ok(())
 }
}

#[cfg(test)]
mod recovery_tests {
 use super::*;use pgp::cert::{CertBuilder,CipherSuite};
 struct Shares{calls:usize,fail_at:usize}
 impl Executor for Shares{
  fn execute(&mut self,c:&Component,input:&[u8],sign:bool)->Result<Zeroizing<Vec<u8>>>{
   ensure!(!sign,"No signing in recovery");self.calls+=1;ensure!(self.calls!=self.fail_at,"Synthetic transport failure");
   let expected=match c.algorithm.as_str(){"ML-KEM-768"=>1088,"ML-KEM-1024"=>1568,"X25519"=>44,"X448"=>68,"P-384"=>120,_=>bail!("Unexpected component")};ensure!(input.len()==expected,"Wrong private input framing");
   Ok(Zeroizing::new(vec![7;match c.algorithm.as_str(){"P-384"=>48,"X448"=>56,_=>32}]))
  }
 }
 fn c(role:&str,alg:&str,public:Vec<u8>)->Component{Component{role:role.into(),algorithm:alg.into(),storage:"piv".into(),slot:"9d".into(),public}}
 #[test]fn recovery_profiles_reject_wrong_mappings_and_never_release_a_partial_result()->Result<()> {
  for(suite,profile)in[(CipherSuite::MLDSA65_Ed25519,pgp::Profile::RFC9580),(CipherSuite::MLDSA87_Ed448,pgp::Profile::RFC9580),(CipherSuite::Cv25519,pgp::Profile::RFC4880),(CipherSuite::P384,pgp::Profile::RFC9580)]{
   let(cert,_)=CertBuilder::new().set_profile(profile)?.set_cipher_suite(suite).add_userid("test@example.invalid").add_transport_encryption_subkey().generate()?;let key=selected(&cert,false)?;
   let(rows,cipher,ephemeral)=match key.mpis(){
    mpi::PublicKey::MLKEM768_X25519{ecdh,mlkem}=>(vec![c("decryption-pq","ML-KEM-768",public_spki(Operation::MlKem768,mlkem.as_ref())?),c("decryption-classical","X25519",public_spki(Operation::X25519,ecdh.as_ref())?)],vec![3;1088],ecdh.to_vec()),
    mpi::PublicKey::MLKEM1024_X448{ecdh,mlkem}=>(vec![c("decryption-pq","ML-KEM-1024",public_spki(Operation::MlKem1024,mlkem.as_ref())?),c("decryption-classical","X448",public_spki(Operation::X448,ecdh.as_ref())?)],vec![3;1568],ecdh.to_vec()),
    mpi::PublicKey::ECDH{curve,q,..}=>{let(alg,spki)=classical(curve,q.value(),false)?;(vec![c("decryption-classical",&alg,spki)],vec![],q.value().to_vec())},_=>bail!("Unexpected generated recipient")
   };
   let request=serde_json::json!({"requestId":"A".repeat(64),"cipherHash":"b".repeat(64),"recipientKey":key.fingerprint().to_hex(),"mlkemCiphertext":B64.encode(cipher),"x25519Ephemeral":B64.encode(ephemeral)});
   let mut bad=rows.clone();bad[0].public[0]^=1;let mut backend=Shares{calls:0,fail_at:0};assert!(decapsulate(&key,&bad,&mut backend,&request).is_err());assert_eq!(backend.calls,0);
   let reply=decapsulate(&key,&rows,&mut backend,&request)?;assert_eq!(backend.calls,rows.len());assert_eq!(reply["recipientKey"],request["recipientKey"]);
   for fail_at in 1..=rows.len(){let mut b=Shares{calls:0,fail_at};assert!(decapsulate(&key,&rows,&mut b,&request).is_err());assert_eq!(b.calls,fail_at);}
  }Ok(())
 }
 #[test]fn v5_second_digest_and_opaque_ids_are_validated_together_before_signing(){
  let mut request=serde_json::json!({"requestId":"A".repeat(64),"digest":B64.encode([1;64]),"inlineDigest":B64.encode([2;64])});assert!(v5_digests(&request).is_ok());
  request["inlineDigest"]=B64.encode([2;63]).into();assert!(v5_digests(&request).is_err());request["inlineDigest"]=B64.encode([2;64]).into();request["requestId"]="a".repeat(64).into();assert!(v5_digests(&request).is_err());
 }
}
