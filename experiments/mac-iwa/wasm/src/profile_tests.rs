//! Real software-only profile round trips, using the component APIs and an
//! independent Sequoia stream implementation. No account, native host, token,
//! filesystem identity, PIN or touch policy is involved.
use super::*;
use pgp::{crypto::{KeyPair,Password}, parse::stream::{DecryptionHelper,DecryptorBuilder},
    packet::{PKESK,SKESK}, serialize::stream::{Message,Encryptor,LiteralWriter,Signer},
    types::SymmetricAlgorithm, crypto::SessionKey};
use std::io::{Read,Write};
const PASSWORD:&str="Disposable profile regression password only";
const EMAIL:&str="profiles@example.invalid";
fn now()->f64{std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as f64}
struct Oracle {cert:Cert,pair:KeyPair,valid:bool}
impl VerificationHelper for Oracle {
 fn get_certs(&mut self,_:&[KeyHandle])->Result<Vec<Cert>>{Ok(vec![self.cert.clone()])}
 fn check(&mut self,structure:MessageStructure)->Result<()>{
  let mut count=0;
  for layer in structure.iter(){if let MessageLayer::SignatureGroup{results}=layer{
   for result in results{ensure!(result.is_ok(),"Independent signature invalid");count+=1;}
  }}
  ensure!(count==1,"Exactly one independent signature required");self.valid=true;Ok(())
 }
}
impl DecryptionHelper for Oracle {
 fn decrypt(&mut self,pk:&[PKESK],sk:&[SKESK],hint:Option<SymmetricAlgorithm>,decrypt:&mut dyn FnMut(Option<SymmetricAlgorithm>,&SessionKey)->bool)->Result<Option<Cert>>{
  ensure!(pk.len()==1&&sk.is_empty(),"One independent recipient required");
  let (algorithm,key)=pk[0].decrypt(&mut self.pair,hint).context("Independent decapsulation failed")?;
  ensure!(decrypt(algorithm.or(hint),&key),"Independent content authentication failed");Ok(Some(self.cert.clone()))
 }
}
fn keypair(cert:&Cert,signing:bool)->KeyPair{
 let policy=StandardPolicy::new();
 let ka=cert.keys().secret().with_policy(&policy,None).alive().revoked(false).find(|k|if signing{k.for_signing()}else{k.for_transport_encryption()}).unwrap();
 let password:Password=PASSWORD.into();
 if ka.key().fingerprint()==cert.fingerprint(){ka.key().clone().role_into_primary().decrypt_secret(&password).unwrap().into_keypair().unwrap()}
 else{ka.key().clone().role_into_subordinate().decrypt_secret(&password).unwrap().into_keypair().unwrap()}
}
fn profile_roundtrip(profile:&str){
 let generated=software::generate(serde_json::json!({"profile":profile,"name":"Disposable interop fixture","email":EMAIL,"password":PASSWORD})).unwrap();
 let info=&generated["public"];
 assert_eq!(info["profile"],profile);
 let secret=B64.decode(generated["encryptedSecret"].as_str().unwrap()).unwrap();
 let cert=Cert::from_bytes(&secret).unwrap();
 let public=info["certificate"].as_str().unwrap();
 let payload=b"From: profiles@example.invalid\r\nTo: profiles@example.invalid\r\nSubject: profile regression\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nExact authenticated test octets.\r\n";
 let request=serde_json::json!({"requestId":"A".repeat(64),"senderCertificate":public,"senderEmail":EMAIL,"payload":B64.encode(payload)});
 let started=now();let(pending,digest)=signing::prepare(&request,started).unwrap();
 let reply=software::sign(serde_json::json!({"encryptedSecret":generated["encryptedSecret"],"password":PASSWORD,"request":digest})).unwrap();
 let signed=signing::finish(pending,&reply,now()).unwrap();
 let encrypted=encrypt_public(&serde_json::json!({"senderCertificate":public,"recipientCertificate":public,"recipientFingerprint":info["fingerprint"],"recipientEmail":EMAIL,"signed":signed["signed"],"payload":signed["payload"]})).unwrap();
 let ciphertext=B64.decode(encrypted["cipher"].as_str().unwrap()).unwrap();
 // Independent stream consumer: it performs its own packet parsing, private
 // decryption, KDF, content authentication and signature validation.
 let policy=StandardPolicy::new();let helper=Oracle{cert:cert.clone().strip_secret_key_material(),pair:keypair(&cert,false),valid:false};
 let mut reader=DecryptorBuilder::from_bytes(&ciphertext).unwrap().with_policy(&policy,None,helper).unwrap();
 let mut clear=Vec::new();reader.read_to_end(&mut clear).unwrap();assert_eq!(clear,payload);assert!(reader.into_helper().valid);
 // Independent sender back to the split software provider. Using Sequoia's
 // stream signer/encryptor avoids reproducing the IWA packet assembly in tests.
 let mut independent=Vec::new();{
  let recipients=cert.keys().with_policy(&policy,None).for_transport_encryption();
  let enc=Encryptor::for_recipients(Message::new(&mut independent),recipients).build().unwrap();
  let signed=Signer::new(enc,keypair(&cert,true)).unwrap().build().unwrap();
  let mut literal=LiteralWriter::new(signed).build().unwrap();literal.write_all(payload).unwrap();literal.finalize().unwrap();
 }
 let request=serde_json::json!({"requestId":"B".repeat(64),"cipher":B64.encode(independent),"recipientCertificate":public,"recipientKey":info["recipientKey"],"purpose":"message"});
 let(pending,components)=decryption::prepare(&request,now()).unwrap();
 let response=software::decapsulate(serde_json::json!({"encryptedSecret":generated["encryptedSecret"],"password":PASSWORD,"request":components})).unwrap();
 let opened=decryption::finish(pending,&response,now()).unwrap();assert_eq!(B64.decode(opened["raw"].as_str().unwrap()).unwrap(),payload);
 assert_eq!(verify_public(&serde_json::json!({"payload":opened["raw"],"signature":opened["signature"],"certificates":[public]})).unwrap()["signatures"][0]["status"],"valid");
 // A substituted share must fail before plaintext release, for both the
 // classical-only and hybrid compatibility constructions.
 let(pending,_)=decryption::prepare(&request,now()).unwrap();let mut damaged=response;
 let size=B64.decode(damaged["x25519Secret"].as_str().unwrap()).unwrap().len();damaged["x25519Secret"]=B64.encode(vec![1;size]).into();
 assert!(decryption::finish(pending,&damaged,now()).is_err());
}
#[test]fn level5_v6_split_software_and_independent_sequoia_both_directions(){profile_roundtrip("level5")}
#[test]fn level3_v4_hybrid_split_software_and_independent_sequoia_both_directions(){profile_roundtrip("level3-v4-hybrid")}
#[test]fn level3_v4_classical_split_software_and_independent_sequoia_both_directions(){profile_roundtrip("level3-v4-classical")}
#[test]fn level5_v4_hybrid_split_software_and_independent_sequoia_both_directions(){profile_roundtrip("level5-v4-hybrid")}
#[test]fn level5_v4_classical_split_software_and_independent_sequoia_both_directions(){profile_roundtrip("level5-v4-classical")}

/// Different security levels must not couple sender signing to recipient KEM.
/// Each side selects its own authenticated key; neither party is downgraded.
fn cross_roundtrip(names:[&str;2]){
 let profiles:[serde_json::Value;2]=names.map(|profile|software::generate(serde_json::json!({"profile":profile,"name":"Cross-level fixture","email":EMAIL,"password":PASSWORD})).unwrap());
 for (sender,recipient) in [(0,1),(1,0)] {
  let own=&profiles[sender];let peer=&profiles[recipient];let payload=b"Cross-level authenticated message\r\n";
  let request=serde_json::json!({"requestId":"C".repeat(64),"senderCertificate":own["public"]["certificate"],"senderEmail":EMAIL,"payload":B64.encode(payload)});
  let(pending,digest)=signing::prepare(&request,now()).unwrap();
  let reply=software::sign(serde_json::json!({"encryptedSecret":own["encryptedSecret"],"password":PASSWORD,"request":digest})).unwrap();
  let signed=signing::finish(pending,&reply,now()).unwrap();
  let encrypted=encrypt_public(&serde_json::json!({"senderCertificate":own["public"]["certificate"],"recipientCertificate":peer["public"]["certificate"],"recipientFingerprint":peer["public"]["fingerprint"],"recipientEmail":EMAIL,"signed":signed["signed"],"payload":signed["payload"]})).unwrap();
  let request=serde_json::json!({"requestId":"D".repeat(64),"cipher":encrypted["cipher"],"recipientCertificate":peer["public"]["certificate"],"recipientKey":peer["public"]["recipientKey"],"purpose":"message"});
  let(pending,components)=decryption::prepare(&request,now()).unwrap();
  let reply=software::decapsulate(serde_json::json!({"encryptedSecret":peer["encryptedSecret"],"password":PASSWORD,"request":components})).unwrap();
  let opened=decryption::finish(pending,&reply,now()).unwrap();
  assert_eq!(B64.decode(opened["raw"].as_str().unwrap()).unwrap(),payload);
  let checked=verify_public(&serde_json::json!({"payload":opened["raw"],"signature":opened["signature"],"certificates":[own["public"]["certificate"]]})).unwrap();
  assert_eq!(checked["signatures"][0]["status"],"valid");assert_eq!(checked["signatures"][0]["pqSigning"],own["public"]["pqSigning"]);
 }
}

#[test]fn level3_and_level5_v6_cross_signing_and_decryption(){cross_roundtrip(["level3","level5"])}
#[test]fn v6_and_v4_hybrid_cross_signing_and_decryption(){cross_roundtrip(["level3","level3-v4-hybrid"])}
#[test]fn v6_and_v4_classical_cross_signing_and_decryption(){cross_roundtrip(["level5","level5-v4-classical"])}

/// Hardware Level 5 compatibility uses P-384, whereas newly created software
/// compatibility identities use P-521. These disposable fixtures model the
/// card's raw component boundary so a 521-bit-only parser cannot masquerade as
/// hardware support. No slot, PKCS#11 module or physical key is accessed.
fn p384_hardware_roundtrip(version:u8,hybrid_encryption:bool){
 use pgp::{cert::{CertBuilder,CipherSuite},crypto::{mpi,Signer as CryptoSigner},types::{HashAlgorithm,KeyFlags,PublicKeyAlgorithmSpecification as Spec}};
 use ml_kem::{kem::Decapsulate,DecapsulationKey,MlKem768};
 let mut builder=CertBuilder::new().set_profile(if version==6{pgp::Profile::RFC9580}else{pgp::Profile::RFC4880}).unwrap()
  .set_cipher_suite(CipherSuite::P384).set_primary_key_flags(KeyFlags::empty().set_certification().set_signing()).add_userid(EMAIL);
 if hybrid_encryption{builder=builder.set_encryption_algorithm(Spec::mlkem768_x25519());}
 let(cert,_)=builder.add_transport_encryption_subkey().generate().unwrap();
 let public=B64.encode(cert.clone().strip_secret_key_material().to_vec().unwrap());
 let info=certificates::inspect_identity_value(&public).unwrap();
 let profile=if version==6{"level5-v6-classical"}else if hybrid_encryption{"level5-v4-hybrid-p384"}else{"level5-v4-classical-p384"};
 assert_eq!(info["supported"],true);assert_eq!(info["profile"],profile);
 assert_eq!(info["pqSigning"],false);assert_eq!(info["pqEncryption"],hybrid_encryption);
 assert!(info["signingAlgorithm"].as_str().unwrap().contains("384"));
 let policy=StandardPolicy::new();
 let mut signer=cert.keys().secret().with_policy(&policy,None).for_signing().next().unwrap().key().clone().into_keypair().unwrap();
 let recipient=cert.keys().secret().with_policy(&policy,None).for_transport_encryption().next().unwrap().key().clone().into_keypair().unwrap();
 let payload=b"From: profiles@example.invalid\r\nTo: profiles@example.invalid\r\nSubject: P-384 hardware boundary regression\r\n\r\nSynthetic P-384 message.\r\n";
 let request=serde_json::json!({"requestId":"E".repeat(64),"senderCertificate":public,"senderEmail":EMAIL,"payload":B64.encode(payload)});
 let(pending,mut response)=signing::prepare(&request,now()).unwrap();
 let digest=B64.decode(response["digest"].as_str().unwrap()).unwrap();
 let signature=signer.sign(HashAlgorithm::SHA512,&digest).unwrap();
 let mpi::Signature::ECDSA{r,s}=signature else{panic!("P-384 fixture signature")};
 // PKCS#11 returns a fixed-width r || s signature, not OpenPGP MPIs and not a
 // DER SEQUENCE. Left-padding is required for rare leading-zero values.
 let mut fixed=vec![0;96];fixed[48-r.value().len()..48].copy_from_slice(r.value());fixed[96-s.value().len()..].copy_from_slice(s.value());
 response["ed25519"]=B64.encode(fixed).into();response["mldsa65"]="".into();
 let signed=signing::finish(pending,&response,now()).unwrap();
 let(pending,_)=signing::prepare(&request,now()).unwrap();let mut wrong_curve=response.clone();wrong_curve["ed25519"]=B64.encode([0;132]).into();
 assert!(signing::finish(pending,&wrong_curve,now()).is_err(),"P-521-width result cannot be accepted for P-384");
 let encrypted=encrypt_public(&serde_json::json!({"senderCertificate":public,"recipientCertificate":public,"recipientFingerprint":info["fingerprint"],"recipientEmail":EMAIL,"signed":signed["signed"],"payload":signed["payload"]})).unwrap();
 let ciphertext=B64.decode(encrypted["cipher"].as_str().unwrap()).unwrap();
 let helper=Oracle{cert:cert.clone().strip_secret_key_material(),pair:recipient.clone(),valid:false};
 let mut reader=DecryptorBuilder::from_bytes(&ciphertext).unwrap().with_policy(&policy,None,helper).unwrap();
 let mut clear=Vec::new();reader.read_to_end(&mut clear).unwrap();assert_eq!(clear,payload);assert!(reader.into_helper().valid);
 // Return traffic is produced by Sequoia's independent stream layer. Only raw
 // private component operations are simulated below; IWA recovers the session
 // key, authenticates the content, and verifies the ordinary P-384 signature.
 let mut independent=Vec::new();{
  let recipients=cert.keys().with_policy(&policy,None).for_transport_encryption();
  let enc=Encryptor::for_recipients(Message::new(&mut independent),recipients).build().unwrap();
  let signed=Signer::new(enc,signer).unwrap().build().unwrap();
  let mut literal=LiteralWriter::new(signed).build().unwrap();literal.write_all(payload).unwrap();literal.finalize().unwrap();
 }
 let request=serde_json::json!({"requestId":"F".repeat(64),"cipher":B64.encode(independent),"recipientCertificate":public,"recipientKey":info["recipientKey"],"purpose":"message"});
 let(pending,mut response)=decryption::prepare(&request,now()).unwrap();
 let ephemeral=B64.decode(response["x25519Ephemeral"].as_str().unwrap()).unwrap();
 recipient.secret().map(|secret|match secret{
  mpi::SecretKeyMaterial::ECDH{scalar}=>{
   let scalar=p384::SecretKey::from_slice(scalar.value()).unwrap();
   let peer=p384::PublicKey::from_sec1_bytes(&ephemeral).unwrap();
   let secret=p384::ecdh::diffie_hellman(scalar.to_nonzero_scalar(),peer.as_affine());
   response["x25519Secret"]=B64.encode(secret.raw_secret_bytes()).into();response["mlkemSecret"]="".into();
  },
  mpi::SecretKeyMaterial::MLKEM768_X25519{ecdh,mlkem}=>{
   let scalar:[u8;32]=ecdh.as_ref().try_into().unwrap();let peer:[u8;32]=ephemeral.as_slice().try_into().unwrap();
   let ciphertext:[u8;1088]=B64.decode(response["mlkemCiphertext"].as_str().unwrap()).unwrap().try_into().unwrap();
   let secret=DecapsulationKey::<MlKem768>::from_seed((&mlkem[..]).try_into().unwrap()).decapsulate((&ciphertext).into());
   response["mlkemSecret"]=B64.encode(secret).into();response["x25519Secret"]=B64.encode(x25519_dalek::x25519(scalar,peer)).into();
  },_=>panic!("P-384 fixture recipient algorithm")});
 let opened=decryption::finish(pending,&response,now()).unwrap();assert_eq!(B64.decode(opened["raw"].as_str().unwrap()).unwrap(),payload);
 let checked=verify_public(&serde_json::json!({"payload":opened["raw"],"signature":opened["signature"],"certificates":[public]})).unwrap();
 assert_eq!(checked["signatures"][0]["status"],"valid");assert_eq!(checked["signatures"][0]["pqSigning"],false);
 let(pending,_)=decryption::prepare(&request,now()).unwrap();response["x25519Secret"]=B64.encode(vec![0;ephemeral.len()]).into();
 assert!(decryption::finish(pending,&response,now()).is_err(),"Invalid classical share must fail authentication");
}
#[test]fn level5_hardware_p384_v6_classical_both_directions(){p384_hardware_roundtrip(6,false)}
#[test]fn level5_hardware_p384_v4_classical_both_directions(){p384_hardware_roundtrip(4,false)}
#[test]fn level5_hardware_p384_v4_hybrid_both_directions(){p384_hardware_roundtrip(4,true)}
