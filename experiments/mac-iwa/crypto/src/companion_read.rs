//! Read-only encrypted-companion transport and native wrapping-share release.
//!
//! The only recognized namespace is the committed companion bank. No endpoint
//! can write objects, reconstruct certificates, decrypt PKCS#12 or persist a
//! wrapping password. Software private operations stay exclusively in WASM.
use super::*;
use crate::mapped::Executor;
use sequoia_pqmail_piv::restore::{Card,ObjectReader};
use sequoia_public_bundle::companion::VerifiedCompanion;
use std::{collections::BTreeMap,path::Path};
use sha2::{Digest,Sha256};
const BANK:u32=0x5f5200;

fn load(card:&mut impl Card,serial:u32)->Result<(Vec<u8>,BTreeMap<String,Vec<u8>>)> {
 ensure!(card.serial()?==serial,"Wrong companion serial");
 let index=card.object(BANK)?.context("No encrypted companion")?;
 ensure!(index.len()==44&&index.starts_with(b"PQCIDX01"),"Invalid companion index");
 let size=u32::from_be_bytes(index[8..12].try_into()?) as usize;ensure!((1..=65536).contains(&size),"Companion size limit");
 let mut encoded=Vec::with_capacity(size);let mut observed=BTreeMap::from([(BANK,index.clone())]);
 for i in 0..size.div_ceil(2048){let tag=BANK+1+i as u32;let chunk=card.object(tag)?.context("Incomplete companion")?;
  ensure!(chunk.len()==12+2048.min(size-i*2048)&&chunk.starts_with(b"PQCCHK01")&&u32::from_be_bytes(chunk[8..12].try_into()?)==i as u32,"Invalid companion chunk");
  encoded.extend_from_slice(&chunk[12..]);observed.insert(tag,chunk);
 }
 ensure!(Sha256::digest(&encoded).as_slice()==&index[12..],"Companion transport digest mismatch");
 // Read a bounded union of the two deployed layouts. The signed companion
 // parser chooses and validates its exact four keys, never arbitrary slots.
 let mut keys=BTreeMap::new();for slot in [0x82,0x83,0x86,0x9c,0x9d] {if let Some(key)=card.public_key(slot)?{ensure!((32..=8192).contains(&key.len()),"Public key bound");keys.insert(format!("{slot:02x}"),key);}}
 for(tag,bytes)in observed{ensure!(card.object(tag)?.as_ref()==Some(&bytes),"Companion changed while reading");}
 for(slot,key)in &keys{ensure!(card.public_key(u8::from_str_radix(slot,16)?)?.as_ref()==Some(key),"Companion public key changed");}
 ensure!(card.serial()?==serial,"Companion serial changed");Ok((encoded,keys))
}

/// The on-card union may include unrelated provisioned slots. Exactly one of
/// the two fixed companion layouts must verify; only that four-key snapshot
/// enters browser state or the later private-operation grant.
fn verified_subset(encoded:&[u8],serial:u32,keys:&BTreeMap<String,Vec<u8>>,cached:Option<&[u8]>)->Result<(VerifiedCompanion,BTreeMap<String,Vec<u8>>)> {
 let mut matches=Vec::new();
 for slots in [["86","9c","9d","82"],["82","9c","9d","83"]] {
  let selected: BTreeMap<_,_>=slots.iter().filter_map(|slot|keys.get(*slot).map(|value|(slot.to_string(),value.clone()))).collect();
  if selected.len()==4 {if let Ok(value)=VerifiedCompanion::parse(encoded,serial,&selected,cached){matches.push((value,selected));}}
 }
 ensure!(matches.len()==1,"Companion signature/public keys/cache did not verify");Ok(matches.remove(0))
}

pub fn read(v:&serde_json::Value)->Result<serde_json::Value>{
 let serial=field(v,"serial")?.parse::<u32>()?;ensure!(serial>0&&serial<=i32::MAX as u32,"Serial limit");
 let mut card=ObjectReader::connect(Path::new(field(v,"objectHelper")?),serial)?;
 let(encoded,keys)=load(&mut card,serial)?;
 let cached=v.get("certificate").map(|c| -> Result<Vec<u8>> {Ok(B64.decode(c.as_str().context("Public cache")?)?)}).transpose()?;
 let (verified,keys)=verified_subset(&encoded,serial,&keys,cached.as_deref())?;
 let mut value=verified.preview();value["encoded"]=B64.encode(encoded).into();
 value["publicKeys"]=serde_json::to_value(keys.into_iter().map(|(k,v)|(k,B64.encode(v))).collect::<BTreeMap<_,_>>())?;Ok(value)
}

/// Reauthenticate the exact ciphertext before executing its no-touch wrapping
/// derive. The public key match happens again inside PKCS#11. The wrapping
/// share is emitted only together with successful message components, under
/// the same one-use PIN grant. No password or private key reaches this worker.
/// Verify companion authority before *any* message-private operation. The
/// original public packet encoding may differ from canonical inventory bytes;
/// compare canonical public certificates, not interchangeable armor framing.
pub fn validate_context(v:&serde_json::Value)->Result<VerifiedCompanion>{
 let stored=&v["hardware"]["companion"];
 let encoded=B64.decode(field(stored,"encoded")?)?;let serial=field(stored,"serial")?.parse()?;
 ensure!(v["hardware"]["serial"]==stored["serial"]&&v["config"]["serial"]==stored["serial"],"Companion serial mismatch");
 let digest=Sha256::digest(&encoded).iter().map(|b|format!("{b:02x}")).collect::<String>();
 ensure!(field(&v["hardware"],"bundleHash")?==digest,"Companion ciphertext changed");
 let keys=stored["publicKeys"].as_object().context("Companion live keys")?.iter().map(|(k,v)|Ok((k.clone(),B64.decode(v.as_str().context("Public key")?)?))).collect::<Result<BTreeMap<_,_>>>()?;
 let certificate=B64.decode(field(stored,"certificate")?)?;
 let verified=VerifiedCompanion::parse(&encoded,serial,&keys,Some(&certificate))?;
 ensure!(public(&B64.encode(verified.certificate_bytes()))?.to_vec()?==public(field(v,"own")?)?.to_vec()?,"Companion certificate changed");
 ensure!(verified.preview()["components"]==v["hardware"]["components"],"Companion role mapping changed");
 Ok(verified)
}

pub fn complete_hardware(v:&serde_json::Value,rows:&[mapped::Component],session:&mut mapped::Session,reply:&mut serde_json::Value)->Result<()> {
 let verified=validate_context(v)?;
 let wrap=rows.iter().find(|c|c.role=="companion-wrap").context("Companion wrapping mapping")?;
 ensure!(wrap.slot==verified.wrapping_slot()&&wrap.algorithm=="P-384","Companion wrapping key mismatch");
 let shared=session.execute(wrap,verified.wrapping_peer(),false)?;ensure!(shared.len()==48&&shared.iter().any(|b|*b!=0),"Companion wrapping share length");
 reply["companion"]=v["hardware"]["companion"].clone();reply["companionShared"]=B64.encode(&*shared).into();Ok(())
}

#[cfg(test)]
mod tests {
 use super::*;
 struct Memory {objects:BTreeMap<u32,Vec<u8>>,keys:BTreeMap<u8,Vec<u8>>,reads:usize,change:bool}
 impl Card for Memory {
  fn serial(&mut self)->Result<u32>{Ok(123)}
  fn public_key(&mut self,slot:u8)->Result<Option<Vec<u8>>>{Ok(self.keys.get(&slot).cloned())}
  fn object(&mut self,tag:u32)->Result<Option<Vec<u8>>>{self.reads+=1;let mut value=self.objects.get(&tag).cloned();if self.change&&self.reads>2{value=Some(vec![9]);}Ok(value)}
 }
 fn fixture()->Memory {
  let bytes=b"opaque encrypted companion";let mut index=b"PQCIDX01".to_vec();index.extend((bytes.len() as u32).to_be_bytes());index.extend(Sha256::digest(bytes));
  let mut chunk=b"PQCCHK01".to_vec();chunk.extend(0u32.to_be_bytes());chunk.extend(bytes);
  Memory{objects:BTreeMap::from([(BANK,index),(BANK+1,chunk)]),keys:BTreeMap::new(),reads:0,change:false}
 }
 #[test]fn bounded_fixed_companion_transport_detects_corruption_and_changes(){
  let mut card=fixture();assert_eq!(load(&mut card,123).unwrap().0,b"opaque encrypted companion");
  for case in 0..5 {let mut card=fixture();match case{0=>{card.objects.remove(&(BANK+1));},1=>{card.objects.get_mut(&BANK).unwrap()[8..12].copy_from_slice(&65537u32.to_be_bytes());},2=>{card.objects.get_mut(&BANK).unwrap()[12]^=1;},3=>{card.objects.get_mut(&(BANK+1)).unwrap()[11]=1;},_=>card.change=true}assert!(load(&mut card,123).is_err());}
 }
}
