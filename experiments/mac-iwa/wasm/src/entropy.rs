//! Operation-local HMAC-DRBG (SHA-512, SP 800-90A Update/Generate).
//! Only explicit software generation installs it. Other randomness requests use
//! the browser CSPRNG directly. No seed/state is serialized or returned.
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};
#[derive(Zeroize, ZeroizeOnDrop)]
struct Drbg { k:[u8;64], v:[u8;64], requests:u64 }
impl Drbg {
 fn mac(&self, parts:&[&[u8]])->[u8;64]{let mut h=Hmac::<Sha512>::new_from_slice(&self.k).expect("fixed HMAC key");for p in parts{h.update(p);}h.finalize().into_bytes().into()}
 fn update(&mut self, seed:&[u8]){
  self.k=self.mac(&[&self.v,&[0],seed]);self.v=self.mac(&[&self.v]);
  if !seed.is_empty(){self.k=self.mac(&[&self.v,&[1],seed]);self.v=self.mac(&[&self.v]);}
 }
 fn new(seed:&[u8])->Self{let mut s=Self{k:[0;64],v:[1;64],requests:0};s.update(seed);s}
 fn fill(&mut self,out:&mut[u8])->Result<(),()>{
  if out.len()>65536||self.requests>=1_000_000{return Err(())}
  for part in out.chunks_mut(64){self.v=self.mac(&[&self.v]);part.copy_from_slice(&self.v[..part.len()]);}
  self.update(&[]);self.requests+=1;Ok(())
 }
}
#[cfg(target_arch="wasm32")]
mod browser {
 use super::*;
 use std::cell::RefCell;
 use wasm_bindgen::prelude::*;
 #[wasm_bindgen]
 extern "C" {
  // Bypass getrandom here: this is the independent OS input, not a recursive
  // call into the temporarily installed DRBG.
  #[wasm_bindgen(js_namespace=["globalThis","crypto"],js_name=getRandomValues,catch)]
  fn os_random(bytes:&mut[u8])->Result<JsValue,JsValue>;
 }
 thread_local!{static ACTIVE:RefCell<Option<Drbg>>=const{RefCell::new(None)};}
 pub struct Scope;
 impl Scope {pub fn assert_used(&self)->anyhow::Result<()>{
  anyhow::ensure!(ACTIVE.with(|s|s.borrow().as_ref().map(|r|r.requests>0).unwrap_or(false)),"Generation did not consume mixed randomness");Ok(())
 }}
 impl Drop for Scope{fn drop(&mut self){ACTIVE.with(|s|{s.borrow_mut().take();});}}
 pub fn start(hardware:&[u8])->anyhow::Result<Scope>{
  anyhow::ensure!(hardware.len()==32,"One 32-byte entropy output required");
  let mut seed=zeroize::Zeroizing::new(vec![0u8;96]);
  os_random(&mut seed).map_err(|_|anyhow::anyhow!("Browser RNG failed"))?;
  seed.extend_from_slice(hardware);seed.extend_from_slice(b"Sequoia IWA key generation entropy v1");
  ACTIVE.with(|s|{anyhow::ensure!(s.borrow().is_none(),"Entropy scope already active");*s.borrow_mut()=Some(Drbg::new(&seed));Ok(())})?;
  Ok(Scope)
 }
 // getrandom 0.4 retains the v03 custom-backend ABI. This cfg is set only for
 // wasm builds; native tooling/tests retain their normal OS random backend.
 #[no_mangle]
 unsafe fn __getrandom_v03_custom(dest:*mut u8,len:usize)->Result<(),getrandom::Error>{
  let bytes=unsafe{std::slice::from_raw_parts_mut(dest,len)};
  ACTIVE.with(|s|{
   if let Some(rng)=s.borrow_mut().as_mut(){return rng.fill(bytes).map_err(|_|getrandom::Error::UNSUPPORTED)}
   for part in bytes.chunks_mut(65536){os_random(part).map_err(|_|getrandom::Error::UNSUPPORTED)?;}Ok(())
  })
 }
}
#[cfg(target_arch="wasm32")]
pub use browser::start;

#[cfg(test)]
mod tests {
 use super::*;
 // Independent Python stdlib HMAC-SHA512 reference, seed bytes 0..223.
 #[test] fn reference_generate_and_post_generate_update(){
  let seed:Vec<u8>=(0..224).collect();let mut rng=Drbg::new(&seed);let mut out=[0u8;64];
  rng.fill(&mut out).unwrap();assert_eq!(out.iter().map(|b|format!("{b:02x}")).collect::<String>(),"57d590a2b696d688b0c99bb19b82929436e151e71014bfc8b5e637ad66af66cd9193aa276ae2aafd809445b551aab5d8aaf8deb8126b5947dbd1cb8e127c0489");
  rng.fill(&mut out).unwrap();assert_eq!(out.iter().map(|b|format!("{b:02x}")).collect::<String>(),"ecb8f00c5cd491c3fb62a6e832ec0e2d62189fcc48b40fc1ae598bf8a76e9b95bcec62907d9ab9013489bc7cb46412d70c9801dab55e65e66cd71203ba9710d8");
  assert!(rng.fill(&mut vec![0u8;65537]).is_err());
  rng.zeroize();assert!(rng.k.iter().all(|b|*b==0)&&rng.v.iter().all(|b|*b==0));
 }
}
