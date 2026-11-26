import {b64,bytes} from './core.js';

// S/MIME shares the two native PQ keys with OpenPGP but needs a separate
// P-384 signing key and P-384 agreement key. The latter also matches the
// existing PQ Mail slot map. Never use the same scalar for both purposes.
export const LEVEL3_SMIME_SLOTS=Object.freeze({
 signing:'83', agreement:'82', mlDsa:'9c', mlKem:'9d',
});
const roles=Object.freeze([
 {purpose:'signing',algorithm:'ECDSA',usages:['sign','verify']},
 {purpose:'agreement',algorithm:'ECDH',usages:['deriveBits']},
 {purpose:'certification',algorithm:'ECDSA',usages:['sign','verify']},
]);

// These records are for the encrypted vault only, not public identity
// metadata or the OpenPGP-only export. Callers own their vault transaction.
const slotFor=purpose=>purpose==='certification'?'8b':LEVEL3_SMIME_SLOTS[purpose];
async function generateEcKey(role){
 const key=await crypto.subtle.generateKey({name:role.algorithm,namedCurve:'P-384'},true,role.usages);
 const secret=new Uint8Array(await crypto.subtle.exportKey('pkcs8',key.privateKey));
 try{return {slot:slotFor(role.purpose),publicKey:b64(await crypto.subtle.exportKey('spki',key.publicKey)),privateKey:b64(secret)};}
 finally{secret.fill(0);}
}
export async function generateNistCertificationKeys(publicFromSeed){
 const seed=crypto.getRandomValues(new Uint8Array(32));
 try{
  const publicKey=await publicFromSeed(seed);
  if(publicKey.length!==1952)throw Error('Invalid certification public key.');
  return {ec:await generateEcKey(roles[2]),pq:{slot:'8a',publicKey:b64(publicKey),privateKey:b64(seed)}};
 }finally{seed.fill(0);}
}
export async function generateLevel3SmimeKeys(){
 const result={};
 for(const role of roles.filter(role=>role.purpose!=='certification')){
  result[role.purpose]=await generateEcKey(role);
 }
 return result;
}

// A backup readback compares the private material as well as the slot and
// public key. A file containing only OpenPGP or certificates cannot qualify.
export function sameLevel3SmimeKeys(expected,restored){
 if(expected==null || restored==null)return expected===restored;
 return roles.filter(role=>role.purpose!=='certification').every(({purpose})=>{
  const key=expected[purpose],copy=restored[purpose];
  return key?.slot===LEVEL3_SMIME_SLOTS[purpose]&&key.slot===copy?.slot&&
   typeof key.privateKey==='string'&&key.privateKey.length>0&&key.privateKey===copy.privateKey&&
   typeof key.publicKey==='string'&&key.publicKey.length>0&&key.publicKey===copy.publicKey;
 });
}

// Derive the PIV import scalar with Web Crypto and clear its mutable DER
// buffer. Keep this API separate from public-key assembly.
export async function level3SmimeImportScalar(purpose,material){
 const role=roles.find(role=>role.purpose===purpose);
 if(!role||material?.slot!==slotFor(purpose))throw Error('Invalid S/MIME key purpose or slot.');
 const der=bytes(material.privateKey);
 try{
  const key=await crypto.subtle.importKey('pkcs8',der,{name:role.algorithm,namedCurve:'P-384'},true,[role.usages[0]]);
  const jwk=await crypto.subtle.exportKey('jwk',key);
  // Validate the public point against the private key before authorizing import.
  const pub=await crypto.subtle.importKey('spki',bytes(material.publicKey),
   {name:role.algorithm,namedCurve:'P-384'},true,role.algorithm==='ECDSA'?['verify']:[]);
  const expected=await crypto.subtle.exportKey('jwk',pub);
  if(jwk.x!==expected.x||jwk.y!==expected.y)throw Error('S/MIME public and private keys do not match.');
  const raw=bytes(jwk.d.replace(/-/g,'+').replace(/_/g,'/'));
  if(raw.length!==48){raw.fill(0);throw Error('Invalid P-384 private scalar.');}
  return raw;
 }finally{der.fill(0);}
}
