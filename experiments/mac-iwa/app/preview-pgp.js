// Diagnostic-only RFC 4880/6637 packet construction. Sequoia independently
// parses the resulting certificates and verifies every message; success never
// grants contact trust or installs these synthetic identities into the vault.
import {p256} from './vendor/curves/nist.js';
import {sha1} from './vendor/hashes/legacy.js';
import {digest,derive,verify} from './preview-sign.js';
const text=s=>new TextEncoder().encode(s);
const cat=(...xs)=>new Uint8Array(xs.flatMap(x=>Array.from(x)));
const u16=n=>[n>>>8&255,n&255],u32=n=>[n>>>24,n>>>16&255,n>>>8&255,n&255];
const packet=(tag,body)=>cat([0xc0|tag,255],u32(body.length),body);
const sub=(tag,body)=>cat([body.length+1,tag],body);
function mpi(bytes){let i=0;while(i<bytes.length&&bytes[i]===0)i++;const b=bytes.slice(i);return cat(u16(b.length?8*(b.length-1)+32-Math.clz32(b[0]):0),b);}
function preparation(type,data,fingerprint,time,flags=false){
 const hashed=cat(sub(2,u32(time)),sub(33,cat([4],fingerprint)),flags?sub(27,[3]):[]);
 const head=cat([4,type,19,8],u16(hashed.length),hashed);
 const preimage=cat(data,head,[4,255],u32(head.length));
 return {preimage,digest:digest(preimage),finish(der){
  const raw=p256.Signature.fromBytes(der,'der').toBytes('compact');
  const unhashed=sub(16,fingerprint.slice(-8));
  return packet(2,cat(head,u16(unhashed.length),unhashed,digest(preimage).slice(0,2),mpi(raw.slice(0,32)),mpi(raw.slice(32))));
 }};
}
export function prepareCertificate(publicKey,index,time){
 const key=cat([4],u32(time),[19,8],new Uint8Array([42,134,72,206,61,3,1,7]),mpi(publicKey));
 const keyHash=cat([0x99],u16(key.length),key),fingerprint=sha1(keyHash);
 const email=`arkg-${index}@example.invalid`,uid=text(`ARKG synthetic test ${index} <${email}>`);
 const self=preparation(0x13,cat(keyHash,[0xb4],u32(uid.length),uid),fingerprint,time,true);
 return {fingerprint,email,self,finish:signature=>cat(packet(6,key),packet(13,uid),self.finish(signature))};
}
export const prepareMessage=(message,fingerprint,time)=>preparation(0,message,fingerprint,time);
export function signedMessage(message,signature,time,fingerprint){
 // One-pass signature metadata lets a streaming OpenPGP verifier select the
 // signer before consuming literal data. The final signature authenticates it.
 return cat(packet(4,cat([3,0,8,19],fingerprint.slice(-8),[1])),packet(11,cat([0x62,0],u32(time),message)),signature);
}
const b64=b=>btoa(String.fromCharCode(...b));
export async function batch(master,sign,checkCertificate,checkMessage,onRow,random=()=>crypto.getRandomValues(new Uint8Array(32))){
 const rows=[],seen=new Set(),time=Math.floor(Date.now()/1000)-1;
 for(let i=1;i<=10;i++){
  const seed=random();let derived;try{derived=derive(master,seed,text('Sequoia previewSign OpenPGP '+i));}finally{seed.fill(0);}
  const cert=prepareCertificate(derived.publicKey,i,time),fp=Array.from(cert.fingerprint,b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
  if(seen.has(fp))throw Error('Duplicate derived public key');seen.add(fp);
  const certSignature=await sign(derived,cert.self.digest,`Key ${i}/10 — certify OpenPGP identity`);
  if(!verify(certSignature,cert.self.preimage,derived.publicKey))throw Error(`Key ${i}: self-signature failed`);
  const certificate=cert.finish(certSignature),info=await checkCertificate(b64(certificate));
  if(info.fingerprint!==fp||!info.emails.includes(cert.email))throw Error(`Key ${i}: Sequoia rejected self-certification`);
  const message=text(`Synthetic ARKG OpenPGP message ${i} of 10. No personal information. ${crypto.randomUUID()}`);
  const prepared=prepareMessage(message,cert.fingerprint,time),der=await sign(derived,prepared.digest,`Key ${i}/10 — sign synthetic OpenPGP message`);
  if(!verify(der,prepared.preimage,derived.publicKey))throw Error(`Key ${i}: message signature failed`);
  const signature=prepared.finish(der),request={certificates:[b64(certificate)],payload:b64(message),signature:b64(signature)};
  const result=await checkMessage(request);
  if(result.signatures?.length!==1||result.signatures[0].status!=='valid'||result.signatures[0].fingerprint!==fp)throw Error(`Key ${i}: Sequoia message verification failed`);
  let tamperedValid=false;
  try{tamperedValid=(await checkMessage({...request,payload:b64(cat(message,[0]))})).signatures?.some(s=>s.status==='valid');}catch{/* A parser/verifier rejection is expected for altered signed bytes. */}
  if(tamperedValid)throw Error(`Key ${i}: altered message verified`);
  const row={index:i,fingerprint:fp,certificateVerified:true,messageVerified:true,tamperedMessageRejected:true,certificate:b64(certificate),signedMessage:b64(signedMessage(message,signature,time,cert.fingerprint)),payload:request.payload,signature:request.signature};
  rows.push(row);await onRow(row);
 }
 return {version:1,result:'PASS',algorithm:'previewSign ARKG-P256 / OpenPGP v4 ECDSA',verifier:'Sequoia WASM',rows};
}
