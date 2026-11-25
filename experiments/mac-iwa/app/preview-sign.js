// Experimental ARKG-P256 public derivation for previewSign v4 (-65539).
// Only ephemeral derivation material exists here; the master private keys stay
// on the authenticator. Never use this diagnostic as a production signing API.
import {p256} from './vendor/curves/nist.js';
import {hash_to_field} from './vendor/curves/abstract/hash-to-curve.js';
import {sha256} from './vendor/hashes/sha2.js';
import {hkdf} from './vendor/hashes/hkdf.js';
import {hmac} from './vendor/hashes/hmac.js';
import {encode} from './ctap2-smartcard.js';
const text=s=>new TextEncoder().encode(s);
const cat=(...a)=>new Uint8Array(a.flatMap(x=>Array.from(x)));
const order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const scalar=(msg,dst)=>hash_to_field(msg,1,{p:order,m:1,k:128,hash:sha256,expand:'xmd',DST:dst})[0][0];
export function point(key){
 if(!(key instanceof Map)||key.get(1)!==2||key.get(-1)!==1||key.get(-2)?.length!==32||key.get(-3)?.length!==32)throw Error('Invalid P-256 COSE key');
 return p256.Point.fromBytes(cat([4],key.get(-2),key.get(-3)));
}
export function derive(master,ikm,context){
 if(!(master instanceof Map)||![-7,-9].includes(master.get(-3))||ikm.length!==32||context.length>64)throw Error('Unsupported ARKG master or context');
 const bl=point(master.get(-1)),kem=point(master.get(-2)),ctx=cat([context.length],context);
 const ephemeral=scalar(ikm,text('ARKG-KEM-ECDH-KG.ARKG-ECDH.ARKG-P256'));
 const cipher=p256.Point.BASE.multiply(ephemeral).toBytes(false);
 const shared=kem.multiply(ephemeral).toBytes(false).slice(1,33);
 const suffix=cat(text('ARKG-ECDH.ARKG-P256ARKG-Derive-Key-KEM.'),ctx);
 const mk=hkdf(sha256,shared,undefined,cat(text('ARKG-KEM-HMAC-mac.'),suffix),32);
 const seed=hkdf(sha256,shared,undefined,cat(text('ARKG-KEM-HMAC-shared.'),suffix),32);
 try{
  const tau=scalar(seed,cat(text('ARKG-BL-EC.ARKG-P256ARKG-Derive-Key-BL.'),ctx));
  return {publicKey:bl.add(p256.Point.BASE.multiply(tau)).toBytes(false),args:encode(new Map([[3,-65539],[-1,cat(hmac(sha256,mk,cipher).slice(0,16),cipher)],[-2,context]]))};
 }finally{shared.fill(0);mk.fill(0);seed.fill(0);}
}
export function verify(signature,message,publicKey){return p256.verify(signature,message,publicKey,{format:'der',lowS:false,prehash:true});}
export const digest=sha256;
