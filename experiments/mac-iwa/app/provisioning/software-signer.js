import init,{provisioning_sign_mldsa65} from '../wasm/sequoia_iwa_verify.js';
import {p384} from '../vendor/curves/nist.js';
import {smimeSignatureInput} from './card-signer.js';

export async function createLevel3SoftwareSigner(material){
 await init();
 const signingKey=(slot,algorithm)=>{
  const key=material.find(row=>row.slot===slot&&row.algorithm===algorithm);
  if(!key)throw Error('Missing software certificate signing component.');
  return key.seed;
 };
 const signPq=(slot,message,context=new Uint8Array())=>
  provisioning_sign_mldsa65(signingKey(slot,'ML-DSA-65'),message,context);
 const signEc=(slot,digest,format)=>p384.sign(digest,signingKey(slot,'P-384'),{prehash:false,format});
 return {
  // Only the certificate coordinator supplies reviewed slot roles. RFC 9980
  // already has its original, verified software certificate and fingerprint.
  async sign({format,slots,algorithm,tbs,digest}){
   if(format==='smime'){
    const {message,context,ecDigest}=await smimeSignatureInput(algorithm,tbs);
    const pq=signPq(slots[0],message,context);
    if(!ecDigest)return pq;
    const ec=signEc(slots[1],ecDigest,'der');
    const signature=new Uint8Array(pq.length+ec.length);
    signature.set(pq);signature.set(ec,pq.length);
    return signature;
   }
   if(format==='openpgp-nist-draft-05')
    return {mldsa:signPq(slots[0],digest),ecdsa:signEc(slots[1],digest.subarray(0,48),'compact')};
   throw Error('Unsupported software provisioning signature.');
  },
  // The existing public bundle format authenticates the payload using the
  // signing certificate at the selected index (the first, pure profile).
  signBundle:payload=>signPq('9c',payload),
 };
}
