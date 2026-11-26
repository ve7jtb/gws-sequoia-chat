import init,{provisioning_verify_mldsa65,provisioning_mldsa65_public} from '../wasm/sequoia_iwa_verify.js';
import {p384} from '../vendor/curves/nist.js';
import {ed25519} from '../vendor/curves/ed25519.js';
import {smimeSignatureInput} from './card-signer.js';

export async function certificationPublicKey(seed){
 await init();
 return provisioning_mldsa65_public(seed);
}

export async function createCertificateVerifier(piv){
 await init();
 const verifyPq=(key,message,context,signature)=>provisioning_verify_mldsa65(key,message,context,signature);

 return {
  rfc9980({digest,publicKey,mldsa,ed25519:traditional}){
   return verifyPq(publicKey.pq,digest,new Uint8Array(),mldsa)&&ed25519.verify(traditional,digest,publicKey.ec);
  },
  experimentalNist({digest,publicKey,mldsa,ecdsa}){
   return verifyPq(publicKey.pq,digest,new Uint8Array(),mldsa)&&
    p384.verify(ecdsa,digest,publicKey.ec,{prehash:false,format:'compact',lowS:false});
  },
  async smime({algorithm,tbs,signature,publicKey}){
   const outer=piv.parseBerTlv(publicKey).get(0x30);
   const raw=piv.parseBerTlv(outer).get(3);
   if(!raw||raw[0]!==0)return false;
   const {message,context,ecDigest}=await smimeSignatureInput(algorithm,tbs);
   if(raw.length!==(ecDigest?2050:1953)||
      !verifyPq(raw.slice(1,1953),message,context,signature.slice(0,3309)))return false;
   return !ecDigest||p384.verify(signature.slice(3309),ecDigest,raw.slice(1953),
    {prehash:false,format:'der',lowS:false});
  },
 };
}
