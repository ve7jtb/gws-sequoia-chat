import {random,b64,bytes} from './core.js';
// PIV transport is injected so Web Smart Card can replace Native Messaging
// without changing the encrypted vault format or introducing a FIDO dependency.
export async function classicalWrap(material){
 const curve=material.algorithm==='ECDH-P256'?'P-256':material.algorithm==='ECDH-P384'?'P-384':null;if(!curve)throw Error('Unsupported curve');
 const recipient=await crypto.subtle.importKey('spki',bytes(material.public),{name:'ECDH',namedCurve:curve},false,[]);
 const ephemeral=await crypto.subtle.generateKey({name:'ECDH',namedCurve:curve},true,['deriveBits']);
 const peer=b64(await crypto.subtle.exportKey('spki',ephemeral.publicKey));
 const raw=new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:recipient},ephemeral.privateKey,curve==='P-256'?256:384));
 const binding={kind:'ecdh',algorithm:material.algorithm,fingerprint:material.fingerprint,public:material.public,peer,serial:material.serial,slot:material.slot};
 return {binding,secret:await reduce(raw)};
}
// Both curves feed a 256-bit wrapping secret into the vault's separate HKDF.
// The per-wrapper context includes both public keys, curve and recipient hash.
export async function reduce(raw){try{return new Uint8Array(await crypto.subtle.digest('SHA-256',raw));}finally{raw.fill(0);}}
export async function classicalOpen(binding,transport){const r=await transport('chat-vault-ecdh',{peer:binding.peer,fingerprint:binding.fingerprint});if(r.fingerprint!==binding.fingerprint)throw Error('Wrong PIV key');try{return await reduce(bytes(r.secret));}finally{delete r.secret;}}
