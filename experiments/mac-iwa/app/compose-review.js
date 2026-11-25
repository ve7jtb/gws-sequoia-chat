// Public certificates and send authorization belong to the signed IWA. Nothing
// in this module persists a message, a contact, a PIN or a native signing grant.
// Each page owns a small memory-only review map; lock/navigation drops the map.
import {b64,bytes64,LIMIT} from './message-mime.js';

const TTL=10*60*1000;
const fingerprint=value=>typeof value==='string'&&/^(?:[A-F0-9]{40}|[A-F0-9]{64})$/.test(value);
function mailbox(value){
 // Outer transport headers contain one bare mailbox, never a display name or
 // caller-provided header syntax. The signed inner MIME remains unchanged.
 if(typeof value!=='string'||value.length>254||! /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+$/.test(value))throw Error('Invalid transport mailbox');
 return value;
}
function encoded(value,limit,label){
 if(typeof value!=='string'||value.length>Math.ceil(limit/3)*4||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))throw Error('Invalid '+label);
 const bytes=bytes64(value);
 if(!bytes.length||bytes.length>limit||b64(bytes)!==value)throw Error('Invalid '+label);
 return bytes;
}
function destination(service,space){
 if((service==='Gmail'||service==='Drive')&&space===service)return space;
 if(service==='Chat'&&typeof space==='string'&&/^spaces\/[A-Za-z0-9_-]+$/.test(space))return space;
 throw Error('Invalid review destination');
}

export function gmailEnvelope(account,recipient,cipher){
 mailbox(account);mailbox(recipient);encoded(cipher,LIMIT,'encrypted message');
 const boundary='sequoia-'+crypto.randomUUID();
 // Use a standard two-part PGP/MIME envelope. Only the generic outer subject
 // is exposed; the subject, body and attachment names are inside ciphertext.
 // Base64 preserves every OpenPGP octet without relying on armor or MIME's
 // newline treatment, and a UUID delimiter cannot occur in base64 content.
 const raw=new TextEncoder().encode('From: '+account+'\r\nTo: '+recipient+'\r\nSubject: Encrypted OpenPGP message\r\nMIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="'+boundary+'"\r\n\r\n'+
  '--'+boundary+'\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n'+
  '--'+boundary+'\r\nContent-Type: application/octet-stream; name="message.pgp"\r\nContent-Disposition: inline; filename="message.pgp"\r\nContent-Transfer-Encoding: base64\r\n\r\n'+cipher.match(/.{1,76}/g).join('\r\n')+'\r\n\r\n--'+boundary+'--\r\n');
 if(raw.length>LIMIT)throw Error('Encrypted PGP/MIME exceeds the preview limit');
 return b64(raw);
}

export function createComposeReviews({certificateStore,identitySelection,now=()=>Date.now(),gate=()=>{}}){
 const pending=new Map();let epoch=0;
 const current=()=>{gate();return epoch;};
 const unchanged=generation=>{gate();if(epoch!==generation)throw Error('Compose review was cleared');};
 function lookup(id,stage){
  if(typeof id!=='string'||! /^[a-f0-9]{48}$/.test(id))throw Error('Invalid compose review');
  const item=pending.get(id),age=item?now()-item.created:-1;
  if(!item||item.stage!==stage||age<0||age>TTL){pending.delete(id);throw Error('Compose review expired or consumed');}
  return item;
 }
 async function consume(id,service,confirmed,account,pgpOnly=false){
  const generation=current(),item=lookup(id,'ready');
  // Sending and explicit ciphertext export share one authorization. Consume it
  // before asynchronous checks so export cannot leave a second sendable copy.
  pending.delete(id);
  if(confirmed!==true||service!==item.material.service||account!==item.account)throw Error('Send confirmation or destination changed');
  await certificateStore.assertContact(item.contact);unchanged(generation);
  if(identitySelection){await identitySelection.assert(item.identity);unchanged(generation);}
  if(now()-item.created<0||now()-item.created>TTL)throw Error('Compose review expired');
  return structuredClone(pgpOnly?{cipher:item.cipher}:item.outgoing);
 }
 return {
  async prepare(nativeMaterial,contact,{account,subject,service,space,identity,compatibilityConfirmed=false}){
   const generation=current();mailbox(account);mailbox(contact?.email);destination(service,space);
   if(typeof subject!=='string'||!subject||subject.length>500||/[\x00-\x1f\x7f]/.test(subject))throw Error('Invalid subject');
   if(!nativeMaterial||! /^[a-f0-9]{48}$/.test(nativeMaterial.review)||!fingerprint(nativeMaterial.signingFingerprint)||nativeMaterial.senderEmail!==account)throw Error('Configured signing identity mismatch');
   encoded(nativeMaterial.senderCertificate,65536,'sender certificate');encoded(contact.certificate,65536,'recipient certificate');
   if(!fingerprint(contact.fingerprint))throw Error('Invalid recipient fingerprint');
   // Re-read the local trust binding after native public-key discovery. A
   // concurrent removal or certificate update must stop before PIN submission.
   // Classical fallback is explicit for either wire signature or encryption;
   // a hybrid profile is never warned merely for containing a classical part.
   if((identity?.version===5)!==(contact?.version===5))throw Error('LibrePGP v5 compatibility currently requires v5 certificates for both sender and recipient. Use v6 for the default message profile.');
   const compatibilityWarnings=[];
   if(identity?.pqSigning===false)compatibilityWarnings.push('This compatibility certificate uses a classical signature; it is not post-quantum resistant.');
   if(contact?.pqEncryption===false)compatibilityWarnings.push('The recipient has only classical encryption in this certificate; confidentiality is not post-quantum resistant.');
   if(compatibilityWarnings.length&&compatibilityConfirmed!==true)throw Error('Confirm the classical compatibility warning before signing.');
   const snapshot=structuredClone(contact);
   await certificateStore.assertContact(snapshot);unchanged(generation);
   // An identity review binds the full certificate and inventory revision,
   // not just a primary fingerprint that can survive subkey replacement.
   if(identitySelection){await identitySelection.validateMaterial(nativeMaterial,identity,'signing');unchanged(generation);}
   for(const [id,item] of pending)if(now()-item.created>TTL)pending.delete(id);
   if(pending.has(nativeMaterial.review)||pending.size>=4)throw Error('Compose review already exists or limit reached');
   const material={review:nativeMaterial.review,senderCertificate:nativeMaterial.senderCertificate,senderEmail:account,
    signingFingerprint:nativeMaterial.signingFingerprint,recipientCertificate:snapshot.certificate,
    recipientEmail:snapshot.email,recipientFingerprint:snapshot.fingerprint,subject,service,...(identity?.provider==='software'?{softwareProfile:identity.profile}:identity?{hardwareProfile:identity.profile}:{}),...(compatibilityWarnings.length?{compatibilityWarnings}:{})};
   pending.set(material.review,{created:now(),stage:'prepared',material:structuredClone(material),contact:snapshot,space,account,identity:identity?structuredClone(identity):null});
   return material;
  },
  async complete(id,cipher){
   const generation=current(),item=lookup(id,'prepared');item.stage='completing';
   try{
    encoded(cipher,LIMIT,'encrypted message');
    await certificateStore.assertContact(item.contact);unchanged(generation);
    if(identitySelection){await identitySelection.assert(item.identity);unchanged(generation);}
    // Ciphertext comes only from the fixed signing worker after its independent
    // signature verification and encryption. This layer validates framing and
    // current trust; it cannot prove plaintext equality without recipient keys.
    const outgoing=item.material.service==='Drive'?{cipher}:item.material.service==='Gmail'?{raw:gmailEnvelope(item.account,item.contact.email,cipher)}:
     {space:item.space,cipher,certificate:item.material.senderCertificate};
    unchanged(generation);item.outgoing=outgoing;item.cipher=cipher;item.stage='ready';
    return {review:id,subject:item.material.subject,recipient:item.contact.email,fingerprint:item.contact.fingerprint,space:item.space,service:item.material.service,...(item.material.compatibilityWarnings?{compatibilityWarnings:item.material.compatibilityWarnings}:{}),
     ...(item.identity?{sender:item.identity.email,serial:item.identity.serial,senderFingerprint:item.identity.fingerprint}:{})};
   }catch(error){pending.delete(id);throw error;}
  },
  async take(id,service,confirmed,account){
   return consume(id,service,confirmed,account);
  },
  async exportPgp(id,account,confirmed){
   // Drive consumes the same trust/identity-bound one-use review as email.
   // Only the verified worker's encrypted packet is released; never MIME or keys.
   const generation=current(),item=lookup(id,'ready');
   const output=await consume(id,item.material.service,confirmed,account,true);
   unchanged(generation);return output;
  },
  async exportEmail(id,account,confirmed){
   // This exports the already encrypted PGP/MIME envelope only. It does not
   // release the signed plaintext MIME, a session key, or a native file path.
   const generation=current(),outgoing=await consume(id,'Gmail',confirmed,account);
   // A page lock can run between promise continuations after consume resolves.
   // Check the export continuation too before passing bytes to its click handler.
   unchanged(generation);
   return {raw:outgoing.raw,name:'encrypted-message.eml',type:'message/rfc822'};
  },
  cancel(id){pending.delete(id);},
  clear(){epoch++;pending.clear();}
 };
}
