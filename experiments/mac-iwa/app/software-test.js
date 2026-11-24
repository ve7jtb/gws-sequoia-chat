// A complete software-only round trip through the same MIME/signing and
// decryption workers used by Compose/Read. The caller supplies a software
// adapter; this module has no native, Google, token or persistence API.
import {signAndEncrypt} from './signing-session.js';
import {decryptWithHardware} from './decryption-session.js';
export async function runSoftwareTest({identity,selection,request,gate,signal,
 createSigningWorker,createDecryptionWorker,onProgress=()=>{},
 sign=signAndEncrypt,decrypt=decryptWithHardware}){
 if(identity?.provider!=='software')throw Error('Select a software identity.');
 const id=crypto.randomUUID(),binding=selection.nativeBinding(identity);
 const check=async()=>{if(signal?.aborted)throw Error('Software test cancelled.');await gate();await selection.assert(identity);if(signal?.aborted)throw Error('Software test cancelled.');};
 const compose={sender:identity.email,recipient:identity.email,subject:'IWA software test '+id,
  body:'Synthetic vault-protected software identity test '+id+'.\nNo email is sent.\n',
  html:'<p>Synthetic software identity test <strong>'+id+'</strong>.</p><p>No email is sent.</p>',
  attachments:[{name:'software-test.bin',data:btoa(String.fromCharCode(...Uint8Array.from({length:64},(_,i)=>(i*37)&255)))}]};
 let signing=0,decapsulation=0;
 const call=async(op,data,options)=>{
  await check();
  if(op==='chat-sign-digest'){if(signing++)throw Error('Repeated signing request.');}
  else if(op==='chat-decapsulate-components'){if(decapsulation++)throw Error('Repeated decryption request.');}
  else if(!['chat-selected-signing-material','chat-selected-decryption-material'].includes(op))throw Error('Unexpected software test request.');
  const result=await request(op,data,options);await check();return result;
 };
 onProgress('Signing and encrypting in the IWA — no PIN or hardware operation.');
 const own=await call('chat-selected-signing-material',{identity:binding});
 await selection.validateMaterial(own,identity,'signing');
 const material={...own,recipientCertificate:identity.certificate,recipientFingerprint:identity.fingerprint,
  recipientEmail:identity.email,subject:compose.subject};
 const encrypted=await sign(material,compose,r=>call('chat-sign-digest',r),{signal,createWorker:createSigningWorker});
 await check();const matched=await selection.match(encrypted.cipher,identity.email);
 if(matched.recipientKey!==identity.recipientKey||!matched.choices.some(c=>c.id===identity.id))throw Error('Software test recipient mismatch.');
 onProgress('Decrypting and verifying text, HTML and attachment in the IWA.');
 // Test self-trust is ephemeral. It does not save a contact or authorize any
 // Google send, and is discarded with the decrypted synthetic content.
 const verification={expectedEmail:identity.email,expectedFingerprint:identity.fingerprint,recipient:identity.email,
  material:{certificates:[identity.certificate],bindings:[{email:identity.email,fingerprint:identity.fingerprint}],saved:[]}};
 const opened=await decrypt({cipher:encrypted.cipher,service:'Hardware test',identity:binding,
  recipientKey:identity.recipientKey,verification,signal,native:call,gate:check,
  validateMaterial:value=>selection.validateMaterial(value,identity,'decryption'),createWorker:createDecryptionWorker});
 await check();
 const attachment=opened.attachments?.[0];
 if(opened.verified!==true||opened.encrypted!==true||opened.signatureStatus!=='valid'||opened.certificateTrust!=='trusted'||
    opened.sender!==identity.email||opened.subject!==compose.subject||opened.text!==compose.body||opened.html!==compose.html||
    opened.signatures?.length!==1||opened.signatures[0].status!=='valid'||opened.signatures[0].trusted!==true||opened.signatures[0].fingerprint!==identity.fingerprint||
    opened.attachments?.length!==1||opened.omittedAttachments!==0||attachment.name!==compose.attachments[0].name||
    attachment.size!==64||attachment.data!==compose.attachments[0].data||signing!==1||decapsulation!==1)
  throw Error('Software signing/decryption verification failed.');
 return {format:'sequoia-iwa-software-test',version:1,id,status:'PASS',fingerprint:identity.fingerprint,
  signatureVerified:true,decryptionVerified:true,payloadVerified:true,privateOperations:{signing,decapsulation},
  nativeRequests:0,messagesSent:0,cardWrites:0};
}
