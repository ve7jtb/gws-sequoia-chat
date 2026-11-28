// Browser-owned, offline hardware-test orchestration. The card transport sees
// only public audit/identity requests and the existing signature/decapsulation
// components. This module has no Google transport, provisioning or file API.
import {signAndEncrypt} from './signing-session.js';
import {decryptWithHardware} from './decryption-session.js';
import {nativeIdentity} from './identities/selection.js';
import {signingFailurePhase} from './signing-phases.js';
export {signingFailureLabel} from './signing-phases.js';

const SLOTS=['9a','9c','9d','9e',...Array.from({length:20},(_,i)=>(0x82+i).toString(16))];
const ordered=value=>Array.isArray(value)?value.map(ordered):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(k=>[k,ordered(value[k])])):value;
const same=(a,b)=>JSON.stringify(ordered(a))===JSON.stringify(ordered(b));
const exact=(value,fields)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...fields].sort().join(',');
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const publicLabel=value=>typeof value==='string'&&value.length>0&&value.length<=80&&!/[\x00-\x1f\x7f]/.test(value);

/** An absent key is explicit, never inferred from an omitted or failed read.
 * Reports contain only the complete fixed public snapshot: no native paths,
 * PINs, private keys or diagnostic stderr can become exported report fields.
 */
export function validateHardwareAudit(value,identity){
 if(!exact(value,['format','version','identity','slots','pinRetries','backendHash'])||value.format!=='sequoia-iwa-hardware-audit'||value.version!==1||!same(value.identity,nativeIdentity(identity))||!digest(value.backendHash)||!Array.isArray(value.slots)||value.slots.length!==24)throw Error('Invalid hardware audit');
 for(let i=0;i<SLOTS.length;i++){
  const slot=value.slots[i],fields=['publicKeySha256','algorithm','origin','pinPolicy','touchPolicy'];
  if(!exact(slot,['slot',...fields])||slot.slot!==SLOTS[i])throw Error('Incomplete hardware audit');
  if(slot.publicKeySha256===null){if(fields.some(k=>slot[k]!==null))throw Error('Invalid empty slot audit');}
  else if(!digest(slot.publicKeySha256)||fields.slice(1).some(k=>!publicLabel(slot[k])))throw Error('Invalid occupied slot audit');
 }
 const pin=value.pinRetries;
 if(!exact(pin,['remaining','maximum'])||!Number.isInteger(pin.maximum)||pin.maximum<1||pin.maximum>255||!Number.isInteger(pin.remaining)||pin.remaining<0||pin.remaining>pin.maximum)throw Error('Invalid PIN retry audit');
 return structuredClone(value);
}

/** Each run signs fresh synthetic text, HTML and binary bytes to its own key.
 * The run identifier detects stale worker results; it is public test content,
 * not a secret, and no application draft or inbox message is read or replaced.
 */
export function hardwareTestFixture(email,runId){
 if(typeof runId!=='string'||!/^[a-f0-9-]{36}$/.test(runId))throw Error('Invalid test identifier');
 const body='Synthetic IWA hardware test '+runId+'.\nSigning, decryption and exact attachment checks.\nNo email is sent.\n';
 const html='<p>Synthetic IWA hardware test <strong>'+runId+'</strong>.</p><p>Signing, decryption and exact attachment checks.</p><p>No email is sent.</p>';
 const bytes=Uint8Array.from({length:64},(_,i)=>(i*37)&255);
 const data=btoa(String.fromCharCode(...bytes));
 return {sender:email,recipient:email,subject:'IWA hardware test '+runId,body,html,attachments:[{name:'hardware-test.bin',data}]};
}

function verifiedPayload(value,compose,identity){
 // readMessage has already verified the signature and authenticated inner
 // headers. Compare every expected MIME alternative and attachment as well;
 // a green crypto result alone cannot conceal truncation or stale content.
 if(!value||value.encrypted!==true||value.verified!==true||value.signatureStatus!=='valid'||value.certificateTrust!=='trusted'||value.sender!==identity.email||value.subject!==compose.subject||value.text!==compose.body||value.html!==compose.html||!Array.isArray(value.signatures)||value.signatures.length!==1||value.signatures[0].status!=='valid'||value.signatures[0].fingerprint!==identity.fingerprint||value.signatures[0].trusted!==true||!Array.isArray(value.attachments)||value.attachments.length!==1||value.omittedAttachments!==0)throw Error('Hardware test verification failed');
 const file=value.attachments[0];
 if(file.name!==compose.attachments[0].name||file.size!==64||file.data!==compose.attachments[0].data)throw Error('Hardware test attachment mismatch');
}

/** Run one sign/encrypt/decrypt cycle with no implicit retry or resume.
 * Native calls are deliberately allowed to settle after browser cancellation:
 * disconnecting is not proof that the token stopped. This retains the UI lock
 * until the attempt completes, then permits only a PIN-free final audit.
 */
export async function runHardwareTest({identity,selection,native,gate,signal,onProgress=()=>{},
 createSigningWorker,createDecryptionWorker,sign=signAndEncrypt,decrypt=decryptWithHardware,
 now=()=>Date.now(),newId=()=>crypto.randomUUID()}){
 const selected=structuredClone(identity),binding=nativeIdentity(selected),id=newId();
 let stage='preflight',before=null,after=null,compose,cipher,opened;
 const inFlight=new Set(),report={format:'sequoia-iwa-hardware-test',version:1,id,
  started:new Date(now()).toISOString(),status:'RUNNING',identity:binding,
  profile:selected.profile||'level3',openPgpVersion:selected.version||6,
  signingAlgorithm:selected.signingAlgorithm||'ML-DSA-65 + Ed25519',
  encryptionAlgorithm:selected.encryptionAlgorithm||'ML-KEM-768 + X25519',
  custody:selected.custody||'hardware',
  steps:[],signatureVerified:false,decryptionVerified:false,payloadVerified:false,
  unchanged:null,messagesSent:0,cardWrites:0,privateAttempts:{signing:0,decryption:0}};
 const progress=(name,message)=>{stage=name;report.steps.push({step:name,status:'running'});onProgress(message);};
 const complete=()=>{report.steps.at(-1).status='passed';};
 const check=async()=>{
  if(signal?.aborted)throw Error('Test cancelled');
  await gate();await selection.assert(selected);
  if(signal?.aborted)throw Error('Test cancelled');
 };
 const request=(op,data)=>{
  // Do not pass the worker's cancellation signal into Native Messaging. Once
  // PIN/touch began, only the card operation can report its final outcome.
  const pending=Promise.resolve().then(()=>native(op,data));inFlight.add(pending);
  pending.then(()=>inFlight.delete(pending),()=>inFlight.delete(pending));return pending;
 };
 try{
  await check();progress('before-audit','Reading all 24 public slots and PIN/touch policies — no PIN required.');
  before=validateHardwareAudit(await request('chat-hardware-audit',{identity:binding}),selected);await check();complete();
  progress('signing','Signing a fresh local test message — enter the PIN only in the PIV dialog, then touch if requested.');
  const material=await request('chat-selected-signing-material',{identity:binding});
  await selection.validateMaterial(material,selected,'signing');await check();
  compose=hardwareTestFixture(selected.email,id);
  const signing={...material,recipientCertificate:selected.certificate,recipientFingerprint:selected.fingerprint,recipientEmail:selected.email,subject:compose.subject};
  const encrypted=await sign(signing,compose,async value=>{
   await check();
   if(report.privateAttempts.signing!==0)throw Error('Duplicate signing request');
   report.privateAttempts.signing++;
   const result=await request('chat-sign-digest',value);
   try{await check();return result;}catch(error){if(result)delete result.companionShared;throw error;}
  },{signal,createWorker:createSigningWorker});
  cipher=encrypted.cipher;await check();report.signatureVerified=true;complete();
  progress('recipient-match','Matching the encrypted recipient to the same saved YubiKey identity in WASM.');
  const matched=await selection.match(cipher,selected.email);await check();
  const recipient=matched.choices.find(choice=>choice.id===selected.id);
  if(!recipient||!same(nativeIdentity(recipient),binding)||recipient.recipientKey!==selected.recipientKey||matched.recipientKey!==selected.recipientKey)throw Error('Hardware test recipient mismatch');
  complete();progress('decryption','Decrypting the local test message — enter the PIN only in the PIV dialog, then touch if requested.');
  // Self-verification is explicitly scoped to this test. This in-memory binding
  // never saves a contact or grants trust to any mailbox in the IWA database.
  const verification={expectedEmail:selected.email,expectedFingerprint:selected.fingerprint,recipient:selected.email,
   material:{certificates:[selected.certificate],bindings:[{email:selected.email,fingerprint:selected.fingerprint}],saved:[]}};
  opened=await decrypt({cipher,service:'Hardware test',identity:binding,recipientKey:selected.recipientKey,verification,signal,
   validateMaterial:async value=>{await selection.validateMaterial(value,selected,'decryption');await check();},
   native:async(op,data)=>{
    await check();
    if(op==='chat-decapsulate-components'){
     if(report.privateAttempts.decryption!==0)throw Error('Duplicate decryption request');
     report.privateAttempts.decryption++;
    }else if(op!=='chat-selected-decryption-material')throw Error('Unexpected test operation');
    return request(op,data);
   },gate:check,createWorker:createDecryptionWorker});
  await check();verifiedPayload(opened,compose,selected);
  report.decryptionVerified=report.payloadVerified=true;complete();report.status='PASS';
 }catch(error){
  if(report.steps.at(-1)?.status==='running')report.steps.at(-1).status='stopped';
  // Export only controlled labels. Low-level errors may contain private input
  // or stale process output and are not an acceptable public diagnostic log.
  report.status=signal?.aborted?'CANCELLED':'STOPPED';report.failureStage=stage;
  // Keep the coarse test stage for older report readers, but distinguish the
  // browser/native signing boundaries using only our closed public vocabulary.
  // Never copy arbitrary provider error properties or diagnostics into exports.
  if(stage==='signing')report.failurePhase=signingFailurePhase(error?.failurePhase);
 }finally{
  await Promise.allSettled([...inFlight]);
  if(before){
   progress('after-audit','Comparing all public keys, PIN/touch policies and retry counts — no PIN required.');
   try{
    // Even after cancellation/failure, this fixed read-only operation is safe.
    // It cannot prompt or start private work. A missing/changed identity is an
    // unconfirmed audit, not permission to switch devices or retry the test.
    after=validateHardwareAudit(await request('chat-hardware-audit',{identity:binding}),selected);
    report.unchanged=same(before,after);complete();
    if(!report.unchanged){report.status='STOPPED';report.failureStage='after-audit';}
   }catch(_){report.unchanged=null;report.steps.at(-1).status='unconfirmed';if(report.status==='PASS')report.status='STOPPED';report.failureStage??='after-audit';}
  }
  // A revision may change while the PIN-free final snapshot is in flight.
  // Preserve that public audit, but do not present a completed green test for
  // an account/identity/vault state that is no longer the one reviewed.
  if(report.status==='PASS')try{await check();}catch(_){report.status='STOPPED';report.failureStage='final-context';}
  if(signal?.aborted){report.status='CANCELLED';report.failureStage??='cancelled';}
  report.finished=new Date(now()).toISOString();
  report.audit={before,after};
  // Test content is transient. The exported report has only public identity,
  // public audits and fixed verification statuses; never shares or ciphertext.
  compose=cipher=opened=undefined;
 }
 return report;
}
