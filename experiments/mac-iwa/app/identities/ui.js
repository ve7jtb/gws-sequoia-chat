// Own public identities are separate from recipient trust. Card operations
// independently verify any selected identity against the live bundle.
import {createIdentityStore} from './store.js';
import {inspectCertificate} from '../certificates/client.js';
import {inspectBundle} from './client.js';
import {parseCardBundle} from './bundle.js';
import {discoverIdentityDevices} from './devices.js';

const MAX_FILE=262144;
const encode=bytes=>btoa(Array.from(bytes,b=>String.fromCharCode(b)).join(''));
const element=(tag,text)=>{const e=document.createElement(tag);e.textContent=text;return e;};

/** Only fixed magic identifies a certificate bundle. A filename/extension is a
 * convenience for the chooser, never proof that imported bytes are public or
 * authenticated. Other inputs go through the public-only WASM certificate parser.
 */
export function identityFileKind(bytes){
 if(!(bytes instanceof Uint8Array)||!bytes.length||bytes.length>MAX_FILE)throw Error('Choose a public certificate or bundle up to 256 KiB.');
 const magic=new TextDecoder().decode(bytes.subarray(0,8));
 if(magic==='PQMAILS1')throw Error('This older uncompressed bundle is unsupported. Export a current compressed certificate bundle from PQ Mail.');
 if(magic==='PQMZIP01'){
  if(bytes.length>65536)throw Error('Certificate bundle exceeds 64 KiB.');
  return 'bundle';
 }
 return 'certificate';
}

/** Initialize after the app's normal bootstrap. All hardware calls here are
 * public reads. Store commits are explicit, atomic, and independent of both
 * Gmail/Chat sign-in and the encrypted credential vault.
 */
export async function initializeIdentities({request,say,isBusy,setBusy,identityStore}){
 const $=id=>document.getElementById(id),store=identityStore||createIdentityStore({inspect:inspectCertificate});
 let pending=null,removal=null,deviceChoice=null,refreshTicket=0;
 const channel=typeof BroadcastChannel==='function'?new BroadcastChannel('sequoia-iwa-own-identities'):null;
 // A second window may change the inventory while this dialog is open. Invalidate
 // its review immediately; the store's revision check independently prevents a
 // missed/delayed notification from overwriting a newer commit.
 function clearReview(){if(pending)store.cancel(pending);pending=null;removal=null;$('identity-review').close();$('identity-remove-dialog').close();}
 async function run(action){
  if(isBusy()){say('An operation is already running.',true);return;}
  setBusy(true);
  try{await action();}catch(e){say(e.message,true);}finally{setBusy(false);}
 }
 function listen(id,action){$(id).addEventListener('click',()=>run(action));}
 async function chooseDevice(){
  const devices=await discoverIdentityDevices(request);
  if(devices.length===1)return devices[0].serial;
  const chooser=$('identity-device');chooser.replaceChildren();
  for(const device of devices){const option=element('option','YubiKey '+device.serial);option.value=device.serial;chooser.append(option);}
  // The outer operation lock disables ordinary actions. These two controls
  // must remain usable while the read-only device choice is pending.
  $('identity-device-continue').disabled=false;$('identity-device-cancel').disabled=false;
  $('identity-device-dialog').showModal();
  return new Promise((resolve,reject)=>{deviceChoice={devices,resolve,reject};});
 }
 function finishDevice(cancelled){
  if(!deviceChoice)return;const choice=deviceChoice;deviceChoice=null;$('identity-device-dialog').close();
  const serial=$('identity-device').value;
  if(cancelled||!choice.devices.some(d=>d.serial===serial))choice.reject(Error('YubiKey restore cancelled.'));
  else choice.resolve(serial);
 }
 $('identity-device-continue').addEventListener('click',()=>finishDevice(false));
 $('identity-device-cancel').addEventListener('click',()=>finishDevice(true));
 $('identity-device-dialog').addEventListener('cancel',()=>finishDevice(true));
 function describeCertificate(parent,c){
  parent.append(element('h4',c.label||'OpenPGP certificate'));
  parent.append(element('p','OpenPGP v'+c.version+' · '+c.algorithms.join(' / ')));
  const fp=element('p',c.fingerprint);fp.className='identity-fingerprint';parent.append(fp);
  if(c.profile)parent.append(element('p','Profile: '+c.profile));
  if(c.components)parent.append(element('p','Component custody: '+c.components.map(part=>part.algorithm+(part.storage==='piv'?' in PIV '+part.slot.toUpperCase():' in encrypted companion')).join('; ')));
  parent.append(element('p','Certified email addresses: '+(c.emails.join(', ')||'None currently valid')));
 }
 function describeSlots(parent,slots){
  if(!slots.length){parent.append(element('p','No verified hardware slot mapping.'));return;}
  const table=document.createElement('table');table.className='identity-slots';
  const head=document.createElement('tr');for(const text of ['Role','PIV slot','Algorithm'])head.append(element('th',text));
  const thead=document.createElement('thead');thead.append(head);table.append(thead);
  const body=document.createElement('tbody');
  for(const s of slots){const row=document.createElement('tr');for(const text of [s.role,s.slot.toUpperCase(),s.algorithm])row.append(element('td',text));body.append(row);}
  table.append(body);parent.append(table);
 }
 function describe(parent,identity){
  parent.append(element('p',identity.serial?'YubiKey serial: '+identity.serial:'Public certificate from file · no hardware mapping'));
  if(identity.companion)parent.append(element('p','Encrypted on-key companion: software private components are unwrapped only in a disposable WASM worker for each operation. This inventory stores ciphertext and public keys only. It provides no hardware isolation for those software components.'));
  if(identity.bundleHash){
   // Older saved entries were authenticated by the native parser. Do not
   // mislabel their provenance merely because this UI now parses new imports
   // in WASM; both retain the same independent live private-operation check.
   parent.append(element('p',(identity.companion?'Signed companion verified. ':'Signed bundle verified. ')+(identity.liveKeysMatched?'All mapped public keys matched the connected YubiKey at import. ':'Hardware keys have not been matched. This identity cannot be selected for private operations yet. ')+(identity.companion?'Companion ciphertext and live keys were checked at import.':identity.generation?'Card generation '+identity.generation+'.':'File bundle: card generation is unavailable; freshness is not established.')));
   const digest=element('p','Bundle SHA-256: '+identity.bundleHash);digest.className='identity-fingerprint';parent.append(digest);
  }
  for(const c of identity.certificates)describeCertificate(parent,c);
  describeSlots(parent,identity.slots);
  for(const warning of identity.warnings)parent.append(element('p',warning));
 }
 async function refresh(){
  const ticket=++refreshTicket,inventory=await store.list();if(ticket!==refreshTicket)return;const list=$('identity-list');list.replaceChildren();
  if(!inventory.identities.length)list.append(element('p','No own identities saved in this IWA yet. Restore from your YubiKey or import a public certificate from file.'));
  for(const identity of inventory.identities){
   const card=document.createElement('article');card.className='identity-card';
   card.append(element('h3','Saved public identity'));
   describe(card,identity);
   if(identity.bundleHash&&!identity.liveKeysMatched){
    const match=element('button','Match connected YubiKey…');
    match.addEventListener('click',()=>run(async()=>{
     clearReview();say('Reading public keys only; no PIN or touch is required.');
     review(await store.previewLiveMatch(identity.id,await request('chat-identity-key-snapshot',{serial:identity.serial})));
    }));card.append(match);
   }
   const remove=element('button','Forget local identity…');
   remove.addEventListener('click',()=>{
    if(isBusy())return;
    removal={id:identity.id,revision:inventory.revision};$('identity-remove-details').textContent=(identity.serial?'YubiKey '+identity.serial+'\n':'')+identity.certificates.map(c=>c.fingerprint).join('\n');$('identity-remove-dialog').showModal();
   });card.append(remove);list.append(card);
  }
 }
 function review(value){
  pending=value;const box=$('identity-review-details');box.replaceChildren();describe(box,value.identity);
  $('identity-review-change').textContent=value.unchanged?'This identity is already saved.':value.replacesExisting?'This replaces the saved public bundle for this YubiKey after confirmation.':'This adds an own public identity to this IWA.';
  $('identity-review-confirmed').checked=false;$('identity-review').showModal();
 }
 listen('identity-refresh',async()=>{await configured();await refresh();say('Own public identities refreshed.');});
 listen('identity-restore',async()=>{
  clearReview();const serial=await chooseDevice();say('Reading public card data from YubiKey '+serial+', then verifying the compressed bundle in this IWA. No PIN is required.');
  // Optional v5 input is public and never supplies its own slot mapping. The
  // WASM bundle parser requires every compatibility component and certified
  // email to match the newly authenticated normal card bundle.
  const v5=$('identity-v5-file').files[0];let compatibilityCertificate;
  if(v5){if(!v5.size||v5.size>MAX_FILE)throw Error('Choose a v5 public certificate up to 256 KiB.');compatibilityCertificate=encode(new Uint8Array(await v5.arrayBuffer()));}
  review(await store.previewBundle(await parseCardBundle(await request('chat-identity-bundle-read',{serial}),inspectBundle,{compatibilityCertificate})));
  say('Review the YubiKey certificate bundle before saving.');
 });
 listen('identity-file-review',async()=>{
  clearReview();const file=$('identity-file').files[0];
  if(!file||!file.size||file.size>MAX_FILE)throw Error('Choose a public certificate or bundle up to 256 KiB.');
  const bytes=new Uint8Array(await file.arrayBuffer()),kind=identityFileKind(bytes),encoded=encode(bytes);
  // File inspection has no native dependency. Save an authenticated but unmatched
  // bundle for offline review; a separate explicit public-key match enables its
  // selection later. This never claims a file proves current card presence.
  review(kind==='bundle'?await store.previewBundle(await inspectBundle(encoded)):await store.previewCertificate(encoded));
  say('Review the imported public identity before saving.');
 });
 listen('identity-review-save',async()=>{
  if(!pending||!$('identity-review-confirmed').checked)throw Error('Review and confirm the certificates and slot mappings first.');
  await store.save(pending,true);clearReview();channel?.postMessage({changed:true});await refresh();
  say('Own public identity saved. Hardware-matched Level 3 RFC 9980 v6 identities are available for sending and decrypting. For an unmatched bundle, use Match connected YubiKey first. Recipient trust and vault enrollment are unchanged.');
 });
 listen('identity-review-cancel',()=>clearReview());
 $('identity-review').addEventListener('cancel',()=>{if(pending)store.cancel(pending);pending=null;});
 listen('identity-remove-cancel',()=>clearReview());
 $('identity-remove-dialog').addEventListener('cancel',()=>{removal=null;});
 listen('identity-remove-confirm',async()=>{
  if(!removal)throw Error('Choose an identity to forget first.');
  await store.remove(removal.id,true,removal.revision);clearReview();channel?.postMessage({changed:true});await refresh();
  say('Local identity forgotten. YubiKey data, contact trust remain unchanged.');
 });
 if(channel)channel.onmessage=()=>{clearReview();refresh().catch(e=>say(e.message,true));};
 window.addEventListener('pagehide',()=>{finishDevice(true);clearReview();channel?.close();});
 await refresh();return {refresh};
}
