// Own public identities are an inventory, separate from recipient trust. This
// controller never passes an imported slot, serial, file path or certificate to
// a private-key operation. The helper's installed signing authority stays fixed.
import {createIdentityStore} from './store.js';
import {inspectCertificate} from '../certificates/client.js';
import {inspectBundle} from './client.js';
import {parseCardBundle} from './bundle.js';

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

/** Initialize after the app's normal bootstrap. All native calls here are
 * public reads. Store commits are explicit, atomic, and independent of both
 * Gmail/Chat sign-in and the encrypted credential vault.
 */
export async function initializeIdentities({request,say,isBusy,setBusy,identityStore}){
 const $=id=>document.getElementById(id),store=identityStore||createIdentityStore({inspect:inspectCertificate});
 let pending=null,removal=null,current=null;
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
 function describeCertificate(parent,c){
  parent.append(element('h4',c.label||'OpenPGP certificate'));
  parent.append(element('p','OpenPGP v'+c.version+' · '+c.algorithms.join(' / ')));
  const fp=element('p',c.fingerprint);fp.className='identity-fingerprint';parent.append(fp);
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
  if(identity.bundleHash){
   // Older saved entries were authenticated by the native parser. Do not
   // mislabel their provenance merely because this UI now parses new imports
   // in WASM; both retain the same independent live private-operation check.
   parent.append(element('p','Signed bundle verified. '+(identity.liveKeysMatched?'All mapped public keys matched the connected YubiKey at import. ':'Hardware keys have not been matched. This identity cannot be selected for private operations yet. ')+(identity.generation?'Card generation '+identity.generation+'.':'File bundle: card generation is unavailable; freshness is not established.')));
   const digest=element('p','Bundle SHA-256: '+identity.bundleHash);digest.className='identity-fingerprint';parent.append(digest);
  }
  for(const c of identity.certificates)describeCertificate(parent,c);
  describeSlots(parent,identity.slots);
  for(const warning of identity.warnings)parent.append(element('p',warning));
 }
 async function refresh(){
  const inventory=await store.list(),list=$('identity-list');list.replaceChildren();
  if(!inventory.identities.length)list.append(element('p','No own identities saved in this IWA yet. Restore from your YubiKey or import a public certificate from file.'));
  for(const identity of inventory.identities){
   const card=document.createElement('article');card.className='identity-card';
   const matches=current&&identity.serial===current.serial&&identity.certificates.some(c=>c.fingerprint===current.fingerprint);
   card.append(element('h3',matches?'Matches default vault identity':'Saved public identity'));
   describe(card,identity);
   if(identity.bundleHash&&!identity.liveKeysMatched){
    const match=element('button','Match connected YubiKey…');
    match.addEventListener('click',()=>run(async()=>{
     clearReview();say('Reading public keys only; no PIN or touch is required.');
     review(await store.previewLiveMatch(identity.id,await request('chat-identity-key-snapshot')));
    }));card.append(match);
   }
   const remove=element('button','Forget local identity…');
   remove.addEventListener('click',()=>{
    if(isBusy())return;
    removal={id:identity.id,revision:inventory.revision};$('identity-remove-details').textContent=(identity.serial?'YubiKey '+identity.serial+'\n':'')+identity.certificates.map(c=>c.fingerprint).join('\n');$('identity-remove-dialog').showModal();
   });card.append(remove);list.append(card);
  }
 }
 async function configured(){
  // This certificate is read from fixed native configuration. It is displayed
  // separately, never automatically inserted into the IWA inventory or trusted.
  const value=await request('chat-identity-current');
  const cert=await inspectCertificate(value.certificate);
  if(cert.fingerprint!==value.fingerprint)throw Error('Configured identity fingerprint mismatch.');
  current=value;const box=$('identity-current');box.replaceChildren();
  box.append(element('p','YubiKey serial: '+value.serial+' · default native identity for existing vault enrollment'));
  describeCertificate(box,{...cert,label:'Current public certificate'});describeSlots(box,value.slots);
 }
 function review(value){
  pending=value;const box=$('identity-review-details');box.replaceChildren();describe(box,value.identity);
  $('identity-review-change').textContent=value.unchanged?'This identity is already saved.':value.replacesExisting?'This replaces the saved public bundle for this YubiKey after confirmation.':'This adds an own public identity to this IWA.';
  $('identity-review-confirmed').checked=false;$('identity-review').showModal();
 }
 listen('identity-refresh',async()=>{await configured();await refresh();say('Own public identities refreshed.');});
 listen('identity-restore',async()=>{
  clearReview();say('Reading public card data, then verifying the compressed bundle in this IWA. No PIN is required.');
  review(await store.previewBundle(await parseCardBundle(await request('chat-identity-bundle-read'),inspectBundle)));
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
  say('Own public identity saved. Hardware-matched, supported v6 profiles are available in Compose and incoming matching. For an unmatched bundle, use Match connected YubiKey first. Recipient trust and vault enrollment are unchanged.');
 });
 listen('identity-review-cancel',()=>clearReview());
 $('identity-review').addEventListener('cancel',()=>{if(pending)store.cancel(pending);pending=null;});
 listen('identity-remove-cancel',()=>clearReview());
 $('identity-remove-dialog').addEventListener('cancel',()=>{removal=null;});
 listen('identity-remove-confirm',async()=>{
  if(!removal)throw Error('Choose an identity to forget first.');
  await store.remove(removal.id,true,removal.revision);clearReview();channel?.postMessage({changed:true});await refresh();
  say('Local identity forgotten. YubiKey data, contact trust and the configured helper remain unchanged.');
 });
 if(channel)channel.onmessage=()=>{clearReview();refresh().catch(e=>say(e.message,true));};
 window.addEventListener('pagehide',()=>{clearReview();channel?.close();});
 // Startup must work without an extension/native host. Native enrollment is
 // read only after the user explicitly requests Read default vault identity from helper.
 $('identity-current').textContent='Default vault identity metadata is available through Read default vault identity from helper. No hardware is contacted at startup.';
 await refresh();return {refresh};
}
