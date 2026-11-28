// All remote and signed message text is rendered with textContent. No remote
// HTML, scripts, images or links execute. Imported software-key passwords are
// cleared from the form immediately and stored only inside the encrypted vault.
const $=id=>document.getElementById(id);
const isDrive=()=>$("transport").value==="drive";
const isMail=()=>$("transport").value!=="chat";
const service=()=>isDrive()?"Drive":isMail()?"Gmail":"Chat";
const browserGoogleOperations=new Set(['chat-mail-connect','chat-mail-list','chat-mail-read','chat-mail-open','chat-mail-prepare','chat-drive-prepare','chat-prepare','chat-mail-send','chat-spaces','chat-messages','chat-open','chat-send']);
let ownEmail="";
let accountSettings,accountSnapshot=null,accountReview=null,accountSettingsKey='',normalizeAccount,legacyAccountEmail;
let certificateReview=null,managementReview=null;
let identityUi,softwareUi,ownIdentityStore,hardwareIdentitySelection,identitySelection,certificateStore,composeReviews,migrationReview=null,readerEvidence=null,signingAbort=null,decryptionAbort=null,readerGeneration=0;
let sendIdentities=[],decryptionChoice=null,identityListGeneration=0;
let hardwareTestAbort=null,hardwareTestReport=null,softwareTestAbort=null;
let contacts=[],spaces=[],spaceNext='',pages=[''],page=0,next='',review=null,openMessage=null,cert=null,busy=false;
// Local encrypted email is staged only until the user selects its expected
// trusted signer. It is never uploaded, cached, or treated as a provider ID.
let localEncrypted=null;
const say=(text,error=false)=>{$('result').textContent=text;$('result').classList.toggle('error',error);};
// UI locking is separate from the transport so one signing session can retain
// the lock across WASM preparation, one native digest request, and finalization.
function operationBusy(active) {
 busy=active;$('transport').disabled=active;$('busy').hidden=!active;
 if($('hardware-transport'))$('hardware-transport').disabled=active;
 // The lock blocks a second operation, while the active operation can
 // still wait for review, FIDO entropy, PIN entry, or management approval.
 const operationDialogs='#combined-level3-confirm, #fido-pin-dialog, #smartcard-pin-dialog, #piv-management-dialog';
 document.querySelectorAll('button').forEach(b=>{
  if(!b.closest(operationDialogs))b.disabled=active;
 });
 // A test can be cancelled while its native PIN/touch attempt settles. The
 // coordinator retains this lock and performs only a final public audit.
 $('test-cancel').disabled=!active||!hardwareTestAbort;
 $('test-export').disabled=active||!hardwareTestReport;
 $('software-test-export').disabled=active||!softwareUi?.hasReport?.();
 // Lock is always available to invalidate software work; terminating a worker
 // or abandoning a native request never silently retries the private operation.
 $('vault-lock').disabled=!window.vaultIsUnlocked?.();
 if(!active){$('newer').disabled=page===0;$('older').disabled=!next;}
}
function nativeRequest(op,data={},options={}) {
 // Public metadata stays available while locked. Recheck the vault immediately
 // before each private operation, including the new digest-only signing route.
 if(['chat-selected-signing-material','chat-selected-decryption-material','chat-sign-digest'].includes(op)||
    (['chat-decryption-material','chat-decapsulate-components'].includes(op)&&data.service!=='Vault')){try{window.vaultGate?.();}catch(e){return Promise.reject(e);}}
 return requestCompanion(op,data,{...options,progress:say});
}
// Route hardware requests explicitly through the user-selected hardware transport
// ('native' helper PKCS#11 or 'smartcard' navigator.smartCard). No silent fallback.
function hardwareRequest(op,data={},options={}) {
 if(['chat-selected-signing-material','chat-selected-decryption-material','chat-sign-digest'].includes(op)||
    (['chat-decryption-material','chat-decapsulate-components'].includes(op)&&data.service!=='Vault')){
   try{window.vaultGate?.();}catch(e){return Promise.reject(e);}
 }
 if(window.hardwareTransport){
  return window.hardwareTransport.dispatch(op,data,options,nativeRequest,{identityStore:ownIdentityStore,say,
   inspectPublicBundle:async encoded=>{
    const {inspectBundle}=await import('./identities/client.js');
    return inspectBundle(encoded);
   },
   prepareVault:async serial=>{
    const {prepareVaultMaterial}=await import('./vault/hardware.js');
    const {inspectBundle,inspectIdentity}=await import('./identities/client.js');
    const {parseCardBundle}=await import('./identities/bundle.js');
    return prepareVaultMaterial({serial,piv:window.SequoiaSmartCardPiv,inspectBundle,inspectIdentity,parseCardBundle,store:ownIdentityStore});
   },
   prepareLevel3VaultUnlock:async(serial,recipientKey,progress)=>{
    const {prepareLevel3VaultUnlock}=await import('./vault/hardware.js');
    const {inspectBundle,inspectIdentity}=await import('./identities/client.js');
    return prepareLevel3VaultUnlock({serial,recipientKey,piv:window.SequoiaSmartCardPiv,inspectBundle,inspectIdentity,progress});
   },
   assertVault:()=>{if(!window.vaultOperationActive?.())throw Error('Vault operation ended');},
   authorizeIdentity:async ref=>{
    window.vaultGate();
    const {choices}=await hardwareIdentitySelection.list(ownEmail);
    const selected=choices.find(c=>c.serial===ref?.serial&&c.fingerprint===ref?.fingerprint&&c.certificateHash===ref?.certificateHash&&c.bundleHash===ref?.bundleHash);
    if(!selected)throw Error('Select a current saved hardware identity.');
    const {parseCardBundle,assertSelectedCardIdentity}=await import('./identities/bundle.js');
    const {inspectBundle,inspectIdentity}=await import('./identities/client.js');
    const fresh=await parseCardBundle(await window.SequoiaSmartCardPiv.readPublicSnapshotViaSmartCard(selected.serial,true),inspectBundle);
    await assertSelectedCardIdentity(fresh,selected,inspectIdentity);
    await hardwareIdentitySelection.assert(selected);
    return {...selected,slots:fresh.slots};
   },
   assertIdentity:async selected=>{window.vaultGate();await hardwareIdentitySelection.assert(selected);},
   signingInput:async(selected,request)=>{
    const {smartcardSigningInput}=await import('./identities/client.js');
    return (await smartcardSigningInput({certificate:selected.certificate,signingFingerprint:request.signingFingerprint,digest:request.digest})).mu;
   }
  });
 }
 return nativeRequest(op,data,options);
}
// Provider choice is pinned by a revision-checked inventory snapshot. An error
// in software custody never causes a native key lookup or a hardware retry.
function identityRequest(snapshot){
 if(snapshot?.provider==='software'){
  if(!window.softwareIdentities)throw Error('Software identity provider is not ready.');
  return window.softwareIdentities.native(snapshot);
 }
 if(snapshot&&Object.hasOwn(snapshot,'provider'))throw Error('Unknown identity provider.');
 return hardwareRequest;
}
function custodyLabel(identity){return identity.hardware?.privateRemoved?'YubiKey '+identity.hardware.serial+' · vault certificate':identity.provider==='software'?'Software (experimental) · '+identity.name:'YubiKey '+identity.serial+(identity.custody==='hardware-companion'?' + encrypted software companion':'');}
// Display only the selected certificate's authenticated component mapping.
// A legacy record's identity.slots is the union of ALL bundle profiles, including
// S/MIME and compatibility keys, so using that union would misstate which keys
// this operation will use. It is neither a fallback map nor native authority.
function operationSlots(identity,purpose){
 const components=identity.components?.filter(c=>c.role.startsWith(purpose));
 if(components?.length)return components.map(c=>c.storage==='piv'?c.slot.toUpperCase()+' ('+c.algorithm+')':c.algorithm+' in encrypted companion').join(' + ');
 // Older public inventories can still be independently authorized by native
 // code. Do not invent slot numbers from their profile name: a fresh read-only
 // bundle restore adds the exact per-certificate mapping to the local record.
 return 'verified from the current signed manifest (restore this bundle again to display exact slots)';
}
// Public inspector capabilities, not the presence of a classical component,
// control fallback warnings. A modern hybrid signature is still PQ protected.
function compatibilityWarnings(sender,recipient){
 const warnings=[];
 if(sender?.pqSigning===false)warnings.push('The selected compatibility identity uses classical signing, which is not post-quantum resistant.');
 if(recipient?.pqEncryption===false)warnings.push('This recipient certificate uses classical encryption, which is not post-quantum resistant.');
 return warnings;
}
function versionRank(identity){return ({6:0,5:1,4:2})[identity.version||6]??3;}
function contactLabel(contact){return contact.email+' · v'+(contact.version||6)+' · '+(contact.pqEncryption===false?'classical encryption':'hybrid encryption')+' · '+contact.fingerprint.slice(-12);}
// Certificate bytes and trust decisions stay within the signed IWA origin.
// Legacy operation names below are UI aliases, not native capabilities.
function assertAccount(snapshot=accountSnapshot){
 if(!accountSettings||!snapshot)throw Error('Configure your Google account in Account first.');
 if(snapshot.email!==ownEmail)throw Error('Account settings changed; review the account and sign in again.');
 return accountSettings.assert(snapshot);
}
function dispatchRequest(op,data={}) {
 if(op==='chat-cert-list')return certificateStore.list();
 if(op==='chat-verification-material')return certificateStore.material();
 if(op==='chat-preview')return certificateStore.preview(data.certificate);
 if(op==='chat-cert-save')return certificateStore.save(data.certificate);
 if(op==='chat-trust')return certificateStore.trust(data.certificate,data.email,data.fingerprint,data.confirmed);
 if(op==='chat-cert-untrust')return certificateStore.untrust(data.fingerprint,data.email,data.confirmed);
 if(op==='chat-cert-delete')return certificateStore.remove(data.fingerprint,data.confirmed);
 if(op==='chat-mail-cert-save'||op==='chat-mail-cert-trust')return persistVerifiedSigner(op,data);
 if(browserGoogleOperations.has(op)){
  // A failed/not-yet-loaded browser module must not silently turn an ordinary
  // Google request into native messaging. There is no legacy transport fallback.
  if(!window.googleTransport?.handles(op))throw Error('Browser Google transport is not ready. Reload this IWA.');
  const snapshot=accountSnapshot;assertAccount(snapshot);
  // Carry a revision-bound account through asynchronous Google and identity
  // work. A second window changing settings invalidates it even before the
  // storage event arrives; no native configuration is a fallback authority.
  return window.googleTransport.call(op,data,hardwareRequest,{account:snapshot.email,contacts,certificateStore,composeReviews,identitySelection,identityRequest,assertAccount:()=>assertAccount(snapshot)}).then(result=>{assertAccount(snapshot);return result;});
 }
 return hardwareRequest(op,data);
}
function call(op,data={}) {
 if(busy)return Promise.reject(Error('An operation is already running.'));
 operationBusy(true);
 return Promise.resolve().then(()=>dispatchRequest(op,data)).finally(()=>operationBusy(false));
}
function event(id,fn){$(id).addEventListener('click',()=>Promise.resolve().then(fn).catch(e=>say(e.message,true)));}
function clearPendingOpen(){openMessage=null;localEncrypted=null;$('open').close();cancelDecryptionChoice();}
function beginReading(){clearPendingOpen();readerEvidence=null;$('reader').hidden=true;return ++readerGeneration;}
function assertReading(generation){if(generation!==readerGeneration)throw Error('Message view changed or locked; open it again.');}
function options(id,rows,value,label){const el=$(id),old=el.value;el.replaceChildren();for(const row of rows){const o=document.createElement('option');o.value=value(row);o.textContent=label(row);el.append(o);}if([...el.options].some(o=>o.value===old))el.value=old;}
function renderContacts(){const ordered=[...contacts].sort((a,b)=>a.email.localeCompare(b.email)||versionRank(a)-versionRank(b)||Number(a.pqEncryption===false)-Number(b.pqEncryption===false));for(const id of ['recipient','signer'])options(id,ordered,c=>c.id,contactLabel);$('contact-list').replaceChildren();for(const c of ordered){const el=document.createElement('div');el.className='contact';el.textContent=contactLabel(c)+'\n'+c.fingerprint;$('contact-list').append(el);}}
// Local inventory is independent of Gmail/Chat login and never prompts for PINs.
async function refreshCertificates(){const r=await call('chat-cert-list');contacts=r.contacts;renderContacts();renderSavedCertificates(r.certificates);}
// A v4 hybrid view and its classical-only view can share both signing key and
// primary fingerprint. Include encryption capability so Compose, decryption and
// hardware-test selectors do not present those distinct packet views identically.
function identityLabel(c){return c.email+' · v'+(c.version||6)+' '+(c.signingAlgorithm||'signing algorithm checked from certificate')+' · encrypt: '+(c.encryptionAlgorithm||'algorithm checked from certificate')+' · '+custodyLabel(c)+' · '+c.fingerprint.slice(-12);}
async function refreshSendIdentities(){
 const generation=++identityListGeneration;
 if(!identitySelection||!ownEmail){sendIdentities=[];for(const id of ['send-identity','test-identity'])options(id,[],c=>c.id,identityLabel);$('send-identity-help').textContent='Configure your Google account in Account, then restore its supported public identity in Identities.';return;}
 const account=ownEmail,snapshot=accountSnapshot;
 const listed=await identitySelection.list(account);
 if(generation!==identityListGeneration||account!==ownEmail||snapshot!==accountSnapshot)return;
 sendIdentities=[...listed.choices].sort((a,b)=>versionRank(a)-versionRank(b)||Number(a.pqSigning===false)-Number(b.pqSigning===false));
 const before=$('send-identity').value;options('send-identity',sendIdentities,c=>c.id,identityLabel);
 options('test-identity',sendIdentities.filter(c=>c.provider!=='software'),c=>c.id,identityLabel);
 // This preference contains only a public inventory identifier. It never
 // selects a native executable, slot or grant, and is revalidated on every use.
 let remembered;try{remembered=localStorage.getItem('sequoia-iwa-send-identity');}catch(_){}
 const hasHybridV6=sendIdentities.some(c=>(c.version||6)===6&&c.pqSigning===true);
 if(!sendIdentities.some(c=>c.id===before)&&sendIdentities.some(c=>c.id===remembered&&(c.version||6)===6&&(!hasHybridV6||c.pqSigning!==false)))$('send-identity').value=remembered;
 updateIdentityHelp();
}
function updateIdentityHelp(){
 const selected=sendIdentities.find(c=>c.id===$('send-identity').value);
 $('send-identity-help').textContent=!selected?'Restore a matching YubiKey identity, or unlock the vault and create or import a software OpenPGP identity.':selected.hardware?.privateRemoved?'Hardware-only vault identity: keys are checked against YubiKey '+selected.hardware.serial+' before the PIV PIN prompt. Signing uses 9c/84; decryption uses 9d/85. '+compatibilityWarnings(selected,selected).join(' '):selected.provider==='software'?'Software (experimental): keys are unlocked only in a disposable browser worker. The vault must remain unlocked; no YubiKey signing operation is used. '+compatibilityWarnings(selected,selected).join(' '):'The selected signed manifest is checked against its YubiKey before the PIN prompt. Signing: '+operationSlots(selected,'signing')+'. Decryption: '+operationSlots(selected,'decryption')+'. '+compatibilityWarnings(selected,selected).join(' ');
}
$('send-identity').addEventListener('change',()=>{updateIdentityHelp();
 invalidateCertificateViews();try{localStorage.setItem('sequoia-iwa-send-identity',$('send-identity').value);}catch(_){}
});
// Store changes invalidate both sending reviews and pending recipient choices.
// Independent revision checks still catch a delayed/lost broadcast.
const ownIdentityUpdates=typeof BroadcastChannel==='function'?new BroadcastChannel('sequoia-iwa-own-identities'):null;
if(ownIdentityUpdates)ownIdentityUpdates.onmessage=()=>{invalidateCertificateViews();refreshSendIdentities().catch(e=>say(e.message,true));};
function invalidateCertificateViews(){
 hardwareTestAbort?.abort();softwareTestAbort?.abort();
 // A stored trust change must invalidate prepared sends and old green reader
 // labels, including changes made in another IWA window. An in-flight native
 // operation is never retried or unlocked by this public-storage notification.
 readerGeneration++;composeReviews?.clear();review=null;clearPendingOpen();readerEvidence=null;
 certificateReview=null;$('confirm-send').close();$('mail-cert-confirm').close();
 $('reader').hidden=true;$('read-certificates').replaceChildren();
 $('read-body').textContent=$('read-subject').textContent=$('verified').textContent='';
 $('read-html').replaceChildren();$('read-files').replaceChildren();
}
const certificateUpdates=typeof BroadcastChannel==='function'?new BroadcastChannel('sequoia-iwa-public-certificates'):null;
async function certificatesChanged(){
 invalidateCertificateViews();certificateUpdates?.postMessage({changed:true});
 await refreshCertificates();
}
if(certificateUpdates)certificateUpdates.onmessage=()=>{
 invalidateCertificateViews();
 // Reading IndexedDB does not acquire a native-operation lock. If another
 // window changes trust while signing, completion/send rechecks reject it.
 certificateStore?.list().then(r=>{contacts=r.contacts;renderContacts();renderSavedCertificates(r.certificates);}).catch(e=>say(e.message,true));
};
function renderSavedCertificates(rows){
 $('saved-certificates').replaceChildren();
 if(!rows.length)$('saved-certificates').textContent='No saved certificates.';
 for(const c of rows){
  const row=document.createElement('div');row.className='contact';const info=document.createElement('p');
  info.textContent='OpenPGP v'+c.version+' · '+c.algorithms.join(' / ')+'\n'+c.fingerprint+'\nTrusted emails (saved bindings): '+(c.trustedEmails.join(', ')||'None')+'\n'+(c.hybridContact?'Hybrid sending contact':'Verification certificate');row.append(info);
  for(const email of c.emails.filter(email=>!c.trustedEmails.includes(email))){
   const button=document.createElement('button');button.textContent='Mark trusted for '+email+'…';
   button.addEventListener('click',()=>reviewCertificateChange('trust',c.fingerprint,email));row.append(button);
  }
  for(const email of c.trustedEmails){const button=document.createElement('button');button.textContent='Remove trust for '+email+'…';button.addEventListener('click',()=>reviewCertificateChange('chat-cert-untrust',c.fingerprint,email));row.append(button);}
  const del=document.createElement('button');del.textContent='Delete saved certificate…';del.addEventListener('click',()=>reviewCertificateChange('chat-cert-delete',c.fingerprint));row.append(del);$('saved-certificates').append(row);
 }
}
function reviewCertificateChange(op,fingerprint,email){
 managementReview={op,fingerprint,...(email?{email}:{})};
 $('manage-cert-title').textContent=op==='trust'?'Trust this email and public key?':op==='chat-cert-delete'?'Delete saved public certificate?':'Remove certificate trust?';
 $('manage-cert-details').textContent='Full primary fingerprint: '+fingerprint+(email?'\nEmail: '+email:'');
 $('manage-cert-help').textContent=op==='trust'?'Independently verify this full fingerprint. Trust applies only to this email and primary key, not every email on the certificate.':op==='chat-cert-delete'?'Removes this IWA public certificate and all its email trust bindings. The native migration backup is unchanged and will not be imported automatically. No YubiKey keys are deleted.':'Removes trust only for this email and fingerprint. The public certificate remains available for mathematical signature verification.';
 $('manage-cert-apply').textContent=op==='trust'?'Mark trusted':op==='chat-cert-delete'?'Delete saved certificate':'Remove trust';$('manage-cert-confirm').showModal();
}
event('refresh-certificates',refreshCertificates);
event('manage-cert-cancel',()=>{managementReview=null;$('manage-cert-confirm').close();});
event('manage-cert-apply',async()=>{
 const r=managementReview;managementReview=null;$('manage-cert-confirm').close();if(!r)throw Error('Review the selected certificate first.');
 if(r.op==='trust'){
  const c=await certificateStore.get(r.fingerprint);
  await call('chat-trust',{certificate:c.certificate,email:r.email,fingerprint:r.fingerprint,confirmed:true});
 }else{const {op,...fields}=r;await call(op,{...fields,confirmed:true});}
 await certificatesChanged();say(r.op==='trust'?'Trust saved in this IWA for the selected email and fingerprint.':r.op==='chat-cert-delete'?'IWA certificate and its trust removed.':'Trust removed for the selected email; certificate kept.');
});
event('migration-review',async()=>{
 // Reading legacy public files is the only certificate-store operation exposed
 // by the native bridge. Import and trust changes occur only after this review.
 const snapshot=await call('chat-certificate-migration');
 const rows=[];for(const encoded of snapshot.certificates){const c=await certificateStore.preview(encoded);rows.push('OpenPGP v'+c.version+' · '+c.fingerprint+'\n'+c.algorithms.join(' / '));}
 migrationReview=snapshot;
 $('migration-details').textContent=rows.join('\n\n')+'\n\nExisting trust bindings:\n'+(snapshot.bindings.map(b=>b.email+' → '+b.fingerprint).join('\n')||'None');
 $('migration-confirmed').checked=false;$('migration-dialog').showModal();
});
event('migration-cancel',()=>{migrationReview=null;$('migration-dialog').close();});
event('migration-import',async()=>{
 if(!migrationReview||!$('migration-confirmed').checked)throw Error('Review and confirm the existing certificate and trust bindings first.');
 const snapshot=migrationReview;migrationReview=null;$('migration-dialog').close();
 await certificateStore.importLegacy(snapshot,true);await certificatesChanged();
 say('Certificates and reviewed trust copied into this IWA. Native public files remain unchanged; they will not be reimported automatically.');
});
// Service labels are derived together so hidden controls and dialogs cannot
// retain wording from the previously selected transport.
function serviceLabels(){
 const mail=isMail(),name=service(),drive=isDrive();
 $('service-title').textContent='Sequoia '+name+' Lab';
 $('service-lead').textContent=name+' transport. Hardware or vault-protected software identities. Encrypted and verified by Sequoia.';
 $('login').textContent='Sign in to '+name;
 $('connect').textContent='Connect / reconnect '+name;
 $('google-auth').textContent='Continue to '+name+' sign-in';
 $('inbox-tab').textContent=mail?'Gmail inbox':'Chat conversations';
 $('inbox-title').textContent=mail?'Gmail inbox':'Chat conversations';
 for(const id of ['space','space-label'])$(id).hidden=mail;
 for(const id of ['mail-query','mail-query-label'])$(id).hidden=!mail;
 $('more-spaces').hidden=mail||!spaceNext;
 $('compose-title').textContent='Signed and encrypted '+name+(mail?' email':' bundle');
 $('compose-help').textContent=mail?'Send encrypted PGP/MIME email to the selected trusted recipient.':'Send the encrypted bundle and public certificate to the selected Chat conversation.';
 $('compose-destination').textContent=mail?'Gmail: email to the selected trusted recipient':'Chat conversation: '+($('space').selectedOptions[0]?.textContent??'Connect and select a conversation first');
 $('prepare').textContent='Sign and prepare '+name+(mail?' email…':' bundle…');
 $('send-title').textContent='Send encrypted '+name+(mail?' email?':' bundle?');
 $('send-help').textContent=mail?'Gmail sends encrypted PGP/MIME. Subject, text and attachments stay inside encryption.':'Chat sends linked bundle/certificate messages. Subject, text and attachments stay inside encryption.';
 $('send').textContent='Send via '+name;
 // Reset shared reader controls on every service switch; Drive has no mail inbox.
 $('load').textContent=drive?'Browse encrypted Drive files':'Load messages';
 for(const id of ['local-mail','local-mail-label','newer','older'])$(id).hidden=drive;
 $('clear-reader').textContent=drive?'Clear file':'Clear message';
 $('save-encrypted').hidden=!mail||isDrive();
 $('send').hidden=isDrive();$('drive-upload').hidden=!isDrive();
 if(isDrive()){
  $('inbox-tab').textContent='Decrypted files';$('inbox-title').textContent='Decrypted Drive files';
  $('mail-query').hidden=true;$('mail-query-label').hidden=true;
  $('compose-title').textContent='Sign and encrypt files for Drive';
  $('compose-help').textContent='Attach files and choose a trusted recipient. The selected software or YubiKey identity signs locally; only a .pgp ciphertext is uploaded.';
  $('compose-destination').textContent='Google Drive — new encrypted file';
  $('prepare').textContent='Sign and prepare encrypted files…';
  $('send-title').textContent='Upload signed and encrypted files to Drive?';
  $('send-help').textContent='Only the .pgp ciphertext is uploaded. Google sharing permissions remain unchanged. No email or Chat message is sent.';
 }
 $('open-title').textContent=drive?'Decrypt and verify Drive file':'Decrypt and verify '+name+(mail?' email':' bundle');
 $('open-help').textContent=(mail?'Verify against the selected trusted sender certificate.':'The attached certificate must match this trusted contact.')+' Choose the matching hardware or unlocked software identity next.';
 $('decrypt').textContent='Decrypt '+name;
}
function tab(name){if(['ssh','local-files'].includes(name)&&!window.vaultIsUnlocked?.())return;if(name!=='inbox'){readerGeneration++;readerEvidence=null;clearPendingOpen();}document.querySelectorAll('.tab').forEach(el=>el.hidden=el.id!==name);document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===name));serviceLabels();}
document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>{tab(b.dataset.tab);if(b.dataset.tab==='contacts')refreshCertificates().catch(e=>say(e.message,true));if(b.dataset.tab==='identities'){identityUi?.refresh().catch(e=>say(e.message,true));softwareUi?.refresh().catch(e=>say(e.message,true));}}));
function clearAccountSession(){
 window.dispatchEvent(new Event('iwa-account-changed'));
 // Public configuration can change while the vault remains enrolled/unlocked.
 // Drop only account-bound transient work: Google tokens, pending signatures,
 // decrypted readers and one-use send/export reviews. Never rewrite the vault.
 window.googleTransport?.clear();signingAbort?.abort();decryptionAbort?.abort();invalidateCertificateViews();
 accountReview=null;$('account-review-dialog').close();
 $('messages').replaceChildren();spaces=[];spaceNext='';options('space',[],s=>s.name,s=>s.title);
 pages=[''];page=0;next='';$('more-spaces').hidden=true;
}
async function refreshAccount(){
 ownEmail='';accountSnapshot=null;
 try{accountSnapshot=accountSettings.read();ownEmail=accountSnapshot?.email||'';}
 finally{
  $('account').textContent=ownEmail?'Google account: '+ownEmail+' · saved in this IWA':'No Google account configured. Open Account to set it up.';
  $('account-email').value=ownEmail;
  $('account-current').textContent=ownEmail?'Configured account: '+ownEmail:'No public account setting saved.';
  await refreshSendIdentities();
 }
}
function reviewAccount(email,source){
 if(!accountSettings)throw Error('Account settings are still loading.');
 accountReview={email:normalizeAccount(email),expected:accountSettings.read()};
 $('account-review-details').textContent='Google account: '+accountReview.email+'\nSource: '+source;
 $('account-review-confirmed').checked=false;$('account-review-dialog').showModal();
}
event('account-review',()=>reviewAccount($('account-email').value,'Entered in this IWA'));
event('account-migrate',async()=>{
 // This is an optional, user-triggered public read. It is deliberately absent
 // from startup, contacts, identity inventory refresh and Google sign-in.
 const legacy=await call('chat-state');reviewAccount(legacyAccountEmail(legacy),'Existing helper configuration (email only)');
});
event('account-review-cancel',()=>{accountReview=null;$('account-review-dialog').close();});
$('account-review-dialog').addEventListener('cancel',()=>{accountReview=null;});
event('account-save',async()=>{
 if(busy)throw Error('Finish the current operation first.');
 if(!accountReview||!$('account-review-confirmed').checked)throw Error('Review and confirm the account email first.');
 const selected=accountReview;accountSettings.save(selected.email,selected.expected,true);
 clearAccountSession();await refreshAccount();say('Account saved in this IWA. Unlock the vault and sign in to Google.');
});
event('account-forget',async()=>{
 if(busy)throw Error('Finish the current operation first.');
 if(!window.confirm('Forget this IWA’s public account email and clear its Google session? Your saved vault, identities and contacts remain available.'))return;
 accountSettings.clear(true);clearAccountSession();await refreshAccount();say('Public account setting removed. Configure an account before signing in.');
});
window.addEventListener('iwa-vault-restored',()=>{
 if(!accountSettings)return;
 clearAccountSession();
 Promise.all([refreshAccount(),refreshCertificates(),identityUi?.refresh(),softwareUi?.refresh()]).catch(error=>say(error.message,true));
});
window.addEventListener('storage',event=>{
 if(!accountSettings||(event.key!==accountSettingsKey&&event.key!==null))return;
 clearAccountSession();refreshAccount().then(()=>say('Account settings changed in another window. Sign in again.')).catch(error=>say(error.message,true));
});
async function bootstrap(){
 const [{createCertificateStore,createIndexedDbStorage},{inspectCertificate},{createComposeReviews},{createIdentityStore},{createIdentitySelection},{inspectIdentity,matchRecipients},accountModule]=await Promise.all([
  import('./certificates/store.js'),import('./certificates/client.js'),import('./compose-review.js'),import('./identities/store.js'),import('./identities/selection.js'),import('./identities/client.js'),import('./account-settings.js')]);
 accountSettings=accountModule.createAccountSettings();accountSettingsKey=accountModule.ACCOUNT_SETTINGS_KEY;
 normalizeAccount=accountModule.accountEmail;legacyAccountEmail=accountModule.legacyAccount;
 certificateStore=createCertificateStore({inspect:inspectCertificate,storage:createIndexedDbStorage()});
 ownIdentityStore=createIdentityStore({inspect:inspectCertificate});
 hardwareIdentitySelection=createIdentitySelection({store:ownIdentityStore,inspect:inspectIdentity,match:matchRecipients});
 const {createProviderSelection}=await import('./identities/providers.js');
 identitySelection=createProviderSelection({hardware:hardwareIdentitySelection,software:()=>window.softwareIdentities,match:matchRecipients});
 composeReviews=createComposeReviews({certificateStore,identitySelection,gate:()=>{window.vaultGate?.();assertAccount();}});
 // Public inventory and file import must work even when the native helper is
 // unavailable. Startup loads only IWA public stores; hardware metadata is read
 // only when the user explicitly invokes a hardware control or migration.
 const {initializeIdentities}=await import('./identities/ui.js');
 identityUi=await initializeIdentities({request:hardwareRequest,say,isBusy:()=>busy,setBusy:operationBusy,identityStore:ownIdentityStore});
 const {initializeSoftwareUi}=await import('./software-ui.js');
 softwareUi=initializeSoftwareUi({isBusy:()=>busy,setBusy:operationBusy,say,account:()=>ownEmail,
  changed:async()=>{invalidateCertificateViews();await refreshSendIdentities();},
  test:async(identity,onProgress,backupBinding)=>{
   const account=accountSnapshot;assertAccount(account);softwareTestAbort=new AbortController();
   try{
    const {runSoftwareTest}=await import('./software-test.js');
    const normal=identityRequest(identity);
    const request=backupBinding?async(op,data,options)=>{
     if(op==='chat-sign-digest'||op==='chat-decapsulate-components'){
      const {operateImportedKey}=await import('./piv-import.js');const {review,service,...component}=data;
      return operateImportedKey(op==='chat-sign-digest'?'sign':'decapsulate',component,backupBinding,{...options,signal:softwareTestAbort.signal,guard:async()=>{assertAccount(account);window.vaultGate?.();await identitySelection.assert(identity);}});
     }
     return normal(op,data,options);
    }:normal;
    return await runSoftwareTest({identity,selection:identitySelection,request,hardware:!!backupBinding||!!identity.hardware?.privateRemoved,
     gate:()=>{assertAccount(account);window.vaultGate?.();},signal:softwareTestAbort.signal,onProgress,
     createSigningWorker:()=>new Worker(signingWorkerURL(),{type:'module'}),
     createDecryptionWorker:()=>new Worker(decryptionWorkerPolicy?decryptionWorkerPolicy.createScriptURL('/decryption-worker.js'):'/decryption-worker.js',{type:'module'})});
   }finally{softwareTestAbort=null;}
  }});
 await refreshCertificates();
 const {initializeSsh}=await import('./ssh/ui.js');await initializeSsh({window,document}).refresh();
 const {initializeLocalFiles}=await import('./local-files/ui.js');initializeLocalFiles({window,document});
 await refreshAccount();await softwareUi.refresh();
 say(ownEmail?'Ready. Local certificates and account settings are available; unlock the vault and sign in to Google.':'Ready. Configure your Google account in Account. Contacts, saved identities and the existing vault are available.');tab(ownEmail?'inbox':'account-settings');
}
async function loadSpaces(token=''){if(isDrive()){tab('drive-files');return driveList();}if(isMail()){const a=await call('chat-mail-connect');say('Gmail connected: '+a.account);pages=[''];page=0;await messages();return;}const r=await call('chat-spaces',{page:token});spaces=token?[...spaces,...r.spaces]:r.spaces;spaceNext=r.next;options('space',spaces,s=>s.name,s=>s.title);$('more-spaces').hidden=!spaceNext;say('Chat connected. Select a conversation to read messages.');}
async function messages(token=''){if(isDrive()){tab('drive-files');return driveList();}const r=await call(isMail()?'chat-mail-list':'chat-messages',isMail()?{page:token,query:$('mail-query').value}:{space:$('space').value,page:token});next=r.next;$('messages').replaceChildren();for(const m of r.messages){const b=document.createElement('button');b.textContent=(m.encrypted?'🔒 Encrypted bundle · ':'')+m.time+'\n'+m.text;b.addEventListener('click',()=>{if(isMail()&&!m.encrypted){readOrdinary(m.name).catch(e=>say(e.message,true));return;}if(!m.encrypted){say('This is a Google Chat text/certificate message, not an encrypted bundle.');return;}if(!contacts.length){say('Import and trust the sender’s certificate first.',true);tab('contacts');return;}openRemoteMessage(m.name);});$('messages').append(b);}$('newer').disabled=page===0;$('older').disabled=!next;say(service()+' messages loaded. Encrypted content is decrypted only when opened.');}
function openRemoteMessage(name){
 // Each provider selection owns a fresh dialog. In particular, a local file
 // dismissed with Escape must not win over this newly selected message ID.
 beginReading();openMessage=name;serviceLabels();$('open').showModal();
}
// Escape produces a native dialog cancel event rather than clicking our Cancel
// button. Drop the staged ciphertext on both paths before another selection.
$('open').addEventListener('cancel',clearPendingOpen);
// Ordinary mail never borrows the green trusted-signature result from a
// previously opened encrypted message, and never asks for a YubiKey PIN.
// Keep only this displayed message in memory. Saving/trusting re-verifies its
// captured bytes in a new WASM worker; UI labels alone never authorize trust.
async function persistVerifiedSigner(op,data){
 const evidence=readerEvidence,generation=readerGeneration;
 if(!evidence||evidence.message!==data.message)throw Error('Open and verify this message again.');
 const material=await certificateStore.material();
 const result=await runMessageWorker(evidence.packet,material);
 await certificateStore.assertRevision(material.revision);assertReading(generation);
 if(readerEvidence!==evidence)throw Error('Displayed message changed; review its certificate again.');
 const found=result.certificateActions?.find(c=>c.fingerprint===data.fingerprint);
 if(result.signatureStatus!=='valid'||!found?.certificate)throw Error('No valid signature from the selected certificate.');
 if(op==='chat-mail-cert-save')return certificateStore.save(found.certificate);
 if(data.confirmed!==true||!found.canTrust||found.email!==data.email)throw Error('Review the current sender email and full fingerprint first.');
 return certificateStore.trust(found.certificate,found.email,found.fingerprint,true);
}
function renderCertificateActions(message,items){
 $('read-certificates').replaceChildren();
 for(const c of items||[]){
  const row=document.createElement('div');const label=document.createElement('p');
  label.textContent='Signing certificate · '+c.algorithm+'\n'+c.fingerprint+'\n'+(c.saved?'Saved locally':'Not saved')+' · '+(c.trusted?'Trusted for '+c.email:'Not trusted');row.append(label);
  if(!c.saved){const save=document.createElement('button');save.textContent='Save certificate (no trust)';save.addEventListener('click',async()=>{try{await call('chat-mail-cert-save',{message,fingerprint:c.fingerprint});await certificatesChanged();await readOrdinary(message);say('Public certificate saved in this IWA. Saving does not grant trust.');}catch(e){say(e.message,true);}});row.append(save);}
  if(c.canTrust&&!c.trusted){const trust=document.createElement('button');trust.textContent='Mark trusted for '+c.email+'…';trust.addEventListener('click',()=>{certificateReview={message,fingerprint:c.fingerprint,email:c.email};$('mail-cert-details').textContent='Email: '+c.email+'\nFull primary fingerprint: '+c.fingerprint+'\nAlgorithm: '+c.algorithm;$('mail-cert-confirm').showModal();});row.append(trust);}
  if(!c.canTrust){const warning=document.createElement('p');warning.textContent='Trust unavailable: the From email is not a current self-certified mailbox on this certificate.';row.append(warning);}
  $('read-certificates').append(row);
 }
}
event('mail-cert-cancel',()=>{certificateReview=null;$('mail-cert-confirm').close();});
event('mail-cert-trust',async()=>{const selected=certificateReview;certificateReview=null;$('mail-cert-confirm').close();if(!selected)throw Error('Review the certificate first.');await call('chat-mail-cert-trust',{...selected,confirmed:true});await certificatesChanged();await readOrdinary(selected.message);say('Certificate saved and trusted in this IWA only for '+selected.email+' and its full primary fingerprint.');});
async function readOrdinary(message){
 const generation=beginReading();
 const packet=await call('chat-mail-read',{message});
 const material=await call('chat-verification-material');
 const r=await processMessage(packet,material);
 // A late worker response must not revive a green trust label after another
 // window removed trust, or reveal a message after vault lock/reader clear.
 await certificateStore.assertRevision(material.revision);assertReading(generation);
 if(r.encrypted){say('This message is encrypted. Reload the inbox to open it with the trusted signer.');return;}

 readerEvidence={message,packet};showOrdinary(r,message);
}
function showOrdinary(r,message){
 $('read-subject').textContent=r.subject;
 $('verified').textContent=mailSecuritySummary(r)+'\n'+(r.signatures||[]).filter(s=>s.fingerprint).map(s=>(s.candidateOnly?'Candidate certificate (sender NOT authenticated): ':'Primary fingerprint: ')+s.fingerprint+' · '+s.algorithm).join('\n')+'\n'+(r.warning?r.warning+'\n':'')+r.notice+' From (outer header): '+r.sender+(r.omittedAttachments?' '+r.omittedAttachments+' attachment(s) omitted by size/count limits.':'');
 $('verified').classList.toggle('error',r.signatureStatus!=='valid'||r.certificateTrust!=='trusted');
 $('read-body').textContent=r.text;
 $('toggle-html').hidden=!r.html;
 renderSafeHtml($('read-html'),r.html||'');
 $('read-html').hidden=!!r.text||!r.html;$('read-body').hidden=!$('read-html').hidden;
 renderFiles(r.attachments);if(message)renderCertificateActions(message,r.certificateActions);else $('read-certificates').replaceChildren();$('reader').hidden=false;
 say('Gmail message opened — not encrypted; signature: '+r.signatureStatus+'; certificate trust: '+r.certificateTrust+'.');
}
event('login',async()=>{
 if(isDrive())return driveConnect();
 const snapshot=accountSnapshot;assertAccount(snapshot);
 await window.googleTransport.login(snapshot.email);assertAccount(snapshot);
 say('Google connected directly. Access lasts until expiry or vault lock.');await loadSpaces();
});
event('connect',()=>loadSpaces());event('more-spaces',()=>loadSpaces(spaceNext));
event('status',async()=>{const r=await call('status');say(r.connected?'Expected YubiKey '+r.serial+' is connected.':'Connect key '+r.serial+'.');});
event('load',async()=>{pages=[''];page=0;await messages();});
event('older',async()=>{if(!next)return;pages[++page]=next;await messages(next);});event('newer',async()=>{if(page>0)await messages(pages[--page]);});
event('prepare',async()=>{
 if(review)composeReviews.cancel(review);review=null;
 if(busy)throw Error('An operation is already running.');
 if((!isMail()&&!$('space').value)||!$('recipient').value||!$('subject').value||!$('body').value)throw Error('Select a conversation and trusted recipient, then enter a subject and message.');
 const recipient=contacts.find(c=>c.id===$('recipient').value);
 if(!recipient)throw Error('Choose a trusted recipient.');
 // Snapshot editable fields before any asynchronous work. Changes typed while
 // the native PIN dialog is open cannot change what this operation signs.
 const mail=isMail(),space=$('space').value,senderChoice=$('send-identity').value;
 const compose={sender:ownEmail,recipient:recipient.email,subject:$('subject').value,
  body:$('body').value,html:$('formatted').checked?formatMessage($('body').value):''};
 operationBusy(true);let prepared=null;signingAbort=new AbortController();
 try {
  const selected=await certificateStore.trustedContact(recipient.id);
  const sender=await identitySelection.get(senderChoice,ownEmail);
  const snapshot=accountSnapshot;
  const assertSender=async()=>{assertAccount(snapshot);await identitySelection.assert(sender);assertAccount(snapshot);if($('send-identity').value!==senderChoice)throw Error('Sending identity changed; prepare again.');};
  await assertSender();
  const warnings=compatibilityWarnings(sender,selected);
  const compatibilityConfirmed=!warnings.length||window.confirm(warnings.join('\n\n')+'\n\nContinue with this compatibility profile?');
  if(!compatibilityConfirmed)throw Error('Compatibility signing/encryption cancelled before private operations.');
  await certificateStore.assertContact(selected);await assertSender();
  compose.attachments=await attachmentData();
  // This metadata-only route does not receive MIME or prompt for a PIN.
  const material=await dispatchRequest(isDrive()?'chat-drive-prepare':mail?'chat-mail-prepare':'chat-prepare',{
   ...(!mail?{space}:{}),contact:recipient.id,subject:compose.subject,identity:senderChoice,compatibilityConfirmed});
  prepared=material.review;
  const {signAndEncrypt}=await import('./signing-session.js');
  const encrypted=await signAndEncrypt(material,compose,
   async request=>{
    await certificateStore.assertContact(selected);await assertSender();
    const result=await identityRequest(sender)('chat-sign-digest',request,{signal:signingAbort.signal});
    try{await assertSender();return result;}catch(error){if(result)delete result.companionShared;throw error;}
   },
   {createWorker:()=>new Worker(signingWorkerURL(),{type:'module'}),signal:signingAbort.signal});
  await assertSender();const r=await composeReviews.complete(material.review,encrypted.cipher);
  review=r.review;$('send-details').textContent='Send as: '+r.sender+' · '+custodyLabel(sender)+'\nSigning certificate: '+r.senderFingerprint+'\nSubject: '+r.subject+'\n'+(mail?'Service: ':'Chat conversation: ')+r.space+'\nRecipient: '+r.recipient+'\nFingerprint: '+r.fingerprint+(r.compatibilityWarnings?.length?'\n\n'+r.compatibilityWarnings.join('\n'):'');
  $('confirm-send').showModal();say(service()+' signature constructed and verified in WASM; encrypted message ready for review.');
 } catch(e){if(prepared)composeReviews.cancel(prepared);throw e;}
 finally {signingAbort=null;operationBusy(false);}
});
event('cancel-send',()=>{$('confirm-send').close();if(review)composeReviews.cancel(review);review=null;});
event('save-encrypted',async()=>{
 if(busy)throw Error('An operation is already running.');
 const rid=review,generation=readerGeneration;review=null;$('confirm-send').close();
 if(!rid||!isMail())throw Error('Prepare a new encrypted email first.');
 operationBusy(true);
 try{
  // The explicit export action consumes the same one-use review as Send and
  // rechecks trust, vault state, account and expiry before releasing ciphertext.
  const saved=await composeReviews.exportEmail(rid,ownEmail,true);
  // The final UI continuation must also observe any lock/trust invalidation
  // that occurred while the export authorization promise was resolving.
  assertReading(generation);window.vaultGate?.();assertAccount();
  const bytes=Uint8Array.from(atob(saved.raw),c=>c.charCodeAt(0));
  const url=URL.createObjectURL(new Blob([bytes],{type:saved.type})),a=document.createElement('a');
  a.href=url;a.download=saved.name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  say('Encrypted email exported locally; nothing sent. Prepare again before sending.');
 }finally{operationBusy(false);}
});
event('send',async()=>{const rid=review;review=null;$('confirm-send').close();if(!rid)throw Error('Prepare a new bundle first.');const r=await call(isMail()?'chat-mail-send':'chat-send',{review:rid,confirmed:true});say((isMail()?'Gmail message sent: ':'Chat message sent: ')+r.sent);$('subject').value='';$('body').value='';$('files').value='';$('file-list').textContent='';});
event('cancel-open',clearPendingOpen);
function cancelDecryptionChoice(){
 const pending=decryptionChoice;decryptionChoice=null;$('matched-identity').close();
 pending?.reject(Error('Decryption identity selection cancelled; no private operation performed.'));
}
function reviewMatchedIdentity(matched,generation,account){
 if(decryptionChoice)cancelDecryptionChoice();
 return new Promise((resolve,reject)=>{
  decryptionChoice={matched,generation,account,resolve,reject};
  options('decrypt-identity',matched.choices,c=>c.id,identityLabel);
  $('matched-identity-help').textContent=matched.choices.length===1?'The encrypted recipient packet matches this saved identity. Review its custody provider before continuing.':'More than one saved identity matches this recipient key. Select its custody provider; no private operation has started.';
  showMatchedIdentity();$('matched-identity').showModal();
 });
}
function showMatchedIdentity(){
 const selected=decryptionChoice?.matched.choices.find(c=>c.id===$('decrypt-identity').value);
 $('matched-identity-details').textContent=selected?custodyLabel(selected)+'\nOpenPGP v'+(selected.version||6)+' · '+(selected.encryptionAlgorithm||'ML-KEM-768 + X25519')+(selected.hardware?.privateRemoved?'\nUses the unlocked vault mapping and the YubiKey PIV PIN prompt.':selected.provider==='software'?'\nUses the unlocked vault; no hardware PIN prompt.':'\nComponents: '+operationSlots(selected,'decryption')+'; enter PIN only in the native dialog.')+'\nCertificate: '+selected.fingerprint+'\nRecipient subkey: '+selected.recipientKey:'';
}
$('decrypt-identity').addEventListener('change',showMatchedIdentity);
event('matched-identity-cancel',cancelDecryptionChoice);
$('matched-identity').addEventListener('cancel',cancelDecryptionChoice);
event('matched-identity-continue',async()=>{
 const pending=decryptionChoice;if(!pending)throw Error('Match the encrypted message again.');
 const selected=pending.matched.choices.find(c=>c.id===$('decrypt-identity').value);
 try{
  if(!selected)throw Error('Select the matching identity.');
  await identitySelection.assert(selected);assertReading(pending.generation);assertAccount(pending.account);window.vaultGate?.();
  if(decryptionChoice!==pending)throw Error('Recipient selection changed.');
  decryptionChoice=null;$('matched-identity').close();pending.resolve(selected);
 }catch(error){decryptionChoice=null;$('matched-identity').close();pending.reject(error);}
});
async function decryptSelected(){
 if(busy)throw Error('An operation is already running.');
 const account=accountSnapshot;assertAccount(account);
 // Capture a local envelope before clearing the pending dialog. A late lock,
 // tab change or trust update still changes readerGeneration and blocks both
 // PIN submission and display; no fallback to a remote message ID is allowed.
 const local=localEncrypted,name=openMessage,fromDrive=localEncrypted?.source==='Drive',generation=beginReading();$('read-certificates').replaceChildren();
 if(!local&&!name)throw Error('Open an encrypted message first.');
 const selectedService=local?'Gmail':service(),selectedContact=$('signer').value;
 const selected=await certificateStore.trustedContact(selectedContact);
 const packet=local||await call(isMail()?'chat-mail-open':'chat-open',{message:name,contact:selectedContact});
 const material=await certificateStore.material();
 const envelope=packet.cipher?packet:await processMessage(packet,material);
 if(!envelope.encrypted||!envelope.cipher)throw Error('No supported encrypted envelope.');
 // Match the named PKESK fingerprint in WASM before contacting any private
 // backend. Stored labels or the currently selected Compose identity cannot
 // override which key the encrypted message addresses.
 // Recheck sender trust, reader generation and vault state across every await.
 await certificateStore.assertContact(selected);
 assertReading(generation);window.vaultGate?.();
 operationBusy(true);let matched;
 try{matched=await identitySelection.match(envelope.cipher,account.email);}finally{operationBusy(false);}
 await certificateStore.assertContact(selected);assertReading(generation);assertAccount(account);window.vaultGate?.();
 const recipient=await reviewMatchedIdentity(matched,generation,account);
 const r=await decryptInIwa({cipher:envelope.cipher,service:selectedService,native:identityRequest(recipient),identity:identitySelection.nativeBinding(recipient),recipientKey:recipient.recipientKey,
  validateMaterial:material=>identitySelection.validateMaterial(material,recipient,'decryption'),
  verification:{material:await certificateStore.material(),expectedEmail:selected.email,
   expectedFingerprint:selected.fingerprint,recipient:recipient.email},
  gate:async()=>{await certificateStore.assertContact(selected);await identitySelection.assert(recipient);assertReading(generation);assertAccount(account);window.vaultGate?.();}});
 await certificateStore.assertContact(selected);await identitySelection.assert(recipient);assertReading(generation);assertAccount(account);window.vaultGate?.();
 if(!r.verified)throw Error('Signature verification failed.');
 $('read-subject').textContent=r.subject;$('verified').classList.remove('error');
 $('verified').textContent='Encryption: Encrypted (decrypted) with '+custodyLabel(recipient)+' · Signature: Valid · Certificate trust: Trusted '+r.sender+'\n'+r.signatures[0].fingerprint+' · '+(r.signatures[0].algorithm||'')+(r.warning?'\n'+r.warning:'');
 $('read-body').textContent=r.text;$('toggle-html').hidden=!r.html;renderSafeHtml($('read-html'),r.html||'');
 $('read-html').hidden=true;$('read-body').hidden=false;renderFiles(r.attachments);$('reader').hidden=false;
 say((fromDrive?'Drive file':local?'Local email':selectedService)+' decryption and signature verification passed using IWA trust.');
}
event('decrypt',decryptSelected);
event('clear-reader',()=>{readerGeneration++;readerEvidence=null;clearPendingOpen();$('read-certificates').replaceChildren();$('reader').hidden=true;$('read-html').replaceChildren();$('read-files').replaceChildren();$('read-subject').textContent=$('read-body').textContent=$('verified').textContent='';});
event('preview',async()=>{cert=null;const f=$('certificate').files[0];if(!f||f.size>262144)throw Error('Select a public certificate up to 256 KiB.');let str='';for(const byte of new Uint8Array(await f.arrayBuffer()))str+=String.fromCharCode(byte);const encoded=btoa(str),info=await call('chat-preview',{certificate:encoded});cert={encoded,info};$('cert-info').textContent=info.fingerprint+'\n'+info.algorithms.join(' · ');options('email',info.emails,e=>e,e=>e);$('trust-confirm').checked=false;$('trust-panel').hidden=false;});
event('save-public',async()=>{
 if(!cert)throw Error('Review the public certificate first.');
 await call('chat-cert-save',{certificate:cert.encoded});await certificatesChanged();
 $('trust-panel').hidden=true;cert=null;say('Public certificate saved in this IWA without granting trust.');
});
event('trust',async()=>{
 if(!cert||!$('trust-confirm').checked)throw Error('Independently verify and confirm the full fingerprint first.');
 await call('chat-trust',{certificate:cert.encoded,email:$('email').value,fingerprint:cert.info.fingerprint,confirmed:true});
 await certificatesChanged();$('trust-panel').hidden=true;cert=null;
 say('Certificate saved in this IWA; trust granted only for the selected email and primary fingerprint.');
});
// Test orchestration lives entirely in the IWA. It uses a reviewed saved
// identity and the same component APIs as Compose/Read; no native test runner,
// Java classpath, mail transport, contact mutation or provisioning is involved.
event('test',async()=>{
 if(busy)throw Error('An operation is already running.');
 const account=accountSnapshot;assertAccount(account);window.vaultGate?.();
 const choice=$('test-identity').value,selected=await hardwareIdentitySelection.get(choice,ownEmail);
 if(!window.confirm('Run one local signing/decryption test with YubiKey '+selected.serial+'?\nOpenPGP v'+selected.version+' · '+selected.signingAlgorithm+' / '+selected.encryptionAlgorithm+'\nSigning: '+operationSlots(selected,'signing')+'. Decryption: '+operationSlots(selected,'decryption')+'.\n'+compatibilityWarnings(selected,selected).join(' ')+'\nExpect two native PIN operations; touch if requested. No email, keys, certificates or policies will be changed.'))return;
 hardwareTestReport=null;$('test-details').textContent='';hardwareTestAbort=new AbortController();operationBusy(true);
 try{
  const {runHardwareTest,signingFailureLabel}=await import('./hardware-test.js');
  const gate=async()=>{assertAccount(account);window.vaultGate?.();if($('test-identity').value!==choice)throw Error('Test identity changed.');};
  const result=await runHardwareTest({identity:selected,selection:hardwareIdentitySelection,native:hardwareRequest,gate,signal:hardwareTestAbort.signal,
   createSigningWorker:()=>new Worker(signingWorkerURL(),{type:'module'}),
   createDecryptionWorker:()=>new Worker(decryptionWorkerPolicy?decryptionWorkerPolicy.createScriptURL('/decryption-worker.js'):'/decryption-worker.js',{type:'module'}),
   onProgress:message=>{$('test-progress').textContent=message;say(message);}});
  hardwareTestReport=result;
  const unchanged=result.unchanged===true?'All 24 slot records, keys, PIN/touch policies, PIN retry counts and backend hashes unchanged.':result.unchanged===false?'Public audit changed — inspect the report before another operation.':'Unchanged status could not be confirmed — inspect the report before another operation.';
  // Report the selected certificate's actual algorithms. Packet version and
  // successful cryptographic verification do not imply post-quantum protection:
  // v4 compatibility can have classical signing with either hybrid or classical
  // encryption, and the ordinary Level 5 P-384 v6 view is classical as well.
  $('test-details').textContent=result.status+' — YubiKey '+selected.serial+'\n'+selected.fingerprint+'\n'+
   'Signature ('+(selected.signingAlgorithm||'algorithm checked from certificate')+'): '+(result.signatureVerified?'verified':'not completed')+'\nDecryption ('+(selected.encryptionAlgorithm||'algorithm checked from certificate')+') and exact text/HTML/attachment: '+(result.payloadVerified?'verified':'not completed')+'\n'+unchanged+'\n'+compatibilityWarnings(selected,selected).join('\n')+'\nNo email sent; no card writes requested.';
  // Resolve the code through a fixed label table again at the display boundary.
  // Reports do not expose native stderr, WASM exception text or private inputs.
  if(result.failurePhase)$('test-details').textContent+='\nStopped while: '+signingFailureLabel(result.failurePhase)+'.';
  $('test-progress').textContent=result.status==='PASS'?'Local hardware test complete. Independent Sequoia interoperability remains a separate test.':'Test stopped without automatic retry.';
  say(result.status==='PASS'?'PASS — IWA signing, decryption and unchanged hardware audit.':result.status+' — review Hardware test results before trying again.',result.status!=='PASS');
 }finally{hardwareTestAbort=null;operationBusy(false);}
});
event('test-cancel',()=>{hardwareTestAbort?.abort();$('test-cancel').disabled=true;$('test-progress').textContent='Cancelling. Waiting for any native attempt to settle, then checking public keys and policies. No private operation will be retried.';});
$('test-identity').addEventListener('change',()=>hardwareTestAbort?.abort());
event('test-export',()=>{
 if(busy||!hardwareTestReport)throw Error('Complete a hardware test first.');
 // Export is explicit and contains public device identifiers. The report has
 // no PIN, private key, message payload, ciphertext or component secret.
 const url=URL.createObjectURL(new Blob([JSON.stringify(hardwareTestReport,null,2)+'\n'],{type:'application/json'})),link=document.createElement('a');
 link.href=url;link.download='sequoia-iwa-hardware-test-'+hardwareTestReport.id+'.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
bootstrap().catch(e=>say(e.message,true));

// Attachment bytes stay in browser memory and the signing worker. Only the
// digest crosses Native Messaging; browser transport sends the final ciphertext.
async function attachmentData(){const files=[...$('files').files];if(files.length>10||files.reduce((n,f)=>n+f.size,0)>131072)throw Error('Maximum 10 attachments and 128 KiB total.');const result=[];for(const f of files){let binary='';for(const b of new Uint8Array(await f.arrayBuffer()))binary+=String.fromCharCode(b);result.push({name:f.name,data:btoa(binary)});}return result;}
$('files').addEventListener('change',()=>{$('file-list').textContent=[...$('files').files].map(f=>f.name+' ('+f.size+' bytes)').join(' · ');});
for(const [id,prefix,suffix] of [['bold','**','**'],['italic','*','*'],['heading','# ',''],['list','- ','']])event(id,()=>{const e=$('body'),a=e.selectionStart,b=e.selectionEnd;e.setRangeText(prefix+e.value.slice(a,b)+suffix,a,b,'select');e.focus();});
event('toggle-html',()=>{const show=$('read-html').hidden;$('read-html').hidden=!show;$('read-body').hidden=show;});
function renderFiles(files){$('read-files').replaceChildren();for(const f of files){const b=document.createElement('button');b.textContent='Save '+f.name+' ('+f.size+' bytes)';b.addEventListener('click',()=>{const bytes=Uint8Array.from(atob(f.data),c=>c.charCodeAt(0)),url=URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'})),a=document.createElement('a');a.href=url;a.download=f.name.replace(/[\\/\x00-\x1f]/g,'_');a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});$('read-files').append(b);}}

$('transport').addEventListener('change',()=>{if(busy)return;readerGeneration++;composeReviews?.clear();readerEvidence=null;review=null;clearPendingOpen();$('messages').replaceChildren();$('reader').hidden=true;pages=[''];page=0;next='';serviceLabels();$('google-auth').hidden=true;say('Connect '+service()+' or sign in to authorize access.');});

async function readLocalFile(file){
 if(busy)throw Error('An operation is already running.');
 const generation=beginReading();if(!file)return;if(file.size>262144)throw Error('Local message exceeds 256 KiB.');
 const bytes=new Uint8Array(await file.arrayBuffer());let binary='';for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));
 const material=await call('chat-verification-material');const r=await processMessage({raw:btoa(binary)},material);
 await certificateStore.assertRevision(material.revision);assertReading(generation);
 if(r.encrypted){
  if(!r.cipher)throw Error('No supported encrypted envelope.');
  if(!contacts.length)throw Error('Import and trust the expected sender certificate before decrypting.');
  // Store only the parsed ciphertext, never local paths or outer sender claims.
  // The next dialog requires an existing trusted contact; signed inner headers
  // and the fixed configured recipient are verified after native decapsulation.
  localEncrypted={encrypted:true,cipher:r.cipher};
  $('open-title').textContent='Decrypt and verify local email';
  $('open-help').textContent='Select the expected trusted sender. This local file is not uploaded. Choose the matching identity next.';
  $('decrypt').textContent='Decrypt local email';$('open').showModal();
  say('Encrypted local email ready; review the expected trusted sender.');return;
 }
 showOrdinary(r,null);say('Local copy verified with baseline WASM; no upload, certificate save or trust change.');
}
$('local-mail').addEventListener('change',async()=>{try{await readLocalFile($('local-mail').files[0]);}catch(e){say(e.message,true);}finally{$('local-mail').value='';}});

// Browser-staged ciphertext and captured verification evidence are transient.
// Lock/exit cannot leave an actionable send ticket or a stale trust dialog.
window.addEventListener('iwa-vault-locked',()=>{
 clearDrive();signingAbort?.abort();decryptionAbort?.abort();invalidateCertificateViews();identityListGeneration++;
 // Hide software choices synchronously. A delayed older inventory read cannot
 // repopulate them after locking, even if its public validation was in flight.
 sendIdentities=sendIdentities.filter(c=>c.provider!=='software');options('send-identity',sendIdentities,c=>c.id,identityLabel);updateIdentityHelp();
 refreshSendIdentities().catch(e=>say(e.message,true));
});
for(const event of ['iwa-vault-unlocked','iwa-software-identities-changed'])window.addEventListener(event,()=>{invalidateCertificateViews();refreshSendIdentities().catch(e=>say(e.message,true));});
window.addEventListener('pagehide',()=>{clearDrive();softwareTestAbort?.abort();hardwareTestAbort?.abort();readerGeneration++;signingAbort?.abort();decryptionAbort?.abort();composeReviews?.clear();readerEvidence=null;clearPendingOpen();certificateUpdates?.close();ownIdentityUpdates?.close();});

// Drive is a separate, least-privilege session. It does not reuse Gmail/Chat
// bearer tokens or persist OAuth material. The public review is consumed before
// uploading so a failure can never silently re-send or fall back to email.
let driveClient=null,drivePage='',driveAuth=null;
function driveVaultGate(){window.vaultGate();if(!window.vaultIsUnlocked?.())throw Error('Create and unlock the credential vault first (Vault tab).');}
async function driveTransport(){
 if(!driveClient){const {createDriveFiles}=await import('./drive-files.js');driveClient=createDriveFiles({gate:driveVaultGate});}
 return driveClient;
}
function clearDrive(){driveAuth?.abort();driveAuth=null;driveClient?.clear();drivePage='';$('drive-auth').hidden=true;$('drive-files-list').replaceChildren();$('drive-status').textContent='Drive disconnected; temporary access token cleared.';}
async function driveConnect(){
 if(busy)throw Error('An operation is already running.');driveVaultGate();clearDrive();
 const auth=new AbortController();driveAuth=auth;operationBusy(true);
 try{
  const {runLoopbackPkceOAuth,getLoopbackClientId,getLoopbackClientSecret}=await import('./google-loopback-oauth.js');
  const {DRIVE_SCOPE}=await import('./drive-files.js'),clientId=getLoopbackClientId();
  const session=await runLoopbackPkceOAuth({clientId,clientSecret:getLoopbackClientSecret(clientId),scopes:[DRIVE_SCOPE],signal:auth.signal,
   onAuthUrl:url=>{$('drive-auth').href=url;$('drive-auth').hidden=false;}});
  window.vaultGate();if(driveAuth!==auth||auth.signal.aborted)throw Error('Drive sign-in cancelled');
  (await driveTransport()).connect(session);$('drive-auth').hidden=true;
  $('drive-status').textContent='Drive connected with drive.file only. No files uploaded. Select the intended Google account in consent; storage account may differ from signing identity.';
 }finally{operationBusy(false);}
}
async function driveList(more=false){
 const result=await (await driveTransport()).list(more?drivePage:'');
 if(!more)$('drive-files-list').replaceChildren();
 for(const file of result.files||[]){const option=document.createElement('option');option.value=file.id;option.textContent=file.name+' · '+file.modifiedTime;$('drive-files-list').append(option);}
 drivePage=result.nextPageToken||'';$('drive-status').textContent='App-created encrypted files loaded. '+(drivePage?'More files available.':'End of list.');
}
event('drive-connect',driveConnect);event('drive-disconnect',clearDrive);
event('drive-list',()=>driveList());event('drive-more',()=>{if(drivePage)return driveList(true);});
event('drive-upload',async()=>{
 if(busy)throw Error('An operation is already running.');
 const rid=review,snapshot=accountSnapshot;review=null;$('confirm-send').close();
 if(!rid||!isDrive())throw Error('Prepare a new Drive file first.');operationBusy(true);
 try{
  const output=await composeReviews.exportPgp(rid,ownEmail,true);window.vaultGate();assertAccount(snapshot);
  const result=await (await driveTransport()).upload(output.cipher);
  say('Encrypted file uploaded to Drive: '+result.name+'. No email sent.');$('drive-status').textContent='Upload complete: '+result.name;
 }catch(error){throw Error(error.message+' Upload outcome may be uncertain if a request reached Google. Check the Drive list before preparing another upload.');}
 finally{operationBusy(false);}
});
async function driveDownload(open){
 if(busy)throw Error('An operation is already running.');
 const generation=readerGeneration,snapshot=accountSnapshot,file=$('drive-files-list').value;operationBusy(true);
 try{
  const cipher=await (await driveTransport()).download(file);assertReading(generation);assertAccount(snapshot);window.vaultGate();
  if(!open){
   const raw=Uint8Array.from(atob(cipher),c=>c.charCodeAt(0)),url=URL.createObjectURL(new Blob([raw],{type:'application/pgp-encrypted'})),a=document.createElement('a');
   a.href=url;a.download='encrypted-file.pgp';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
   say('Encrypted .pgp downloaded. Its signature has not yet been verified.');return;
  }
  if(!contacts.length)throw Error('Import and trust the expected sender certificate before decrypting.');
  tab('inbox');beginReading();localEncrypted={encrypted:true,cipher,source:'Drive'};
  $('open-title').textContent='Decrypt and verify Drive file';$('open-help').textContent='Select the expected trusted signer. The matching software or YubiKey recipient identity will be selected before decryption. Nothing is saved or trusted automatically.';
  $('decrypt').textContent='Decrypt and verify';$('open').showModal();say('Encrypted Drive file downloaded; choose its trusted signer.');
 }finally{operationBusy(false);}
}
event('drive-open',()=>driveDownload(true));event('drive-save',()=>driveDownload(false));
