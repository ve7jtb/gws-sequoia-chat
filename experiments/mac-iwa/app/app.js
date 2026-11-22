// All remote and signed message text is rendered with textContent. No remote
// HTML, scripts, images or links execute; credentials never enter this page.
const $=id=>document.getElementById(id);
const isMail=()=>$("transport").value==="mail";
const service=()=>isMail()?"Gmail":"Chat";
let ownEmail="";
let certificateReview=null,managementReview=null;
let contacts=[],spaces=[],spaceNext='',pages=[''],page=0,next='',review=null,openMessage=null,cert=null,busy=false;
const say=(text,error=false)=>{$('result').textContent=text;$('result').classList.toggle('error',error);};
function call(op,data={}) {
 if(busy)return Promise.reject(Error('An operation is already running.'));
 busy=true;$('transport').disabled=true;$('busy').hidden=false;document.querySelectorAll('button').forEach(b=>b.disabled=true);
 return new Promise((resolve,reject)=>{
  let port,finished=false;
  function finish(err,value){if(finished)return;finished=true;busy=false;$('transport').disabled=false;$('busy').hidden=true;document.querySelectorAll('button').forEach(b=>b.disabled=false);$('newer').disabled=page===0;$('older').disabled=!next;if(port)port.disconnect();err?reject(err):resolve(value);}
  try {
   port=chrome.runtime.connect(EXTENSION_ID,{name:'sequoia-chat'});
   port.onMessage.addListener(r=>{if(r.type==='progress'){say(r.message);return;}if(r.type==='error')finish(Error(r.message));else finish(null,r.data??r);});
   port.onDisconnect.addListener(()=>{const e=chrome.runtime.lastError;if(!finished)finish(Error(e?'Native bridge unavailable. Check the extension/helper installation.':'Connection closed; check local results before retrying.'));});
   port.postMessage({op,...data});
  }catch(_){finish(Error('Companion extension unavailable.'));}
 });
}
function event(id,fn){$(id).addEventListener('click',()=>Promise.resolve().then(fn).catch(e=>say(e.message,true)));}
function options(id,rows,value,label){const el=$(id),old=el.value;el.replaceChildren();for(const row of rows){const o=document.createElement('option');o.value=value(row);o.textContent=label(row);el.append(o);}if([...el.options].some(o=>o.value===old))el.value=old;}
function renderContacts(){for(const id of ['recipient','signer'])options(id,contacts,c=>c.id,c=>c.email);$('contact-list').replaceChildren();for(const c of contacts){const el=document.createElement('div');el.className='contact';el.textContent=c.email+'\n'+c.fingerprint;$('contact-list').append(el);}}
// Local inventory is independent of Gmail/Chat login and never prompts for PINs.
async function refreshCertificates(){const r=await call('chat-cert-list');contacts=r.contacts;renderContacts();renderSavedCertificates(r.certificates);}
function renderSavedCertificates(rows){
 $('saved-certificates').replaceChildren();
 if(!rows.length)$('saved-certificates').textContent='No saved certificates.';
 for(const c of rows){
  const row=document.createElement('div');row.className='contact';const info=document.createElement('p');
  info.textContent='OpenPGP v'+c.version+' · '+c.algorithms.join(' / ')+'\n'+c.fingerprint+'\nTrusted emails (saved bindings): '+(c.trustedEmails.join(', ')||'None')+'\n'+(c.hybridContact?'Hybrid sending contact':'Verification certificate');row.append(info);
  for(const email of c.trustedEmails){const button=document.createElement('button');button.textContent='Remove trust for '+email+'…';button.addEventListener('click',()=>reviewCertificateChange('chat-cert-untrust',c.fingerprint,email));row.append(button);}
  const del=document.createElement('button');del.textContent='Delete saved certificate…';del.addEventListener('click',()=>reviewCertificateChange('chat-cert-delete',c.fingerprint));row.append(del);$('saved-certificates').append(row);
 }
}
function reviewCertificateChange(op,fingerprint,email){managementReview={op,fingerprint,...(email?{email}:{})};$('manage-cert-title').textContent=op==='chat-cert-delete'?'Delete saved public certificate?':'Remove certificate trust?';$('manage-cert-details').textContent='Full primary fingerprint: '+fingerprint+(email?'\nEmail: '+email:'');$('manage-cert-help').textContent=op==='chat-cert-delete'?'Removes this locally saved public certificate and all its local email trust bindings. You can re-import the public certificate later. No YubiKey keys, identities, mail or sender attachments are deleted.':'Removes trust only for this email and fingerprint. The public certificate remains saved and can still verify signatures, but this binding will no longer be trusted.';$('manage-cert-apply').textContent=op==='chat-cert-delete'?'Delete saved certificate':'Remove trust';$('manage-cert-confirm').showModal();}
event('refresh-certificates',refreshCertificates);
event('manage-cert-cancel',()=>{managementReview=null;$('manage-cert-confirm').close();});
event('manage-cert-apply',async()=>{const r=managementReview;managementReview=null;$('manage-cert-confirm').close();if(!r)throw Error('Review the selected certificate first.');const {op,...fields}=r;const result=await call(op,{...fields,confirmed:true});contacts=result.contacts;renderContacts();renderSavedCertificates(result.certificates);review=null;openMessage=null;$('reader').hidden=true;$('read-certificates').replaceChildren();say(op==='chat-cert-delete'?'Saved public certificate and its local trust removed.':'Trust removed for the selected email; certificate kept.');});
// Service labels are derived together so hidden controls and dialogs cannot
// retain wording from the previously selected transport.
function serviceLabels(){
 const mail=isMail(),name=service();
 $('service-title').textContent='Sequoia '+name+' Lab';
 $('service-lead').textContent=name+' transport. YubiKey signatures. Encrypted and verified by Sequoia.';
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
 $('open-title').textContent='Decrypt and verify '+name+(mail?' email':' bundle');
 $('open-help').textContent=(mail?'Verify against the selected trusted sender certificate.':'The attached certificate must match this trusted contact.')+' Enter the PIN only in the native dialog that follows.';
 $('decrypt').textContent='Decrypt '+name+' with YubiKey';
}
function tab(name){document.querySelectorAll('.tab').forEach(el=>el.hidden=el.id!==name);document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===name));serviceLabels();}
document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>{tab(b.dataset.tab);if(b.dataset.tab==='contacts')refreshCertificates().catch(e=>say(e.message,true));}));
async function bootstrap(){const r=await call('chat-state');ownEmail=r.account;contacts=r.contacts;renderContacts();$('account').textContent='Configured sending identity: '+r.account+' · YubiKey '+r.serial;say('Ready. Sign in to that Google account or reconnect its saved session.');tab('inbox');}
async function loadSpaces(token=''){if(isMail()){const a=await call('chat-mail-connect');say('Gmail connected: '+a.account);pages=[''];page=0;await messages();return;}const r=await call('chat-spaces',{page:token});spaces=token?[...spaces,...r.spaces]:r.spaces;spaceNext=r.next;options('space',spaces,s=>s.name,s=>s.title);$('more-spaces').hidden=!spaceNext;say('Chat connected. Select a conversation to read messages.');}
async function messages(token=''){const r=await call(isMail()?'chat-mail-list':'chat-messages',isMail()?{page:token,query:$('mail-query').value}:{space:$('space').value,page:token});next=r.next;$('messages').replaceChildren();for(const m of r.messages){const b=document.createElement('button');b.textContent=(m.encrypted?'🔒 Encrypted bundle · ':'')+m.time+'\n'+m.text;b.addEventListener('click',()=>{if(isMail()&&!m.encrypted){readOrdinary(m.name).catch(e=>say(e.message,true));return;}if(!m.encrypted){say('This is a Google Chat text/certificate message, not an encrypted bundle.');return;}if(!contacts.length){say('Import and trust the sender’s certificate first.',true);tab('contacts');return;}openMessage=m.name;$('open').showModal();});$('messages').append(b);}$('newer').disabled=page===0;$('older').disabled=!next;say(service()+' messages loaded. Encrypted content is decrypted only when opened.');}
// Ordinary mail never borrows the green trusted-signature result from a
// previously opened encrypted message, and never asks for a YubiKey PIN.
// Certificate actions carry only a message identifier and a full fingerprint.
// The helper re-fetches and verifies the message, never trusting UI assertions.
function renderCertificateActions(message,items){
 $('read-certificates').replaceChildren();
 for(const c of items||[]){
  const row=document.createElement('div');const label=document.createElement('p');
  label.textContent='Signing certificate · '+c.algorithm+'\n'+c.fingerprint+'\n'+(c.saved?'Saved locally':'Not saved')+' · '+(c.trusted?'Trusted for '+c.email:'Not trusted');row.append(label);
  if(!c.saved){const save=document.createElement('button');save.textContent='Save certificate (no trust)';save.addEventListener('click',async()=>{try{await call('chat-mail-cert-save',{message,fingerprint:c.fingerprint});await readOrdinary(message);say('Public certificate saved locally. Saving does not grant trust.');}catch(e){say(e.message,true);}});row.append(save);}
  if(c.canTrust&&!c.trusted){const trust=document.createElement('button');trust.textContent='Mark trusted for '+c.email+'…';trust.addEventListener('click',()=>{certificateReview={message,fingerprint:c.fingerprint,email:c.email};$('mail-cert-details').textContent='Email: '+c.email+'\nFull primary fingerprint: '+c.fingerprint+'\nAlgorithm: '+c.algorithm;$('mail-cert-confirm').showModal();});row.append(trust);}
  if(!c.canTrust){const warning=document.createElement('p');warning.textContent='Trust unavailable: the From email is not a current self-certified mailbox on this certificate.';row.append(warning);}
  $('read-certificates').append(row);
 }
}
event('mail-cert-cancel',()=>{certificateReview=null;$('mail-cert-confirm').close();});
event('mail-cert-trust',async()=>{const selected=certificateReview;certificateReview=null;$('mail-cert-confirm').close();if(!selected)throw Error('Review the certificate first.');await call('chat-mail-cert-trust',{...selected,confirmed:true});await readOrdinary(selected.message);say('Certificate saved and trusted only for '+selected.email+' and its full primary fingerprint.');});
async function readOrdinary(message){
 $('reader').hidden=true;
 const packet=await call('chat-mail-read',{message});
 const material=await call('chat-verification-material');
 const r=await processMessage(packet,material);
 if(r.encrypted){say('This message is encrypted. Reload the inbox to open it with the trusted signer.');return;}

 showOrdinary(r,message);
}
function showOrdinary(r,message){
 $('read-subject').textContent=r.subject;
 $('verified').textContent=mailSecuritySummary(r)+'\n'+(r.signatures||[]).filter(s=>s.fingerprint).map(s=>(s.candidateOnly?'Candidate certificate (sender NOT authenticated): ':'Primary fingerprint: ')+s.fingerprint+' · '+s.algorithm).join('\n')+'\n'+r.notice+' From (outer header): '+r.sender+(r.omittedAttachments?' '+r.omittedAttachments+' attachment(s) omitted by size/count limits.':'');
 $('verified').classList.toggle('error',r.signatureStatus!=='valid'||r.certificateTrust!=='trusted');
 $('read-body').textContent=r.text;
 $('toggle-html').hidden=!r.html;
 renderSafeHtml($('read-html'),r.html||'');
 $('read-html').hidden=!!r.text||!r.html;$('read-body').hidden=!$('read-html').hidden;
 renderFiles(r.attachments);if(message)renderCertificateActions(message,r.certificateActions);else $('read-certificates').replaceChildren();$('reader').hidden=false;
 say('Gmail message opened — not encrypted; signature: '+r.signatureStatus+'; certificate trust: '+r.certificateTrust+'.');
}
event('login',async()=>{const result=await call(isMail()?'chat-mail-login':'chat-login');const url=new URL(result.authorizationUrl);if(url.origin!=='https://accounts.google.com'||!['/o/oauth2/auth','/o/oauth2/v2/auth'].includes(url.pathname))throw Error('Unexpected sign-in address');const link=document.getElementById('google-auth');link.href=url.href;link.hidden=false;say('Click Continue to Google sign-in, complete consent, then choose Connect / reconnect '+service()+'.');});
event('connect',()=>loadSpaces());event('more-spaces',()=>loadSpaces(spaceNext));
event('status',async()=>{const r=await call('status');say(r.connected?'Expected YubiKey '+r.serial+' is connected.':'Connect key '+r.serial+'.');});
event('load',async()=>{pages=[''];page=0;await messages();});
event('older',async()=>{if(!next)return;pages[++page]=next;await messages(next);});event('newer',async()=>{if(page>0)await messages(pages[--page]);});
event('prepare',async()=>{review=null;if((!isMail()&&!$('space').value)||!$('recipient').value||!$('subject').value||!$('body').value)throw Error('Select a conversation and trusted recipient, then enter a subject and message.');const recipient=contacts.find(c=>c.id===$('recipient').value);if(!recipient)throw Error('Choose a trusted recipient.');const mime=await processMessage(null,null,{sender:ownEmail,recipient:recipient.email,subject:$('subject').value,body:$('body').value,html:$('formatted').checked?formatMessage($('body').value):'',attachments:await attachmentData()});const signed=await call(isMail()?'chat-mail-prepare':'chat-prepare',{...(!isMail()?{space:$('space').value}:{}),contact:recipient.id,subject:$('subject').value,mime});const encrypted=await processMessage(null,null,null,{...signed,payload:mime});const r=await call('chat-encryption-complete',{review:signed.review,cipher:encrypted.cipher});review=r.review;$('send-details').textContent='Subject: '+r.subject+'\n'+(isMail()?'Service: ':'Chat conversation: ')+r.space+'\nRecipient: '+r.recipient+'\nFingerprint: '+r.fingerprint;$('confirm-send').showModal();say(service()+' signature verified locally; encrypted message ready for review.');});
event('cancel-send',()=>{$('confirm-send').close();review=null;});
event('send',async()=>{const rid=review;review=null;$('confirm-send').close();if(!rid)throw Error('Prepare a new bundle first.');const r=await call(isMail()?'chat-mail-send':'chat-send',{review:rid,confirmed:true});say((isMail()?'Gmail message sent: ':'Chat message sent: ')+r.sent);$('subject').value='';$('body').value='';$('files').value='';$('file-list').textContent='';});
event('cancel-open',()=>{$('open').close();openMessage=null;});event('decrypt',async()=>{const name=openMessage;$('read-certificates').replaceChildren();$('open').close();$('reader').hidden=true;const selectedService=service(),selectedContact=$('signer').value;const packet=await call(isMail()?'chat-mail-open':'chat-open',{message:name,contact:selectedContact});const material=await call('chat-verification-material');const envelope=packet.cipher?packet:await processMessage(packet,material);if(!envelope.encrypted||!envelope.cipher)throw Error('No supported encrypted envelope.');const clear=await call('chat-decrypt',{contact:selectedContact,payload:envelope.cipher,service:selectedService});const r=await processMessage(clear,material);if(!r.verified)throw Error('Signature verification failed.');$('read-subject').textContent=r.subject;$('verified').classList.remove('error');$('verified').textContent='Encryption: Encrypted (decrypted) · Signature: Valid hybrid · Certificate trust: Trusted '+r.sender+'\n'+r.signatures[0].fingerprint;$('read-body').textContent=r.text;$('toggle-html').hidden=!r.html;renderSafeHtml($('read-html'),r.html||'');$('read-html').hidden=true;$('read-body').hidden=false;renderFiles(r.attachments);$('reader').hidden=false;say(service()+' decryption and signature verification passed.');});
event('clear-reader',()=>{$('read-certificates').replaceChildren();$('reader').hidden=true;$('read-html').replaceChildren();$('read-files').replaceChildren();$('read-subject').textContent=$('read-body').textContent=$('verified').textContent='';});
event('preview',async()=>{cert=null;const f=$('certificate').files[0];if(!f||f.size>262144)throw Error('Select a public certificate up to 256 KiB.');let str='';for(const byte of new Uint8Array(await f.arrayBuffer()))str+=String.fromCharCode(byte);const encoded=btoa(str),info=await call('chat-preview',{certificate:encoded});cert={encoded,info};$('cert-info').textContent=info.fingerprint+'\n'+info.algorithms.join(' · ');options('email',info.emails,e=>e,e=>e);$('trust-confirm').checked=false;$('trust-panel').hidden=false;});
event('trust',async()=>{if(!cert||!$('trust-confirm').checked)throw Error('Independently verify and confirm the full fingerprint first.');const r=await call('chat-trust',{certificate:cert.encoded,email:$('email').value,fingerprint:cert.info.fingerprint,confirmed:true});contacts=r.contacts;renderContacts();$('trust-panel').hidden=true;cert=null;say('Certificate saved; trust granted only for the selected email and primary fingerprint.');});
event('test',async()=>{if(!window.confirm('Run the fixed hardware test? Three native PIN dialogs; no key or policy changes.'))return;const r=await call('test');$('test-details').textContent=JSON.stringify(r,null,2);say(r.passed&&r.unchanged?'PASS — signing, decryption and unchanged slot records.':'Test stopped; inspect local results.',!r.passed);});
bootstrap().catch(e=>say(e.message,true));

// File bytes cross Native Messaging only as bounded data, never as paths.
async function attachmentData(){const files=[...$('files').files];if(files.length>10||files.reduce((n,f)=>n+f.size,0)>131072)throw Error('Maximum 10 attachments and 128 KiB total.');const result=[];for(const f of files){let binary='';for(const b of new Uint8Array(await f.arrayBuffer()))binary+=String.fromCharCode(b);result.push({name:f.name,data:btoa(binary)});}return result;}
$('files').addEventListener('change',()=>{$('file-list').textContent=[...$('files').files].map(f=>f.name+' ('+f.size+' bytes)').join(' · ');});
for(const [id,prefix,suffix] of [['bold','**','**'],['italic','*','*'],['heading','# ',''],['list','- ','']])event(id,()=>{const e=$('body'),a=e.selectionStart,b=e.selectionEnd;e.setRangeText(prefix+e.value.slice(a,b)+suffix,a,b,'select');e.focus();});
event('toggle-html',()=>{const show=$('read-html').hidden;$('read-html').hidden=!show;$('read-body').hidden=show;});
function renderFiles(files){$('read-files').replaceChildren();for(const f of files){const b=document.createElement('button');b.textContent='Save '+f.name+' ('+f.size+' bytes)';b.addEventListener('click',()=>{const bytes=Uint8Array.from(atob(f.data),c=>c.charCodeAt(0)),url=URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'})),a=document.createElement('a');a.href=url;a.download=f.name.replace(/[\\/\x00-\x1f]/g,'_');a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});$('read-files').append(b);}}

$('transport').addEventListener('change',()=>{if(busy)return;review=null;openMessage=null;$('messages').replaceChildren();$('reader').hidden=true;pages=[''];page=0;next='';serviceLabels();$('google-auth').hidden=true;say('Connect '+service()+' or sign in to authorize access.');});

$('local-mail').addEventListener('change',async()=>{try{
 $('reader').hidden=true;const file=$('local-mail').files[0];if(!file)return;if(file.size>262144)throw Error('Local message exceeds 256 KiB.');
 const bytes=new Uint8Array(await file.arrayBuffer());let binary='';for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));
 const material=await call('chat-verification-material');const r=await processMessage({raw:btoa(binary)},material);
 if(r.encrypted)throw Error('Open encrypted mail through the selected account.');showOrdinary(r,null);say('Local copy verified with baseline WASM; no upload, certificate save or trust change.');
}catch(e){say(e.message,true);}finally{$('local-mail').value='';}});
