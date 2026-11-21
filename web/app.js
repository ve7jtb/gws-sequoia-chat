'use strict';
// The launch capability lives only in this page's memory. Remove it from the
// visible URL immediately; no local/session storage, cookies or service worker.
const token = location.hash.slice(1);
history.replaceState(null, '', '/');
const $ = id => document.getElementById(id);
let state = {}, spaces = [], space = null, nextSpace = '', page = '', pages = [], nextPage = '';
let review = null, pending = null, contactFile = null, contactInfo = null, loginTimer = null;
let downloads = [];
function status(text, error = false) { $('status').textContent = text; $('status').classList.toggle('error', error); }
function busy(text) { $('busy-text').textContent = text; $('busy').hidden = false; document.querySelector('main').inert = true; $('clear').disabled = true; }
function idle() { $('busy').hidden = true; document.querySelector('main').inert = false; $('clear').disabled = false; }
async function api(route, data = {}) {
  const response = await fetch('/api/' + route, {method: 'POST', headers: {'Content-Type': 'application/json', Authorization: 'Bearer ' + token}, body: JSON.stringify(data), cache: 'no-store', credentials: 'omit', redirect: 'error'});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'The local operation failed.');
  return result;
}
// All async UI actions share one busy state. Neither exception messages from
// subprocesses nor user-supplied HTML are inserted into the document as markup.
function on(id, event, task, message = 'Working locally…') {
  $(id).addEventListener(event, async e => {
    e.preventDefault(); busy(message);
    try { await task(e); } catch (err) { status(err.message, true); }
    finally { idle(); }
  });
}
function option(select, value, label) { const o = document.createElement('option'); o.value = value; o.textContent = label; select.append(o); }
function options(id, rows, label, old = $(id).value) {
  const el = $(id); el.replaceChildren();
  for (const row of rows) option(el, row.id, label(row));
  if ([...el.options].some(o => o.value === old)) el.value = old;
}
function node(tag, text, cls) { const n = document.createElement(tag); n.textContent = text; if (cls) n.className = cls; return n; }
function tab(id) {
  clearReader();
  for (const panel of document.querySelectorAll('.tab')) panel.hidden = panel.id !== id;
  for (const button of document.querySelectorAll('nav button')) button.setAttribute('aria-selected', String(button.dataset.tab === id));
}
for (const button of document.querySelectorAll('nav button')) button.addEventListener('click', () => tab(button.dataset.tab));
function emails(identityId, selectId) {
  const own = (state.identities || []).find(x => x.id === $(identityId).value);
  options(selectId, (own?.info.emails || []).map(email => ({id:email})), x => x.id);
}
function renderState(data) {
  state = data;
  options('profile', state.profiles.map(id => ({id})), x => x.id, state.profile || $('profile').value);
  for (const id of ['compose-identity', 'open-identity']) options(id, state.identities, x => x.name + ' · ' + x.info.emails.join(', '));
  for (const id of ['compose-contact', 'open-contact']) options(id, state.contacts, x => x.email + ' · ' + x.info.fingerprint.slice(-12));
  emails('compose-identity', 'compose-sender'); emails('open-identity', 'open-recipient');
  $('contact-list').replaceChildren();
  if (!state.contacts.length) $('contact-list').append(node('p','No trusted contacts yet. Review a public certificate above.','hint'));
  for (const contact of state.contacts) {
    const row = node('div', '', 'contact-card');
    row.append(node('strong', contact.email), node('code', contact.info.fingerprint), node('p', contact.info.algorithms.join(' · '), 'hint'));
    const remove = node('button', 'Remove trust', 'secondary'); row.append(remove);
    remove.addEventListener('click', async () => {
      if (!confirm('Remove trust for ' + contact.email + ' and this fingerprint?')) return;
      busy('Removing trust…');
      try { renderState(await api('remove-trust', {contact:contact.id})); status('Trust removed.'); }
      catch (err) { status(err.message,true); } finally { idle(); }
    });
    $('contact-list').append(row);
  }
  $('identity-list').replaceChildren();
  for (const own of state.identities) {
    const card = node('div','','contact-card');
    card.append(node('strong',own.name),node('p',own.info.emails.join(', ')),node('code',own.info.fingerprint),node('p',own.info.algorithms.join(' · '),'hint'));
    $('identity-list').append(card);
  }
  if (!state.identities.length) $('identity-list').append(node('p','No software identities found. Create one using the CLI, then rescan.'));
}
function renderSpaces() {
  const term = $('filter').value.toLowerCase(); $('spaces').replaceChildren();
  for (const item of spaces.filter(x => (x.displayName || x.name).toLowerCase().includes(term))) {
    const b = node('button','','space-row' + (space?.name === item.name ? ' selected' : ''));
    b.append(node('strong',item.displayName || item.name),node('small',item.spaceType || 'Chat'));
    b.addEventListener('click', async () => {
      busy('Loading messages…');
      const previous={space,page,pages};
      try { space=item;page='';pages=[];renderSpaces();await loadMessages(); }
      catch (err) { space=previous.space;page=previous.page;pages=previous.pages;renderSpaces();status(err.message,true); } finally { idle(); }
    }); $('spaces').append(b);
  }
  if (!$('spaces').children.length) $('spaces').append(node('p','No matching conversations.','hint'));
  options('compose-space',spaces.map(x => ({id:x.name, name:x.displayName || x.name})),x => x.name,space?.name);
  $('more-spaces').hidden = !nextSpace;
}
async function loadSpaces(more=false) {
  const result = await api('spaces',{pageToken:more ? nextSpace : ''});
  spaces = more ? [...spaces,...(result.spaces || [])] : (result.spaces || []);
  nextSpace = result.nextPageToken || '';renderSpaces();
}
// Object URLs retain decoded attachments while the reader is open. Revoke
// every one on navigation/clear so old messages do not accumulate behind the
// UI. This releases references, not a guarantee of zeroization in browser RAM.
function clearReader() {
  for (const url of downloads) URL.revokeObjectURL(url); downloads=[];
  for (const id of ['read-subject','verification','read-addresses','read-fingerprint','read-text','read-files']) $(id).replaceChildren();
  $('read-html').srcdoc='';$('read-html').hidden=true;$('reader').hidden=true;
}
async function loadMessages() {
  clearReader();
  const result = await api('messages',{space:space.name,pageToken:page});
  nextPage=result.nextPageToken || '';$('chat-title').textContent=space.displayName || 'Conversation';$('space-name').textContent=space.name;
  $('messages').replaceChildren();$('messages').classList.remove('empty');
  for (const item of result.messages || []) {
    const row=node('div','','contact-card');
    row.append(node('small',(item.createTime ? new Date(item.createTime).toLocaleString() : '') + ' · ' + (item.sender?.displayName || item.sender?.name || 'Chat participant')));
    row.append(node('p',item.text || '(Attachment)'));
    const bundle=(item.attachment || []).some(a=>a.contentName==='message.pgp');
    if (bundle) {
      const b=node('button','Decrypt and verify…','secondary');
      b.addEventListener('click',()=>requestPassword({kind:'open',message:item.name}));row.append(b);
    } else if ((item.attachment || []).length) row.append(node('p','Public certificate or other attachment. No automatic trust is granted.','hint'));
    $('messages').append(row);
  }
  if (!$('messages').children.length) $('messages').append(node('p','No messages on this page.','hint'));
  $('newer').disabled=!pages.length;$('older').disabled=!nextPage;$('compose-here').disabled=false;$('refresh-messages').disabled=false;
  status('Conversation loaded. Encrypted content is opened only on request.');
}
async function connected(result) {
  spaces=result.spaces || [];nextSpace=result.nextPageToken || '';state.profile=$('profile').value;
  $('connection').textContent='Connected · ' + state.profile;$('welcome').hidden=true;$('workspace').hidden=false;
  tab('chats');$('compose-service').value='chat';composeMode();renderSpaces();status('Connected. Select a conversation or compose a new bundle.');
}
on('connect','click',async()=> $('service').value==='mail' ? connectMail() : connected(await api('connect',{profile:$('profile').value})),'Connecting to Google Chat…');
on('login','click',async()=>{
  await api($('service').value==='mail'?'mail-login':'login',{profile:$('profile').value});status('Complete Google sign-in in the browser window.');
  clearInterval(loginTimer);
  loginTimer=setInterval(async()=>{
    try {
      const r=await api('login-status');if(r.running)return;clearInterval(loginTimer);
      status(r.success?'Google sign-in finished. Click Connect / reconnect.':'Google sign-in did not finish. Try signing in again.',!r.success);
    }catch(err){clearInterval(loginTimer);status(err.message,true);}
  },2000);
},'Starting Google sign-in…');
on('chat-connect','click',async()=>connected(await api('connect',{profile:$('profile').value})),'Connecting Google Chat…');
on('refresh-spaces','click',()=>loadSpaces(),'Loading conversations…');
on('more-spaces','click',()=>loadSpaces(true),'Loading more conversations…');
$('filter').addEventListener('input',renderSpaces);
on('refresh-messages','click',()=>loadMessages(),'Refreshing messages…');
on('older','click',async()=>{const old=page;page=nextPage;try{await loadMessages();pages.push(old);$('newer').disabled=false;}catch(e){page=old;throw e;}},'Loading older messages…');
on('newer','click',async()=>{const old=page;page=pages[pages.length-1];try{await loadMessages();pages.pop();$('newer').disabled=!pages.length;}catch(e){page=old;throw e;}},'Loading newer messages…');
$('compose-here').addEventListener('click',()=>{$('compose-service').value='chat';composeMode();$('compose-space').value=space.name;tab('compose');$('subject').focus();});
$('compose-identity').addEventListener('change',()=>emails('compose-identity','compose-sender'));
$('open-identity').addEventListener('change',()=>emails('open-identity','open-recipient'));
function requestPassword(operation) {
  if (!state.identities.length || !state.contacts.length) {status('Add a software identity and a trusted contact first.',true);tab('contacts');return;}
  if(operation.kind.endsWith('open'))clearReader();
  pending=operation;$('password').value='';$('open-choices').hidden=!operation.kind.endsWith('open');
  $('unlock-title').textContent=operation.kind.endsWith('open')?'Decrypt and verify':'Sign and encrypt';
  $('unlock-help').textContent=operation.kind.endsWith('open')?'Choose your identity and the independently trusted sender. Unverified plaintext will not be shown.':'Unlock the selected software identity to prepare this bundle. Nothing is sent yet.';
  $('unlock').showModal();$('password').focus();
}
$('compose-form').addEventListener('submit',e=>{e.preventDefault();requestPassword({kind:$('compose-service').value==='mail'?'mail-prepare':'prepare'});});
function cancelUnlock(){pending=null;$('password').value='';$('unlock').close();}
$('cancel-unlock').addEventListener('click',cancelUnlock);
$('unlock').addEventListener('cancel',cancelUnlock);
async function encodeFile(file) {
  const bytes=new Uint8Array(await file.arrayBuffer());let raw='';
  for(let i=0;i<bytes.length;i+=32768)raw+=String.fromCharCode(...bytes.subarray(i,i+32768));
  return btoa(raw);
}
on('unlock-form','submit',async()=>{
  const operation=pending;pending=null;
  let password=$('password').value;$('password').value='';$('unlock').close();
  try {
    if(operation.kind.endsWith('prepare')){
      const files=[...$('attachments').files];
      if(files.length>20 || files.reduce((n,f)=>n+f.size,0)>10*1024*1024)throw new Error('Use at most 20 files totaling 10 MiB.');
      const attachments=[];for(const f of files)attachments.push({name:f.name,data:await encodeFile(f)});
      review=await api(operation.kind,{identity:$('compose-identity').value,contact:$('compose-contact').value,sender:$('compose-sender').value,space:$('compose-space').value,subject:$('subject').value,text:$('body').value,html:$('html').value,attachments,password});
      $('review-subject').textContent=review.subject;
      $('review-title').textContent=review.service==='mail'?'Send encrypted email?':'Send encrypted Chat bundle?';
      $('confirm-send').textContent=review.service==='mail'?'Send email via Gmail':'Send to Google Chat';
      $('review-notice').textContent=review.service==='mail'?'Your public certificate is inside the encrypted message. Google sees the routing addresses and generic outer subject.':'Your public certificate is visible to conversation participants; the subject and body stay encrypted.';
      $('review-details').textContent='Profile: '+review.profile+(review.service==='mail'?'\nTransport: Gmail PGP/MIME':'\nConversation: '+review.space)+'\nFrom: '+review.sender+'\nTo: '+review.recipient+'\nRecipient fingerprint: '+review.recipient_fingerprint+'\nEncrypted size: '+review.bytes.toLocaleString()+' bytes';
      $('review').showModal();status('Bundle encrypted and signed locally. Review before sending.');
    } else {
      const r=await api(operation.kind,{message:operation.message,identity:$('open-identity').value,recipient:$('open-recipient').value,contact:$('open-contact').value,password});
      displayMessage(r);status('Decryption and signature verification passed. Plaintext is not saved automatically.');
    }
  }finally{password='';}
},'Processing with Sequoia…');
// A review handle authorizes one server-held ciphertext/destination pair.
// Discard it on cancellation; editing browser form fields must not modify an
// already reviewed payload or resurrect an earlier send capability.
async function discardReview(){review=null;await api('discard');}
on('cancel-send','click',async()=>{$('review').close();await discardReview();status('Prepared bundle discarded. Nothing was sent.');});
$('review').addEventListener('cancel',()=>{discardReview().catch(()=>{});});
on('confirm-send','click',async()=>{
  const id=review?.review;const service=review?.service;review=null;$('review').close();
  const result=await api(service==='mail'?'mail-send':'send',{review:id,confirmed:true});$('compose-form').reset();composeMode();emails('compose-identity','compose-sender');
  if(service==='mail'){tab('mail');status('Email sent via Gmail. '+result.sent);}
  else {tab('chats');if(space)await loadMessages();status('Message sent via Google Chat. '+(result.sent || ''));}
},'Sending encrypted content…');
$('close-reader').addEventListener('click',clearReader);
on('preview-contact','click',async()=>{
  const file=$('contact-file').files[0];if(!file || file.size>1024*1024)throw new Error('Choose a public certificate up to 1 MiB.');
  contactFile=await encodeFile(file);contactInfo=await api('preview-contact',{certificate:contactFile});
  $('contact-fingerprint').textContent=contactInfo.fingerprint;$('contact-algorithms').textContent=contactInfo.algorithms.join(' · ');
  options('contact-email',contactInfo.emails.map(id=>({id})),x=>x.id);$('trust-confirm').checked=false;$('contact-review').hidden=false;
  status('Certificate parsed. Verify its full fingerprint before granting trust.');
},'Inspecting public certificate…');
on('trust-contact','click',async()=>{
  if(!$('trust-confirm').checked)throw new Error('Verify the fingerprint independently and check the confirmation first.');
  renderState(await api('trust-contact',{certificate:contactFile,fingerprint:contactInfo.fingerprint,email:$('contact-email').value,confirmed:true}));
  contactFile=null;contactInfo=null;$('contact-review').hidden=true;$('contact-file').value='';status('Certificate saved. Only the selected email and full fingerprint are trusted.');
},'Saving trusted contact…');
on('rescan','click',async()=>{renderState(await api('rescan'));status('Identities and contacts refreshed.');});
on('clear','click',async()=>{
  if(!confirm('Clear displayed messages and any unsent draft? Google credentials and saved contacts will remain.'))return;
  await api('clear');clearMail();clearInterval(loginTimer);review=null;pending=null;contactFile=null;contactInfo=null;clearReader();
  $('compose-form').reset();composeMode();$('password').value='';$('review-subject').textContent='';$('review-details').textContent='';$('contact-review').hidden=true;$('contact-file').value='';spaces=[];space=null;pages=[];page='';nextPage='';
  $('messages').replaceChildren();$('spaces').replaceChildren();$('workspace').hidden=true;$('welcome').hidden=false;$('connection').textContent='Not connected';
  status('Local session cleared. Reconnect when ready.');
});
(async()=>{
  busy('Loading local identities and profiles…');
  try{if(!token)throw new Error('Open this page using the Sequoia Chat launcher. Reloading requires a fresh launch link.');renderState(await api('bootstrap'));status('Ready. Choose a gws account profile to connect.');}
  catch(err){status(err.message,true);}finally{idle();}
})();
