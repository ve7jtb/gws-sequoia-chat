// All remote and signed message text is rendered with textContent. No remote
// HTML, scripts, images or links execute; credentials never enter this page.
const $=id=>document.getElementById(id);
let contacts=[],spaces=[],spaceNext='',pages=[''],page=0,next='',review=null,openMessage=null,cert=null,busy=false;
const say=(text,error=false)=>{$('result').textContent=text;$('result').classList.toggle('error',error);};
function call(op,data={}) {
 if(busy)return Promise.reject(Error('An operation is already running.'));
 busy=true;$('busy').hidden=false;document.querySelectorAll('button').forEach(b=>b.disabled=true);
 return new Promise((resolve,reject)=>{
  let port,finished=false;
  function finish(err,value){if(finished)return;finished=true;busy=false;$('busy').hidden=true;document.querySelectorAll('button').forEach(b=>b.disabled=false);$('newer').disabled=page===0;$('older').disabled=!next;if(port)port.disconnect();err?reject(err):resolve(value);}
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
function tab(name){document.querySelectorAll('.tab').forEach(el=>el.hidden=el.id!==name);document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===name));$('compose-destination').textContent='Conversation: '+($('space').selectedOptions[0]?.textContent??'Connect and select a conversation first');}
document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>tab(b.dataset.tab)));
async function bootstrap(){const r=await call('chat-state');contacts=r.contacts;renderContacts();$('account').textContent='Configured sending identity: '+r.account+' · YubiKey '+r.serial;say('Ready. Sign in to that Google account or reconnect its saved session.');tab('inbox');}
async function loadSpaces(token=''){const r=await call('chat-spaces',{page:token});spaces=token?[...spaces,...r.spaces]:r.spaces;spaceNext=r.next;options('space',spaces,s=>s.name,s=>s.title);$('more-spaces').hidden=!spaceNext;say('Chat connected. Select a conversation to read messages.');}
async function messages(token=''){const r=await call('chat-messages',{space:$('space').value,page:token});next=r.next;$('messages').replaceChildren();for(const m of r.messages){const b=document.createElement('button');b.textContent=(m.encrypted?'🔒 Encrypted bundle · ':'')+m.time+'\n'+m.text;b.addEventListener('click',()=>{if(!m.encrypted){say('This is a Google Chat text/certificate message, not an encrypted bundle.');return;}if(!contacts.length){say('Import and trust the sender’s certificate first.',true);tab('contacts');return;}openMessage=m.name;$('open').showModal();});$('messages').append(b);}$('newer').disabled=page===0;$('older').disabled=!next;say('Messages loaded. Encrypted content is decrypted only when opened.');}
event('login',async()=>{const result=await call('chat-login');const url=new URL(result.authorizationUrl);if(url.origin!=='https://accounts.google.com'||!['/o/oauth2/auth','/o/oauth2/v2/auth'].includes(url.pathname))throw Error('Unexpected sign-in address');const link=document.getElementById('google-auth');link.href=url.href;link.hidden=false;say('Click Continue to Google sign-in, complete consent, then choose Connect / reconnect Chat.');});
event('connect',()=>loadSpaces());event('more-spaces',()=>loadSpaces(spaceNext));
event('status',async()=>{const r=await call('status');say(r.connected?'Expected YubiKey '+r.serial+' is connected.':'Connect key '+r.serial+'.');});
event('load',async()=>{pages=[''];page=0;await messages();});
event('older',async()=>{if(!next)return;pages[++page]=next;await messages(next);});event('newer',async()=>{if(page>0)await messages(pages[--page]);});
event('prepare',async()=>{review=null;if(!$('space').value||!$('recipient').value||!$('subject').value||!$('body').value)throw Error('Select a conversation and trusted recipient, then enter a subject and message.');const r=await call('chat-prepare',{space:$('space').value,contact:$('recipient').value,subject:$('subject').value,body:$('body').value});review=r.review;$('send-details').textContent='Subject: '+r.subject+'\nConversation: '+r.space+'\nRecipient: '+r.recipient+'\nFingerprint: '+r.fingerprint;$('confirm-send').showModal();say('Signature verified locally; encrypted bundle ready for review.');});
event('cancel-send',()=>{$('confirm-send').close();review=null;});
event('send',async()=>{const rid=review;review=null;$('confirm-send').close();if(!rid)throw Error('Prepare a new bundle first.');const r=await call('chat-send',{review:rid,confirmed:true});say('Chat message sent: '+r.sent);$('subject').value='';$('body').value='';});
event('cancel-open',()=>{$('open').close();openMessage=null;});event('decrypt',async()=>{const name=openMessage;$('open').close();$('reader').hidden=true;const r=await call('chat-open',{message:name,contact:$('signer').value});if(!r.verified)throw Error('Signature verification failed.');$('read-subject').textContent=r.subject;$('verified').textContent='Decrypted · Valid hybrid signature · Trusted '+r.sender+'\n'+r.fingerprint;$('read-body').textContent=r.text+(r.attachments.length?'\n\nAttachments present (preview does not export them): '+r.attachments.map(a=>a.name+' ('+a.size+' bytes)').join(', '):'');$('reader').hidden=false;say('Decryption and signature verification passed.');});
event('clear-reader',()=>{$('reader').hidden=true;$('read-subject').textContent=$('read-body').textContent=$('verified').textContent='';});
event('preview',async()=>{cert=null;const f=$('certificate').files[0];if(!f||f.size>262144)throw Error('Select a public certificate up to 256 KiB.');let str='';for(const byte of new Uint8Array(await f.arrayBuffer()))str+=String.fromCharCode(byte);const encoded=btoa(str),info=await call('chat-preview',{certificate:encoded});cert={encoded,info};$('cert-info').textContent=info.fingerprint+'\n'+info.algorithms.join(' · ');options('email',info.emails,e=>e,e=>e);$('trust-confirm').checked=false;$('trust-panel').hidden=false;});
event('trust',async()=>{if(!cert||!$('trust-confirm').checked)throw Error('Independently verify and confirm the full fingerprint first.');const r=await call('chat-trust',{certificate:cert.encoded,email:$('email').value,fingerprint:cert.info.fingerprint,confirmed:true});contacts=r.contacts;renderContacts();$('trust-panel').hidden=true;cert=null;say('Certificate saved; trust granted only for the selected email and primary fingerprint.');});
event('test',async()=>{if(!window.confirm('Run the fixed hardware test? Three native PIN dialogs; no key or policy changes.'))return;const r=await call('test');$('test-details').textContent=JSON.stringify(r,null,2);say(r.passed&&r.unchanged?'PASS — signing, decryption and unchanged slot records.':'Test stopped; inspect local results.',!r.passed);});
bootstrap().catch(e=>say(e.message,true));
