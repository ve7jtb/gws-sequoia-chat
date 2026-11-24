// Exercise the actual app's dispatch, verified-certificate action, and reader
// orchestration. Browser/worker/IndexedDB edges are narrow fakes: no external
// message, certificate, account or native hardware is accessed by these tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../app/app.js',import.meta.url),'utf8');
const fp='A'.repeat(64),mail='sender@example.invalid';
const certificate=Buffer.from('synthetic public certificate').toString('base64');
const packet={raw:Buffer.from('synthetic captured message bytes').toString('base64')};
const verified=()=>({signatureStatus:'valid',certificateTrust:'untrusted',encrypted:false,
 certificateActions:[{fingerprint:fp,email:mail,canTrust:true,certificate}],signatures:[{status:'valid',fingerprint:fp}]});
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
function application({software=false}={}){
 const nodes=new Map(),events=new Map(),native=[],storage=[],displays=[],decryptions=[],matches=[];
 const matchedShown=deferred(),softwareCalls=[];
 let revision=1,identityRevision=1,accountChanged=false,unlocked=true,worker=async()=>verified();
 const ownIdentity=()=>({id:'saved-identity',revision:identityRevision,serial:'12345678',
  ...(software?{provider:'software',name:'Local test',vaultId:'vault',identityId:'local'}:{}),
  email:'recipient@example.invalid',fingerprint:'B'.repeat(64),recipientKey:'C'.repeat(64),
  certificateHash:'d'.repeat(64),bundleHash:'e'.repeat(64)});
 const nativeBinding=identity=>{if(software)return {provider:'software',identityId:identity.identityId,vaultId:identity.vaultId,email:identity.email};const {serial,email,fingerprint,certificateHash,bundleHash}=identity;
  return {serial,email,fingerprint,certificateHash,bundleHash};};
 // WASM matching and the own-identity store have independent integration
 // suites. This fake preserves their public snapshot/revision contract while
 // exercising the shipped dialog and pre-PIN orchestration unchanged.
 const selections={
  async match(cipher,account){matches.push({cipher,account});return {choices:[ownIdentity()],recipientKey:'C'.repeat(64)};},
  async assert(identity){if(identity.revision!==identityRevision)throw Error('Own identity changed');},
  nativeBinding,async validateMaterial(){throw Error('The coordinator is mocked in this UI test');}
 };
 function element(){return {hidden:true,value:'',checked:false,textContent:'',files:[],options:[],selectedOptions:[],listeners:new Map(),
  classList:{toggle(){},remove(){}},addEventListener(name,fn){this.listeners.set(name,fn);},
  replaceChildren(){this.options=[];this.value='';},append(item){this.options.push(item);if(this.options.length===1)this.value=item.value;},
  close(){this.open=false;},showModal(){this.open=true;}};}
 const node=id=>{if(!nodes.has(id)){const e=element();if(id==='transport')e.value='mail';
  if(id==='matched-identity')e.showModal=function(){this.open=true;matchedShown.resolve();};nodes.set(id,e);}return nodes.get(id);};
 const inventory={certificates:[],contacts:[]};
 const store={
  async list(){storage.push(['list']);return inventory;},
  async material(){storage.push(['material']);return {certificates:[],bindings:[],saved:[],revision};},
  async preview(raw){storage.push(['preview',raw]);return {fingerprint:fp};},
  async save(raw){storage.push(['save',raw]);return inventory;},
  async trust(...args){storage.push(['trust',...args]);return inventory;},
  async untrust(...args){storage.push(['untrust',...args]);return inventory;},
  async remove(...args){storage.push(['remove',...args]);return inventory;},
  async assertRevision(expected){storage.push(['assertRevision',expected]);if(expected!==revision)throw Error('Certificate store changed');},
  async trustedContact(id){storage.push(['trustedContact',id]);if(id!=='contact')throw Error('Untrusted contact');return {id,email:mail,fingerprint:fp,revision};},
  async assertContact(contact){storage.push(['assertContact',contact.id]);if(contact.revision!==revision)throw Error('Certificate store changed');}
 };
 const context={Promise,Error,AbortController,structuredClone,setTimeout,clearTimeout,Uint8Array,btoa:value=>Buffer.from(value,'binary').toString('base64'),
  document:{getElementById:node,querySelectorAll:()=>[],createElement:element},
  EXTENSION_ID:'synthetic-extension',
  window:{softwareIdentities:software?{native:selected=>{assert.equal(selected.provider,'software');return async(op,data)=>{softwareCalls.push({op,data});return {software:true};};}}:undefined,addEventListener:(name,fn)=>events.set(name,fn),vaultGate(){if(!unlocked)throw Error('Vault locked');},googleTransport:{handles:op=>op==='chat-mail-read',call:async()=>({...packet})}},
  chrome:{runtime:{connect(){
   const listeners=[];
   return {disconnect(){},onMessage:{addListener:fn=>listeners.push(fn)},onDisconnect:{addListener(){}},
    postMessage(request){native.push(request);queueMicrotask(()=>listeners.forEach(fn=>fn({type:'result',data:{ok:true}})));}};
  }}},
  accountSettingsArg:{assert:s=>{if(accountChanged)throw Error('Account settings changed');return s.email;}},storeArg:store,identitySelectionArg:selections,workerArg:(...args)=>worker(...args),displayArg:(result,message)=>{displays.push({result,message});node('reader').hidden=false;},
  // Keep the real app's trust/reader checks around its new WASM coordinator.
  // The coordinator's component/native boundary is tested separately; this
  // narrow fake proves the UI never sends the complete ciphertext to native.
  decryptInIwa:async request=>{decryptions.push(request);await request.gate();const result=await worker({cipher:request.cipher,...request.verification});await request.gate();return result;},
  mailSecuritySummary:()=>'',renderSafeHtml:()=>{},formatMessage:value=>value
 };
 vm.createContext(context);
 // Suppress only automatic startup, which needs a real IndexedDB/worker URL.
 // Functions, native routing, DOM event registration and lock listeners remain
 // exactly those shipped by the app, rather than reimplemented test copies.
 assert.equal(source.split('bootstrap().catch(e=>say(e.message,true));').length,2);
 vm.runInContext(source.replace('bootstrap().catch(e=>say(e.message,true));',''),context);
 vm.runInContext("certificateStore=storeArg;identitySelection=identitySelectionArg;composeReviews={clear(){}};ownEmail='recipient@example.invalid';accountSnapshot={email:ownEmail,revision:'synthetic'};accountSettings=accountSettingsArg;contacts=[{id:'contact',email:'sender@example.invalid'}];runMessageWorker=(...args)=>workerArg(...args);processMessage=(...args)=>workerArg(...args);showOrdinary=(...args)=>displayArg(...args);",context);
 node('signer').value='contact';
 return {context,native,softwareCalls,storage,displays,decryptions,matches,node,matchedShown:matchedShown.promise,
  async chooseMatched(){await matchedShown.promise;await node('matched-identity-continue').listeners.get('click')();},
  reviseIdentity:()=>identityRevision++,reviseAccount:()=>accountChanged=true,
  setWorker:fn=>worker=fn,
  revise:()=>revision++,
  evidence(){context.evidenceArg={message:'message-id',packet:{...packet}};vm.runInContext('readerEvidence=evidenceArg;',context);},
  currentEvidence:()=>vm.runInContext('readerEvidence',context),
  lock(){unlocked=false;events.get('iwa-vault-locked')();},
  invalidate(){context.invalidateCertificateViews();},
  pendingLocal:()=>vm.runInContext('localEncrypted',context),
  pagehide(){events.get('pagehide')();},
  changeService(){node('transport').value='chat';node('transport').listeners.get('change')();}
 };
}

test('all public certificate and trust UI aliases stay in IWA storage',async()=>{
 const a=application();
 for(const [op,data] of [
  ['chat-cert-list',{}],['chat-verification-material',{}],['chat-preview',{certificate}],['chat-cert-save',{certificate}],
  ['chat-trust',{certificate,email:mail,fingerprint:fp,confirmed:true}],
  ['chat-cert-untrust',{email:mail,fingerprint:fp,confirmed:true}],['chat-cert-delete',{fingerprint:fp,confirmed:true}]
 ])await a.context.call(op,data);
 assert.deepEqual(a.storage.map(call=>call[0]),['list','material','preview','save','trust','untrust','remove']);
 assert.equal(a.native.length,0);
 // Message discovery now carries the selected public authority tuple, but
 // does not send MIME or permit the browser to select native executable paths.
 await a.context.nativeRequest('chat-selected-decryption-material',{service:'Gmail',identity:{serial:'12345678'}});
 assert.equal(a.native.length,1);assert.equal(a.native[0].op,'chat-selected-decryption-material');
});

test('attached-certificate save re-verifies captured bytes and never grants trust',async()=>{
 const a=application();a.evidence();let calls=0;
 a.setWorker(async raw=>{calls++;assert.equal(raw.raw,packet.raw);return verified();});
 await a.context.call('chat-mail-cert-save',{message:'message-id',fingerprint:fp});
 assert.equal(calls,1);assert.equal(a.native.length,0);
 assert.deepEqual(a.storage.filter(c=>['save','trust'].includes(c[0])),[['save',certificate]]);
});

test('attached-certificate trust requires a valid signature, exact email and explicit confirmation',async()=>{
 for(const extra of [{confirmed:false},{email:'other@example.invalid'}]){
  const a=application();a.evidence();
  await assert.rejects(a.context.call('chat-mail-cert-trust',{message:'message-id',fingerprint:fp,email:mail,confirmed:true,...extra}),/Review/);
  assert.equal(a.storage.some(c=>c[0]==='trust'),false);
 }
 const a=application();a.evidence();
 await a.context.call('chat-mail-cert-trust',{message:'message-id',fingerprint:fp,email:mail,confirmed:true});
 assert.deepEqual(a.storage.find(c=>c[0]==='trust'),['trust',certificate,mail,fp,true]);assert.equal(a.native.length,0);
});

test('invalid/candidate signatures, wrong fingerprints and missing evidence cannot save a key',async()=>{
 for(const change of [r=>({...r,signatureStatus:'invalid'}),r=>({...r,certificateActions:[{fingerprint:fp,candidateOnly:true}]}),r=>({...r,certificateActions:[{...r.certificateActions[0],fingerprint:'B'.repeat(64)}]})]){
  const a=application();a.evidence();a.setWorker(async()=>change(verified()));
  await assert.rejects(a.context.call('chat-mail-cert-save',{message:'message-id',fingerprint:fp}),/No valid signature/);
  assert.equal(a.storage.some(c=>c[0]==='save'),false);assert.equal(a.native.length,0);
 }
 const a=application();await assert.rejects(a.context.call('chat-mail-cert-save',{message:'message-id',fingerprint:fp}),/Open and verify/);
});

test('ordinary message displays only after current revision and reader generation checks',async()=>{
 const a=application();await a.context.readOrdinary('message-id');
 assert.equal(a.displays.length,1);assert.equal(a.displays[0].message,'message-id');
 assert.ok(a.storage.some(c=>c[0]==='assertRevision'));assert.equal(a.currentEvidence().message,'message-id');
});

test('late ordinary verification cannot revive a reader after lock or trust change',async()=>{
 for(const invalidate of ['lock','revision','view']){
  const a=application(),started=deferred(),pending=deferred();
  a.setWorker(()=>{started.resolve();return pending.promise;});
  const read=a.context.readOrdinary('message-id');await started.promise;
  if(invalidate==='lock')a.lock();else if(invalidate==='revision')a.revise();else a.invalidate();
  pending.resolve(verified());await assert.rejects(read,/changed|locked/);
  assert.equal(a.displays.length,0);assert.equal(a.node('reader').hidden,true);assert.equal(a.currentEvidence(),null);
 }
});

test('late attached-key verification cannot save or re-trust after lock or trust change',async()=>{
 for(const operation of ['chat-mail-cert-save','chat-mail-cert-trust'])for(const invalidate of ['lock','revision','view']){
  const a=application(),started=deferred(),pending=deferred();a.evidence();
  a.setWorker(()=>{started.resolve();return pending.promise;});
  const action=a.context.call(operation,{message:'message-id',fingerprint:fp,email:mail,confirmed:true});await started.promise;
  if(invalidate==='lock')a.lock();else if(invalidate==='revision')a.revise();else a.invalidate();
  pending.resolve(verified());await assert.rejects(action,/changed|locked|again/);
  assert.equal(a.storage.some(c=>['save','trust'].includes(c[0])),false);assert.equal(a.native.length,0);
 }
});

function localFile(){const bytes=new TextEncoder().encode('Synthetic encrypted MIME');return {size:bytes.length,arrayBuffer:async()=>bytes.buffer};}
const localCipher={encrypted:true,cipher:'c3ludGhldGljIGNpcGhlcg=='};
test('local encrypted mail sends full ciphertext only to WASM with current IWA trust, without account transport',async()=>{
 const a=application();let calls=0;
 a.setWorker(async request=>{
  if(calls++===0)return localCipher;
  assert.equal(request.expectedEmail,mail);assert.equal(request.expectedFingerprint,fp);assert.equal(request.recipient,'recipient@example.invalid');
  return {verified:true,subject:'Signed subject',sender:mail,text:'Signed body',html:'',attachments:[],signatures:[{fingerprint:fp}]};
 });
 await a.context.readLocalFile(localFile());assert.equal(a.node('open').open,true);assert.equal(a.native.length,0);
 const opening=a.context.decryptSelected();await a.chooseMatched();await opening;
 assert.equal(a.native.length,0);
 assert.equal(a.decryptions.length,1);assert.equal(a.decryptions[0].cipher,localCipher.cipher);assert.equal(a.decryptions[0].service,'Gmail');
 assert.equal(a.pendingLocal(),null);assert.equal(a.node('reader').hidden,false);
 assert.match(a.node('verified').textContent,/Trusted sender@example.invalid/);
 assert.ok(a.storage.filter(c=>c[0]==='assertContact').length>=3);
 assert.equal(a.storage.some(c=>['save','trust'].includes(c[0])),false);
});

test('pending local ciphertext is discarded by lock, trust change, tab, service and page exit',async()=>{
 for(const invalidate of [a=>a.lock(),a=>a.invalidate(),a=>a.context.tab('contacts'),a=>a.changeService(),a=>a.pagehide(),a=>a.context.clearPendingOpen()]){
  const a=application();a.setWorker(async()=>localCipher);await a.context.readLocalFile(localFile());
  assert.ok(a.pendingLocal());invalidate(a);assert.equal(a.pendingLocal(),null);assert.equal(a.node('open').open,false);
  await assert.rejects(a.context.decryptSelected(),/Open an encrypted message/);assert.equal(a.native.length,0);
 }
});

test('late local file parse cannot re-open a decryption dialog after lock or trust change',async()=>{
 for(const change of ['lock','revision','tab']){
  const a=application(),started=deferred(),pending=deferred();
  a.setWorker(()=>{started.resolve();return pending.promise;});
  const reading=a.context.readLocalFile(localFile());await started.promise;
  if(change==='lock')a.lock();else if(change==='revision')a.revise();else a.context.tab('contacts');
  pending.resolve(localCipher);await assert.rejects(reading,/changed|locked/);
  assert.equal(a.pendingLocal(),null);assert.equal(a.native.length,0);
 }
});

test('late local decryption verification cannot display plaintext after lock or trust removal',async()=>{
 for(const change of ['lock','revision']){
  const a=application(),started=deferred(),pending=deferred();let calls=0;
  a.setWorker(()=>{if(calls++===0)return localCipher;started.resolve();return pending.promise;});
  await a.context.readLocalFile(localFile());const opening=a.context.decryptSelected();await a.chooseMatched();await started.promise;
  if(change==='lock')a.lock();else a.revise();
  pending.resolve({verified:true,subject:'Signed subject',sender:mail,text:'Signed body',html:'',attachments:[],signatures:[{fingerprint:fp}]});
  await assert.rejects(opening,/changed|locked/);assert.equal(a.node('reader').hidden,true);
  assert.equal(a.node('read-body').textContent,'');assert.equal(a.native.length,0);assert.equal(a.decryptions.length,1);
 }
});

test('Escape and a new provider selection cannot reuse a local encrypted envelope',async()=>{
 for(const escape of [false,true]){
  const a=application();let calls=0;const requested=[];
  const remoteCipher='cmVtb3RlIGNpcGhlcg==';
  a.context.window.googleTransport={handles:op=>op==='chat-mail-open',call:async(op,data)=>{requested.push([op,data.message]);return {encrypted:true,cipher:remoteCipher};}};
  a.setWorker(async()=>calls++===0?localCipher:{verified:true,subject:'Remote signed subject',sender:mail,text:'Remote signed body',html:'',attachments:[],signatures:[{fingerprint:fp}]});
  await a.context.readLocalFile(localFile());assert.ok(a.pendingLocal());
  if(escape){a.node('open').listeners.get('cancel')();assert.equal(a.pendingLocal(),null);assert.equal(a.node('open').open,false);}
  // The remote selection must clear old local state even if cancellation was
  // triggered through some other UI path, and restore provider-specific labels.
  a.context.openRemoteMessage('remote-message-id');assert.equal(a.pendingLocal(),null);
  assert.equal(a.node('open-title').textContent,'Decrypt and verify Gmail email');
  const opening=a.context.decryptSelected();await a.chooseMatched();await opening;
  assert.deepEqual(requested,[['chat-mail-open','remote-message-id']]);
  assert.equal(a.native.length,0);assert.equal(a.decryptions.length,1);assert.equal(a.decryptions[0].cipher,remoteCipher);
 }
});

// Matching is public-only; the selection dialog cannot retain authority after
// its inventory changes or the user locks/navigates away. Both failures must
// occur before the coordinator could ask native code for a PIN or card share.
test('matched identity dialog shows the recipient key and requires explicit continuation',async()=>{
 const a=application();let calls=0;
 a.setWorker(async()=>calls++===0?localCipher:{verified:true,subject:'Signed subject',sender:mail,text:'Signed body',html:'',attachments:[],signatures:[{fingerprint:fp}]});
 await a.context.readLocalFile(localFile());const opening=a.context.decryptSelected();await a.matchedShown;
 assert.equal(a.node('matched-identity').open,true);assert.equal(a.decryptions.length,0);
 assert.match(a.node('matched-identity-details').textContent,/YubiKey 12345678/);
 assert.match(a.node('matched-identity-details').textContent,/Recipient subkey: C{64}/);
 assert.equal(a.matches.length,1);assert.equal(a.matches[0].cipher,localCipher.cipher);
 await a.chooseMatched();await opening;
 assert.equal(a.decryptions[0].identity.serial,'12345678');assert.equal(a.decryptions[0].recipientKey,'C'.repeat(64));
 assert.equal(typeof a.decryptions[0].validateMaterial,'function');
});
test('stale matched identity or cancelled view never reaches decryption',async()=>{
 for(const change of ['identity','account','lock','view']){
  const a=application();a.setWorker(async()=>localCipher);await a.context.readLocalFile(localFile());
  const opening=a.context.decryptSelected(),rejected=assert.rejects(opening,/changed|cancelled|locked/);
  await a.matchedShown;
  if(change==='identity'||change==='account'){change==='identity'?a.reviseIdentity():a.reviseAccount();await a.chooseMatched();}
  else if(change==='lock')a.lock();else a.invalidate();
  await rejected;assert.equal(a.decryptions.length,0);assert.equal(a.native.length,0);
  assert.equal(a.node('reader').hidden,true);assert.equal(a.node('matched-identity').open,false);
 }
});

test('software recipient review identifies vault custody and dispatches only to software provider',async()=>{
 const a=application({software:true});let calls=0;
 a.setWorker(async()=>calls++===0?localCipher:{verified:true,subject:'Signed subject',sender:mail,text:'Signed body',html:'',attachments:[],signatures:[{fingerprint:fp}]});
 await a.context.readLocalFile(localFile());const opening=a.context.decryptSelected();await a.matchedShown;
 assert.match(a.node('matched-identity-details').textContent,/Software \(experimental\) · Local test/);
 assert.match(a.node('matched-identity-details').textContent,/no hardware PIN prompt/);
 assert.ok(!a.node('matched-identity-details').textContent.includes('Slots:'));
 await a.chooseMatched();await opening;
 const request=a.decryptions[0];assert.equal(request.identity.provider,'software');
 const response=await request.native('chat-selected-decryption-material',{identity:request.identity,service:'Gmail'});
 assert.equal(response.software,true);assert.equal(a.softwareCalls.length,1);assert.equal(a.native.length,0);
});
test('software provider disappearing after review cannot fall back to native hardware',async()=>{
 const a=application({software:true});a.setWorker(async()=>localCipher);
 await a.context.readLocalFile(localFile());const opening=a.context.decryptSelected(),rejected=assert.rejects(opening,/Software identity provider/);
 await a.matchedShown;a.context.window.softwareIdentities=undefined;await a.chooseMatched();await rejected;
 assert.equal(a.decryptions.length,0);assert.equal(a.softwareCalls.length,0);assert.equal(a.native.length,0);
});
