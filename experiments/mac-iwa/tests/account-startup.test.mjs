// Execute the shipped application controller. Only module loading, DOM,
// public certificate parsing/storage and provider responses are narrow fakes.
// This catches native startup regressions that a source-text assertion cannot.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
import * as accountModule from '../app/account-settings.js';
import {createTransport} from '../app/google-transport.js';
import {createProviderSelection} from '../app/identities/providers.js';
import {signingFailureLabel} from '../app/signing-phases.js';
const source=fs.readFileSync(new URL('../app/app.js',import.meta.url),'utf8');
function memoryStorage(){const rows=new Map();return {getItem:key=>rows.get(key)??null,setItem:(key,value)=>rows.set(key,value),removeItem:key=>rows.delete(key)};}
function application(savedEmail){
 const storage=memoryStorage(),settings=accountModule.createAccountSettings({storage,newRevision:()=>webcrypto.randomUUID()});
 if(savedEmail)settings.save(savedEmail,null,true);
 const nodes=new Map(),events=new Map(),native=[],network=[],profiles=[],dispatched=[];let clears=0,reviewClears=0,certificateReads=0;
 function element(){return {hidden:true,value:'',textContent:'',checked:false,options:[],selectedOptions:[],files:[],listeners:new Map(),
  classList:{toggle(){},remove(){}},addEventListener(name,fn){this.listeners.set(name,fn);},replaceChildren(){this.options=[];this.value='';},
  append(child){this.options.push(child);if(this.options.length===1)this.value=child.value;},close(){this.open=false;},showModal(){this.open=true;}};}
 const node=id=>{if(!nodes.has(id)){const e=element();if(id==='transport')e.value='mail';nodes.set(id,e);}return nodes.get(id);};
 const certificates={list:async()=>{certificateReads++;return {contacts:[],certificates:[]};}};
 const modules={
  './account-settings.js':{...accountModule,createAccountSettings:()=>settings},
  './certificates/store.js':{createCertificateStore:()=>certificates,createIndexedDbStorage:()=>({})},
  './certificates/client.js':{inspectCertificate:()=>assert.fail('No certificate to parse at startup')},
  './compose-review.js':{createComposeReviews:()=>({clear(){reviewClears++;}})},
  './identities/store.js':{createIdentityStore:()=>({})},
  './identities/selection.js':{createIdentitySelection:()=>({list:async()=>({choices:[]})})},
  // Keep the real custody router: startup must not probe either key provider.
  './identities/providers.js':{createProviderSelection},
  './ssh/ui.js':{initializeSsh:()=>({refresh:async()=>{}})},
  './software-ui.js':{initializeSoftwareUi:()=>({refresh:async()=>{}})},
  './identities/client.js':{},
  // initializeIdentities has a separate behavioral no-native-startup test.
  './identities/ui.js':{initializeIdentities:async()=>({refresh:async()=>{}})}
 };
 const session={profile:async expected=>{profiles.push(expected);return {account:expected};},clear:()=>{clears++;},
  request:async(origin,path)=>{network.push({origin,path});
   if(path.includes('format=raw'))return {raw:btoa('synthetic ordinary email')};
   if(path.includes('/gmail/'))return {messages:[]};
   if(path.startsWith('/v1/spaces?'))return {spaces:[{name:'spaces/test',displayName:'Test conversation'}]};
   return {messages:[]};}};
 const transport=createTransport(session);
 const context={Promise,Error,Event,AbortController,structuredClone,Set,setTimeout,clearTimeout,Uint8Array,localStorage:storage,
  document:{getElementById:node,createElement:element,querySelectorAll:()=>[]},EXTENSION_ID:'synthetic-extension',
  window:{addEventListener:(name,fn)=>events.set(name,fn),dispatchEvent:event=>{dispatched.push(event.type);events.get(event.type)?.(event);return true;},vaultGate(){},googleTransport:transport,confirm:()=>true},
  chrome:{runtime:{connect(){const listeners=[];return {disconnect(){},onMessage:{addListener:fn=>listeners.push(fn)},onDisconnect:{addListener(){}},postMessage(request){native.push(request);queueMicrotask(()=>listeners.forEach(fn=>fn({type:'result',data:{account:'legacy@example.invalid',serial:'12345678',identity:{fingerprint:'public'}}})));}};}}},
  loadModule:async path=>{if(!modules[path])assert.fail('Unexpected import '+path);return modules[path];}
 };
 vm.createContext(context);
 // Replace only the dynamic-import expression with a dependency seam. All
 // bootstrap, account event handling, routing and invalidation code is real.
 vm.runInContext(source.replaceAll('import(','loadModule(').replace('bootstrap().catch(e=>say(e.message,true));',''),context);
 return {context,modules,settings,storage,node,events,native,network,profiles,dispatched,clears:()=>clears,reviewClears:()=>reviewClears,certificateReads:()=>certificateReads,
  click:async id=>node(id).listeners.get('click')(),start:()=>context.bootstrap()};
}
test('empty and saved IWA settings both start without native or Google calls',async()=>{
 for(const email of [undefined,'sender@example.invalid']){
  const a=application(email);await a.start();
  assert.equal(a.native.length,0);assert.equal(a.network.length,0);assert.equal(a.certificateReads(),1);
  assert.match(a.node('account').textContent,email?/sender@example.invalid/:/No Google account/);
  await a.context.refreshCertificates();assert.equal(a.native.length,0);
  if(!email){await a.click('login');assert.match(a.node('result').textContent,/Configure/);assert.equal(a.profiles.length,0);}
 }
});
test('ordinary Gmail and Chat operations use browser transport with the IWA account and no helper',async()=>{
 const a=application('sender@example.invalid');await a.start();
 for(const [op,data] of [['chat-mail-connect',{}],['chat-mail-list',{query:'',page:''}],['chat-mail-read',{message:'abc'}],['chat-spaces',{page:''}],['chat-messages',{space:'spaces/test',page:''}]])await a.context.call(op,data);
 assert.equal(a.native.length,0);assert.equal(a.network.length,4);assert.deepEqual(a.profiles,Array(5).fill('sender@example.invalid'));
 // Losing the browser module cannot turn a read into a legacy native request.
 a.context.window.googleTransport=null;await assert.rejects(a.context.call('chat-mail-read',{message:'abc'}),/Browser Google transport/);assert.equal(a.native.length,0);
});
test('manual configuration requires review and confirmation and preserves local inventory',async()=>{
 const a=application();await a.start();a.node('account-email').value='Sender@Example.Invalid';await a.click('account-review');
 assert.equal(a.node('account-review-dialog').open,true);assert.equal(a.settings.read(),null);
 await a.click('account-save');assert.equal(a.settings.read(),null);assert.match(a.node('result').textContent,/confirm/);
 a.node('account-review-confirmed').checked=true;await a.click('account-save');
 assert.equal(a.settings.read().email,'sender@example.invalid');assert.equal(a.native.length,0);assert.equal(a.clears(),1);
 assert.equal(a.certificateReads(),1);assert.ok(a.reviewClears()>0);
 assert.deepEqual(a.dispatched,['iwa-account-changed']);
});
test('legacy account is read only on explicit migration and is not saved until reviewed',async()=>{
 const a=application();await a.start();assert.equal(a.native.length,0);await a.click('account-migrate');
 assert.equal(a.native.length,1);assert.equal(a.native[0].op,'chat-state');assert.equal(a.settings.read(),null);
 assert.match(a.node('account-review-details').textContent,/legacy@example.invalid/);
 a.node('account-review-confirmed').checked=true;await a.click('account-save');
 assert.equal(a.settings.read().email,'legacy@example.invalid');assert.deepEqual(Object.keys(a.settings.read()).sort(),['email','revision','version']);
});
test('changed storage blocks calls before the storage event and then clears account-bound UI work',async()=>{
 const a=application('sender@example.invalid');await a.start();const before=a.settings.read();
 a.settings.save('other@example.invalid',before,true);
 await assert.rejects(a.context.call('chat-mail-connect'),/changed/);assert.equal(a.profiles.length,0);
 a.events.get('storage')({key:accountModule.ACCOUNT_SETTINGS_KEY});await new Promise(resolve=>setImmediate(resolve));
 assert.equal(a.clears(),1);assert.ok(a.reviewClears()>0);assert.equal(a.node('reader').hidden,true);
 assert.match(a.node('account').textContent,/other@example.invalid/);assert.equal(a.native.length,0);
 assert.deepEqual(a.dispatched,['iwa-account-changed']);
});

// Exercise the real Hardware test button, selection and lock/export controls;
// cryptographic orchestration is tested separately with the shipped workers.
test('hardware test UI selects a saved identity and runs only the browser coordinator',async()=>{
 const a=application('sender@example.invalid'),selected={id:'saved',serial:'123456',email:'sender@example.invalid',fingerprint:'A'.repeat(64)};
 a.modules['./identities/selection.js']={createIdentitySelection:()=>({list:async()=>({choices:[selected]}),get:async(id,email)=>{assert.equal(id,selected.id);assert.equal(email,selected.email);return selected;}})};
 let calls=0;
 a.modules['./hardware-test.js']={runHardwareTest:async options=>{
  calls++;await options.gate();assert.equal(options.identity,selected);assert.equal(a.node('test-cancel').disabled,false);assert.equal(a.node('test-export').disabled,true);
  options.onProgress('Synthetic step');assert.equal(a.node('test-progress').textContent,'Synthetic step');
  return {id:'public-test',status:'PASS',unchanged:true,signatureVerified:true,payloadVerified:true};
 }};
 await a.start();assert.equal(a.node('test-identity').value,selected.id);await a.click('test');
 assert.equal(calls,1);assert.equal(a.native.length,0);assert.equal(a.network.length,0);
 assert.match(a.node('test-details').textContent,/All 24 slot records/);assert.equal(a.node('test-export').disabled,false);assert.equal(a.node('test-cancel').disabled,true);
 assert.equal(a.node('test-identity').value,selected.id);assert.equal(a.node('send-identity').value,selected.id);
});
test('locked vault blocks Hardware test before metadata, confirmation or private work',async()=>{
 const a=application('sender@example.invalid');let confirmed=false;
 a.context.window.vaultGate=()=>{throw Error('Unlock the vault first');};a.context.window.confirm=()=>{confirmed=true;return true;};
 await a.start();await a.click('test');assert.match(a.node('result').textContent,/Unlock the vault/);
 assert.equal(confirmed,false);assert.equal(a.native.length,0);assert.equal(a.network.length,0);
});

test('software Compose choices show software custody and never enter the hardware-test chooser',async()=>{
 const a=application('sender@example.invalid'),selected={id:'software:saved',provider:'software',name:'My software key',email:'sender@example.invalid',fingerprint:'A'.repeat(64)};
 a.context.window.softwareIdentities={list:async()=>({choices:[selected],revision:1})};
 await a.start();assert.match(a.node('send-identity').options[0].textContent,/Software \(experimental\) · My software key/);
 assert.ok(!a.node('send-identity').options[0].textContent.includes('YubiKey'));assert.equal(a.node('test-identity').options.length,0);
 assert.match(a.node('send-identity-help').textContent,/no YubiKey signing/);assert.equal(a.native.length,0);
});
test('older identity inventory cannot replace a newer vault-lock refresh',async()=>{
 const a=application('sender@example.invalid');await a.start();let resolveOld,reads=0;
 const selected={id:'software:stale',provider:'software',name:'Old unlocked key',email:'sender@example.invalid',fingerprint:'A'.repeat(64)};
 a.context.selectionArg={list:async()=>{if(++reads===1)return new Promise(r=>{resolveOld=r;});return {choices:[],revision:2};}};
 vm.runInContext('identitySelection=selectionArg;',a.context);
 const older=a.context.refreshSendIdentities();a.events.get('iwa-vault-locked')();await new Promise(r=>setImmediate(r));
 assert.equal(a.node('send-identity').options.length,0);resolveOld({choices:[selected],revision:1});await older;
 assert.equal(a.node('send-identity').options.length,0);assert.equal(a.node('test-identity').options.length,0);assert.equal(a.native.length,0);
});
test('new Compose selection prefers v6 and labels Level5/v4/v5 algorithms without reviving a stored classical default',async()=>{
 const a=application('sender@example.invalid'),make=(id,version,signingAlgorithm)=>({id,version,signingAlgorithm,provider:'software',name:id,email:'sender@example.invalid',fingerprint:'A'.repeat(version===4?40:64),pqSigning:version===6,pqEncryption:true});
 const choices=[make('v4',4,'ECDSA P-521'),make('v5',5,'Ed25519'),make('v6',6,'ML-DSA-87 + Ed448')];
 a.context.window.softwareIdentities={list:async()=>({choices,revision:1})};a.storage.setItem('sequoia-iwa-send-identity','v4');await a.start();
 assert.equal(a.node('send-identity').value,'v6');assert.match(a.node('send-identity').options[0].textContent,/v6 ML-DSA-87 \+ Ed448/);assert.match(a.node('send-identity').options[2].textContent,/v4 ECDSA P-521/);
 // An explicit in-window compatibility selection is kept while the user works.
 a.node('send-identity').value='v4';await a.context.refreshSendIdentities();assert.equal(a.node('send-identity').value,'v4');assert.match(a.node('send-identity-help').textContent,/classical signing/);
 assert.equal(a.native.length,0);assert.equal(a.network.length,0);
});
test('compatibility warning policy never warns merely because a hybrid contains a classical component',async()=>{
 const a=application();assert.equal(a.context.compatibilityWarnings({pqSigning:true},{pqEncryption:true}).length,0);
 assert.equal(a.context.compatibilityWarnings({pqSigning:false},{pqEncryption:true}).length,1);
 assert.equal(a.context.compatibilityWarnings({pqSigning:true},{pqEncryption:false}).length,1);
 assert.equal(a.context.compatibilityWarnings({pqSigning:false},{pqEncryption:false}).length,2);
 const label=a.context.contactLabel({email:'recipient@example.invalid',version:4,pqEncryption:false,fingerprint:'A'.repeat(40)});
 assert.match(label,/v4/);assert.match(label,/classical encryption/);assert.match(label,/AAAAAAAAAAAA/);
});

test('a remembered classical v6 hardware view cannot override a newly available hybrid v6 default',async()=>{
 const a=application('sender@example.invalid'),make=(id,pqSigning)=>({id,version:6,profile:pqSigning?'level5':'level5-v6-classical',pqSigning,pqEncryption:pqSigning,email:'sender@example.invalid',serial:'123',fingerprint:'A'.repeat(64),slots:[],signingAlgorithm:pqSigning?'ML-DSA-87 + Ed448':'ECDSA P-384'});
 const choices=[make('classical',false),make('hybrid',true)];
 a.modules['./identities/selection.js']={createIdentitySelection:()=>({list:async()=>({choices})})};a.storage.setItem('sequoia-iwa-send-identity','classical');
 await a.start();assert.equal(a.node('send-identity').value,'hybrid');
 a.node('send-identity').value='classical';await a.context.refreshSendIdentities();assert.equal(a.node('send-identity').value,'classical');assert.match(a.node('send-identity-help').textContent,/classical signing/);
 assert.equal(a.native.length,0);
});

// All of these views deliberately share an email, serial and primary
// fingerprint. In particular, a stripped classical v4 view retains the primary
// fingerprint of its hybrid sibling; only the full certificate view and its
// encryption capability distinguish the two choices in the real selector.
function hardwareView(id,version,signingAlgorithm,encryptionAlgorithm,pqSigning,pqEncryption,components){
 return {id,version,signingAlgorithm,encryptionAlgorithm,pqSigning,pqEncryption,
  email:'sender@example.invalid',serial:'123456',fingerprint:'A'.repeat(version===4?40:64),components,
  // Legacy inventories hold the union of every profile in the public bundle.
  // Keep unrelated compatibility/S/MIME keys here to detect accidental use of
  // this union for a selected certificate's confirmation or help text.
  slots:[{slot:'9c',role:'signing-pq',algorithm:'ML-DSA-65'},{slot:'84',role:'signing-classical',algorithm:'Ed25519'},
   {slot:'88',role:'signing-classical',algorithm:'Ed25519'},{slot:'83',role:'signing-classical',algorithm:'ECDSA-P384'},
   {slot:'9d',role:'decryption-pq',algorithm:'ML-KEM-768'},{slot:'85',role:'decryption-classical',algorithm:'X25519'},
   {slot:'89',role:'decryption-classical',algorithm:'X25519'},{slot:'82',role:'decryption-classical',algorithm:'ECDH-P384'}]};
}
const pivComponent=(role,slot,algorithm)=>({role,slot,algorithm,storage:'piv'});
const hybridDecryption=[pivComponent('decryption-pq','9d','ML-KEM-768'),pivComponent('decryption-classical','85','X25519')];
const hardwareViews=[
 hardwareView('v6-hybrid',6,'ML-DSA-65 + Ed25519','ML-KEM-768 + X25519',true,true,
  [pivComponent('signing-pq','9c','ML-DSA-65'),pivComponent('signing-classical','84','Ed25519'),...hybridDecryption]),
 hardwareView('v4-hybrid',4,'Ed25519','ML-KEM-768 + X25519',false,true,
  [pivComponent('signing-classical','88','Ed25519'),...hybridDecryption]),
 hardwareView('v4-classical',4,'Ed25519','X25519',false,false,
  [pivComponent('signing-classical','88','Ed25519'),pivComponent('decryption-classical','89','X25519')]),
 hardwareView('v5-hybrid',5,'Ed25519','ML-KEM-768 + X25519 (LibrePGP)',false,true,
  [pivComponent('signing-classical','88','Ed25519'),...hybridDecryption]),
 hardwareView('v6-classical',6,'ECDSA P-384','ECDH P-384',false,false,
  [pivComponent('signing-classical','83','ECDSA-P384'),pivComponent('decryption-classical','82','ECDH-P384')])
];
function hardwareApplication(choices){
 const a=application('sender@example.invalid');
 a.modules['./identities/selection.js']={createIdentitySelection:()=>({list:async()=>({choices}),
  get:async(id,email)=>{assert.equal(email,'sender@example.invalid');const selected=choices.find(row=>row.id===id);assert.ok(selected);return selected;}})};
 a.modules['./hardware-test.js']={runHardwareTest:async options=>{
  // This seam replaces only private cryptography. Selection, confirmation and
  // result rendering execute the shipped controller, without a native request.
  await options.gate();return {id:'public-test',status:'PASS',unchanged:true,signatureVerified:true,payloadVerified:true};
 }};
 return a;
}
test('hardware selectors distinguish v4 hybrid and classical views with the same signing key and fingerprint',async()=>{
 const a=hardwareApplication(hardwareViews.filter(row=>row.version===4));await a.start();
 for(const id of ['send-identity','test-identity']){
  const rows=a.node(id).options;assert.equal(rows.length,2);assert.notEqual(rows[0].textContent,rows[1].textContent);
  for(const row of rows){assert.match(row.textContent,/v4 Ed25519/);assert.match(row.textContent,/YubiKey 123456/);assert.match(row.textContent,/AAAAAAAAAAAA$/);}
  assert.match(rows[0].textContent,/encrypt: ML-KEM-768 \+ X25519/);assert.match(rows[1].textContent,/encrypt: X25519/);
 }
 assert.equal(a.native.length,0);assert.equal(a.network.length,0);
});
for(const selected of hardwareViews)test('hardware confirmation and PASS describe only the selected '+selected.id+' capabilities',async()=>{
 const a=hardwareApplication([selected]);let confirmation='';a.context.window.confirm=text=>{confirmation=text;return true;};
 await a.start();await a.click('test');
 // Read what a person actually sees, including the two distinct operation
 // sections. This fails if either section falls back to the bundle-wide union.
 const sections=/Signing: (.*?)\. Decryption: (.*?)\./.exec(confirmation);assert.ok(sections);
 for(const [purpose,text] of [['signing',sections[1]],['decryption',sections[2]]]){
  const expected=selected.components.filter(row=>row.role.startsWith(purpose)).map(row=>row.slot.toUpperCase());
  assert.deepEqual([...text.matchAll(/\b(9C|84|88|83|9D|85|89|82) \(/g)].map(match=>match[1]),expected);
 }
 const result=a.node('test-details').textContent;
 assert.ok(result.includes('Signature ('+selected.signingAlgorithm+'): verified'));
 assert.ok(result.includes('Decryption ('+selected.encryptionAlgorithm+') and exact text/HTML/attachment: verified'));
 assert.doesNotMatch(result,/Hybrid signature:|Hybrid decryption/);
 for(const text of [confirmation,result]){
  assert.equal(text.includes('uses classical signing'),!selected.pqSigning);
  assert.equal(text.includes('uses classical encryption'),!selected.pqEncryption);
 }
 assert.match(result,/All 24 slot records/);assert.equal(a.native.length,0);assert.equal(a.network.length,0);
});
test('legacy hardware records never advertise aggregate slots as the selected operation mapping',async()=>{
 const selected=structuredClone(hardwareViews[0]);delete selected.components;
 const a=hardwareApplication([selected]);let confirmation='';a.context.window.confirm=text=>{confirmation=text;return true;};
 await a.start();await a.click('test');
 for(const text of [confirmation,a.node('send-identity-help').textContent]){
  assert.match(text,/current signed manifest/);assert.match(text,/restore this bundle again to display exact slots/);
  assert.doesNotMatch(text,/\b(?:9C|84|88|83|9D|85|89|82) \(/);
 }
 assert.match(a.node('test-details').textContent,/^PASS/);assert.equal(a.native.length,0);assert.equal(a.network.length,0);
});
test('hardware test failure display resolves only fixed signing phase labels',async()=>{
 for(const phase of ['native-signature','companion-completion','signature-finalization','recipient-encryption','SECRET native diagnostic']){
  const a=hardwareApplication([hardwareViews[0]]);
  a.modules['./hardware-test.js']={signingFailureLabel,runHardwareTest:async()=>({id:'public-test',status:'STOPPED',unchanged:true,
   signatureVerified:false,payloadVerified:false,failurePhase:phase,message:'SECRET',stderr:'SECRET'})};
  await a.start();await a.click('test');
  assert.ok(a.node('test-details').textContent.includes('Stopped while: '+signingFailureLabel(phase)+'.'));
  assert.ok(!a.node('test-details').textContent.includes('SECRET'));assert.equal(a.native.length,0);assert.equal(a.network.length,0);
 }
});
