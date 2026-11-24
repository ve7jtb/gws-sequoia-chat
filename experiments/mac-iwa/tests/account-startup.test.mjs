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
const source=fs.readFileSync(new URL('../app/app.js',import.meta.url),'utf8');
function memoryStorage(){const rows=new Map();return {getItem:key=>rows.get(key)??null,setItem:(key,value)=>rows.set(key,value),removeItem:key=>rows.delete(key)};}
function application(savedEmail){
 const storage=memoryStorage(),settings=accountModule.createAccountSettings({storage,newRevision:()=>webcrypto.randomUUID()});
 if(savedEmail)settings.save(savedEmail,null,true);
 const nodes=new Map(),events=new Map(),native=[],network=[],profiles=[];let clears=0,reviewClears=0,certificateReads=0;
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
 const context={Promise,Error,AbortController,structuredClone,Set,setTimeout,clearTimeout,Uint8Array,localStorage:storage,
  document:{getElementById:node,createElement:element,querySelectorAll:()=>[]},EXTENSION_ID:'synthetic-extension',
  window:{addEventListener:(name,fn)=>events.set(name,fn),vaultGate(){},googleTransport:transport,confirm:()=>true},
  chrome:{runtime:{connect(){const listeners=[];return {disconnect(){},onMessage:{addListener:fn=>listeners.push(fn)},onDisconnect:{addListener(){}},postMessage(request){native.push(request);queueMicrotask(()=>listeners.forEach(fn=>fn({type:'result',data:{account:'legacy@example.invalid',serial:'12345678',identity:{fingerprint:'public'}}})));}};}}},
  loadModule:async path=>{if(!modules[path])assert.fail('Unexpected import '+path);return modules[path];}
 };
 vm.createContext(context);
 // Replace only the dynamic-import expression with a dependency seam. All
 // bootstrap, account event handling, routing and invalidation code is real.
 vm.runInContext(source.replaceAll('import(','loadModule(').replace('bootstrap().catch(e=>say(e.message,true));',''),context);
 return {context,settings,storage,node,events,native,network,profiles,clears:()=>clears,reviewClears:()=>reviewClears,certificateReads:()=>certificateReads,
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
});
