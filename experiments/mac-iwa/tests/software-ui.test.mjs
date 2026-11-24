// The real controller runs against a minimal DOM, with delayed file/provider
// promises to model vault-lock and account-change races. No secrets leave the
// synthetic fixture; no file, hardware, Google or IndexedDB API is invoked.
import test from 'node:test';import assert from 'node:assert/strict';
import {initializeSoftwareUi} from '../app/software-ui.js';
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
const cleanupRegistered=new WeakSet();
function fixture(t){
 const previous={document:globalThis.document,window:globalThis.window,confirm:globalThis.confirm};
 const nodes=new Map(),messages=[],imports=[],changed=[],row={id:'software:a',name:'Synthetic',certificate:btoa('public'),fingerprint:'A'.repeat(64),emails:['me@example.invalid']};
 let unlocked=true,busy=false,email='me@example.invalid',records=async()=>[],importer=async()=>row,tester=async()=>({id:'synthetic',status:'PASS'});
 const node=()=>({value:'',textContent:'',disabled:false,checked:false,files:[],children:[],append(child){this.children.push(child);},replaceChildren(){this.children=[];},click(){this.onclick?.();}});
 const get=id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);};
 const window=new EventTarget();window.vaultIsUnlocked=()=>unlocked;window.vaultGate=()=>{if(!unlocked)throw Error('Vault locked');};
 window.softwareIdentities={records:()=>records(),get:async()=>row,import:async(value,account,options)=>{imports.push({value:structuredClone(value),account});return importer(value,account,options);},remove:async()=>{}};
 globalThis.document={getElementById:get,createElement:node};globalThis.window=window;globalThis.confirm=()=>true;
 if(!cleanupRegistered.has(t)){cleanupRegistered.add(t);t.after(()=>{for(const [key,value] of Object.entries(previous))value===undefined?delete globalThis[key]:globalThis[key]=value;});}
 const ui=initializeSoftwareUi({isBusy:()=>busy,setBusy:value=>{busy=value;},say:(message,error)=>messages.push({message,error}),account:()=>email,changed:async()=>changed.push(true),test:(...args)=>tester(...args)});
 get('software-name').value=' Synthetic ';get('software-password').value='fixture password';get('software-custody-confirm').checked=true;
 get('software-file').value='synthetic.pgp';get('software-file').files=[{name:'synthetic.pgp',size:4,arrayBuffer:async()=>Uint8Array.of(1,2,3,4).buffer}];
 return {ui,get,imports,messages,changed,row,window,busy:()=>busy,
  file:read=>{get('software-file').files[0].arrayBuffer=read;},records:value=>{records=value;},importer:value=>{importer=value;},tester:value=>{tester=value;},
  lock(){unlocked=false;window.dispatchEvent(new Event('iwa-vault-locked'));},
  account(){email='other@example.invalid';window.dispatchEvent(new Event('iwa-account-changed'));},
  pagehide(){window.dispatchEvent(new Event('pagehide'));},
  run:()=>get('software-import').onclick(),button:label=>get('software-identities').children.flatMap(x=>x.children).find(x=>x.textContent===label)};
}
test('import clears password immediately before file reading and leaves no form password during KDF',async t=>{
 const f=fixture(t),file=deferred(),kdf=deferred();f.file(()=>file.promise);f.importer(()=>kdf.promise);
 const running=f.run();assert.equal(f.get('software-password').value,'');assert.equal(f.busy(),true);assert.equal(f.imports.length,0);
 file.resolve(Uint8Array.of(1,2,3,4).buffer);await new Promise(r=>setImmediate(r));assert.equal(f.imports.length,1);assert.equal(f.get('software-password').value,'');
 assert.equal(f.imports[0].value.password,'fixture password');assert.equal(f.imports[0].account,'me@example.invalid');
 kdf.resolve(f.row);await running;assert.equal(f.busy(),false);assert.equal(f.get('software-file').value,'');assert.equal(f.changed.length,1);
});
test('lock, changed account and page exit during file reading prevent any import',async t=>{
 for(const event of ['lock','account','pagehide']){const f=fixture(t),file=deferred();f.file(()=>file.promise);const running=f.run();
 f[event]();file.resolve(Uint8Array.of(1,2,3,4).buffer);await running;assert.equal(f.imports.length,0);assert.equal(f.changed.length,0);
 assert.equal(f.get('software-password').value,'');assert.equal(f.get('software-file').value,'');assert.match(f.messages.at(-1).message,/context changed/);}
});
test('file and KDF failures clear credentials and cannot report a successful import',async t=>{
 for(const stage of ['file','kdf']){const f=fixture(t);if(stage==='file')f.file(async()=>{throw Error('Read failed');});else f.importer(async()=>{throw Error('KDF failed');});
 await f.run();assert.equal(f.get('software-password').value,'');assert.equal(f.get('software-file').value,'');assert.equal(f.changed.length,0);
 assert.equal(f.busy(),false);assert.match(f.messages.at(-1).message,/failed/);}
});
test('late inventory after lock or account change cannot restore identity rows',async t=>{
 for(const event of ['lock','account','pagehide']){const f=fixture(t),inventory=deferred();f.records(()=>inventory.promise);const refreshing=f.ui.refresh();f[event]();
 inventory.resolve([f.row]);await refreshing;assert.equal(f.get('software-identities').children.length,0);}
});
test('late software test result after lock or changed account cannot restore PASS or export authority',async t=>{
 for(const event of ['lock','account','pagehide']){const f=fixture(t),result=deferred();f.records(async()=>[f.row]);f.tester(()=>result.promise);await f.ui.refresh();
 const testing=f.button('Test signing and decryption — no email').onclick();await new Promise(r=>setImmediate(r));f[event]();
 result.resolve({id:'synthetic',status:'PASS'});await testing;assert.equal(f.get('software-test-export').disabled,true);assert.ok(!f.get('software-test-result').textContent.startsWith('PASS'));}
});
test('account change and page exit abort an import already inside the KDF and suppress success',async t=>{
 for(const event of ['account','pagehide']){
  const f=fixture(t),started=deferred();
  f.importer((_value,_email,{signal}={})=>new Promise((_resolve,reject)=>{
   started.resolve(signal);
   signal?.addEventListener('abort',()=>reject(Error('Import cancelled')),{once:true});
  }));
  const running=f.run(),signal=await started.promise;
  assert.ok(signal instanceof AbortSignal,'The import must have an operation-scoped AbortSignal');
  f[event]();assert.equal(signal.aborted,true);await running;
  assert.equal(f.changed.length,0);assert.ok(!f.messages.some(x=>x.message.includes('identity saved')));
 }
});
