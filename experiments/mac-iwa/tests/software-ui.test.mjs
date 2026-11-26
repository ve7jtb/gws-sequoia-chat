// The real controller runs against a minimal DOM, with delayed file/provider
// promises to model vault-lock and account-change races. No secrets leave the
// synthetic fixture; no file, hardware, Google or IndexedDB API is invoked.
import test from 'node:test';import assert from 'node:assert/strict';
import {initializeSoftwareUi} from '../app/software-ui.js';
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
const cleanupRegistered=new WeakSet();
function fixture(t){
 const previous={document:globalThis.document,window:globalThis.window,confirm:globalThis.confirm};
 const nodes=new Map(),messages=[],imports=[],creates=[],exports=[],changed=[],row={id:'software:a',name:'Synthetic',version:6,profile:'level3',certificate:btoa('public'),fingerprint:'A'.repeat(64),emails:['me@example.invalid']};
 let unlocked=true,busy=false,email='me@example.invalid',records=async()=>[],importer=async()=>row,creator=async()=>row,exporter=async()=>({encryptedSecret:btoa('encrypted output'),version:6,fingerprint:row.fingerprint}),tester=async()=>({id:'synthetic',status:'PASS'});
 const node=()=>({value:'',textContent:'',disabled:false,checked:false,files:[],children:[],append(child){this.children.push(child);},replaceChildren(){this.children=[];},click(){this.onclick?.();},showModal(){this.open=true;},close(){this.open=false;},focus(){},addEventListener(){}});
 const get=id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);};
 const window=new EventTarget();window.vaultIsUnlocked=()=>unlocked;window.vaultGate=()=>{if(!unlocked)throw Error('Vault locked');};
 window.softwareIdentities={records:()=>records(),get:async()=>row,
  import:async(value,account,options)=>{imports.push({value:structuredClone(value),account});return importer(value,account,options);},
  importP12:async(value,account,options)=>{imports.push({p12:true,value:structuredClone(value),account});return importer(value,account,options);},
  create:async(value,account,options)=>{creates.push({value:structuredClone(value),account});return creator(value,account,options);},
  export:async(row,password,options)=>{exports.push({row,password});return exporter(row,password,options);},remove:async()=>{}};
 globalThis.document={getElementById:get,createElement:node};globalThis.window=window;globalThis.confirm=()=>true;
 if(!cleanupRegistered.has(t)){cleanupRegistered.add(t);t.after(()=>{for(const [key,value] of Object.entries(previous))value===undefined?delete globalThis[key]:globalThis[key]=value;});}
 const ui=initializeSoftwareUi({isBusy:()=>busy,setBusy:value=>{busy=value;},say:(message,error)=>messages.push({message,error}),account:()=>email,changed:async()=>changed.push(true),test:(...args)=>tester(...args)});
 get('software-name').value=' Synthetic ';get('software-password').value='fixture password';get('software-custody-confirm').checked=true;
 get('software-create-profile').value='level3';
 get('software-file').value='synthetic.pgp';get('software-file').files=[{name:'synthetic.pgp',size:4,arrayBuffer:async()=>Uint8Array.of(1,2,3,4).buffer}];
 return {ui,get,imports,creates,exports,messages,changed,row,window,busy:()=>busy,
  file:read=>{get('software-file').files[0].arrayBuffer=read;},records:value=>{records=value;},importer:value=>{importer=value;},creator:value=>{creator=value;},exporter:value=>{exporter=value;},tester:value=>{tester=value;},
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

test('create defaults to v6 and requests no file password',async t=>{
 const f=fixture(t);await f.get('software-create').onclick();assert.deepEqual(f.creates,[{value:{name:'Synthetic',profile:'level3',entropy:false},account:'me@example.invalid'}]);assert.equal(f.changed.length,1);assert.equal(f.imports.length,0);
});
test('classical compatibility creation requires its explicit warning confirmation',async t=>{
 const f=fixture(t);let warning;globalThis.confirm=message=>{warning=message;return false;};f.get('software-create-profile').value='level5-v4-classical';await f.get('software-create').onclick();assert.match(warning,/signing.*not post-quantum/);assert.match(warning,/encryption is also classical/);assert.equal(f.creates.length,0);
});
test('a generation result after lock cannot display saved success',async t=>{
 const f=fixture(t),result=deferred();f.creator(()=>result.promise);const pending=f.get('software-create').onclick();f.lock();result.resolve(f.row);await pending;assert.equal(f.changed.length,0);assert(!f.messages.some(x=>x.message.includes('created in the encrypted vault')));
});
test('PKCS12 files are routed to the dedicated authenticated converter',async t=>{
 const f=fixture(t);f.get('software-file').files[0].name='synthetic.p12';await f.run();assert.equal(f.imports[0].p12,true);assert.equal(f.imports[0].value.password,'fixture password');assert('p12'in f.imports[0].value);assert(!('encryptedSecret'in f.imports[0].value));assert.equal(f.get('software-password').value,'');
});
test('encrypted export password is masked, cleared before KDF, and abandoned on account change',async t=>{
 const f=fixture(t),result=deferred();f.records(async()=>[f.row]);f.exporter(()=>result.promise);await f.ui.refresh();await f.button('Export encrypted identity…').onclick();assert.equal(f.get('software-export-dialog').open,true);
 f.get('software-export-password').value='synthetic export password';f.get('software-export-repeat').value='synthetic export password';const pending=f.get('software-export-save').onclick();assert.equal(f.get('software-export-password').value,'');assert.equal(f.get('software-export-repeat').value,'');
 f.account();result.resolve({encryptedSecret:btoa('encrypted'),version:6,fingerprint:f.row.fingerprint});await pending;assert.equal(f.get('software-export-dialog').open,false);assert(!f.messages.some(x=>x.message.includes('identity exported')));
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

// Commit notifications and the initiating form both refresh the inventory. A
// slower earlier read must not resurrect a removed row or duplicate the newest
// cards merely because both requests belong to the same unlocked vault epoch.
test('overlapping inventory reads render only the newest snapshot',async t=>{
 const f=fixture(t),old=deferred(),latest=deferred();let calls=0;f.records(()=>++calls===1?old.promise:latest.promise);
 const first=f.ui.refresh(),second=f.ui.refresh();latest.resolve([{...f.row,name:'Newest'}]);await second;
 assert.equal(f.get('software-identities').children.length,1);assert.match(f.get('software-identities').children[0].children[0].textContent,/Newest/);
 old.resolve([{...f.row,name:'Stale'}, {...f.row,name:'Removed'}]);await first;
 assert.equal(f.get('software-identities').children.length,1);assert.match(f.get('software-identities').children[0].children[0].textContent,/Newest/);
});

// Exercise the actual review button through the read-only hardware boundary.
test('backup-first review reaches read-only card inventory before asking for credentials', async t=>{
 const f=fixture(t);
 t.mock.method(globalThis,'confirm',()=>assert.fail('Inventory failure must stop before confirmation'));
 const previousChannel=globalThis.SequoiaSecureChannel,previousPiv=globalThis.SequoiaSmartCardPiv;
 t.after(()=>{
  if(previousChannel===undefined)delete globalThis.SequoiaSecureChannel;
  else globalThis.SequoiaSecureChannel=previousChannel;
  if(previousPiv===undefined)delete globalThis.SequoiaSmartCardPiv;
  else globalThis.SequoiaSmartCardPiv=previousPiv;
 });
 globalThis.SequoiaSecureChannel={isRequired:()=>true};
 globalThis.SequoiaSmartCardPiv={inspectEmptyPivCandidate:async()=>{throw Error('Synthetic inventory stop');}};
 f.window.SequoiaSmartCardPiv=globalThis.SequoiaSmartCardPiv;
 f.get('combined-level3-mode').value='backup';
 f.get('combined-level3-nist').checked=true;
 await f.get('combined-level3-review').onclick();
 assert.deepEqual(f.messages.at(-1),{message:'Synthetic inventory stop',error:true});
 assert.equal(f.get('piv-management-dialog').open,undefined);
 assert.equal(f.creates.length,0);
});

test('factory management key requires its own action; a blank custom field stays blank',async t=>{
 const {managementPrompt}=await import('../app/piv-backup-ui.js');
 const {FACTORY_MANAGEMENT_KEY}=await import('../app/piv-import.js');
 const previous=globalThis.document,nodes=new Map();
 t.after(()=>{if(previous===undefined)delete globalThis.document;else globalThis.document=previous;});
 globalThis.document={getElementById(id){
  if(!nodes.has(id))nodes.set(id,Object.assign(new EventTarget(),{showModal(){},close(){},focus(){}}));
  return nodes.get(id);
 }};
 const get=globalThis.document.getElementById;
 const factory=get('piv-management-factory'),input=get('piv-management-value');
 let result=managementPrompt(24,{allowFactory:true});
 assert.equal(factory.hidden,false);
 factory.dispatchEvent(new Event('click'));
 assert.equal(await result,FACTORY_MANAGEMENT_KEY);
 assert.equal(input.value,'');
 result=managementPrompt(24,{allowFactory:false});
 assert.equal(factory.hidden,true);
 factory.dispatchEvent(new Event('click'));
 get('piv-management-ok').dispatchEvent(new Event('click'));
 assert.equal(await result,'');
});
