import test from 'node:test';
import assert from 'node:assert/strict';
import {Vault,random,b64} from '../app/vault/core.js';
import {createSoftwareIdentityStore} from '../app/software/store.js';
import {createSoftwareClient} from '../app/software/client.js';
const account='alice@example.invalid',password='software test password',encryptedSecret=b64(new TextEncoder().encode('disposable encrypted-secret fixture'));
const certificate=b64(new TextEncoder().encode('disposable public certificate fixture'));
const certificateHash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',Uint8Array.from(atob(certificate),x=>x.charCodeAt(0))))].map(x=>x.toString(16).padStart(2,'0')).join('');
const metadata={supported:true,version:6,hybridContact:true,certificate,certificateHash,fingerprint:'A'.repeat(64),signingFingerprint:'B'.repeat(64),recipientKey:'C'.repeat(64),emails:[account,'alias@example.invalid'],algorithms:['ML-DSA-65 + Ed25519','ML-KEM-768 + X25519']};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
async function harness(entropyCollector){
 const engine=new Vault(),secret=random(32),wrapper={id:crypto.randomUUID(),type:'prf',name:'Test passkey',binding:{salt:b64(random(32)),credentialId:b64(random(32))}};
 await engine.create(wrapper,secret);let saved=structuredClone(engine.record),epoch=1,revision=saved.revision,changed=0,writes=0,calls=[],publicInfo=structuredClone(metadata),override;
 const state=()=>({unlocked:engine.unlocked,vaultId:engine.record?.id,revision,epoch,items:engine.data?.items||[]});
 const check=s=>{const now=state();assert(now.unlocked);assert.equal(s.vaultId,now.vaultId);assert.equal(s.revision,now.revision);assert.equal(s.epoch,now.epoch);assert.equal(saved.id,now.vaultId);assert.equal(saved.revision,now.revision);};
 const access={verifyRecovery:async proof=>{if(!proof?.verified)throw Error('Recovery verification required');},snapshot:state,assertCurrent:async s=>check(s),replaceItems:async(items,s,{signal})=>{check(s);if(signal.aborted)throw Error('cancelled');engine.data.items=items;await engine.save();check(s);if(signal.aborted)throw Error('cancelled');saved=structuredClone(engine.record);revision=saved.revision;writes++;}};
 const cryptoCall=async(op,input,options)=>{
  calls.push(op);if(override)return override(op,input,options);
  assert.equal(input.encryptedSecret,encryptedSecret);if(input.password!==password)throw Error('Wrong password');
  if(op==='inspect')return structuredClone(metadata);
  const r=input.request;return op==='sign'?{...r,ed25519:b64(new Uint8Array(64)),mldsa65:b64(new Uint8Array(3309))}:{...r,mlkemSecret:b64(new Uint8Array(32).fill(3)),x25519Secret:b64(new Uint8Array(32).fill(4))};
 };
 const store=createSoftwareIdentityStore({access,inspectPublic:async()=>structuredClone(publicInfo),cryptoCall,entropyCollector,changed:()=>changed++});
 return {engine,store,secret,wrapper,calls,get saved(){return saved;},get writes(){return writes;},get changed(){return changed;},setCrypto:fn=>override=fn,setPublic:v=>publicInfo=v,
  async import(){return store.import({name:'My software key',encryptedSecret,password},account);},
  lock(){store.cancel();epoch++;engine.lock();},async unlock(){await engine.unlock(saved,wrapper.id,secret);},
  externalChange(){saved.revision++;},async mutate(){engine.data.items.push({id:crypto.randomUUID(),name:'other',kind:'secret setting',value:'unrelated'});await engine.save();saved=structuredClone(engine.record);revision=saved.revision;}
 };
}
function signRequest(material){return {review:material.review,requestId:'D'.repeat(64),signingFingerprint:metadata.signingFingerprint,hashAlgorithm:10,digest:b64(new Uint8Array(64).fill(6))};}
async function signing(h,selected){const native=h.store.native(selected),material=await native('chat-selected-signing-material',{identity:h.store.nativeBinding(selected)});return {native,material,request:signRequest(material)};}

test('software import persists only in encrypted vault and survives lock/restart with public-only snapshots',async()=>{
 const h=await harness(),s=await h.import();assert.equal(h.writes,1);assert.equal(s.provider,'software');assert.equal(s.email,account);assert(!('password'in s));assert(!('encryptedSecret'in s));
 const disk=JSON.stringify(h.saved);assert(!disk.includes(password));assert(!disk.includes(encryptedSecret));assert(!disk.includes('My software key'));assert(!disk.includes(metadata.fingerprint));
 h.lock();assert.deepEqual((await h.store.list(account)).choices,[]);assert.deepEqual(await h.store.records(),[]);await assert.rejects(h.store.assert(s));
 await h.unlock();const fresh=(await h.store.list(account)).choices[0];assert.equal(fresh.fingerprint,s.fingerprint);assert.notEqual(fresh.epoch,s.epoch);await assert.rejects(h.store.assert(s));assert(await h.store.assert(fresh));
});
test('wrong password, uncertified account, hash substitution, secret metadata and duplicate import never write',async()=>{
 const h=await harness();for(const [value,email] of [[{name:'key',encryptedSecret,password:'wrong'},account],[{name:'key',encryptedSecret,password},'other@example.invalid']])await assert.rejects(h.store.import(value,email));assert.equal(h.writes,0);
 for(const change of [v=>v.certificateHash='f'.repeat(64),v=>v.password='must not pass',v=>v.supported=false,v=>v.version=4]){const v=structuredClone(metadata);change(v);h.setCrypto(async()=>v);await assert.rejects(h.import());assert.equal(h.writes,0);}
 h.setCrypto(null);await h.import();await assert.rejects(h.import(),/already saved/);assert.equal(h.writes,1);
});
test('software adapter uses one-use reviews and exact public bindings with no hardware route',async()=>{
 const h=await harness(),selected=await h.import(),{native,material,request}=await signing(h,selected);
 await h.store.validateMaterial(material,selected,'signing');const response=await native('chat-sign-digest',request);assert.equal(response.requestId,request.requestId);assert.equal(h.calls.filter(x=>x==='sign').length,1);
 await assert.rejects(native('chat-sign-digest',request),/already used/);await assert.rejects(native('status',{}),/Unsupported/);
 const next=await signing(h,selected);await assert.rejects(next.native('chat-sign-digest',{...next.request,signingFingerprint:'E'.repeat(64)}),/binding mismatch/);await assert.rejects(next.native('chat-sign-digest',next.request),/already used/);
 assert.equal(h.calls.filter(x=>x==='sign').length,1);
});
test('software decryption adapter binds service, recipient and all ephemeral response inputs',async()=>{
 const h=await harness(),selected=await h.import(),native=h.store.native(selected),identity=h.store.nativeBinding(selected);
 const material=await native('chat-selected-decryption-material',{identity,service:'Gmail'});await h.store.validateMaterial(material,selected,'decryption');
 const request={review:material.review,service:'Gmail',requestId:'D'.repeat(64),cipherHash:'d'.repeat(64),recipientKey:selected.recipientKey,mlkemCiphertext:b64(new Uint8Array(1088)),x25519Ephemeral:b64(new Uint8Array(32).fill(1))};
 const result=await native('chat-decapsulate-components',request);assert.equal(result.recipientKey,selected.recipientKey);assert.equal(atob(result.mlkemSecret).length,32);
 await assert.rejects(native('chat-decapsulate-components',request),/already used/);
 const m2=await native('chat-selected-decryption-material',{identity,service:'Chat'});h.setCrypto(async(op,input)=>({...input.request,mlkemSecret:b64(new Uint8Array(32)),x25519Secret:b64(new Uint8Array(32))}));
 await assert.rejects(native('chat-decapsulate-components',{...request,review:m2.review,service:'Chat'}),/Invalid software component/);
});
test('lock during pending import aborts worker and cannot persist a late result',async()=>{
 const h=await harness(),d=deferred();let activeSignal;h.setCrypto(async(op,input,{signal})=>{activeSignal=signal;return d.promise;});
 const pending=h.import();await new Promise(resolve=>setImmediate(resolve));h.lock();assert(activeSignal.aborted);d.resolve(metadata);await assert.rejects(pending);assert.equal(h.writes,0);assert.equal(h.engine.data,null);
});
test('lock during signing rejects late components and invalidates every existing grant',async()=>{
 const h=await harness(),selected=await h.import(),p=await signing(h,selected),d=deferred(),entered=deferred();let activeSignal;
 h.setCrypto(async(op,input,{signal})=>{activeSignal=signal;entered.resolve();return d.promise;});const pending=p.native('chat-sign-digest',p.request);await entered.promise;h.lock();assert(activeSignal.aborted);
 d.resolve({...p.request,ed25519:b64(new Uint8Array(64)),mldsa65:b64(new Uint8Array(3309))});await assert.rejects(pending);await h.unlock();await assert.rejects(p.native('chat-sign-digest',p.request));
});
test('other-window or same-window vault changes invalidate review and prevent private calls',async()=>{
 for(const modify of [h=>h.externalChange(),h=>h.mutate()]){const h=await harness(),selected=await h.import(),p=await signing(h,selected);await modify(h);await assert.rejects(p.native('chat-sign-digest',p.request));assert.equal(h.calls.filter(x=>x==='sign').length,0);}
});
test('removal is explicit and revision bound; expired identities can still be removed',async()=>{
 const h=await harness(),selected=await h.import();h.setPublic({...metadata,supported:false});assert.deepEqual((await h.store.list(account)).choices,[]);const rows=await h.store.records();assert.equal(rows.length,1);
 await h.store.remove(rows[0]);assert.equal(h.writes,2);assert.deepEqual(await h.store.records(),[]);await assert.rejects(h.store.remove(selected));
});
test('selected material cannot substitute account, certificate, provider or subkeys',async()=>{
 const h=await harness(),s=await h.import(),p=await signing(h,s);
 for(const mutate of [m=>m.identity.provider='hardware',m=>m.senderEmail='other@example.invalid',m=>m.senderCertificate=btoa('other'),m=>m.signingFingerprint='E'.repeat(64)]){const value=structuredClone(p.material);mutate(value);await assert.rejects(h.store.validateMaterial(value,s,'signing'));}
 assert.equal((await h.store.list('other@example.invalid')).choices.length,0);
});

class FakeWorker{constructor(){this.terminated=false;}postMessage(value){this.request=value;}terminate(){this.terminated=true;}}
test('one-shot software client terminates on success and accepts only bound fixed-schema result',async()=>{
 let worker;const client=createSoftwareClient({createWorker:()=>worker=new FakeWorker()});const pending=client('inspect',{encryptedSecret,password});const id=worker.request.id;worker.onmessage({data:{id,ok:true,result:metadata}});assert.deepEqual(await pending,metadata);assert(worker.terminated);
 const bad=client('inspect',{encryptedSecret,password});worker.onmessage({data:{id:'other',ok:true,result:metadata}});await assert.rejects(bad,/different operation/);assert(worker.terminated);
});
test('software client cancellation/timeout kills worker; raw worker errors are never reflected',async()=>{
 let worker;const client=createSoftwareClient({createWorker:()=>worker=new FakeWorker(),timeoutMs:5});const c=new AbortController(),pending=client('inspect',{encryptedSecret,password},{signal:c.signal});c.abort();await assert.rejects(pending,/cancelled/);assert(worker.terminated);
 const failed=client('inspect',{encryptedSecret,password});worker.onmessage({data:{id:worker.request.id,ok:false,error:password}});await assert.rejects(failed,e=>!e.message.includes(password));assert(worker.terminated);
 const timed=client('inspect',{encryptedSecret,password});await assert.rejects(timed,/timed out/);assert(worker.terminated);
});
test('vault cannot be revived by an unlock or save promise that resolves after lock',async()=>{
 const h=await harness(),v=h.engine,saved=structuredClone(h.saved);v.lock();const unlock=v.unlock(saved,h.wrapper.id,h.secret);v.lock();await assert.rejects(unlock,/cancelled/);assert(!v.unlocked);assert.equal(v.data,null);
 await v.unlock(saved,h.wrapper.id,h.secret);v.data.items.push({kind:'secret setting',value:'temporary'});const save=v.save();v.lock();await assert.rejects(save,/cancelled/);assert(!v.unlocked);assert.equal(v.record,null);
});

test('guarded vault persistence aborts before put when lock occurs during IndexedDB lookup',async()=>{
 const {persist}=await import('../app/vault/core.js');const h=await harness();let lookup,transaction,closed=false,put=false,guardValid=true;
 const previous=globalThis.indexedDB;
 globalThis.indexedDB={open(){const opening={};queueMicrotask(()=>{opening.result={close(){closed=true;},transaction(){transaction={objectStore:()=>({get(){lookup={};return lookup;},put(){put=true;}}),abort(){queueMicrotask(()=>transaction.onabort?.());}};return transaction;}};opening.onsuccess();});return opening;}};
 try{const controller=new AbortController();const pending=persist(h.saved,h.saved.revision,{signal:controller.signal,guard:()=>{if(!guardValid)throw Error('locked');}});await new Promise(resolve=>setImmediate(resolve));guardValid=false;controller.abort();await assert.rejects(pending,/cancelled/);lookup.result=h.saved;lookup.onsuccess();assert.equal(put,false);assert(closed);}finally{globalThis.indexedDB=previous;}
});

test('creation uses a fresh random password inside the encrypted vault and survives a new unlock',async()=>{
 const h=await harness();let generated;
 h.setCrypto(async(op,input)=>{assert.equal(op,'generate');generated=structuredClone(input);return {encryptedSecret,public:metadata};});
 const selected=await h.store.create({name:'Created locally',profile:'level3'},account);
 assert.equal(generated.email,account);assert.equal(generated.profile,'level3');assert.equal(atob(generated.password).length,32);
 assert(!JSON.stringify(h.saved).includes(generated.password));assert(!JSON.stringify(selected).includes(generated.password));
 h.lock();await h.unlock();assert.equal((await h.store.list(account)).choices[0].fingerprint,metadata.fingerprint);
 assert.equal(h.writes,1);assert.equal(h.calls.filter(x=>x==='generate').length,1);
});
test('locking during creation rejects late generated keys and never commits a vault item',async()=>{
 const h=await harness(),entered=deferred(),result=deferred();let signal;
 h.setCrypto(async(_op,_input,options)=>{signal=options.signal;entered.resolve();return result.promise;});
 const pending=h.store.create({name:'cancelled',profile:'level5'},account);await entered.promise;h.lock();assert(signal.aborted);
 result.resolve({encryptedSecret,public:metadata});await assert.rejects(pending);assert.equal(h.writes,0);
});
test('portable encrypted export changes only the output password and binds the original certificate',async()=>{
 const h=await harness(),selected=await h.import(),before=JSON.stringify(h.saved);let input;
 h.setCrypto(async(op,value)=>{assert.equal(op,'export');input=structuredClone(value);return {encryptedSecret:btoa('new encrypted bytes'),public:metadata};});
 const output=await h.store.export(selected,'new independent export password');
 assert.equal(input.password,password);assert.equal(input.newPassword,'new independent export password');assert.equal(output.fingerprint,selected.fingerprint);
 assert(!('password'in output));assert.equal(JSON.stringify(h.saved),before);assert.equal(h.writes,1);
 await assert.rejects(h.store.export(selected,'short'),/at least 12/);
 h.setCrypto(async()=>({encryptedSecret,public:{...metadata,signingFingerprint:'D'.repeat(64)}}));
 await assert.rejects(h.store.export(selected,'new independent export password'),/changed the certificate/);
});
test('export cannot return ciphertext after a vault lock or identity replacement',async()=>{
 const h=await harness(),selected=await h.import(),entered=deferred(),result=deferred();h.setCrypto(async()=>{entered.resolve();return result.promise;});
 const pending=h.store.export(selected,'new independent export password');await entered.promise;h.lock();result.resolve({encryptedSecret,public:metadata});await assert.rejects(pending);assert.equal(h.writes,1);
});
test('PKCS12 conversion commits only encrypted OpenPGP material and a new vault-held password',async()=>{
 const h=await harness();let source;
 h.setCrypto(async(op,input)=>{assert.equal(op,'import-p12');source=structuredClone(input);return {encryptedSecret,public:metadata};});
 const selected=await h.store.importP12({name:'Imported P12',p12:btoa('encrypted synthetic pfx'),password:'source p12 password'},account);
 assert.equal(source.password,'source p12 password');assert.equal(atob(source.newPassword).length,32);assert.equal(selected.fingerprint,metadata.fingerprint);
 const saved=h.engine.data.items[0];assert.equal(saved.password,source.newPassword);assert(!('p12'in saved));assert.equal(saved.encryptedSecret,encryptedSecret);
 assert(!JSON.stringify(h.saved).includes(source.newPassword));assert(!JSON.stringify(h.saved).includes(source.p12));
});
test('Level5 and v4 software profiles enforce their exact component sizes and warning capabilities',async()=>{
 for(const profile of ['level5','level3-v4-hybrid','level5-v4-classical']){
  const h=await harness(),version=profile.includes('-v4-')?4:6,n=version===4?40:64,pqSigning=version===6,pqEncryption=!profile.endsWith('-classical');
  const info={...metadata,version,profile,pqSigning,pqEncryption,signingAlgorithm:version===6?'ML-DSA-87 + Ed448':profile.startsWith('level5')?'ECDSA':'EdDSA',encryptionAlgorithm:pqEncryption?'ML-KEM hybrid':'ECDH',fingerprint:'A'.repeat(n),signingFingerprint:'B'.repeat(n),recipientKey:'C'.repeat(n)};
  h.setPublic(info);h.setCrypto(async()=>info);const selected=await h.import();assert.equal(selected.version,version);assert.equal(selected.pqSigning,pqSigning);assert.equal(selected.pqEncryption,pqEncryption);
  const native=h.store.native(selected),material=await native('chat-selected-signing-material',{identity:h.store.nativeBinding(selected)});
  const request={review:material.review,requestId:'D'.repeat(64),signingFingerprint:info.signingFingerprint,hashAlgorithm:10,digest:b64(new Uint8Array(64))};
  h.setCrypto(async(_op,input)=>({...input.request,ed25519:b64(new Uint8Array(profile==='level5'?114:profile.startsWith('level5')?132:64)),mldsa65:pqSigning?b64(new Uint8Array(4627)):''}));
  assert.equal((await native('chat-sign-digest',request)).signingFingerprint,info.signingFingerprint);
  const next=await native('chat-selected-signing-material',{identity:h.store.nativeBinding(selected)});
  h.setCrypto(async(_op,input)=>({...input.request,ed25519:b64(new Uint8Array(63)),mldsa65:''}));await assert.rejects(native('chat-sign-digest',{...request,review:next.review}));
 }
});
test('compatibility metadata cannot silently claim post-quantum signing or encryption',async()=>{
 const h=await harness(),base={...metadata,version:4,profile:'level3-v4-classical',fingerprint:'A'.repeat(40),signingFingerprint:'B'.repeat(40),recipientKey:'C'.repeat(40),signingAlgorithm:'EdDSA',encryptionAlgorithm:'ECDH'};
 for(const caps of [{pqSigning:true,pqEncryption:false},{pqSigning:false,pqEncryption:true}]){h.setCrypto(async()=>({...base,...caps}));await assert.rejects(h.import(),/capabilities/);assert.equal(h.writes,0);}
});

test('verified backup keeps public binding and removal survives a vault restart',async()=>{
 const h=await harness(),selected=await h.import();
 const slots=['86','87','9c','84','9d','85'].map(slot=>({slot,publicKeySha256:'e'.repeat(64)}));
 const handle=await h.store.saveHardware(selected,{serial:'12345678'},{publicKeysMatch:true,signingVerified:true,decryptionVerified:true,slots});
 assert.equal(handle.identity.hardware.privateRemoved,false);
 assert(h.engine.data.items[0].encryptedSecret);await h.store.assertHardware(handle);
 // A separate recovery-key check authenticates the file without changing
 // the vault revision or clearing any recoverable software key material.
 const writesBeforeRecovery=h.writes;
 await assert.rejects(h.store.verifyRecoveryBackup(handle.identity,{}),/Recovery verification/);
 await h.store.verifyRecoveryBackup(handle.identity,{verified:true});
 assert.equal(h.writes,writesBeforeRecovery);
 assert.equal(h.engine.data.items[0].encryptedSecret,encryptedSecret);
 await assert.rejects(h.store.removePrivate(handle.identity,handle),/Recovery verification/);
 assert.equal(h.engine.data.items[0].encryptedSecret,encryptedSecret);
 await h.store.removePrivate(handle.identity,handle,{verified:true});
 assert.equal(h.engine.data.items[0].encryptedSecret,'');assert.equal(h.engine.data.items[0].password,'');
 assert.equal(h.engine.data.items[0].public.certificate,certificate);assert.equal(h.engine.data.items[0].hardware.serial,'12345678');
 h.lock();await h.unlock();const restored=await h.store.get(selected.id,account);
 assert.equal(restored.hardware.privateRemoved,true);assert.equal(restored.certificate,certificate);
 await assert.rejects(h.store.export(restored,'another test password'),/YubiKey only/);
});
test('failed hardware proof cannot persist a backup or authorize removal',async()=>{
 const h=await harness(),selected=await h.import();
 await assert.rejects(h.store.saveHardware(selected,{serial:'12345678'},{publicKeysMatch:true,signingVerified:false,decryptionVerified:true}),/proof/);
 assert.equal(h.engine.data.items[0].encryptedSecret,encryptedSecret);
 await assert.rejects(h.store.removePrivate(selected,{identity:selected}));
});

test('single-touch material reaches only generation and is cleared without entering vault records',async()=>{
 const entropy=new Uint8Array(32).fill(73);let inputRef;
 const h=await harness(async({guard})=>{await guard();return entropy;});
 h.setCrypto(async(op,input)=>{assert.equal(op,'generate');assert.equal(atob(input.hardwareEntropy).length,32);inputRef=input;return {encryptedSecret,public:metadata};});
 await h.store.create({name:'Mixed entropy',profile:'level3',entropy:true},account);
 assert(entropy.every(v=>v===0));assert.equal(inputRef.hardwareEntropy,'');
 assert(!JSON.stringify(h.engine.data).includes('hardwareEntropy'));assert.equal(h.writes,1);
});
test('backup-first entropy is pinned to the reviewed card and is not forwarded to the key generator',async()=>{
 const h=await harness(async({serial,guard})=>{
  assert.equal(serial,'12345678');await guard();return new Uint8Array(32).fill(42);
 });
 const request={name:'Bound entropy',profile:'level3',entropy:true};
 h.setCrypto(async(op,input)=>{
  assert.equal(op,'generate');assert.equal(Object.hasOwn(input,'serial'),false);
  assert.equal(Object.hasOwn(input,'entropySerial'),false);
  return {encryptedSecret,public:metadata};
 });
 await assert.rejects(h.store.create(request,account,{entropySerial:'other'}),/Invalid provisioning entropy serial/);
 await h.store.create(request,account,{entropySerial:'12345678'});
 assert.equal(h.writes,1);
});
test('locking during entropy collection prevents generation and clears returned contribution',async()=>{
 const entropy=new Uint8Array(32).fill(41);let h;
 h=await harness(async()=>{h.lock();return entropy;});
 await assert.rejects(h.store.create({name:'Cancelled entropy',profile:'level3',entropy:true},account));
 assert(entropy.every(v=>v===0));assert.equal(h.writes,0);assert.equal(h.calls.length,0);
});

test('optional Level 3 S/MIME secrets are persisted with OpenPGP inside the encrypted vault',async()=>{
 const h=await harness();
 h.setCrypto(async()=>({encryptedSecret,public:metadata}));
 const selected=await h.store.create({name:'Level 3 combined',profile:'level3',includeSmime:true},account);
 assert.equal(selected.smimeKeys,undefined);
 const before=h.engine.data.items[0].smimeKeys;
 assert.equal(before.signing.slot,'83');
 assert.equal(before.agreement.slot,'82');
 assert(!JSON.stringify(h.saved).includes(before.signing.privateKey));
 assert(!JSON.stringify(h.saved).includes(before.agreement.privateKey));
 h.lock();
 await h.unlock();
 assert.deepEqual(h.engine.data.items[0].smimeKeys,before);
});

// The real vault encrypts the auxiliary seeds, while public snapshots expose
// only capability flags. PRF is mandatory even if the UI is bypassed.
test('SSH creation requires PRF and encrypted restart preserves both distinct seeds',async()=>{
 const contribution=new Uint8Array(32).fill(91),h=await harness(async()=>contribution);
 const sshKeys={version:1,entropy:'prf-mixed-v1',pq:{slot:'8c',algorithm:'ML-DSA-44',seed:b64(new Uint8Array(32).fill(11)),publicKey:b64(new Uint8Array(1312).fill(12))},ed:{slot:'8d',algorithm:'Ed25519',seed:b64(new Uint8Array(32).fill(21)),publicKey:b64(new Uint8Array(32).fill(22))}};
 const expected=structuredClone(sshKeys);
 await assert.rejects(h.store.create({name:'SSH',profile:'level3',includeSsh:true},account),/PRF/);
 h.setCrypto(async(op,input)=>{assert.equal(op,'generate');assert.equal(input.includeSsh,true);assert.equal(atob(input.hardwareEntropy).length,32);return {encryptedSecret,public:metadata,sshKeys};});
 const selected=await h.store.create({name:'SSH',profile:'level3',includeSsh:true,entropy:true},account);
 assert(selected.hasSsh);assert(!('sshKeys'in selected));assert(contribution.every(x=>x===0));
 assert.equal(sshKeys.pq.seed,'');assert.equal(sshKeys.ed.seed,'');
 assert(!JSON.stringify(h.saved).includes(expected.pq.seed));
 h.lock();await h.unlock();
 assert.deepEqual(h.engine.data.items[0].sshKeys,expected);
});
