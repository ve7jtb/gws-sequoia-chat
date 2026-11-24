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
async function harness(){
 const engine=new Vault(),secret=random(32),wrapper={id:crypto.randomUUID(),type:'prf',name:'Test passkey',binding:{salt:b64(random(32)),credentialId:b64(random(32))}};
 await engine.create(wrapper,secret);let saved=structuredClone(engine.record),epoch=1,revision=saved.revision,changed=0,writes=0,calls=[],publicInfo=structuredClone(metadata),override;
 const state=()=>({unlocked:engine.unlocked,vaultId:engine.record?.id,revision,epoch,items:engine.data?.items||[]});
 const check=s=>{const now=state();assert(now.unlocked);assert.equal(s.vaultId,now.vaultId);assert.equal(s.revision,now.revision);assert.equal(s.epoch,now.epoch);assert.equal(saved.id,now.vaultId);assert.equal(saved.revision,now.revision);};
 const access={snapshot:state,assertCurrent:async s=>check(s),replaceItems:async(items,s,{signal})=>{check(s);if(signal.aborted)throw Error('cancelled');engine.data.items=items;await engine.save();check(s);if(signal.aborted)throw Error('cancelled');saved=structuredClone(engine.record);revision=saved.revision;writes++;}};
 const cryptoCall=async(op,input,options)=>{
  calls.push(op);if(override)return override(op,input,options);
  assert.equal(input.encryptedSecret,encryptedSecret);if(input.password!==password)throw Error('Wrong password');
  if(op==='inspect')return structuredClone(metadata);
  const r=input.request;return op==='sign'?{...r,ed25519:b64(new Uint8Array(64)),mldsa65:b64(new Uint8Array(3309))}:{...r,mlkemSecret:b64(new Uint8Array(32).fill(3)),x25519Secret:b64(new Uint8Array(32).fill(4))};
 };
 const store=createSoftwareIdentityStore({access,inspectPublic:async()=>structuredClone(publicInfo),cryptoCall,changed:()=>changed++});
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
