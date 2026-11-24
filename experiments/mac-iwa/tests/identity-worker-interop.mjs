// Verify the browser client and actual WASM worker together with a disposable
// Sequoia fixture. It contains no user key or credential and never calls native.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {Worker as Thread} from 'node:worker_threads';
import {createHash} from 'node:crypto';
import {inspectIdentity,matchRecipients,inspectBundle} from '../app/identities/client.js';
import {createIdentitySelection} from '../app/identities/selection.js';
import {parseCardBundle} from '../app/identities/bundle.js';
import {createIdentityStore} from '../app/identities/store.js';
import {createMemoryStorage} from '../app/certificates/store.js';

const path=process.env.IWA_SPLIT_DECAP_FIXTURE;
assert(path,'Set IWA_SPLIT_DECAP_FIXTURE to the disposable Sequoia software fixture');
const fixture=JSON.parse(fs.readFileSync(path));
class BrowserWorker{
 constructor(url,options){
  assert.equal(url,'/identities/worker.js');assert.deepEqual(options,{type:'module'});
  this.thread=new Thread(new URL('./identity-worker-node.mjs',import.meta.url),{type:'module'});
  this.thread.on('message',data=>this.onmessage?.({data}));this.thread.on('error',error=>this.onerror?.(error));
 }
 postMessage(data){this.thread.postMessage(data);}
 terminate(){return this.thread.terminate();}
}
globalThis.Worker=BrowserWorker;

test('shipped identity inspector binds canonical public certificate and operational subkeys',async()=>{
 const info=await inspectIdentity(fixture.certificate);
 assert.equal(info.supported,true);assert.equal(info.version,6);
 assert.equal(info.recipientKey,fixture.request.recipientKey);
 assert.match(info.signingFingerprint,/^[A-F0-9]{64}$/);
 assert.equal(info.certificateHash,createHash('sha256').update(Buffer.from(info.certificate,'base64')).digest('hex'));
 assert.deepEqual(info.emails,['fixture@example.invalid']);
 await assert.rejects(inspectIdentity(Buffer.from('not a public certificate').toString('base64')),/rejected/);
});

test('shipped matcher chooses only an exact recipient and preserves ambiguity for UI choice',async()=>{
 const request={cipher:fixture.request.cipher,candidates:[
  {id:'different-card',certificate:fixture.vault.request.recipientCertificate},
  {id:'selected-card',certificate:fixture.certificate}]};
 const result=await matchRecipients(request);
 assert.equal(result.cipherHash,fixture.reply.cipherHash);assert.equal(result.recipientKey,fixture.request.recipientKey);
 assert.deepEqual(result.matches.map(x=>x.id),['selected-card']);
 const info=await inspectIdentity(fixture.certificate);
 assert.equal(result.matches[0].fingerprint,info.fingerprint);assert.equal(result.matches[0].certificateHash,info.certificateHash);
 assert.equal(result.matches[0].signingFingerprint,info.signingFingerprint);
 const ambiguous=await matchRecipients({...request,candidates:[{id:'first',certificate:fixture.certificate},{id:'second',certificate:fixture.certificate}]});
 assert.deepEqual(ambiguous.matches.map(x=>x.id),['first','second']);
 assert.deepEqual((await matchRecipients({...request,candidates:[]})).matches,[]);
});

test('matching rejects malformed packets, duplicate candidates and extra authority fields',async()=>{
 const good={cipher:fixture.request.cipher,candidates:[{id:'one',certificate:fixture.certificate}]};
 for(const value of [{...good,cipher:Buffer.from('plaintext').toString('base64')},
  {...good,cipher:good.cipher+'AAAA'},
  {...good,candidates:[good.candidates[0],good.candidates[0]]},
  {...good,candidates:[{...good.candidates[0],slot:'9d'}]}])await assert.rejects(matchRecipients(value),/rejected/);
});

test('an aborted public review cannot return a late recipient selection',async()=>{
 const controller=new AbortController();controller.abort();
 await assert.rejects(matchRecipients({cipher:fixture.request.cipher,candidates:[]},{signal:controller.signal}),/cancelled/);
 const pending=new AbortController(),operation=inspectIdentity(fixture.certificate,{signal:pending.signal});
 pending.abort();await assert.rejects(operation,/cancelled/);
});

test('actual WASM outputs satisfy saved-identity matching and selected native material bindings',async()=>{
 // Use the same inspector and matcher as the shipped IWA. Only the public
 // inventory and native response are synthetic: this catches API field/case/
 // canonical-hash drift that isolated tests with mocked inspectors cannot.
 const inspected=await inspectIdentity(fixture.certificate),email=inspected.emails[0];
 const inventory={revision:1,identities:[{
  id:'test-yubikey:123',serial:'123',bundleSignatureVerified:true,liveKeysMatched:true,
  bundleHash:'c'.repeat(64),slots:[],certificates:[inspected]
 }]};
 const selection=createIdentitySelection({store:{list:async()=>structuredClone(inventory)},
  inspect:inspectIdentity,match:matchRecipients});
 const candidates=await selection.list(email);assert.equal(candidates.choices.length,1);
 assert.deepEqual((await selection.list('other@example.invalid')).choices,[]);
 const matched=await selection.match(fixture.request.cipher,email);
 assert.equal(matched.cipherHash,fixture.reply.cipherHash);
 assert.equal(matched.recipientKey,fixture.request.recipientKey);
 assert.equal(matched.choices[0].id,candidates.choices[0].id);
 const chosen=matched.choices[0],binding=selection.nativeBinding(chosen);
 assert.deepEqual(Object.keys(binding).sort(),['bundleHash','certificateHash','email','fingerprint','serial']);
 const material={identity:binding,recipientCertificate:fixture.certificate,
  recipientKey:fixture.request.recipientKey};
 assert.equal(await selection.validateMaterial(material,chosen,'decryption'),material);
 const substituted={...material,recipientCertificate:fixture.vault.request.recipientCertificate};
 await assert.rejects(selection.validateMaterial(substituted,chosen,'decryption'),/differs/);
 // A saved-identity edit invalidates the reviewed match before it could be
 // used to obtain/redeem a native private-operation grant.
 inventory.revision++;
 await assert.rejects(selection.validateMaterial(material,chosen,'decryption'),/changed/);
});

test('actual bundle worker authenticates public bytes and binds every live key before selection',async()=>{
 const publicFixture=JSON.parse(fs.readFileSync(new URL('../crypto/tests/data/restore-level3.json',import.meta.url)));
 const offline=await inspectBundle(publicFixture.hybrid);
 assert.equal(offline.bundleSignatureVerified,true);assert.equal(offline.liveKeysMatched,false);
 assert.equal(offline.slots.length,10);assert.equal(offline.certificates.length,3);
 const snapshot={format:'sequoia-iwa-public-snapshot',version:1,serial:offline.serial,generation:1,bundle:publicFixture.hybrid,warnings:[],
  slots:['9a','9c','9d','9e',...Array.from({length:20},(_,i)=>(0x82+i).toString(16))].map(slot=>({slot,publicKeySha256:publicFixture.keys[slot]?createHash('sha256').update(Buffer.from(publicFixture.keys[slot],'base64')).digest('hex'):null}))};
 const live=await parseCardBundle(snapshot,inspectBundle);
 assert.equal(live.liveKeysMatched,true);assert.equal(live.source,'yubikey');
 assert.equal(live.bundleHash,createHash('sha256').update(Buffer.from(publicFixture.hybrid,'base64')).digest('hex'));
 const changed=structuredClone(snapshot);changed.slots.find(s=>s.slot==='87').publicKeySha256='0'.repeat(64);
 await assert.rejects(parseCardBundle(changed,inspectBundle),/does not match/);
 // Certificate policy parsing follows bundle authentication in the real UI.
 // Reuse the actual certificate WASM API below rather than a native parser.
 const {inspect_public}=await import('../app/wasm/sequoia_iwa_verify.js');
 const inspect=async encoded=>JSON.parse(inspect_public(JSON.stringify({certificate:encoded})));
 // The normal inspector uses its own worker; that worker is tested separately.
 // Here initialize the same module explicitly for a complete public-store check.
 const wasm=await import('../app/wasm/sequoia_iwa_verify.js');
 await wasm.default({module_or_path:fs.readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});
 const store=createIdentityStore({inspect,storage:createMemoryStorage()});
 await store.save(await store.previewBundle(offline),true);
 const selection=createIdentitySelection({store,inspect:inspectIdentity,match:matchRecipients});
 const email=(await store.list()).identities[0].certificates[0].emails[0];
 assert.deepEqual((await selection.list(email)).choices,[]);
 await store.save(await store.previewBundle(live),true);
 assert.equal((await selection.list(email)).choices.length,1);
});
