// Deterministic public stand-ins isolate storage/review races. Real public-key
// parsing and signed-bundle validation are independently tested by WASM/native
// suites; this test never reads an account, authenticator, or private key.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createIdentityStore} from '../app/identities/store.js';
import {createMemoryStorage} from '../app/certificates/store.js';

const encoded=n=>Buffer.from('synthetic own public certificate '+n).toString('base64');
const fp=n=>n.toString(16).toUpperCase().padStart(64,'A');
function setup(){
 const storage=createMemoryStorage(),infos=new Map();let time=1000;
 function info(n,extra={}){const value={certificate:encoded(n),fingerprint:fp(n),version:6,algorithms:['ML-DSA-65+Ed25519','ML-KEM-768+X25519'],emails:['alice@example.invalid'],hybridContact:true,...extra};infos.set(encoded(n),value);return value;}
 info(1);info(2,{fingerprint:'B'.repeat(40),version:4,algorithms:['EdDSA','ML-KEM-768+X25519'],hybridContact:false});info(3,{fingerprint:'B'.repeat(40),version:4,algorithms:['EdDSA','ECDH'],hybridContact:false});
 const inspect=async raw=>{if(!infos.has(raw))throw Error('Private or malformed certificate rejected');return structuredClone(infos.get(raw));};
 const store=createIdentityStore({inspect,storage,now:()=>time});
 return {store,storage,inspect,infos,info,advance:ms=>time+=ms};
}
function snapshot(overrides={}){
 return {format:'sequoia-iwa-identity-preview',version:1,source:'yubikey',serial:'123456',bundleHash:'1'.repeat(64),generation:3,certificates:[{kind:'openpgp',label:'OpenPGP v6',certificate:encoded(1)},{kind:'openpgp',label:'OpenPGP v4 hybrid',certificate:encoded(2)},{kind:'openpgp',label:'OpenPGP v4 classical',certificate:encoded(3)}],slots:[{role:'OpenPGP signing',slot:'9c',algorithm:'ML-DSA-65',publicKeySha256:'2'.repeat(64)},{role:'OpenPGP signing',slot:'84',algorithm:'Ed25519',publicKeySha256:'3'.repeat(64)}],bundleSignatureVerified:true,liveKeysMatched:true,warnings:[],...overrides};
}

test('own inventory starts empty and preview alone does not save or grant trust',async()=>{
 const {store,storage}=setup();assert.deepEqual(await store.list(),{identities:[],revision:0});
 const r=await store.previewCertificate(encoded(1));assert.equal(r.revision,0);assert.equal(r.identity.serial,null);assert.deepEqual(r.identity.slots,[]);assert.equal(r.identity.liveKeysMatched,false);assert.equal(r.identity.bundleSignatureVerified,false);
 assert.equal(await storage.read(),null);assert.equal(r.identity.source,'certificate-file');assert.deepEqual(r.identity.certificates[0].emails,['alice@example.invalid']);
});
test('reviewed bundle stores all three certificate views, serial and slots without trust',async()=>{
 const {store,storage}=setup(),r=await store.previewBundle(snapshot());
 await assert.rejects(store.save(r,false),/confirmation/);assert.equal(await storage.read(),null);
 const saved=await store.save(r,true),identity=saved.identities[0];assert.equal(saved.revision,1);assert.equal(identity.id,'yubikey:123456');assert.equal(identity.certificates.length,3);assert.equal(identity.certificates[1].fingerprint,identity.certificates[2].fingerprint);assert.notEqual(identity.certificates[1].certificateHash,identity.certificates[2].certificateHash);assert.deepEqual(identity.slots,snapshot().slots);
 const state=await storage.read();assert.equal(state.format,'sequoia-iwa-identities');assert.equal(JSON.stringify(state).includes('trusted'),false);assert.equal(JSON.stringify(state).includes('privateKey'),false);
});
test('saved identity survives restart but does not select a native backend',async()=>{
 const {store,storage,inspect}=setup();await store.save(await store.previewBundle(snapshot()),true);
 const reopened=createIdentityStore({inspect,storage});assert.deepEqual(await reopened.list(),await store.list());assert.equal(typeof reopened.select,'undefined');assert.equal(typeof reopened.sign,'undefined');assert.equal(typeof reopened.trust,'undefined');
});
test('offline authenticated bundles persist without claiming live hardware and can later be matched',async()=>{
 const {store,storage,inspect}=setup();
 const offline=snapshot({source:'file',generation:0,liveKeysMatched:false});
 await store.save(await store.previewBundle(offline),true);
 const reopened=createIdentityStore({inspect,storage});
 assert.equal((await reopened.list()).identities[0].liveKeysMatched,false);
 const slots=['9a','9c','9d','9e',...Array.from({length:20},(_,i)=>(0x82+i).toString(16))];
 const live={format:'sequoia-iwa-public-snapshot',version:1,serial:'123456',slots:slots.map(slot=>({slot,publicKeySha256:offline.slots.find(s=>s.slot===slot)?.publicKeySha256||null})),warnings:[]};
 const wrong=structuredClone(live);wrong.slots.find(s=>s.slot==='84').publicKeySha256='f'.repeat(64);
 await assert.rejects(reopened.previewLiveMatch('yubikey:123456',wrong),/does not match/);
 const review=await reopened.previewLiveMatch('yubikey:123456',live);
 assert.equal((await reopened.list()).identities[0].liveKeysMatched,false);
 await reopened.save(review,true);
 assert.equal((await reopened.list()).identities[0].liveKeysMatched,true);
 assert.equal((await reopened.list()).identities[0].generation,0);
 assert.equal((await reopened.list()).identities[0].source,'file');
});
test('an identity removed during live-match inspection cannot be resurrected under a new revision',async()=>{
 const {store,storage,inspect}=setup(),offline=snapshot({source:'file',generation:0,liveKeysMatched:false});
 await store.save(await store.previewBundle(offline),true);
 let release,started;const waiting=new Promise(r=>started=r),pause=new Promise(r=>release=r);let first=true;
 const delayed=createIdentityStore({storage,inspect:async raw=>{if(first){first=false;started();await pause;}return inspect(raw);}});
 const slots=['9a','9c','9d','9e',...Array.from({length:20},(_,i)=>(0x82+i).toString(16))];
 const live={format:'sequoia-iwa-public-snapshot',version:1,serial:'123456',slots:slots.map(slot=>({slot,publicKeySha256:offline.slots.find(s=>s.slot===slot)?.publicKeySha256||null})),warnings:[]};
 const pending=delayed.previewLiveMatch('yubikey:123456',live);await waiting;
 await store.remove('yubikey:123456',true,1);release();
 await assert.rejects(pending,/changed during hardware matching/);
 assert.deepEqual((await store.list()).identities,[]);
});
test('canonical public imports are idempotent and remain unmapped',async()=>{
 const {store,infos}=setup();infos.set(encoded(4),infos.get(encoded(1)));
 await store.save(await store.previewCertificate(encoded(4)),true);const r=await store.previewCertificate(encoded(1));assert.equal(r.replacesExisting,true);assert.equal(r.unchanged,true);
 const saved=await store.save(r,true);assert.equal(saved.identities.length,1);assert.equal(saved.identities[0].certificates[0].certificate,encoded(1));assert.equal(saved.identities[0].serial,null);
});
test('same device bundle replacement requires a new review and retains unrelated certificate inventory',async()=>{
 const {store}=setup();await store.save(await store.previewBundle(snapshot()),true);await store.save(await store.previewCertificate(encoded(2)),true);
 const updated=snapshot({source:'file',generation:0,bundleHash:'4'.repeat(64)}),r=await store.previewBundle(updated);assert.equal(r.replacesExisting,true);assert.equal(r.unchanged,false);
 const saved=await store.save(r,true);assert.equal(saved.identities.length,2);assert.equal(saved.identities[0].generation,0);assert.equal(saved.identities[0].source,'file');assert.equal(saved.identities[1].serial,null);
});
test('a mutated, consumed, cancelled or expired review cannot be committed',async()=>{
 const {store,storage,advance}=setup();let r=await store.previewBundle(snapshot()),changed=structuredClone(r);changed.identity.serial='654321';
 await assert.rejects(store.save(changed,true),/expired or changed/);await assert.rejects(store.save(r,true),/expired or changed/);assert.equal(await storage.read(),null);
 r=await store.previewBundle(snapshot());store.cancel(r);await assert.rejects(store.save(r,true),/expired or changed/);
 r=await store.previewBundle(snapshot());advance(600001);await assert.rejects(store.save(r,true),/expired or changed/);assert.equal(await storage.read(),null);
 r=await store.previewBundle(snapshot());await store.save(r,true);await assert.rejects(store.save(r,true),/expired or changed/);
});
test('another window mutation invalidates an old preview without overwriting it',async()=>{
 const {store,storage,inspect}=setup(),other=createIdentityStore({storage,inspect});
 const a=await store.previewBundle(snapshot()),b=await other.previewCertificate(encoded(1));await other.save(b,true);
 await assert.rejects(store.save(a,true),/changed in another window/);assert.equal((await store.list()).identities.length,1);assert.equal((await store.list()).identities[0].serial,null);
});
test('public policy changes during review require another review',async()=>{
 const {store,infos,storage}=setup(),r=await store.previewCertificate(encoded(1));infos.set(encoded(1),{...infos.get(encoded(1)),emails:[],hybridContact:false});
 await assert.rejects(store.save(r,true),/policy changed/);assert.equal(await storage.read(),null);
});
test('malformed, private, repeated or unverified snapshots never reach persistence',async()=>{
 const {store,storage}=setup();
 await assert.rejects(store.previewCertificate('not base64'),/encoding/);await assert.rejects(store.previewCertificate(encoded(99)),/Private or malformed/);
 const mutations=[s=>s.pin='not allowed',s=>s.bundleSignatureVerified=false,s=>s.liveKeysMatched=false,s=>s.serial='0',s=>s.serial='4294967296',s=>s.source='network',s=>s.source='file',s=>s.generation=0,s=>s.slots[0].slot='../9c',s=>s.slots.push({...s.slots[0]}),s=>s.slots[0].publicKeySha256='wrong',s=>s.certificates.push({...s.certificates[0]}),s=>s.certificates[0].kind='private',s=>s.certificates[1].certificate=s.certificates[0].certificate];
 for(const mutate of mutations){const invalid=snapshot();mutate(invalid);await assert.rejects(store.previewBundle(invalid));}
 assert.equal(await storage.read(),null);
});
test('stored digest and identifier substitutions fail closed on restart',async()=>{
 const {store,storage,inspect}=setup();await store.save(await store.previewBundle(snapshot()),true);const good=await storage.read();
 const tampered=structuredClone(good);tampered.records[0].source.slots[0].slot='88';await assert.rejects(createIdentityStore({storage:createMemoryStorage(tampered),inspect}).list(),/integrity/);
 const wrongId=structuredClone(good);wrongId.records[0].id='yubikey:654321';await assert.rejects(createIdentityStore({storage:createMemoryStorage(wrongId),inspect}).list(),/identifier mismatch/);
 await assert.rejects(createIdentityStore({storage:createMemoryStorage({...good,pin:'not allowed'}),inspect}).list(),/record/);
});
test('failed persistence leaves the previous inventory intact',async()=>{
 const {storage,inspect}=setup(),store=createIdentityStore({inspect,storage:{read:()=>storage.read(),compareAndSwap:async()=>{throw Error('Quota exceeded');}}});
 await assert.rejects(store.save(await store.previewBundle(snapshot()),true),/Quota/);assert.equal(await storage.read(),null);
});
test('removing a local own identity needs confirmation and preserves unrelated inventory',async()=>{
 const {store}=setup();await store.save(await store.previewBundle(snapshot()),true);await store.save(await store.previewCertificate(encoded(1)),true);
 await assert.rejects(store.remove('yubikey:123456',false,2),/confirmation/);const r=await store.remove('yubikey:123456',true,2);assert.equal(r.identities.length,1);assert.equal(r.identities[0].serial,null);
 await assert.rejects(store.remove('yubikey:123456',true,3),/no longer exists/);
});
test('stale removal review cannot delete a same-serial replacement from another window',async()=>{
 const {store,storage,inspect}=setup();await store.save(await store.previewBundle(snapshot()),true);const reviewed=(await store.list()).revision;
 const other=createIdentityStore({storage,inspect});await other.save(await other.previewBundle(snapshot({generation:4,bundleHash:'4'.repeat(64)})),true);
 await assert.rejects(store.remove('yubikey:123456',true,reviewed),/changed since removal review/);await assert.rejects(store.remove('yubikey:123456',true),/changed since removal review/);
 assert.equal((await store.list()).identities[0].generation,4);
});
test('inventory and review counts are bounded',async()=>{
 const {store,info}=setup();const pending=[];for(let i=0;i<8;i++)pending.push(await store.previewCertificate(encoded(1)));
 await assert.rejects(store.previewCertificate(encoded(1)),/Too many pending/);pending.forEach(r=>store.cancel(r));
 for(let i=1;i<=16;i++){info(i);await store.save(await store.previewCertificate(encoded(i)),true);}
 info(17);await assert.rejects(store.save(await store.previewCertificate(encoded(17)),true),/Unsupported own-identity store/);assert.equal((await store.list()).identities.length,16);
});

function companionSnapshot(){
 const value=snapshot({format:'sequoia-iwa-companion-preview',generation:0,bundleHash:'5'.repeat(64),certificates:[{kind:'openpgp',label:'Level 5 companion',certificate:encoded(1),profile:'LEVEL5_COMPANION',components:[{role:'signing-pq',algorithm:'ML-DSA-87',storage:'piv',slot:'9c',publicKey:encoded(50)},{role:'signing-classical',algorithm:'Ed448',storage:'companion',slot:'',publicKey:encoded(51)}]}]});
 value.companion={encoded:btoa('encrypted companion bytes'),serial:123456,publicKeys:{'9c':encoded(50),'82':encoded(52)},certificate:encoded(1)};
 return value;
}
test('encrypted companion coexists with ordinary bundle and persists ciphertext/public custody only',async()=>{
 const {store,storage,inspect}=setup();await store.save(await store.previewBundle(snapshot()),true);
 const review=await store.previewBundle(companionSnapshot());assert.equal(review.replacesExisting,false);
 const result=await store.save(review,true);assert.deepEqual(result.identities.map(i=>i.id),['yubikey:123456','yubikey:123456:companion']);
 assert.equal(result.identities[0].certificates.length,3);assert.equal(result.identities[1].certificates[0].components[1].storage,'companion');
 const reopened=createIdentityStore({inspect,storage});assert.deepEqual(await reopened.list(),result);
 const saved=JSON.stringify(await storage.read());for(const secret of ['companionShared','password','privateKey','pin'])assert.ok(!saved.includes('"'+secret+'"'));
});
test('companion schema rejects unwrap secrets, wrong serials and ambiguous component custody',async()=>{
 const {store,storage}=setup();
 for(const alter of [s=>s.companion.companionShared=btoa('secret'),s=>s.companion.password='not allowed',s=>s.companion.serial=654321,s=>s.certificates[0].components[1].slot='88',s=>s.certificates[0].components[0].storage='software',s=>s.certificates[0].components.push({...s.certificates[0].components[0]})]){
  const value=companionSnapshot();alter(value);await assert.rejects(store.previewBundle(value));
 }
 assert.equal(await storage.read(),null);
});
