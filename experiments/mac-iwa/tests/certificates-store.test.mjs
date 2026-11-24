// These storage tests use deterministic public-only stand-ins. A separate WASM
// suite exercises real OpenPGP parsing/policy, so persistence behavior can be
// tested without secrets, a token, a browser account or Native Messaging.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createCertificateStore,createMemoryStorage,migrationDigest} from '../app/certificates/store.js';
const fp=n=>n.toString(16).toUpperCase().padStart(64,'A');
const encoded=n=>Buffer.from('synthetic public certificate '+n).toString('base64');
function setup(){
 const storage=createMemoryStorage(),infos=new Map();
 function info(n,extra={}){const value={certificate:encoded(n),fingerprint:fp(n),version:6,algorithms:['ML-DSA-65+Ed25519','ML-KEM-768+X25519'],emails:['alice@example.invalid','alias@example.invalid'],hybridContact:true,...extra};infos.set(encoded(n),value);return value;}
 info(1);info(2,{emails:['bob@example.invalid']});
 const inspect=async certificate=>{const v=infos.get(certificate);if(!v)throw Error('Rejected public certificate');return structuredClone(v);};
 const store=createCertificateStore({inspect,storage});
 return {store,storage,inspect,infos,info};
}
async function legacy(values,bindings){const snapshot={version:1,certificates:values.map(v=>v.certificate),saved:values.map(v=>v.fingerprint),bindings};snapshot.sourceDigest=await migrationDigest(snapshot);return snapshot;}

test('empty store is read-only; save canonical public material never grants trust',async()=>{
 const {store,storage}=setup();assert.equal((await store.list()).revision,0);assert.equal(await storage.read(),null);
 const rows=await store.save(encoded(1));assert.equal(rows.revision,1);assert.equal(rows.certificates.length,1);assert.deepEqual(rows.contacts,[]);assert.deepEqual(rows.certificates[0].trustedEmails,[]);
 assert.equal((await store.get(fp(1))).certificate,encoded(1));assert.equal((await store.material()).saved[0],fp(1));
});
test('trust is explicit and binds only the selected email and full primary fingerprint',async()=>{
 const {store}=setup();
 await assert.rejects(store.trust(encoded(1),'alice@example.invalid',fp(1),false),/confirmation/);
 await assert.rejects(store.trust(encoded(1),'mallory@example.invalid',fp(1),true),/self-certified/);
 await assert.rejects(store.trust(encoded(1),'alice@example.invalid',fp(2),true),/self-certified/);
 const r=await store.trust(encoded(1),'ALICE@example.invalid',fp(1),true);assert.equal(r.contacts.length,1);assert.equal(r.contacts[0].email,'alice@example.invalid');
 assert.deepEqual((await store.material()).bindings,[{email:'alice@example.invalid',fingerprint:fp(1)}]);
 assert.deepEqual(await store.trustedContact(r.contacts[0].id.toLowerCase()),r.contacts[0]);
});
test('same fingerprint with updated packets never silently inherits trust',async()=>{
 const {store,infos}=setup();await store.trust(encoded(1),'alice@example.invalid',fp(1),true);
 infos.set(encoded(3),{...infos.get(encoded(1)),certificate:encoded(3)});
 await assert.rejects(store.save(encoded(3)),/Certificate changed/);
 await assert.rejects(store.trust(encoded(3),'alias@example.invalid',fp(1),true),/Certificate changed/);
 assert.equal((await store.get(fp(1))).certificate,encoded(1));assert.equal((await store.list()).revision,1);
});
test('untrust affects one email only; certificate removal preserves unrelated bindings',async()=>{
 const {store}=setup();await store.trust(encoded(1),'alice@example.invalid',fp(1),true);await store.trust(encoded(1),'alias@example.invalid',fp(1),true);await store.trust(encoded(2),'bob@example.invalid',fp(2),true);
 await store.untrust(fp(1),'alice@example.invalid',true);assert.deepEqual((await store.list()).certificates[0].trustedEmails,['alias@example.invalid']);
 assert.equal((await store.get(fp(1))).certificate,encoded(1));await store.remove(fp(1),true);
 assert.deepEqual((await store.material()).bindings,[{email:'bob@example.invalid',fingerprint:fp(2)}]);
});
test('public certificates and trust survive a new store instance',async()=>{
 const {store,storage,inspect}=setup();await store.trust(encoded(1),'alice@example.invalid',fp(1),true);
 const reopened=createCertificateStore({inspect,storage});assert.deepEqual(await reopened.list(),await store.list());
});
test('expiry or revocation removes usable bindings without deleting the saved evidence',async()=>{
 const {store,infos}=setup();const r=await store.trust(encoded(1),'alice@example.invalid',fp(1),true),old=r.contacts[0];
 infos.set(encoded(1),{...infos.get(encoded(1)),emails:[],hybridContact:false});
 assert.deepEqual((await store.material()).bindings,[]);assert.equal((await store.list()).certificates.length,1);assert.deepEqual((await store.list()).contacts,[]);
 await assert.rejects(store.trustedContact(old.id),/no longer valid/);await assert.rejects(store.trust(encoded(1),'alice@example.invalid',fp(1),true),/self-certified/);
});
test('classical v4 trust is available to verification but not hybrid Compose',async()=>{
 const {store,infos}=setup(),fingerprint='A'.repeat(40);infos.set(encoded(1),{...infos.get(encoded(1)),fingerprint,version:4,algorithms:['EdDSA','ECDH'],hybridContact:false});
 const r=await store.trust(encoded(1),'alice@example.invalid',fingerprint,true);assert.deepEqual(r.contacts,[]);assert.equal((await store.material()).bindings[0].fingerprint,fingerprint);
});
test('contact snapshots fail after a trust revision, including remove-and-retrust ABA',async()=>{
 const {store}=setup();const snapshot=(await store.trust(encoded(1),'alice@example.invalid',fp(1),true)).contacts[0];
 assert.deepEqual(await store.assertContact(snapshot),snapshot);
 await store.untrust(fp(1),'alice@example.invalid',true);await store.trust(encoded(1),'alice@example.invalid',fp(1),true);
 await assert.rejects(store.assertContact(snapshot),/changed/);
 const fresh=await store.trustedContact(snapshot.id);await assert.rejects(store.assertContact({...fresh,certificateHash:'0'.repeat(64)}),/changed/);
 await assert.rejects(store.assertContact({...fresh,slot:'9c'}),/record/);
});
test('verification material cannot retain a stale trusted badge across another window mutation',async()=>{
 const {store,storage,inspect}=setup();await store.trust(encoded(1),'alice@example.invalid',fp(1),true);
 const material=await store.material();assert.equal(await store.assertRevision(material.revision),true);
 const other=createCertificateStore({inspect,storage});await other.untrust(fp(1),'alice@example.invalid',true);
 await assert.rejects(store.assertRevision(material.revision),/changed during verification/);
 await assert.rejects(store.assertRevision('2'),/changed during verification/);
});
test('concurrent stores cannot overwrite another window transaction',async()=>{
 const {storage,inspect}=setup();let releases=[],arrived=0,releaseBoth;
 const ready=new Promise(resolve=>releaseBoth=resolve);
 const delayed=async certificate=>{if(++arrived<=2){await new Promise(resolve=>releases.push(resolve));}return inspect(certificate);};
 const a=createCertificateStore({storage,inspect:delayed}),b=createCertificateStore({storage,inspect:delayed});
 const one=a.save(encoded(1)),two=b.save(encoded(2));
 // Let both mutations capture revision zero before allowing public inspection.
 await new Promise(resolve=>setImmediate(resolve));assert.equal(releases.length,2);releases.forEach(f=>f());releaseBoth();await ready;
 const outcomes=await Promise.allSettled([one,two]);assert.equal(outcomes.filter(o=>o.status==='fulfilled').length,1);assert.equal(outcomes.filter(o=>o.status==='rejected').length,1);
 assert.equal((await a.list()).certificates.length,1);assert.equal((await a.list()).revision,1);
});
test('storage failure cannot leave partial trust behind',async()=>{
 const {storage,inspect}=setup();const store=createCertificateStore({inspect,storage:{read:()=>storage.read(),compareAndSwap:async()=>{throw Error('Quota exceeded');}}});
 await assert.rejects(store.trust(encoded(1),'alice@example.invalid',fp(1),true),/Quota/);assert.equal(await storage.read(),null);
});
test('tampered persisted hashes and unexpected schema fields fail closed',async()=>{
 const {store,storage,inspect}=setup();await store.save(encoded(1));const saved=await storage.read();saved.records[0].certificateHash='0'.repeat(64);
 await assert.rejects(createCertificateStore({inspect,storage:createMemoryStorage(saved)}).list(),/integrity/);
 await assert.rejects(createCertificateStore({inspect,storage:createMemoryStorage({...saved,pin:'not allowed'})}).list(),/record/);
});
test('limits are enforced before any persistence; private/malformed input cannot save',async()=>{
 const {store,storage,info}=setup();await assert.rejects(store.save('bad encoding'),/encoding/);await assert.rejects(store.save(Buffer.from('private key').toString('base64')),/Rejected/);
 const big=Buffer.alloc(200001).toString('base64');info(3,{certificate:big});
 const largeStore=createCertificateStore({storage,inspect:async()=>({certificate:big,fingerprint:fp(3),version:6,algorithms:['test'],emails:['a@example.invalid'],hybridContact:false})});
 await assert.rejects(largeStore.save(big),/storage limit/);assert.equal(await storage.read(),null);
 for(let i=1;i<=24;i++){info(i);await store.save(encoded(i));}info(25);await assert.rejects(store.save(encoded(25)),/Unsupported certificate store/);assert.equal((await store.list()).certificates.length,24);
});
test('migration requires explicit review and atomically imports public material and exact bindings',async()=>{
 const {store,infos}=setup(),snapshot=await legacy([infos.get(encoded(1)),infos.get(encoded(2))],[{email:'alice@example.invalid',fingerprint:fp(1)}]);
 await assert.rejects(store.importLegacy(snapshot,false),/confirmation/);assert.equal((await store.list()).revision,0);
 const r=await store.importLegacy(snapshot,true);assert.equal(r.certificates.length,2);assert.equal(r.contacts.length,1);assert.equal(r.migration.sourceDigest,snapshot.sourceDigest);assert.equal(r.revision,1);
});
test('migration never resurrects removed native trust on restart or same-snapshot replay',async()=>{
 const {store,infos,storage,inspect}=setup(),snapshot=await legacy([infos.get(encoded(1))],[{email:'alice@example.invalid',fingerprint:fp(1)}]);
 await store.importLegacy(snapshot,true);await store.remove(fp(1),true);const reopened=createCertificateStore({inspect,storage});
 assert.deepEqual((await reopened.importLegacy(snapshot,true)).contacts,[]);assert.equal((await reopened.list()).revision,2);
 const newer=await legacy([infos.get(encoded(2))],[]);await assert.rejects(reopened.importLegacy(newer,true),/already completed/);
});
test('migration rejects substituted checksum, fingerprint, dangling or unvalidated email atomically',async()=>{
 const {store,infos,storage}=setup(),original=await legacy([infos.get(encoded(1))],[{email:'alice@example.invalid',fingerprint:fp(1)}]);
 const checksum={...original,sourceDigest:'0'.repeat(64)};await assert.rejects(store.importLegacy(checksum,true),/checksum/);
 for(const mutate of [s=>s.saved=[fp(2)],s=>s.bindings[0].email='mallory@example.invalid',s=>s.bindings[0].fingerprint=fp(2),s=>s.certificates.push(s.certificates[0])]){
  const invalid=structuredClone(original);mutate(invalid);invalid.sourceDigest=await migrationDigest(invalid);await assert.rejects(store.importLegacy(invalid,true));assert.equal(await storage.read(),null);
 }
});
test('migration merges only matching certificates; conflicts leave preexisting state intact',async()=>{
 const {store,infos}=setup();await store.trust(encoded(1),'alice@example.invalid',fp(1),true);
 const before=await store.list();infos.set(encoded(3),{...infos.get(encoded(1)),certificate:encoded(3)});
 const changed=await legacy([infos.get(encoded(3))],[]);await assert.rejects(store.importLegacy(changed,true),/Certificate changed/);assert.deepEqual(await store.list(),before);
});

test('explicit v4/v5 encryption capability is distinct from PQ signature and v6 is preferred',async()=>{
 const {store,info}=setup();
 const modern=info(5,{encryptionSupported:true,pqEncryption:true,pqSigning:true});
 const libre=info(6,{version:5,encryptionSupported:true,pqEncryption:true,pqSigning:false});
 const legacy=info(7,{version:4,fingerprint:'7'.repeat(40),hybridContact:false,encryptionSupported:true,pqEncryption:false,pqSigning:false,algorithms:['ECDSA','ECDH']});
 for(const c of [legacy,libre,modern])await store.trust(c.certificate,'alice@example.invalid',c.fingerprint,true);
 const contacts=(await store.list()).contacts;
 assert.deepEqual(contacts.map(c=>c.version),[6,5,4]);
 assert.equal(contacts[1].pqEncryption,true);assert.equal(contacts[1].pqSigning,false);
 assert.equal(contacts[2].pqEncryption,false);await store.assertContact(contacts[2]);
 await assert.rejects(store.assertContact({...contacts[2],pqEncryption:true}),/changed/);
});
test('invalid capability metadata never creates a sending contact',async()=>{
 const {store,info}=setup();info(8,{encryptionSupported:'yes',pqEncryption:false,pqSigning:false});
 await assert.rejects(store.save(encoded(8)),/capability/);
 info(8,{encryptionSupported:true,pqEncryption:false,pqSigning:false});
 await assert.rejects(store.save(encoded(8)),/hybrid contact/);
});
