import {test} from 'node:test';
import assert from 'node:assert/strict';
import {USER_PIV_SLOTS} from '../app/piv-backup-plan.js';
import {createProvisioning} from '../app/piv-provisioning.js';
function fixture({failImport=false,proof=true,failSave=false}={}){
 const calls=[],seeds=[],logs=[];
 const snapshot={serial:'12345678',supportedAlgorithms:['ML-DSA-65','Ed25519','ML-KEM-768','X25519'],slots:USER_PIV_SLOTS.map(slot=>({slot,keyPresent:false,certificatePresent:false}))};
 const identity={profile:'level3',fingerprint:'TEST',certificateHash:'HASH'};
 const card={inspect:async()=>structuredClone(snapshot),importAll:async(plan,material,{guard,completed})=>{
  for(const key of plan.keys){await guard();calls.push('import:'+key.slot);await completed(key.slot);if(failImport)throw Error('Transport lost');}
 },verify:async()=>{calls.push('verify');return {publicKeysMatch:proof,signingVerified:proof,decryptionVerified:proof};}};
 const vault={assert:async()=>{},material:async(i,p)=>p.keys.map(k=>{const seed=new Uint8Array(32).fill(7);seeds.push(seed);return {seed};}),saveHardware:async()=>{if(failSave)throw Error('Persistence failed');calls.push('saveHardware');return {serial:snapshot.serial};},assertHardware:async()=>{},removePrivate:async()=>{calls.push('removePrivate');}};
 const controller=createProvisioning({card,vault,journal:{save:async r=>logs.push(structuredClone(r))}});
 return {controller,identity,snapshot,calls,seeds,logs,vault};
}
test('detected serial review, complete import and verification precede separately confirmed removal',async()=>{
 const f=fixture(),r=await f.controller.discover(f.identity);assert.equal(r.plan.serial,'12345678');assert.deepEqual(f.calls,[]);
 const result=await f.controller.provision(r.id,{confirmed:true});assert.equal(result.verified,true);assert.equal(f.calls.includes('removePrivate'),false);
 assert(f.seeds.every(s=>s.every(b=>b===0)));assert.equal(f.logs.at(-1).state,'verified');
 await assert.rejects(f.controller.removeSoftwareKeys(r.id),/confirmation/);await f.controller.removeSoftwareKeys(r.id,{confirmed:true});assert.equal(f.calls.at(-1),'removePrivate');
 await assert.rejects(f.controller.removeSoftwareKeys(r.id,{confirmed:true}));
});
test('partial import, failed proof or hardware persistence never authorize deletion',async()=>{
 for(const options of [{failImport:true},{proof:false},{failSave:true}]){
  const f=fixture(options),r=await f.controller.discover(f.identity);await assert.rejects(f.controller.provision(r.id,{confirmed:true}));
  await assert.rejects(f.controller.removeSoftwareKeys(r.id,{confirmed:true}));assert(!f.calls.includes('removePrivate'));
  assert(f.seeds.every(s=>s.every(b=>b===0)));assert(!JSON.stringify(f.logs).includes('seed'));
 }
});
test('device swap or unrelated occupied slot after review prevents every import',async()=>{
 for(const change of [f=>f.snapshot.serial='87654321',f=>f.snapshot.slots[0].keyPresent=true]){
  const f=fixture(),r=await f.controller.discover(f.identity);change(f);await assert.rejects(f.controller.provision(r.id,{confirmed:true}));assert.deepEqual(f.calls,[]);
 }
});
test('cancelled operation and unconfirmed review cannot export private material',async()=>{
 const f=fixture(),r=await f.controller.discover(f.identity);await assert.rejects(f.controller.provision(r.id));
 const c=new AbortController();c.abort();await assert.rejects(f.controller.provision(r.id,{confirmed:true,signal:c.signal}));assert.equal(f.seeds.length,0);
});
