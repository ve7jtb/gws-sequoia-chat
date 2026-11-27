import test from 'node:test';
import assert from 'node:assert/strict';
import {p384} from '@noble/curves/nist.js';
import {provisionLevel3} from '../app/provisioning/level3-transaction.js';
import {planLevel3Provisioning,USER_PIV_SLOTS} from '../app/piv-backup-plan.js';

function fixture(mode,{badCertificate=false,includeSsh=false}={}){
 const serial='12345678',email='test@example.invalid';
 const blank={serial,slots:USER_PIV_SLOTS.map(slot=>({slot,keyPresent:false,certificatePresent:false})),
  supportedAlgorithms:['ML-DSA-44','ML-DSA-65','Ed25519','ML-KEM-768','X25519','P-384']};
 const plan=planLevel3Provisioning({profile:'level3',mode,includeSmime:true,includeExperimentalNist:true,includeSsh,...blank});
 const lengths={'ML-DSA-44':1312,'ML-DSA-65':1952,Ed25519:32,'ML-KEM-768':1184,X25519:32,'P-384':97};
 const events=[],slotWrites=[],journal=[];
 const rows=plan.keys.map((rule,index)=>{
  const publicKey=new Uint8Array(lengths[rule.component]).fill(index+1);
  if(rule.component==='P-384')publicKey[0]=4;
  return {...rule,publicKey,origin:mode==='backup'?'imported':'generated',publicKeySha256:'f'.repeat(64)};
 });
 const material=rows.map(({slot})=>({slot,seed:new Uint8Array(32).fill(99)}));
 const certificate=btoa('existing RFC 9980 certificate');
 async function mutate(plan,{attempting,completed}){
  for(const {slot} of plan.keys){
   await attempting(slot);
   assert.equal(journal.at(-1).attempted,slot);
   slotWrites.push(slot);
   await completed(slot);
  }
 }
 const options={review:{plan,name:'Test',email,identity:{certificate}},confirmed:true,guard:async()=>{},
  createSoftwareSigner:async()=>({sign:async ({format,slots})=>{
   events.push('software signature');
   if(format==='openpgp-nist-draft-05')return {mldsa:new Uint8Array(3309),ecdsa:new Uint8Array(96)};
   return slots.length===1?new Uint8Array(3309):Uint8Array.from({length:3317},(_,i)=>i===3309?0x30:0);
  },signBundle:async()=>new Uint8Array(3309)}),
  inspectBundle:async()=>({bundleSignatureVerified:true,serial,slots:rows.filter(row=>!['8a','8b','8c','8d'].includes(row.slot))}),
  journal:{save:async record=>journal.push(structuredClone(record))},
  card:{inspect:async()=>blank,readPublicKeys:async()=>rows,plannedPublicKeys:async()=>rows,
   importAll:async(plan,keys,options)=>{events.push('import');assert.equal(keys,material);assert(options.bundle.length>0);
    await mutate(plan,options);
    await options.bundleAttempting(0x5f5000);
    await options.bundleCompleted(0x5f5000);
    return rows;
   },
   generateAll:async(plan,options)=>{events.push('generate');await mutate(plan,options);}},
  piv:{async signProvisioningComponents(_identity,components){
   events.push('sign');
   return components.map(c=>c.algorithm===0xe3?new Uint8Array(3309):c.algorithm===0xe0?new Uint8Array(64):
    p384.Signature.fromBytes(new Uint8Array(96).fill(1),'compact').toBytes('der'));
  }},
  verify:{rfc9980:async()=>true,experimentalNist:async()=>true,smime:async()=>!badCertificate},
  inspectRfc9980:async()=>({supported:true,profile:'level3',emails:[email]}),
  vault:{prepareBackup:async()=>{events.push('encrypted backup');return material;},
   async stageCertificates(){events.push('staged verified certificates');},
   async saveCertificates({certificates}){
    events.push('save');
    assert.equal(certificates.defaultOpenPgp,'rfc9980');
    assert(certificates.smime.pure.encryption.length>0);
    assert(certificates.experimentalNist.certificate.length>0);
    if(mode==='backup')assert.equal(btoa(String.fromCharCode(...certificates.rfc9980)),certificate);
   }},
 };
 return {options,events,slotWrites,journal,material};
}

for(const mode of ['backup','on-card']){
 test(mode+' transaction journals writes, verifies certificates and commits them together',async()=>{
  const f=fixture(mode);
  assert.equal((await provisionLevel3(f.options)).defaultOpenPgp,'rfc9980');
  if(mode==='backup'){
   assert.equal(f.events[0],'encrypted backup');
   assert.equal(f.events.filter(e=>e==='software signature').length,9);
   assert(!f.events.includes('sign'));
   assert.deepEqual(f.events.slice(-3),['staged verified certificates','import','save']);
  }else{
   assert.equal(f.events[0],'generate');
   assert(f.events.includes('sign'));
   assert(!f.events.includes('software signature'));
  }
  assert.equal(f.events.at(-1),'save');
  assert.equal(f.journal.at(-1).state,'saved');
  assert.equal(f.slotWrites.length,10);
  if(mode==='backup')assert(f.material.every(row=>!row.seed.some(Boolean)));
 });
}
test('a rejected software signature prevents any card mutation or final vault commit',async()=>{
 const f=fixture('backup',{badCertificate:true});
 await assert.rejects(provisionLevel3(f.options),/verification failed/);
 assert(!f.events.includes('save'));
 assert.deepEqual(f.journal,[]);
 assert.deepEqual(f.slotWrites,[]);
 assert(f.material.every(row=>!row.seed.some(Boolean)));
});

test('certificate-only recovery checks all imported public keys and never enters key write paths',async()=>{
 const f=fixture('backup');
 const plan=f.options.review.plan;
 const rows=await f.options.card.readPublicKeys(plan);
 const expected=rows.map(({slot,component,publicKey})=>({slot,algorithm:component,publicKey}));
 f.options.resume={version:1,serial:plan.serial,operation:plan.operation,state:'issuing',
  completed:plan.keys.map(key=>key.slot),attempted:null};
 f.options.vault.recoveryPublicKeys=async()=>expected;
 f.options.card.verifyImportedKeys=async (selected,keys)=>{
  assert.equal(selected.serial,plan.serial);
  assert.equal(keys,expected);
  f.events.push('verify live keys');
  return rows;
 };
 f.options.card.inspect=async()=>assert.fail('Recovery must not open the empty-card path');
 f.options.withTouch=async(serial,_guard,perform)=>{
  assert.equal(serial,plan.serial);
  f.events.push('touch prompt');
  return perform(()=>{});
 };
 for(const invalid of [{attempted:'9c'},{completed:['9c']},{identityId:'other vault item'}]){
  const resume={...f.options.resume,...invalid};
  await assert.rejects(provisionLevel3({...f.options,resume}),/complete matching import journal/);
  assert.deepEqual(f.events,[]);
 }
 await assert.rejects(provisionLevel3({...f.options,card:{...f.options.card,
  verifyImportedKeys:async()=>{throw Error('Live public key differs from staged identity');}}}),/Live public key/);
 assert.deepEqual(f.events,[]);
 await provisionLevel3(f.options);
 assert.deepEqual(f.slotWrites,[]);
 assert.equal(f.events[0],'verify live keys');
 assert(f.events.includes('touch prompt'));
 assert.equal(f.events.at(-1),'save');
 assert.equal(f.journal.at(-1).state,'saved');
});

for(const mode of ['backup','on-card'])test('complete SSH '+mode+' transaction journals all twelve keys',async()=>{
 const f=fixture(mode,{includeSsh:true});
 await provisionLevel3(f.options);
 assert.equal(f.slotWrites.length,12);
 assert.equal(f.journal.at(-1).includeSsh,true);
 assert.deepEqual(f.slotWrites.slice(-2),['8c','8d']);
 assert.equal(f.journal.at(-1).state,'saved');
});

test('a signed bundle with a different source public key cannot reach card import',async()=>{
 const f=fixture('backup'),inspect=f.options.inspectBundle;
 f.options.inspectBundle=async()=>{
  const bundle=await inspect();
  bundle.slots=bundle.slots.map(slot=>slot.slot==='84'?{...slot,publicKeySha256:'e'.repeat(64)}:slot);
  return bundle;
 };
 await assert.rejects(provisionLevel3(f.options),/does not match the reviewed software keys/);
 assert.deepEqual(f.slotWrites,[]);
 assert(!f.events.includes('staged verified certificates'));
 assert(f.material.every(row=>!row.seed.some(Boolean)));
});
