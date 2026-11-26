import test from 'node:test';
import assert from 'node:assert/strict';
import {p384} from '@noble/curves/nist.js';
import {provisionLevel3} from '../app/provisioning/level3-transaction.js';
import {planLevel3Provisioning,USER_PIV_SLOTS} from '../app/piv-backup-plan.js';

function fixture(mode,{badCertificate=false}={}){
 const serial='12345678',email='test@example.invalid';
 const blank={serial,slots:USER_PIV_SLOTS.map(slot=>({slot,keyPresent:false,certificatePresent:false})),
  supportedAlgorithms:['ML-DSA-65','Ed25519','ML-KEM-768','X25519','P-384']};
 const plan=planLevel3Provisioning({profile:'level3',mode,includeSmime:true,includeExperimentalNist:true,...blank});
 const lengths={'ML-DSA-65':1952,Ed25519:32,'ML-KEM-768':1184,X25519:32,'P-384':97};
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
  journal:{save:async record=>journal.push(structuredClone(record))},
  card:{inspect:async()=>blank,readPublicKeys:async()=>rows,
   importAll:async(plan,keys,options)=>{events.push('import');assert.equal(keys,material);await mutate(plan,options);},
   generateAll:async(plan,options)=>{events.push('generate');await mutate(plan,options);}},
  piv:{async signProvisioningComponents(_identity,components){
   events.push('sign');
   return components.map(c=>c.algorithm===0xe3?new Uint8Array(3309):c.algorithm===0xe0?new Uint8Array(64):
    p384.Signature.fromBytes(new Uint8Array(96).fill(1),'compact').toBytes('der'));
  }},
  verify:{rfc9980:async()=>true,experimentalNist:async()=>true,smime:async()=>!badCertificate},
  inspectRfc9980:async()=>({supported:true,profile:'level3',emails:[email]}),
  vault:{prepareBackup:async()=>{events.push('encrypted backup');return material;},
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
  assert.deepEqual(f.events.slice(0,mode==='backup'?2:1),mode==='backup'?['encrypted backup','import']:['generate']);
  assert.equal(f.events.at(-1),'save');
  assert.equal(f.journal.at(-1).state,'saved');
  assert.equal(f.slotWrites.length,10);
  if(mode==='backup')assert(f.material.every(row=>!row.seed.some(Boolean)));
 });
}
test('a rejected signature leaves a resume journal and never saves the certificate set',async()=>{
 const f=fixture('backup',{badCertificate:true});
 await assert.rejects(provisionLevel3(f.options),/verification failed/);
 assert(!f.events.includes('save'));
 assert.equal(f.journal.at(-1).state,'issuing');
 assert(f.material.every(row=>!row.seed.some(Boolean)));
});
