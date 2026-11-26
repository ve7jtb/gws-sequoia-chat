import test from 'node:test';
import assert from 'node:assert/strict';
import {USER_PIV_SLOTS,planLevel3Provisioning} from '../app/piv-backup-plan.js';
import {issueProvisionedLevel3} from '../app/provisioning/level3-issuance.js';

for(const mode of ['backup','on-card']){
 test(mode+' binds S/MIME and draft certificate signing to verified PIV roles',async()=>{
  const plan=planLevel3Provisioning({profile:'level3',mode,serial:'12345678',
   slots:USER_PIV_SLOTS.map(slot=>({slot,keyPresent:false,certificatePresent:false})),
   supportedAlgorithms:['ML-DSA-65','Ed25519','ML-KEM-768','X25519','P-384'],
   includeSmime:true,includeExperimentalNist:true,
  });
  const sizes={'ML-DSA-65':1952,'Ed25519':32,'ML-KEM-768':1184,X25519:32,'P-384':97};
  const rows=plan.keys.map((key,index)=>{
   const publicKey=new Uint8Array(sizes[key.component]).fill(index+1);
   if(key.component==='P-384')publicKey[0]=4;
   return {...key,publicKey,origin:mode==='backup'?'imported':'generated'};
  });
  const calls=[];
  const provider={serial:plan.serial,operation:plan.operation,readPublicKeys:async()=>rows,
   async sign(operation){
    calls.push(operation);
    if(operation.format==='rfc9980')return Uint8Array.of(1);
    if(operation.format==='smime'){
     const pure=operation.slots.length===1;
     const result=new Uint8Array(pure?3309:3410);if(!pure)result[3309]=0x30;
     return result;
    }
    return {ecdsa:new Uint8Array(96),mldsa:new Uint8Array(3309)};
   }};
  const request={plan,email:'test@example.invalid',provider,guard:async()=>{},
   verify:{smime:async()=>true,experimentalNist:async()=>true},
   rfc9980:({sign})=>sign({role:'certification',digest:new Uint8Array(64)}),
  };
  const result=await issueProvisionedLevel3(request);
  assert.equal(result.defaultOpenPgp,'rfc9980');
  assert(result.smime.hybrid.signing.length>0);
  assert(result.experimentalNist.certificate.length>0);
  assert.deepEqual(calls.map(call=>call.slots),[
   ['86','87'],['9c'],['9c'],['9c','83'],['9c','83'],
   ['8a','8b'],['8a','8b'],['9c','83'],['8a','8b'],['8a','8b'],
  ]);
  rows.find(r=>r.slot==='8b').touch='always';
  await assert.rejects(issueProvisionedLevel3(request),/readback mismatch/);
  assert.equal(calls.length,10);
 });
}
