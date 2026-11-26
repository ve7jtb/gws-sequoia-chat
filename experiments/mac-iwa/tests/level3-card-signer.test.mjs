import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {p384} from '@noble/curves/nist.js';
import {createLevel3CardSigner} from '../app/provisioning/card-signer.js';

test('card signer enforces roles and prepares protocol-bound PIV inputs',async()=>{
 const serial='12345678',plan={serial,certificates:{
  rfc9980:{signing:['9c','84']},
  experimentalNist:{certification:['8a','8b'],signing:['9c','83']},
  smime:{pure:{signing:['9c']},hybrid:{signing:['9c','83']}},
 }};
 const readback=[['9c','ML-DSA-65'],['84','Ed25519'],['83','P-384'],['8a','ML-DSA-65'],['8b','P-384']]
  .map(([slot,component],index)=>({slot,component,publicKeySha256:'a'.repeat(64),
   publicKey:new Uint8Array(component==='ML-DSA-65'?1952:97).fill(index+1)}));
 const calls=[];
 const scalar=p384.utils.randomSecretKey();
 const signer=createLevel3CardSigner({plan,readback,guard:async()=>{},promptPin:async()=>{},piv:{
  async signProvisioningComponents(identity,components){
   assert.equal(identity.serial,serial);
   calls.push(components);
   return components.map(c=>c.algorithm===0xe3?new Uint8Array(3309):c.algorithm===0xe0
    ?new Uint8Array(64):p384.sign(c.input,scalar,{prehash:false,format:'der'}));
  },
 }});
 try{
  const request={format:'openpgp-nist-draft-05',role:'certification',serial,digest:new Uint8Array(64).fill(2),slots:['8a','8b']};
  const result=await signer(request);
  assert.equal(result.ecdsa.length,96);
  assert.deepEqual(calls[0].map(c=>c.slot),['8a','8b']);
  const shake=b=>createHash('shake256',{outputLength:64}).update(b).digest();
  const tr=shake(readback.find(row=>row.slot==='8a').publicKey);
  assert.deepEqual(Buffer.from(calls[0][0].input),shake(Buffer.concat([tr,Buffer.alloc(2),request.digest])));
  assert.deepEqual(calls[0][1].input,request.digest.slice(0,48));
  await assert.rejects(signer({...request,slots:['9c','83']}),/reviewed roles/);
  assert.equal(calls.length,1);
 }finally{scalar.fill(0);}
});
