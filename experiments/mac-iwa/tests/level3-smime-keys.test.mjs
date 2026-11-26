import test from 'node:test';
import assert from 'node:assert/strict';
import {generateLevel3SmimeKeys,level3SmimeImportScalar,sameLevel3SmimeKeys} from '../app/vault/level3-smime-keys.js';

test('Level 3 S/MIME generates distinct P-384 keys with verified import scalars',async()=>{
 const keys=await generateLevel3SmimeKeys();
 const signing=await level3SmimeImportScalar('signing',keys.signing);
 const agreement=await level3SmimeImportScalar('agreement',keys.agreement);
 try{
  assert.equal(signing.length,48);
  assert.equal(agreement.length,48);
  assert.notDeepEqual(signing,agreement);
  assert.equal(keys.signing.slot,'83');
  assert.equal(keys.agreement.slot,'82');
  assert(sameLevel3SmimeKeys(keys,structuredClone(keys)));
  assert(!sameLevel3SmimeKeys(keys,undefined));
  await assert.rejects(level3SmimeImportScalar('signing',{...keys.signing,publicKey:keys.agreement.publicKey}),/do not match/);
 }finally{signing.fill(0);agreement.fill(0);}
});
