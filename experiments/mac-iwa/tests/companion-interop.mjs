// Run the shipped browser WASM and the actual disposable-worker completion
// utility against explicitly exported synthetic vectors. No native helper,
// account, real private key, PIN, device write or network exists in this test.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import init, {companion_inspect, companion_complete} from '../app/wasm/sequoia_iwa_verify.js';
import {completeCompanion} from '../app/companion/complete.js';
const directory=process.argv[2];
assert(directory,'Disposable companion vector directory required');
await init({module_or_path:fs.readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const results=[];
for(const profile of ['level3','level5'])for(const operation of ['sign','decapsulate']){
  const vector=JSON.parse(fs.readFileSync(path.join(directory,`${profile}-${operation}.json`),'utf8'));
  assert.equal(vector.testOnly,true);
  const input=vector.input,preview=JSON.parse(companion_inspect(JSON.stringify(input.response.companion)));
  assert.equal(preview.profile,profile==='level3'?'LEVEL3_POLYFILL':'LEVEL5_COMPANION');
  assert.equal(preview.components.length,7);
  const actual=JSON.parse(companion_complete(JSON.stringify(input)));
  assert.deepEqual(actual,vector.expected,'Actual browser WASM must reproduce independently computed native fixture components');
  const response=structuredClone(input.response);
  assert.deepEqual(await completeCompanion(operation,input.certificate,input.request,response),vector.expected);
  assert.equal(response.companionShared,'');
  assert(!('companion' in response));
  // The finalizer must not get any component from the wrong operation, changed
  // certificate, bad AEAD wrapping share or attacker-modified public mapping.
  for(const mutation of ['share','request','certificate','public']){
    const damaged=structuredClone(input);
    if(mutation==='share')damaged.response.companionShared=Buffer.alloc(48,1).toString('base64');
    if(mutation==='request')damaged.response.requestId='E'.repeat(64);
    if(mutation==='certificate')damaged.certificate=Buffer.from('wrong certificate').toString('base64');
    if(mutation==='public')damaged.response.companion.serial=2;
    assert.throws(()=>companion_complete(JSON.stringify(damaged)),undefined,mutation);
  }
  results.push({profile,operation,inspect:true,completion:true,workerUtility:true,negativeChecks:4});
}
const report={status:'PASS',runtime:'shipped browser WASM',results,hardwareOperations:0,keysChanged:0,policiesChanged:0};
fs.writeFileSync(path.join(directory,'browser-results.json'),JSON.stringify(report,null,2));
console.log(JSON.stringify(report));
