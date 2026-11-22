// Execute the exact browser-target WASM module under Node for repeatable checks.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import init,{verify_detached} from '../pkg/sequoia_iwa_verify.js';
await init({module_or_path:fs.readFileSync(new URL('../pkg/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const vectors=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const compact=s=>s.map(({status,fingerprint,signingFingerprint,algorithm,candidateOnly})=>({status,fingerprint,signingFingerprint,algorithm,candidateOnly}));
for(const test of vectors.cases){
 const start=performance.now();const actual=JSON.parse(verify_detached(JSON.stringify(test.request)));
 assert.deepEqual(compact(actual.signatures),compact(test.expected),test.name);
 console.log(`PASS ${test.name}: ${actual.signatures.map(s=>s.status).join(',')} (${(performance.now()-start).toFixed(1)} ms)`);
}
for(const value of ['{}','!',JSON.stringify({certificates:Array(33).fill(''),payload:'',signature:''}),'x'.repeat(800001)]){
 assert.throws(()=>verify_detached(value));
}
console.log('PASS malformed and oversized inputs rejected');
