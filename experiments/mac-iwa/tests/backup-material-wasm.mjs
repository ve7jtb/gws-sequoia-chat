// Disposable software identity only; no test keys or passwords are written.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import init,{software_generate,software_backup_material} from '../app/wasm/sequoia_iwa_verify.js';
globalThis.self=globalThis;
await init({module_or_path:fs.readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const password='Disposable software backup test password';
const created=JSON.parse(software_generate(JSON.stringify({profile:'level3',email:'backup@example.invalid',name:'Backup test',password})));
const keys=JSON.parse(software_backup_material(JSON.stringify({encryptedSecret:created.encryptedSecret,password})));
assert.equal(keys.certificateHash,created.public.certificateHash);assert.equal(keys.keys.length,6);
assert.deepEqual(keys.keys.map(k=>k.slot).sort(),['84','85','86','87','9c','9d']);
for(const k of keys.keys){assert.equal(Buffer.from(k.seed,'base64').length,k.algorithm==='ML-KEM-768'?64:32);k.seed='';}
assert.throws(()=>software_backup_material(JSON.stringify({encryptedSecret:created.encryptedSecret,password:'wrong password'})));
console.log('PASS: real WASM generated Level 3 identity, exported six matching import seeds, and rejected a wrong password');
