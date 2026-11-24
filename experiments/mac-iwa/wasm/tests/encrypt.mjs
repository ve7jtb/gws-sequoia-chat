// Use the exact browser-target baseline module; native Sequoia independently
// decrypts and verifies it. Only disposable test secret keys enter this runner.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import init,{encrypt_signed} from '../pkg/sequoia_iwa_verify.js';
await init({module_or_path:fs.readFileSync(new URL('../pkg/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const dir=process.argv[2],sq=process.env.TEST_SQ;
assert(sq,'TEST_SQ required');
const request=JSON.parse(fs.readFileSync(path.join(dir,'request.json')));
const encrypt=r=>Buffer.from(JSON.parse(encrypt_signed(JSON.stringify(r))).cipher,'base64');
const a=encrypt(request),b=encrypt(request);
assert(!a.equals(b),'Fresh random encryption must produce different ciphertexts');
for(const [name,cipher] of [['first',a],['second',b]]){
 const input=path.join(dir,name+'.pgp'),output=path.join(dir,name+'.mime');fs.writeFileSync(input,cipher);
 const result=spawnSync(sq,['--home=none','--cert-store=none','--key-store=none','decrypt','--recipient-file',path.join(dir,'recipient-secret.pgp'),'--signer-file',path.join(dir,'sender-public.pgp'),'--signatures','1','--output',output,input],{encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);
 if(process.env.IWA_CRYPTO_ORACLE_BIN){
  const check=spawnSync(process.env.IWA_CRYPTO_ORACLE_BIN,[],{input:JSON.stringify({op:'check-ciphertext',peer:request.recipientCertificate,payload:cipher.toString('base64')}),encoding:'utf8'});
  assert.equal(check.status,0,check.stderr);assert.equal(JSON.parse(check.stdout).valid,true);
 }
 assert.deepEqual(fs.readFileSync(output),Buffer.from(request.payload,'base64'));
}
for(const changed of [
 {...request,recipientFingerprint:'0'.repeat(64)},
 {...request,recipientEmail:'wrong@example.invalid'},
 {...request,payload:Buffer.from('tampered').toString('base64')},
 {...request,signed:Buffer.from('not signed packets').toString('base64')},
 {...request,recipientCertificate:fs.readFileSync(path.join(dir,'recipient-secret.pgp')).toString('base64')},
 {...request,payload:Buffer.alloc(262145).toString('base64')}
])assert.throws(()=>encrypt(changed));
console.log('PASS baseline WASM encryption: two independent Sequoia decrypt/verify exact-byte round trips, fresh randomness, recipient/mailbox mismatch, altered payload, malformed packets, secret-key and oversize rejection');
