// Disposable secret keys only. Independently verify SSH signatures using Node,
// rather than asking the same OpenPGP implementation to verify its own output.
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import {createPublicKey,verify} from 'node:crypto';
import init,{software_generate,software_ssh_compat,software_inspect} from '../app/wasm/sequoia_iwa_verify.js';
globalThis.self=globalThis;await init({module_or_path:fs.readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});
test('passphrase-protected v4 Ed25519 imports sign SSH without exporting secrets',()=>{
 const password='disposable-ssh-import-password',source=JSON.parse(software_generate(JSON.stringify({profile:'level3-v4-classical',email:'ssh@example.invalid',name:'Disposable',password})));
 const input={encryptedSecret:source.encryptedSecret,password,message:Buffer.from('SSH authentication transcript').toString('base64')};
 const metadata=JSON.parse(software_inspect(JSON.stringify({encryptedSecret:source.encryptedSecret,password})));
 assert.equal(metadata.version,4);
 const result=JSON.parse(software_ssh_compat(JSON.stringify(input)));assert.deepEqual(Object.keys(result).sort(),['publicKey','signature']);
 const blob=Buffer.from(result.publicKey,'base64'),key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),blob.subarray(-32)]),format:'der',type:'spki'});
 assert(verify(null,Buffer.from(input.message,'base64'),key,Buffer.from(result.signature,'base64')));
 assert.throws(()=>software_ssh_compat(JSON.stringify({...input,password:'wrong'})));
 assert.equal(JSON.parse(software_ssh_compat(JSON.stringify({...input,message:''}))).signature,'');
 const hybrid=JSON.parse(software_generate(JSON.stringify({profile:'level3',email:'ssh@example.invalid',name:'Disposable hybrid',password})));
 assert.throws(()=>software_ssh_compat(JSON.stringify({...input,encryptedSecret:hybrid.encryptedSecret})));
});
