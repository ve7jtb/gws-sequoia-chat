// Invoked by the native Rust test with disposable software keys, never hardware.
import fs from 'node:fs';import assert from 'node:assert/strict';
import init,{wrap_vault_key,unwrap_vault_key,decrypt_with_session_key} from '../pkg/sequoia_iwa_verify.js';
await init({module_or_path:fs.readFileSync(new URL('../pkg/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const path=process.argv[2],input=JSON.parse(fs.readFileSync(path));
if(process.argv[3]==='wrap'){fs.writeFileSync(path+'.wrapped',wrap_vault_key(JSON.stringify(input)));}
else{const got=JSON.parse(unwrap_vault_key(JSON.stringify(input)));assert.equal(got.secret,input.expected);assert.throws(()=>decrypt_with_session_key(JSON.stringify(input)));for(const change of [v=>v.vaultId='wrong',v=>v.wrapperId='wrong',v=>v.sessionKey=Buffer.alloc(32).toString('base64')]){const bad={...input};change(bad);assert.throws(()=>unwrap_vault_key(JSON.stringify(bad)));}console.log('PASS WASM vault envelope → native decapsulation → WASM unwrap, bindings and signed-message isolation');}
