// Pipe-only WASM side of the hardware soak test. Requests can contain session
// keys, so never write them to disk or echo them in errors. Each process exits
// after one request, modelling a fresh WASM instance on every vault unlock.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import init,{wrap_vault_key,unwrap_vault_key,decrypt_with_session_key} from '../wasm/pkg/sequoia_iwa_verify.js';
await init({module_or_path:fs.readFileSync(new URL('../wasm/pkg/sequoia_iwa_verify_bg.wasm',import.meta.url))});
try {
 const input=JSON.parse(fs.readFileSync(0,'utf8'));
 if(input.op==='wrap')process.stdout.write(wrap_vault_key(JSON.stringify(input)));
 else if(input.op==='unwrap'){
  assert.equal(JSON.parse(unwrap_vault_key(JSON.stringify(input))).secret,input.expected);
  assert.throws(()=>unwrap_vault_key(JSON.stringify({...input,wrapperId:'wrong'})));
  assert.throws(()=>unwrap_vault_key(JSON.stringify({...input,vaultId:'wrong'})));
  assert.throws(()=>unwrap_vault_key(JSON.stringify({...input,sessionKey:Buffer.alloc(32).toString('base64')})));
  // Unsigned vault envelopes must not be accepted by the signed mail API.
  assert.throws(()=>decrypt_with_session_key(JSON.stringify(input)));
  process.stdout.write('{"passed":true}');
 }else throw Error();
}catch(_){process.stderr.write('WASM hardware test rejected\n');process.exitCode=1;}
