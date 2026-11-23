// Native OpenSSL/Sequoia generates and decapsulates a disposable test bundle.
// The exact browser-target baseline decrypts/authenticates it independently.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import init,{decrypt_with_session_key,verify_detached} from '../pkg/sequoia_iwa_verify.js';
await init({module_or_path:fs.readFileSync(new URL('../pkg/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const fixture=JSON.parse(fs.readFileSync(process.argv[2]));
const request=fixture.request;
const open=r=>JSON.parse(decrypt_with_session_key(JSON.stringify(r)));
const clear=open(request);
assert.equal(clear.raw,fixture.payload);
const verified=JSON.parse(verify_detached(JSON.stringify({payload:clear.raw,signature:clear.signature,certificates:[fixture.certificate]})));
assert.equal(verified.signatures.length,1);assert.equal(verified.signatures[0].status,'valid');assert.equal(verified.signatures[0].fingerprint,fixture.fingerprint);
const altered=Buffer.from(request.cipher,'base64');altered[altered.length-1]^=1;
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
for(const bad of [
 {...request,sessionKey:Buffer.alloc(32).toString('base64')},
 {...request,sessionKey:'YQ=='},
 {...request,algorithm:255},
 {...request,recipientKey:'0'.repeat(64)},
 {...request,cipherHash:'0'.repeat(64)},
 {...request,cipher:altered.toString('base64'),cipherHash:hash(altered)},
 {...request,cipher:altered.subarray(0,-16).toString('base64'),cipherHash:hash(altered.subarray(0,-16))},
 {...request,cipher:Buffer.from('plain').toString('base64'),cipherHash:hash(Buffer.from('plain'))}
])assert.throws(()=>open(bad));
console.log('PASS native decapsulation → baseline WASM AEAD decryption → hybrid verification; exact MIME; wrong key/length/algorithm/recipient, ciphertext substitution, bad final tag, truncation and plaintext rejected');
