// Exercise the actual browser-target WASM exports, including one-use state and
// cancellation, with disposable Sequoia software envelopes and component shares.
// The fixture generator is the Rust decryption test; this test never contacts a
// YubiKey, requests a PIN, opens network connections or persists real secrets.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import init,{prepare_decryption,finalize_decryption,cancel_decryption,verify_detached} from '../pkg/sequoia_iwa_verify.js';
await init({module_or_path:fs.readFileSync(new URL('../pkg/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const f=JSON.parse(fs.readFileSync(process.argv[2]));
const prepare=(request=f.request)=>JSON.parse(prepare_decryption(JSON.stringify(request)));
const finish=reply=>JSON.parse(finalize_decryption(JSON.stringify(reply)));
const first=prepare();
for(const name of ['requestId','cipherHash','recipientKey','mlkemCiphertext','x25519Ephemeral'])assert.equal(first[name],f.reply[name]);
assert.equal(Buffer.from(first.mlkemCiphertext,'base64').length,1088);
assert.equal(Buffer.from(first.x25519Ephemeral,'base64').length,32);
const clear=finish(f.reply);assert.equal(clear.raw,f.payload);assert.equal(clear.encrypted,true);
assert.equal(clear.sessionKey,undefined);assert.equal(clear.mlkemSecret,undefined);assert.equal(clear.x25519Secret,undefined);
const verified=JSON.parse(verify_detached(JSON.stringify({payload:clear.raw,signature:clear.signature,certificates:[f.certificate]})));
assert.equal(verified.signatures.length,1);assert.equal(verified.signatures[0].status,'valid');
assert.throws(()=>finish(f.reply),'Successful response is one-use');

// Every binding and both components are checked, with no recovery by resending
// a correct reply after a malformed/incorrect one. Failure consumes state first.
for(const [label,mutate] of [
 ['request',v=>v.requestId='F'.repeat(64)],
 ['fingerprint',v=>v.recipientKey='0'.repeat(64)],
 ['ciphertext-hash',v=>v.cipherHash='0'.repeat(64)],
 ['encapsulation',v=>v.mlkemCiphertext=Buffer.alloc(1088).toString('base64')],
 ['ephemeral',v=>v.x25519Ephemeral=Buffer.alloc(32,7).toString('base64')],
 ['ML-KEM-share',v=>v.mlkemSecret=Buffer.alloc(32,7).toString('base64')],
 ['X25519-share',v=>v.x25519Secret=Buffer.alloc(32,7).toString('base64')],
 ['zero-X25519-share',v=>v.x25519Secret=Buffer.alloc(32).toString('base64')],
 ['short-share',v=>v.mlkemSecret=Buffer.alloc(31).toString('base64')],
 ['extra-field',v=>v.sessionKey='not allowed'],
 ['missing-field',v=>delete v.x25519Secret]
]){
 prepare();const bad={...f.reply};mutate(bad);assert.throws(()=>finish(bad),label);
 assert.throws(()=>finish(f.reply),label+' must consume operation');
}
prepare();assert.throws(()=>prepare(),'Concurrent prepare cannot replace pending state');assert.equal(finish(f.reply).raw,f.payload);
prepare();cancel_decryption();assert.throws(()=>finish(f.reply));
prepare();assert.throws(()=>finalize_decryption('{'));assert.throws(()=>finish(f.reply));
prepare();assert.throws(()=>finalize_decryption(' '.repeat(8193)));assert.throws(()=>finish(f.reply));

// The deadline is taken inside WASM, never accepted from the transport. A slow
// but timely PIN is allowed; backwards clock movement and expiry fail closed.
const now=Date.now;
for(const offset of [360001,-10000]){
 prepare();Date.now=()=>now()+offset;
 try{assert.throws(()=>finish(f.reply));}finally{Date.now=now;}
 assert.throws(()=>finish(f.reply));
}
prepare();Date.now=()=>now()+60000;
try{assert.equal(finish(f.reply).raw,f.payload);}finally{Date.now=now;}
for(const patch of [{recipientKey:'0'.repeat(64)},{purpose:'other'},{slot:'9d'},
 {cipher:Buffer.from('plaintext').toString('base64')},{requestId:'a'.repeat(64)}]){
 assert.throws(()=>prepare({...f.request,...patch}));
}
prepare(f.vault.request);const vault=finish(f.vault.reply);assert.equal(vault.raw,f.vault.payload);assert.equal(vault.signature,'');
prepare({...f.vault.request,purpose:'message'});assert.throws(()=>finish(f.vault.reply),'Unsigned vault is not accepted as a signed message');
console.log('PASS split WASM PKESK parsing, RFC 9980 combine/key recovery, authenticated message/vault opening and hybrid verification; wrong bindings/components, extra/missing fields, replay, concurrent preparation, cancel, expiry and malformed replies rejected');
