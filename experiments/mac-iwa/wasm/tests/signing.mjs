// Exercise the exact browser-target WASM module against an independent native
// OpenSSL-backed Sequoia signer.  The fixture creates disposable software keys;
// no application identity, PIN, token or card is used by this regression suite.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import init,{prepare_signing,finalize_signing,cancel_signing,encrypt_signed,verify_detached} from '../pkg/sequoia_iwa_verify.js';
await init({module_or_path:fs.readFileSync(new URL('../pkg/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const dir=process.argv[2],fixture=process.env.IWA_SIGNING_FIXTURE_BIN;
assert(dir&&fixture&&process.env.TEST_SQ,'Fixture directory, IWA_SIGNING_FIXTURE_BIN and TEST_SQ required');
const request=JSON.parse(fs.readFileSync(path.join(dir,'request.json')));
const prepare=(value=request)=>JSON.parse(prepare_signing(JSON.stringify(value)));
const finish=value=>JSON.parse(finalize_signing(JSON.stringify(value)));
function native(args,input){
 const r=spawnSync(fixture,args,{input:JSON.stringify(input),maxBuffer:2*1024*1024});
 assert.equal(r.status,0,r.stderr.toString());return r.stdout;
}
const sign=digest=>JSON.parse(native(['sign',path.join(dir,'sender-secret.pgp')],digest));
const payload=Buffer.from(request.payload,'base64');

// Inspect just the standards-defined new-format packet headers needed by this
// fixture. The independent native verifier remains the cryptographic oracle.
function packets(encoded){
 const bytes=Buffer.from(encoded,'base64'),out=[];let p=0;
 while(p<bytes.length){
  const tag=bytes[p++];assert.equal(tag&0xc0,0xc0);let n=bytes[p++];
  if(n===255){n=bytes.readUInt32BE(p);p+=4;}
  else if(n>=192&&n<224)n=((n-192)<<8)+bytes[p++]+192;
  else assert(n<192,'No partial-length packet expected in this bounded fixture');
  assert(p+n<=bytes.length);out.push({tag:tag&63,body:bytes.subarray(p,p+n)});p+=n;
 }
 return out;
}
function signatureMetadata(value){
 const p=packets(value.signed);assert.deepEqual(p.map(x=>x.tag),[4,11,2]);
 const ops=p[0].body,sig=p[2].body;
 assert.equal(ops[0],6);assert.equal(sig[0],6);assert.equal(ops[4],32);
 const hashedLength=sig.readUInt32BE(4),end=8+hashedLength;
 const unhashedLength=sig.readUInt32BE(end),saltAt=end+4+unhashedLength+2;
 assert.equal(sig[saltAt],32);assert.deepEqual(ops.subarray(5,37),sig.subarray(saltAt+1,saltAt+33));
 let creation;for(let pos=8;pos<end;){const length=sig[pos++];assert(length<192);const type=sig[pos]&127;if(type===2){assert.equal(length,5);creation=sig.readUInt32BE(pos+1);}pos+=length;}
 assert.equal(typeof creation,'number');return {salt:sig.subarray(saltAt+1,saltAt+33),creation};
}

// Round-trip exact bytes in both signed OpenPGP and detached PGP/MIME forms.
const first=prepare(),reply=sign(first),result=finish(reply);
assert.deepEqual(Buffer.from(result.payload,'base64'),payload);
const metadata=signatureMetadata(result);
const verified=native(['verify',path.join(dir,'sender-public.pgp')],result);
assert.deepEqual(verified,payload);
const detached=JSON.parse(verify_detached(JSON.stringify({payload:request.payload,signature:result.signature,certificates:[request.senderCertificate]})));
assert.equal(detached.signatures.length,1);assert.equal(detached.signatures[0].status,'valid');
assert.equal(detached.signatures[0].signingFingerprint,first.signingFingerprint);
assert.throws(()=>finish(reply),'A response cannot be replayed after success');

// Same content gets a new v6 salt, hence a different digest, on every operation.
const second=prepare();assert.notEqual(second.digest,first.digest);
assert.throws(()=>prepare(),'Concurrent preparation must not replace pending state');
const secondResult=finish(sign(second));
assert.deepEqual(native(['verify',path.join(dir,'sender-public.pgp')],secondResult),payload);
assert(!signatureMetadata(secondResult).salt.equals(metadata.salt));

// Independently corrupt every native response binding or component.  A failed
// finalize must consume the operation; resubmitting the genuine reply is denied.
for(const [label,mutate] of [
 ['request',v=>v.requestId='F'.repeat(64)],
 ['fingerprint',v=>v.signingFingerprint='0'.repeat(64)],
 ['hash',v=>v.hashAlgorithm=9],
 ['digest',v=>v.digest=Buffer.alloc(64).toString('base64')],
 ['Ed25519',v=>{const b=Buffer.from(v.ed25519,'base64');b[0]^=1;v.ed25519=b.toString('base64');}],
 ['ML-DSA-65',v=>{const b=Buffer.from(v.mldsa65,'base64');b[0]^=1;v.mldsa65=b.toString('base64');}],
 ['short-Ed25519',v=>v.ed25519=Buffer.alloc(63).toString('base64')],
 ['short-ML-DSA',v=>v.mldsa65=Buffer.alloc(3308).toString('base64')]
]){
 const good=sign(prepare()),bad={...good};mutate(bad);
 assert.throws(()=>finish(bad),label);assert.throws(()=>finish(good),label+' must consume state');
}
const cancelled=sign(prepare());cancel_signing();assert.throws(()=>finish(cancelled));
const malformed=sign(prepare());assert.throws(()=>finalize_signing('{'));assert.throws(()=>finish(malformed));
const oversized=sign(prepare());assert.throws(()=>finalize_signing(' '.repeat(16385)));assert.throws(()=>finish(oversized));

// Advance only the test process clock.  Production code takes its own clock,
// not a caller-supplied deadline, and rejects backwards movement as well.
const realNow=Date.now;
const preparedSecond=Math.floor(realNow()/1000),delayedReply=sign(prepare());
Date.now=()=>realNow()+60000;let delayed;
try{delayed=finish(delayedReply);}finally{Date.now=realNow;}
assert(Math.abs(signatureMetadata(delayed).creation-preparedSecond)<=1,'Preparation timestamp must survive delayed PIN response');
assert.deepEqual(native(['verify',path.join(dir,'sender-public.pgp')],delayed),payload);
for(const offset of [360001,-10000]){
 const ready=sign(prepare());Date.now=()=>realNow()+offset;
 try{assert.throws(()=>finish(ready));}finally{Date.now=realNow;}
 assert.throws(()=>finish(ready));
}

// Reject malformed/oversized inputs and any attempt to supply private material
// as the sender certificate.  Public-only verification never confers trust.
for(const change of [
 {senderEmail:'other@example.invalid'},
 {requestId:'f'.repeat(64)},
 {requestId:'A'.repeat(63)},
 {payload:''},
 {payload:Buffer.alloc(262144-8192+1).toString('base64')},
 {senderCertificate:fs.readFileSync(path.join(dir,'sender-secret.pgp')).toString('base64')},
 {senderCertificate:Buffer.from('invalid certificate').toString('base64')}
])assert.throws(()=>prepare({...request,...change}));

// A complete v6 signed result enters the existing public encryption API without
// a native signing packet constructor.  Sequoia independently decrypts and
// verifies it; altered signed MIME must still fail at the encryption boundary.
if(process.env.TEST_SQ){
 const recipientCertificate=fs.readFileSync(path.join(dir,'recipient-public.pgp')).toString('base64');
 const metadata={recipientEmail:request.recipientEmail,recipientFingerprint:request.recipientFingerprint};
 const encryption={...metadata,senderCertificate:request.senderCertificate,recipientCertificate,payload:result.payload,signed:result.signed};
 const encrypted=JSON.parse(encrypt_signed(JSON.stringify(encryption)));
 const input=path.join(dir,'wasm-signed-encrypted.pgp'),output=path.join(dir,'wasm-signed-encrypted.mime');
 fs.writeFileSync(input,Buffer.from(encrypted.cipher,'base64'));
 const r=spawnSync(process.env.TEST_SQ,['--home=none','--cert-store=none','--key-store=none','--overwrite','decrypt','--recipient-file',path.join(dir,'recipient-secret.pgp'),'--signer-file',path.join(dir,'sender-public.pgp'),'--signatures','1','--output',output,input],{encoding:'utf8'});
 assert.equal(r.status,0,r.stderr);assert.deepEqual(fs.readFileSync(output),payload);
 assert.throws(()=>encrypt_signed(JSON.stringify({...encryption,payload:Buffer.from('tampered').toString('base64')})));
}
console.log('PASS WASM split signing: native OpenSSL verification, detached verification, fresh salt, replay/concurrency/cancel/expiry protection, both-component tampering, binding/length/secret-key limits and signed encryption interop');
