// Full browser orchestration using disposable software keys as the hardware
// oracle. No native PIN dialog, user identity or Google session is accessed.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {Worker} from 'node:worker_threads';
import {spawnSync} from 'node:child_process';
import {signAndEncrypt} from '../app/signing-session.js';
import {readMessage,envelope,bytes64} from '../app/message-mime.js';
import {gmailEnvelope} from '../app/compose-review.js';

const directory=process.argv[2],fixture=process.env.IWA_SIGNING_FIXTURE_BIN,sq=process.env.TEST_SQ;
assert(directory&&fixture&&sq,'Disposable fixture directory, IWA_SIGNING_FIXTURE_BIN and TEST_SQ required');
const input=JSON.parse(fs.readFileSync(path.join(directory,'request.json')));
const fixtureCall=(op,secret,request)=>{
 const r=spawnSync(fixture,[op,path.join(directory,secret)],{input:JSON.stringify(request),maxBuffer:2*1024*1024});
 assert.equal(r.status,0,r.stderr.toString());return JSON.parse(r.stdout);
};
// Obtain public selection using the same PIN-free native operation as the live
// prepare route, with disposable public material rather than installed config.
const nativeBinary=process.env.IWA_CRYPTO_TEST_BIN||path.resolve(path.dirname(fixture),'..','sequoia-iwa-crypto');
const selection=spawnSync(nativeBinary,[],{input:JSON.stringify({op:'signing-material',own:input.senderCertificate}),maxBuffer:16384});
assert.equal(selection.status,0,selection.stderr.toString());
const probe=JSON.parse(selection.stdout);
const material={...input,review:'a'.repeat(48),signingFingerprint:probe.signingFingerprint,
 subject:'WASM signing ✓ — multipart test',service:'Gmail'};
const attachment=Uint8Array.from({length:1024},(_,i)=>i%256);
const compose={sender:input.senderEmail,recipient:input.recipientEmail,subject:material.subject,
 body:'Exact plain text ü\r\nSecond line.',html:'<p>Exact <strong>formatted ü</strong> text.</p>',
 attachments:[{name:'fixture.bin',data:Buffer.from(attachment).toString('base64')}]};
let nativeCalls=0;
class BrowserWorker {
 constructor(){this.thread=new Worker(new URL('./signing-worker-node.mjs',import.meta.url),{type:'module'});
  this.thread.on('message',data=>this.onmessage?.({data}));this.thread.on('error',e=>this.onerror?.(e));}
 postMessage(data){this.thread.postMessage(data);}
 terminate(){return this.thread.terminate();}
}
const options={createWorker:()=>new BrowserWorker(),timeoutMs:30000};
const native=async request=>{
 nativeCalls++;
 assert.deepEqual(Object.keys(request).sort(),['digest','hashAlgorithm','requestId','review','signingFingerprint']);
 assert.equal(Buffer.from(request.digest,'base64').length,64);
 const {review,...digest}=request;return fixtureCall('sign','sender-secret.pgp',digest);
};
const result=await signAndEncrypt(material,compose,native,options);
assert.equal(nativeCalls,1);
const cipher=path.join(directory,'worker-encrypted.pgp'),clear=path.join(directory,'worker-decrypted.mime');
// Exercise the actual IWA-owned PGP/MIME transport wrapper before native sq.
// The envelope exposes only generic headers and must not alter the exact WASM
// ciphertext. No native draft/export route or account credential is involved.
const outgoing=gmailEnvelope(compose.sender,compose.recipient,result.cipher);
const transport=bytes64(outgoing),extracted=envelope(transport);
assert.equal(extracted.kind,'encrypted');
assert.deepEqual(Buffer.from(extracted.cipher),Buffer.from(result.cipher,'base64'));
assert.ok(!new TextDecoder().decode(transport).includes(compose.subject));
fs.writeFileSync(path.join(directory,'worker-encrypted.eml'),transport,{mode:0o600});
fs.writeFileSync(cipher,extracted.cipher,{mode:0o600});
const verified=spawnSync(sq,['--home=none','--cert-store=none','--key-store=none','--overwrite','decrypt',
 '--recipient-file',path.join(directory,'recipient-secret.pgp'),'--signer-file',path.join(directory,'sender-public.pgp'),
 '--output',clear,cipher],{encoding:'utf8'});
assert.equal(verified.status,0,verified.stderr);
const parsed=await readMessage({raw:fs.readFileSync(clear).toString('base64')},{certificates:[],bindings:[],saved:[]},()=>assert.fail('Already verified independently'));
assert.equal(parsed.subject,compose.subject);assert.equal(parsed.sender,compose.sender);
assert.equal(parsed.text.replace(/\r\n/g,'\n').trim(),compose.body.replace(/\r\n/g,'\n'));
assert.equal(parsed.html.trim(),compose.html);assert.equal(parsed.attachments.length,1);
assert.equal(parsed.attachments[0].name,'fixture.bin');assert.deepEqual(Buffer.from(parsed.attachments[0].data,'base64'),Buffer.from(attachment));

// Metadata mismatches and excessive size are rejected in the real worker before
// the native callback. A malformed hardware component never yields ciphertext.
for(const change of [{sender:'wrong@example.invalid'},{recipient:'wrong@example.invalid'},{subject:'Changed subject'},
 {body:'x'.repeat(262144)}]){
 const before=nativeCalls;await assert.rejects(signAndEncrypt(material,{...compose,...change},native,options));assert.equal(nativeCalls,before);
}
await assert.rejects(signAndEncrypt(material,compose,async request=>{
 const response=await native(request);response.mldsa65=Buffer.alloc(3309).toString('base64');return response;
},options));
console.log('PASS real signing worker: one digest-only callback; IWA PGP/MIME wrapper preserves exact ciphertext; native sq decryption and hybrid verification; Unicode/plain/HTML/attachment recovery; pre-PIN metadata/size rejection; altered-component rejection.');
