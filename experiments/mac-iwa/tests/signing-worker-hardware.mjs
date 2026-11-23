// Hardware counterpart to signing-worker-interop.mjs. The real browser signing
// worker runs through the Node Web Worker shim; only its digest request is sent
// over this process's anonymous pipes to the Python native host. PINs never
// enter Node, worker memory, command arguments or this JSON protocol.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {Worker} from 'node:worker_threads';
import {spawnSync} from 'node:child_process';
import readline from 'node:readline';
import {signAndEncrypt} from '../app/signing-session.js';
import {readMessage} from '../app/message-mime.js';

const lines=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
const iterator=lines[Symbol.asyncIterator]();
async function receive(){const r=await iterator.next();assert(!r.done,'Native pipe closed');return JSON.parse(r.value);}
const start=await receive();
assert.equal(start.type,'start');
const {directory,sq,material}=start;
const attachment=Uint8Array.from({length:1024},(_,i)=>i%256);
const compose={sender:material.senderEmail,recipient:material.recipientEmail,subject:material.subject,
 body:'Synthetic physical YubiKey test: WASM constructs the signature.\r\nNo email is sent.',
 html:'<p>Synthetic physical YubiKey test: <strong>WASM constructs the signature.</strong></p><p>No email is sent.</p>',
 attachments:[{name:'synthetic-bytes.bin',data:Buffer.from(attachment).toString('base64')}]};

class BrowserWorker {
 constructor(){this.thread=new Worker(new URL('./signing-worker-node.mjs',import.meta.url),{type:'module'});
  this.thread.on('message',data=>this.onmessage?.({data}));this.thread.on('error',error=>this.onerror?.(error));}
 postMessage(data){this.thread.postMessage(data);}
 terminate(){return this.thread.terminate();}
}
let calls=0;
try {
 const result=await signAndEncrypt(material,compose,async request=>{
  calls++;assert.equal(calls,1,'Hardware must never be retried');
  assert.deepEqual(Object.keys(request).sort(),['digest','hashAlgorithm','requestId','review','signingFingerprint']);
  assert.equal(Buffer.from(request.digest,'base64').length,64);
  // Only this bounded digest request crosses to Python. The selected keys and
  // native signer paths are fixed by installed configuration, not this worker.
  process.stdout.write(JSON.stringify({type:'sign',request})+'\n');
  const response=await receive();assert.equal(response.type,'signature');return response.value;
 },{createWorker:()=>new BrowserWorker(),timeoutMs:360000});
 assert.equal(calls,1);
 const cipher=path.join(directory,'hardware-signed-encrypted.pgp');
 const clear=path.join(directory,'verified-multipart.mime');
 fs.writeFileSync(cipher,Buffer.from(result.cipher,'base64'),{mode:0o600,flag:'wx'});
 // The recipient is disposable software material generated solely for this
 // test. Native sq independently decrypts and verifies the physical sender's
 // hybrid signature without a second YubiKey operation or PIN.
 const checked=spawnSync(sq,['--home=none','--cert-store=none','--key-store=none','decrypt',
  '--recipient-file',path.join(directory,'fixture','recipient-secret.pgp'),
  '--signer-file',path.join(directory,'sender-public.pgp'),'--output',clear,cipher],
  {encoding:'utf8',timeout:60000,maxBuffer:262144});
 fs.writeFileSync(path.join(directory,'independent-sq.log'),checked.stderr||'',{mode:0o600});
 assert.equal(checked.status,0,'Independent sq decryption/signature verification failed');
 const raw=fs.readFileSync(clear);
 const parsed=await readMessage({raw:raw.toString('base64')},{certificates:[],bindings:[],saved:[]},()=>assert.fail('Already independently verified'));
 assert.equal(parsed.subject,compose.subject);assert.equal(parsed.sender,compose.sender);
 assert.equal(parsed.text.replace(/\r\n/g,'\n').trim(),compose.body.replace(/\r\n/g,'\n'));
 assert.equal(parsed.html.trim(),compose.html);assert.equal(parsed.attachments.length,1);
 assert.equal(parsed.attachments[0].name,'synthetic-bytes.bin');
 assert.deepEqual(Buffer.from(parsed.attachments[0].data,'base64'),Buffer.from(attachment));
 process.stdout.write(JSON.stringify({type:'complete',result:{passed:true,nativeSigningRequests:calls,
  signature:'ML-DSA-65 + Ed25519',recipient:'disposable ML-KEM-768 + X25519 software key',
  independentDecryptionAndVerification:true,multipartTextHtmlAndAttachmentVerified:true,
  ciphertextBytes:Buffer.from(result.cipher,'base64').length}})+'\n');
}catch(_){
 // The native host logs only this fixed status, never an arbitrary exception or
 // a native response that could accidentally contain sensitive data.
 process.stdout.write(JSON.stringify({type:'failure',nativeSigningRequests:calls,message:'WASM/hardware interoperability stopped; no retry.'})+'\n');
 process.exitCode=1;
}finally{lines.close();}
