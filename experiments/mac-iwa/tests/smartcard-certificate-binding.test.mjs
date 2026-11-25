// Exercise the real shipped WASM normalization on public certificates only.
// No reader, PIN, private key, account access, or card mutation is involved.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {Worker as Thread} from 'node:worker_threads';
import init,{inspect_identity,smartcard_signing_input} from '../app/wasm/sequoia_iwa_verify.js';
import {smartcardSigningInput} from '../app/identities/client.js';
import {assertSelectedCardIdentity} from '../app/identities/bundle.js';

await init({module_or_path:fs.readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const inspect=certificate=>JSON.parse(inspect_identity(JSON.stringify({certificate})));
const directory=process.env.IWA_IDENTITY_PUBLIC_FIXTURES;
assert(directory,'Set IWA_IDENTITY_PUBLIC_FIXTURES to restored public certificates');
const armored=fs.readFileSync(directory+'/openpgp-v6.asc').toString('base64');
const info=inspect(armored);
const selected={...info,serial:'123456',bundleHash:'a'.repeat(64)};
const fresh={serial:selected.serial,bundleHash:selected.bundleHash,bundleSignatureVerified:true,liveKeysMatched:true,certificates:[{certificate:armored}]};

test('armored card certificate matches canonical stored packets via real WASM',async()=>{
 assert.notEqual(armored,selected.certificate,'Regression fixture must reproduce differing encodings');
 await assertSelectedCardIdentity(fresh,selected,inspect);
});

test('changed bundle, serial, fingerprint, full certificate and evidence fail closed',async()=>{
 for(const patch of [{bundleHash:'b'.repeat(64)},{serial:'654321'},{bundleSignatureVerified:false},{liveKeysMatched:false}])
  await assert.rejects(assertSelectedCardIdentity({...fresh,...patch},selected,inspect));
 for(const patch of [{certificateHash:'b'.repeat(64)},{fingerprint:'B'.repeat(64)},{certificate:selected.certificate+'AA=='}])
  await assert.rejects(assertSelectedCardIdentity(fresh,{...selected,...patch},inspect));
});

test('invalid certificate inspection cannot authorize a private operation',async()=>{
 await assert.rejects(assertSelectedCardIdentity({...fresh,certificates:[{certificate:'AAAA'}]},selected,inspect));
 await assert.rejects(assertSelectedCardIdentity({...fresh,certificates:[]},selected,inspect));
});

test('page client reaches actual worker and WASM for public external-mu preparation',async()=>{
 // Exercise the real message protocol, not a mock dispatcher that could hide
 // hyphen/underscore routing differences. Workers have no card or native API.
 const previous=globalThis.Worker;
 globalThis.Worker=class {
  constructor(url,options){
   assert.equal(url,'/identities/worker.js');assert.deepEqual(options,{type:'module'});
   this.thread=new Thread(new URL('./identity-worker-node.mjs',import.meta.url));
   this.thread.on('message',data=>this.onmessage?.({data}));
   this.thread.on('error',error=>this.onerror?.(error));
  }
  postMessage(data){this.thread.postMessage(data);}
  terminate(){return this.thread.terminate();}
 };
 try{
  const input={certificate:info.certificate,signingFingerprint:info.signingFingerprint,digest:Buffer.alloc(64,23).toString('base64')};
  const result=await smartcardSigningInput(input);
  assert.deepEqual(result,JSON.parse(smartcard_signing_input(JSON.stringify(input))));
  assert.equal(Buffer.from(result.mu,'base64').length,64);
  await assert.rejects(smartcardSigningInput({...input,signingFingerprint:'F'.repeat(64)}));
  await assert.rejects(smartcardSigningInput({...input,digest:'AAAA'}));
 }finally{globalThis.Worker=previous;}
});
