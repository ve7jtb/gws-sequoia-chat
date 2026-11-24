// These tests exercise the asynchronous authorization boundary, not a second
// implementation of OpenPGP. Real crypto/packet tests live in wasm/tests/sign.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import {signAndEncrypt} from '../app/signing-session.js';
import {signingFailureLabel} from '../app/signing-phases.js';

const material = {review: 'a'.repeat(48)};
function fakeWorker(onPost) {
  return {terminated: false, postMessage(value) {onPost(value, this);},
    terminate() {this.terminated = true;}, emit(data) {this.onmessage({data});}};
}
function digestRequest(requestId) {
  return {type: 'sign-request', requestId, request: {requestId,
    signingFingerprint: 'A'.repeat(64), hashAlgorithm: 10,
    digest: Buffer.alloc(64, 7).toString('base64')}};
}
test('relays only the bound digest fields and completes once', async () => {
  let calls = 0, worker;
  const result = await signAndEncrypt(material, {body: 'private MIME content'}, async request => {
    calls++;
    assert.deepEqual(Object.keys(request).sort(), ['digest','hashAlgorithm','requestId','review','signingFingerprint']);
    assert.equal(request.review, material.review);
    assert.equal(request.hashAlgorithm, 10);
    return {testSignature: true};
  }, {createWorker: () => worker = fakeWorker((data, w) => {
    if (data.type === 'prepare') queueMicrotask(() => w.emit(digestRequest(data.requestId)));
    else {assert.deepEqual(data.signature, {testSignature: true}); w.emit({type: 'complete', requestId: data.requestId, cipher: 'YQ=='});}
  })});
  assert.deepEqual(result, {cipher: 'YQ=='}); assert.equal(calls, 1); assert.ok(worker.terminated);
});
test('wrong operation, unexpected completion and malformed digest never invoke hardware', async () => {
  for (const kind of ['wrong-request', 'early-complete', 'bad-digest', 'wrong-hash']) {
    let calls = 0;
    await assert.rejects(signAndEncrypt(material, {}, async () => {calls++;}, {
      createWorker: () => fakeWorker((data,w) => {
        const r = digestRequest(data.requestId);
        if (kind === 'wrong-request') r.requestId = 'B'.repeat(64);
        if (kind === 'early-complete') {r.type = 'complete'; r.cipher = 'YQ==';}
        if (kind === 'bad-digest') r.request.digest = 'YQ==';
        if (kind === 'wrong-hash') r.request.hashAlgorithm = 8;
        queueMicrotask(() => w.emit(r));
      })
    }));
    assert.equal(calls, 0, kind);
  }
});
test('duplicate signing request consumes the session; no second native call or finalization', async () => {
  let calls = 0, finishNative, postedFinalize = false;
  const pending = signAndEncrypt(material, {}, async () => {
    calls++; return new Promise(resolve => {finishNative = resolve;});
  }, {createWorker: () => fakeWorker((data,w) => {
    if (data.type === 'finalize') postedFinalize = true;
    else queueMicrotask(() => {w.emit(digestRequest(data.requestId)); w.emit(digestRequest(data.requestId)); finishNative({});});
  })});
  await assert.rejects(pending, /Unexpected signing response/);
  assert.equal(calls, 1); assert.equal(postedFinalize, false);
});
test('native failure never finalizes or retries', async () => {
  let calls = 0;
  await assert.rejects(signAndEncrypt(material, {}, async () => {calls++; throw Error('cancelled PIN');}, {
    createWorker: () => fakeWorker((data,w) => {
      assert.equal(data.type, 'prepare'); queueMicrotask(() => w.emit(digestRequest(data.requestId)));
    })
  }), error=>{
    assert.match(error.message,/Hardware signing did not complete/);
    assert.equal(error.failurePhase,'native-signature');
    assert.ok(!JSON.stringify(error).includes('cancelled PIN'));return true;
  });
  assert.equal(calls, 1);
});
test('timeout waits for in-flight native operation and discards its late response', async () => {
  let finishNative, settled = false, postedFinalize = false, worker;
  const pending = signAndEncrypt(material, {}, () => new Promise(resolve => {finishNative = resolve;}), {
    timeoutMs: 10, createWorker: () => worker = fakeWorker((data,w) => {
      if (data.type === 'finalize') postedFinalize = true;
      else queueMicrotask(() => w.emit(digestRequest(data.requestId)));
    })
  }).then(() => {settled = true;}, e => {settled = true; throw e;});
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.ok(worker.terminated); assert.equal(settled, false);
  finishNative({}); await assert.rejects(pending, /timed out/);
  assert.equal(postedFinalize, false);
});
test('abort before prepare never starts a worker', async () => {
  const controller = new AbortController(); controller.abort();
  await assert.rejects(signAndEncrypt(material, {}, () => assert.fail('native'), {
    signal: controller.signal, createWorker: () => assert.fail('worker')
  }), /cancelled/);
});
test('abort during signing retains operation lock until the native reply settles', async () => {
  const controller = new AbortController(); let finishNative, settled = false;
  const pending = signAndEncrypt(material, {}, () => new Promise(resolve => {finishNative = resolve;}), {
    signal: controller.signal, createWorker: () => fakeWorker((data,w) => {
      assert.equal(data.type, 'prepare'); queueMicrotask(() => {w.emit(digestRequest(data.requestId)); controller.abort();});
    })
  }).finally(() => {settled = true;});
  await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false);
  finishNative({}); await assert.rejects(pending, /cancelled/);
});
test('worker error fails closed without calling the native signer', async () => {
  let worker;
  await assert.rejects(signAndEncrypt(material, {}, () => assert.fail('native'), {
    createWorker: () => worker = fakeWorker((_,w) => queueMicrotask(() => w.onerror({})))
  }), /no native fallback/);
  assert.ok(worker.terminated);
});

test('v5 inline digest is confined to explicitly authenticated software or hardware compatibility material',async()=>{
 for(const custody of ['softwareProfile','hardwareProfile'])for(const profile of [undefined,'level3','level3-v5-hybrid']){
  let calls=0;
  const operation=signAndEncrypt({...material,[custody]:profile},{},async r=>{calls++;assert.equal(r.inlineDigest,Buffer.alloc(64,9).toString('base64'));return {};},{createWorker:()=>fakeWorker((data,w)=>{
   if(data.type==='prepare'){const r=digestRequest(data.requestId);r.request.inlineDigest=Buffer.alloc(64,9).toString('base64');queueMicrotask(()=>w.emit(r));}
   else w.emit({type:'complete',requestId:data.requestId,cipher:'YQ=='});
  })});
  if(profile==='level3-v5-hybrid'){await operation;assert.equal(calls,1);}
  else {await assert.rejects(operation,/compatibility/);assert.equal(calls,0);}
 }
});


test('companion wrapping share is dropped after handoff and after cancellation',async()=>{
 for(const cancelled of [false,true]){
  const controller=new AbortController(),response={companionShared:'transient wrapping secret',companion:{encoded:'ciphertext'}};
  let transferred;
  const pending=signAndEncrypt(material,{},async()=>{if(cancelled)controller.abort();return response;},{signal:controller.signal,createWorker:()=>fakeWorker((data,w)=>{
   if(data.type==='prepare')queueMicrotask(()=>w.emit(digestRequest(data.requestId)));
   else {transferred=structuredClone(data.signature);w.emit({type:'complete',requestId:data.requestId,cipher:'YQ=='});}
  })});
  if(cancelled)await assert.rejects(pending,/cancelled/);else {await pending;assert.equal(transferred.companionShared,'transient wrapping secret');}
  assert.equal(Object.hasOwn(response,'companionShared'),false);
 }
});

test('worker diagnostics preserve only allowlisted phase codes and discard exception details',async()=>{
 for(const phase of ['signing-preparation','companion-completion','signature-finalization','recipient-encryption','private share: SECRET',undefined]){
  let calls=0;
  await assert.rejects(signAndEncrypt(material,{},async()=>{calls++;return {companionShared:'SECRET'};},{createWorker:()=>fakeWorker((data,w)=>{
   if(data.type==='prepare')queueMicrotask(()=>w.emit(digestRequest(data.requestId)));
   else w.emit({type:'error',requestId:data.requestId,failurePhase:phase,message:'SECRET',stack:'private/path/SECRET'});
  })}),error=>{
   assert.equal(error.failurePhase,['signing-preparation','companion-completion','signature-finalization','recipient-encryption'].includes(phase)?phase:'signing-unknown');
   assert.equal(Object.hasOwn(error,'stack'),true); // Only the local fixed-message stack exists.
   assert.ok(!String(error.stack).includes('SECRET'));assert.ok(!JSON.stringify(error).includes('SECRET'));
   assert.ok(!signingFailureLabel(error.failurePhase).includes('SECRET'));return true;
  });
  assert.equal(calls,1);
 }
});
test('failed structured-clone handoff has a browser phase and still releases the companion share',async()=>{
 const response={companionShared:'SECRET'};let calls=0;
 await assert.rejects(signAndEncrypt(material,{},async()=>{calls++;return response;},{createWorker:()=>fakeWorker((data,w)=>{
  if(data.type==='prepare')queueMicrotask(()=>w.emit(digestRequest(data.requestId)));
  else throw Error('SECRET from failed clone');
 })}),error=>{assert.equal(error.failurePhase,'signing-worker');assert.ok(!String(error).includes('SECRET'));return true;});
 assert.equal(calls,1);assert.equal(Object.hasOwn(response,'companionShared'),false);
});
