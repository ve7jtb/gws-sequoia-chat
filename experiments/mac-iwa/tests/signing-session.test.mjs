// These tests exercise the asynchronous authorization boundary, not a second
// implementation of OpenPGP. Real crypto/packet tests live in wasm/tests/sign.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import {signAndEncrypt} from '../app/signing-session.js';

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
  }), /Hardware signing did not complete/);
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
