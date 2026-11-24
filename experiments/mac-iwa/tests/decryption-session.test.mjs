// Exercise the actual IWA coordinator under asynchronous failures. These are
// boundary tests: mocked hardware never parses packets or supplies real keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {decryptWithHardware} from '../app/decryption-session.js';

// Selected message authority is public-only and contains no caller-selected slot
// or executable. The native helper independently authenticates this binding.
const identity = {serial:'12345678',bundleHash:'d'.repeat(64),fingerprint:'E'.repeat(64),
  certificateHash:'f'.repeat(64),email:'recipient@example.invalid'};
const material = {identity, review: 'a'.repeat(48), recipientKey: 'B'.repeat(64),
  recipientCertificate: Buffer.from('synthetic public certificate').toString('base64')};
const cipher = Buffer.from('whole encrypted OpenPGP message must stay in IWA').toString('base64');
const cipherHash=createHash('sha256').update(Buffer.from(cipher,'base64')).digest('hex');
const verification = {material: {trusted: true}, expectedEmail: 'sender@example.invalid',
  expectedFingerprint: 'C'.repeat(64), recipient: 'recipient@example.invalid'};
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {let resolve;const promise = new Promise(done => {resolve = done;});return {promise, resolve};}
function request(requestId) {return {requestId, cipherHash, recipientKey: material.recipientKey,
  mlkemCiphertext: Buffer.alloc(1088, 17).toString('base64'), x25519Ephemeral: Buffer.alloc(32, 18).toString('base64')};}
function shares(r) {return {...r, mlkemSecret: Buffer.alloc(32, 19).toString('base64'),
  x25519Secret: Buffer.alloc(32, 20).toString('base64')};}
function worker(onPost) {return {terminated: false, posts: [],
  postMessage(value) {const copy = structuredClone(value);this.posts.push(copy);onPost(copy, this);},
  terminate() {this.terminated = true;}, emit(value) {this.onmessage({data: structuredClone(value)});}};}
function options(overrides = {}) {return {cipher, service: 'Gmail', verification,
  identity:structuredClone(identity),validateMaterial:async value=>{
    assert.deepEqual(value.identity,identity,'Native selection differs from the matched identity');
  },...overrides};}
function componentEvent(data, w) {queueMicrotask(() => w.emit({type: 'component-request',
  requestId: data.requestId, request: request(data.requestId)}));}

test('only bound component inputs reach native; full packet, trust and session key stay in IWA', async () => {
  const calls = [];let w, returned;
  const result = await decryptWithHardware(options({native: async (op, value, controls) => {
    calls.push({op, value: structuredClone(value)});assert.ok(controls.signal instanceof AbortSignal);
    if (op === 'chat-selected-decryption-material') {
      assert.deepEqual(value,{service:'Gmail',identity});return structuredClone(material);
    }
    assert.equal(op, 'chat-decapsulate-components');
    assert.deepEqual(Object.keys(value).sort(), ['cipherHash','mlkemCiphertext','recipientKey','requestId','review','service','x25519Ephemeral']);
    assert.equal(value.review, material.review);assert.equal(value.service, 'Gmail');
    assert.ok(!JSON.stringify(value).includes(cipher));
    assert.ok(!JSON.stringify(value).includes('sender@example.invalid'));
    return returned = shares(request(value.requestId));
  }, createWorker: () => w = worker((data, target) => {
    if (data.type === 'prepare') {assert.equal(data.cipher, cipher);assert.deepEqual(data.verification, verification);componentEvent(data, target);}
    else {assert.equal(data.result.mlkemSecret.length, 44);assert.equal(data.result.x25519Secret.length, 44);
      queueMicrotask(() => target.emit({type: 'complete', requestId: data.requestId, result: {verified: true}}));}
  })}));
  assert.deepEqual(result, {verified: true});assert.equal(calls.length, 2);assert.ok(w.terminated);
  assert.equal(returned.mlkemSecret, undefined);assert.equal(returned.x25519Secret, undefined);
});

test('invalid service/purpose and already-aborted operations never contact native', async () => {
  for (const change of [{service: 'SMTP'}, {service: 'Vault'}, {purpose: 'vault'}, {purpose: 'anything'}])
    await assert.rejects(decryptWithHardware(options({...change, native: () => assert.fail('native'), createWorker: () => assert.fail('worker')})), /purpose/);
  const controller = new AbortController();controller.abort();
  await assert.rejects(decryptWithHardware(options({signal: controller.signal,
    native: () => assert.fail('native'), createWorker: () => assert.fail('worker')})), /cancelled/);
});

test('abort while obtaining metadata discards the eventual grant without starting a worker', async () => {
  const controller = new AbortController(), metadata = deferred(),started=deferred();let nativeSignal;
  const running = decryptWithHardware(options({signal: controller.signal,
    native: (_, __, controls) => {nativeSignal = controls.signal;started.resolve();return metadata.promise;},
    createWorker: () => assert.fail('worker after cancellation')}));
  const rejected = assert.rejects(running, /cancelled/);await started.promise;controller.abort();await rejected;
  assert.ok(nativeSignal.aborted);metadata.resolve(structuredClone(material));await tick();
});

test('changed or malformed configured identity stops before worker or hardware', async () => {
  for (const changed of [{...material, recipientKey: 'bad'}, {...material, review: 'bad'},
    {...material, recipientCertificate: 'x'.repeat(90001)}, {...material, recipientKey: 'E'.repeat(64)}]) {
    let calls = 0;
    await assert.rejects(decryptWithHardware(options({recipientKey: material.recipientKey,
      native: async () => {calls++;return changed;}, createWorker: () => assert.fail('worker')})), /identity changed/);
    assert.equal(calls, 1);
  }
});

test('stale operation, wrong key, unexpected completion and extra fields cannot reach hardware', async () => {
  for (const kind of ['wrong-id','wrong-key','wrong-cipher-hash','early-complete','extra-field']) {
    let calls = 0, w;
    await assert.rejects(decryptWithHardware(options({native: async op => {
      calls++;assert.equal(op, 'chat-selected-decryption-material');return structuredClone(material);
    }, createWorker: () => w = worker((data, target) => {
      const event = {type: 'component-request', requestId: data.requestId, request: request(data.requestId)};
      if (kind === 'wrong-id') event.requestId = 'F'.repeat(64);
      if (kind === 'wrong-key') event.request.recipientKey = 'F'.repeat(64);
      // A worker may only obtain shares for the exact ciphertext matched by
      // the page; a well-formed hash for another packet must fail before PIN.
      if (kind === 'wrong-cipher-hash') event.request.cipherHash='f'.repeat(64);
      if (kind === 'early-complete') event.type = 'complete';
      if (kind === 'extra-field') event.request.slot = '9d';
      queueMicrotask(() => target.emit(event));
    })})));
    assert.equal(calls, 1, kind);assert.ok(w.terminated, kind);
  }
});

test('duplicate component request consumes operation without a second private call', async () => {
  const pending = deferred(),started=deferred();let calls = 0, w, first;
  const running = decryptWithHardware(options({native: async op => {
    if (op === 'chat-selected-decryption-material') return structuredClone(material);
    calls++;started.resolve();return pending.promise;
  }, createWorker: () => w = worker((data, target) => {
    assert.equal(data.type, 'prepare');first = {type: 'component-request', requestId: data.requestId, request: request(data.requestId)};
    queueMicrotask(() => target.emit(first));
  })}));
  const rejected = assert.rejects(running, /rejected/);await started.promise;assert.equal(calls, 1);
  w.emit(first);await rejected;pending.resolve(shares(first.request));await tick();
  assert.equal(calls, 1);assert.deepEqual(w.posts.map(p => p.type), ['prepare']);assert.ok(w.terminated);
});

test('native failure never retries or releases a plaintext result', async () => {
  let calls = 0, w;
  await assert.rejects(decryptWithHardware(options({native: async op => {
    if (op === 'chat-selected-decryption-material') return structuredClone(material);
    calls++;throw Error('private operation failed');
  }, createWorker: () => w = worker((data, target) => {assert.equal(data.type, 'prepare');componentEvent(data, target);})})), /private operation failed/);
  assert.equal(calls, 1);assert.ok(w.terminated);assert.equal(w.posts.length, 1);
});

test('timeout aborts transport and rejects late component secrets without finalization', async () => {
  const pending = deferred();let nativeSignal, w, r;
  const running = decryptWithHardware(options({timeoutMs: 15, native: async (op, value, controls) => {
    if (op === 'chat-selected-decryption-material') return structuredClone(material);
    nativeSignal = controls.signal;r = request(value.requestId);return pending.promise;
  }, createWorker: () => w = worker(componentEvent)}));
  await assert.rejects(running, /timed out/);assert.ok(w.terminated);assert.ok(nativeSignal.aborted);
  const reply = shares(r);pending.resolve(reply);await tick();
  assert.equal(w.posts.length, 1);assert.equal(reply.mlkemSecret, undefined);assert.equal(reply.x25519Secret, undefined);
});

test('vault lock during hardware drops its late response and destroys the worker', async () => {
  const controller = new AbortController(), pending = deferred(),started=deferred();let w, r;
  const running = decryptWithHardware(options({signal: controller.signal, native: async (op, value) => {
    if (op === 'chat-selected-decryption-material') return structuredClone(material);
    r = request(value.requestId);started.resolve();return pending.promise;
  }, createWorker: () => w = worker(componentEvent)}));
  const rejected = assert.rejects(running, /cancelled/);await started.promise;controller.abort();await rejected;
  pending.resolve(shares(r));await tick();assert.ok(w.terminated);assert.equal(w.posts.length, 1);
});

test('changed trust before hardware, after hardware or before display fails closed', async () => {
  // Trust/vault checks straddle every async boundary; a prior success cannot
  // authorize a private call or display after a later store revision changes.
  for (const rejectAt of [4,5,6]) {
    let checks = 0, calls = 0, w;
    await assert.rejects(decryptWithHardware(options({gate: async () => {
      checks++;if (checks === rejectAt) throw Error('trust changed');
    }, native: async (op, value) => {
      if (op === 'chat-selected-decryption-material') return structuredClone(material);
      calls++;return shares(request(value.requestId));
    }, createWorker: () => w = worker((data, target) => {
      if (data.type === 'prepare') componentEvent(data, target);
      else queueMicrotask(() => target.emit({type: 'complete', requestId: data.requestId, result: {verified: true}}));
    })})), /trust changed/);
    assert.equal(calls, rejectAt === 4 ? 0 : 1);assert.ok(w.terminated);
  }
});

test('worker error stops before hardware and uses no old native decryption route', async () => {
  const calls = [];let w;
  await assert.rejects(decryptWithHardware(options({native: async op => {
    calls.push(op);return structuredClone(material);
  }, createWorker: () => w = worker((_, target) => queueMicrotask(() => target.onerror({})))})), /no native fallback/);
  assert.deepEqual(calls, ['chat-selected-decryption-material']);assert.ok(w.terminated);
});

test('vault path sends only fixed component inputs while wrapper IDs stay in worker', async () => {
  const vault = {vaultId: 'vault-id', wrapperId: 'wrapper-id'};let calls = 0;
  const result = await decryptWithHardware(options({service: 'Vault', purpose: 'vault', vault,identity:undefined,validateMaterial:undefined,
    recipientKey: material.recipientKey, native: async (op, value) => {
      calls++;assert.equal(value.service, 'Vault');assert.equal(value.vaultId, undefined);assert.equal(value.wrapperId, undefined);
      if(calls===1){assert.equal(op,'chat-decryption-material');assert.deepEqual(value,{service:'Vault'});}
      else assert.equal(op,'chat-decapsulate-components');
      return op === 'chat-decryption-material' ? structuredClone(material) : shares(request(value.requestId));
    }, createWorker: () => worker((data, target) => {
      if (data.type === 'prepare') {assert.deepEqual(data.vault, vault);assert.equal(data.purpose, 'vault');componentEvent(data, target);}
      else queueMicrotask(() => target.emit({type: 'complete', requestId: data.requestId, result: {secret: 'test-only'}}));
    })}));
  assert.deepEqual(result, {secret: 'test-only'});assert.equal(calls, 2);
});

// Neither missing selection nor a mismatched public discovery may prompt for
// a PIN. There is deliberately no fallback to the helper's old fixed key.
test('message decryption requires a matched identity and validator before native discovery',async()=>{
 for(const changed of [{identity:undefined},{validateMaterial:undefined}]){
  await assert.rejects(decryptWithHardware(options({...changed,
   native:()=>assert.fail('No native discovery without a selected identity'),
   createWorker:()=>assert.fail('No worker without selected identity')})),/matched saved identity/);
 }
});
test('changed selected identity is rejected before a worker or private operation starts',async()=>{
 const calls=[];
 await assert.rejects(decryptWithHardware(options({
  native:async(op,value)=>{calls.push(op);assert.deepEqual(value,{service:'Gmail',identity});
   return {...structuredClone(material),identity:{...identity,serial:'87654321'}};},
  createWorker:()=>assert.fail('Do not parse using the wrong native identity')})),/Native selection differs/);
 assert.deepEqual(calls,['chat-selected-decryption-material']);
});
test('inventory change during selected-material validation fails before the PIN boundary',async()=>{
 let current=true;const calls=[];
 await assert.rejects(decryptWithHardware(options({
  gate:async()=>{if(!current)throw Error('Own identity inventory changed');},
  validateMaterial:async()=>{current=false;},
  native:async op=>{calls.push(op);return structuredClone(material);},
  createWorker:()=>assert.fail('No worker after a selected identity changes')})),/inventory changed/);
 assert.deepEqual(calls,['chat-selected-decryption-material']);
});
