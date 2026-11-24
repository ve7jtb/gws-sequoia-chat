// Integration test for the shipped coordinator and worker using independently
// generated Sequoia software fixtures. No hardware, PIN, account or network is
// accessed. Component shares are ephemeral fixture material, never user keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {Worker} from 'node:worker_threads';
import init, {inspect_public} from '../app/wasm/sequoia_iwa_verify.js';
import {decryptWithHardware} from '../app/decryption-session.js';

const path = process.env.IWA_SPLIT_DECAP_FIXTURE;
if (!path) throw Error('Set IWA_SPLIT_DECAP_FIXTURE to the generated software-only fixture');
const fixture = JSON.parse(fs.readFileSync(path, 'utf8'));
await init({module_or_path: fs.readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm', import.meta.url))});
const info = JSON.parse(inspect_public(JSON.stringify({certificate: fixture.certificate})));
const verification = {expectedEmail: 'fixture@example.invalid', expectedFingerprint: info.fingerprint,
  recipient: 'recipient@example.invalid', material: {certificates: [fixture.certificate],
    bindings: [{email: 'fixture@example.invalid', fingerprint: info.fingerprint}], saved: [info.fingerprint]}};
const vault = {vaultId: '11111111-1111-4111-8111-111111111111', wrapperId: '22222222-2222-4222-8222-222222222222'};

class BrowserWorker {
  constructor() {
    this.thread = new Worker(new URL('./decryption-worker-node.mjs', import.meta.url), {type: 'module'});
    this.thread.on('message', data => this.onmessage?.({data}));
    this.thread.on('error', error => this.onerror?.(error));
  }
  postMessage(data) {this.thread.postMessage(data);}
  terminate() {return this.thread.terminate();}
}
function harness(source = fixture, change = {}) {
  const calls = [];
  // The fixture's recipient key is separate from its signature certificate.
  // A synthetic selected-card binding exercises the message route without
  // granting any real device authority or requiring hardware in this test.
  const identity={serial:'12345678',bundleHash:'b'.repeat(64),fingerprint:'C'.repeat(64),
    certificateHash:'d'.repeat(64),email:'recipient@example.invalid'};
  const selectedMaterial={review:'a'.repeat(48),identity,
    recipientCertificate:source.request.recipientCertificate,recipientKey:source.request.recipientKey};
  const native = async (op, value) => {
    calls.push(op);
    if(op==='chat-selected-decryption-material'){
      assert.deepEqual(value,{service:'Gmail',identity});return structuredClone(selectedMaterial);
    }
    if(op==='chat-decryption-material'){
      assert.deepEqual(value,{service:'Vault'});return structuredClone(selectedMaterial);
    }
    assert.equal(op, 'chat-decapsulate-components');
    assert.deepEqual(Object.keys(value).sort(), ['cipherHash','mlkemCiphertext','recipientKey','requestId','review','service','x25519Ephemeral']);
    // The real WASM parser must extract exactly the same public encapsulation
    // inputs as the independent Rust fixture. Never derive mock shares for a
    // changed packet by silently substituting the expected fixture request.
    for (const field of ['cipherHash','recipientKey','mlkemCiphertext','x25519Ephemeral'])
      assert.equal(value[field], source.reply[field], field);
    const {review, service, ...binding} = value;
    const result = {...binding, mlkemSecret: source.reply.mlkemSecret, x25519Secret: source.reply.x25519Secret};
    return change.reply ? change.reply(result) : result;
  };
  return {calls, run: overrides => decryptWithHardware({cipher: source.request.cipher,
    recipientKey: source.request.recipientKey, service: source.request.purpose === 'vault' ? 'Vault' : 'Gmail',
    purpose: source.request.purpose,identity,
    validateMaterial:async value=>{assert.deepEqual(value,selectedMaterial);}, verification: structuredClone(verification), vault,
    native, createWorker: () => new BrowserWorker(), timeoutMs: 30000, ...overrides})};
}

test('actual worker parses, combines, decrypts and verifies a trusted Sequoia message', async () => {
  const h = harness(), result = await h.run();
  assert.deepEqual(h.calls, ['chat-selected-decryption-material','chat-decapsulate-components']);
  assert.equal(result.encrypted, true);assert.equal(result.verified, true);
  assert.equal(result.signatureStatus, 'valid');assert.equal(result.certificateTrust, 'trusted');
  assert.equal(result.sender, 'fixture@example.invalid');assert.equal(result.subject, 'split decapsulation');
  assert.equal(result.text.trim(), 'Synthetic authenticated content.');
  assert.equal(result.sessionKey, undefined);assert.equal(result.mlkemSecret, undefined);assert.equal(result.x25519Secret, undefined);
});

test('actual worker rejects changed component secrets and operation bindings', async () => {
  for (const mutation of [r => ({...r, mlkemSecret: Buffer.alloc(32).toString('base64')}),
    r => ({...r, x25519Secret: Buffer.alloc(32).toString('base64')}),
    r => ({...r, requestId: 'F'.repeat(64)}), r => ({...r, cipherHash: 'e'.repeat(64)})]) {
    const h = harness(fixture, {reply: mutation});
    await assert.rejects(h.run(), /rejected/);
    assert.deepEqual(h.calls, ['chat-selected-decryption-material','chat-decapsulate-components']);
  }
});

test('actual worker rejects malformed recipient packets before a private request', async () => {
  for (const cipher of [Buffer.from('not OpenPGP').toString('base64'), '', fixture.request.cipher + 'AAAA']) {
    const h = harness();await assert.rejects(h.run({cipher}), /rejected/);
    assert.deepEqual(h.calls, ['chat-selected-decryption-material']);
  }
});

test('actual worker enforces selected sender, recipient, full fingerprint and trust after decryption', async () => {
  for (const change of [{expectedEmail: 'wrong@example.invalid'}, {recipient: 'wrong@example.invalid'},
    {expectedFingerprint: 'F'.repeat(64)}, {material: {...verification.material, bindings: []}}]) {
    const h = harness();await assert.rejects(h.run({verification: {...structuredClone(verification), ...change}}), /rejected/);
    assert.deepEqual(h.calls, ['chat-selected-decryption-material','chat-decapsulate-components']);
  }
});

test('actual vault worker authenticates purpose and wrapper IDs without exporting a session key', async () => {
  const h = harness(fixture.vault), result = await h.run();
  assert.deepEqual(result, {secret: Buffer.alloc(32, 7).toString('base64')});
  assert.deepEqual(h.calls, ['chat-decryption-material','chat-decapsulate-components']);
  for (const change of [{vaultId: 'wrong'}, {wrapperId: 'wrong'}]) {
    const altered = harness(fixture.vault);await assert.rejects(altered.run({vault: {...vault, ...change}}), /rejected/);
    assert.deepEqual(altered.calls, ['chat-decryption-material','chat-decapsulate-components']);
  }
  // Unsigned vault content must never take the signed-message acceptance path.
  const unsigned = harness(fixture.vault);
  await assert.rejects(unsigned.run({service: 'Gmail', purpose: 'message'}), /rejected/);
});
