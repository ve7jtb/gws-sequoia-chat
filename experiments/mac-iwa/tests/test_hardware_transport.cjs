const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');

const ctx = {
  Uint8Array, Array, Map, Set, Error, Date,
  crypto: webcrypto,
  module: { exports: {} },
};
ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(__dirname + '/../app/hardware-transport.js', 'utf8'), ctx);
const { createHardwareTransport } = ctx;

(async () => {
  const mem = new Map();
  const storage = { getItem: k => mem.get(k) ?? null, setItem: (k, v) => mem.set(k, v) };
  const nativeCalls = [];
  const nativeRequest = async (op, data) => { nativeCalls.push({ op, data }); return { via: 'native', op }; };

  const pivCalls = [];
  const fakePiv = {
    async listYubiKeys() { pivCalls.push('listYubiKeys'); return [{ serial: '41088108', version: '0.0.1', reader: 'YubiKey' }]; },
    async hardwareAuditViaSmartCard(id) { pivCalls.push('audit:' + id.serial); return { format: 'sequoia-iwa-hardware-audit', version: 1 }; },
    async signDigestViaSmartCard(req) { pivCalls.push('sign:' + req.requestId); return { requestId: req.requestId, ed25519: 'AA==', mldsa65: 'BB==' }; },
    async decapsulateComponentsViaSmartCard(req) { pivCalls.push('decap:' + req.requestId); return { requestId: req.requestId, mlkemShare: 'CC==', x25519Share: 'DD==' }; },
    async readPublicSnapshotViaSmartCard(serial, includeBundle) {
      pivCalls.push('snapshot:' + serial + ':' + includeBundle);
      return { format: 'sequoia-iwa-public-snapshot', version: 1, serial: serial || '41088108', slots: [], warnings: [], ...(includeBundle ? { bundle: 'UFFNWklQMDE=', generation: 4 } : {}) };
    },
    async readVaultMaterialViaSmartCard() {
      pivCalls.push('vault-material');
      return { serial: '41088108', classical: { serial: '41088108', slot: '9d', algorithm: 'ECDH-P256', public: 'SPKI==', fingerprint: 'fp1' }, classicalSlots: [] };
    },
    async ecdhViaSmartCard(req) { pivCalls.push('ecdh'); return { secret: 'EE==', fingerprint: req.fingerprint }; },
  };

  const t = createHardwareTransport({ piv: fakePiv, storage, promptPin: async () => '123456' });

  // Default mode is 'native'
  assert.equal(t.getMode(), 'native');
  const r1 = await t.dispatch('status', {}, {}, nativeRequest);
  assert.equal(r1.via, 'native');
  assert.equal(pivCalls.length, 0);

  // Switch explicitly to 'smartcard'
  t.setMode('smartcard');
  assert.equal(t.getMode(), 'smartcard');

  const st = await t.dispatch('status', {}, {}, nativeRequest);
  assert.equal(st.connected, true);
  assert.equal(st.serial, '41088108');
  assert.equal(nativeCalls.length, 1); // native was NOT called again

  // Device discovery returns strict {serial}-only objects required by identities/devices.js
  const devs = await t.dispatch('chat-identity-devices', {}, {}, nativeRequest);
  assert.equal(JSON.stringify(devs), JSON.stringify({ devices: [{ serial: '41088108' }] }));
  assert.equal(Object.keys(devs.devices[0]).join(), 'serial');

  // Bundle read & key snapshot via smartcard
  const bsnap = await t.dispatch('chat-identity-bundle-read', { serial: '41088108' }, {}, nativeRequest);
  assert.equal(bsnap.generation, 4);
  const ksnap = await t.dispatch('chat-identity-key-snapshot', { serial: '41088108' }, {}, nativeRequest);
  assert.equal(ksnap.format, 'sequoia-iwa-public-snapshot');

  // Non-PIV extension ops still pass through
  const prf = await t.dispatch('vault-prf', { name: 'test' }, {}, nativeRequest);
  assert.equal(prf.via, 'native');

  // Signing ticket + signDigest flow via smartcard
  const id = { serial: '41088108', fingerprint: 'F'.repeat(64), certificateHash: 'a'.repeat(64), email: 'u@example.test', certificate: 'CERT', signingFingerprint: 'S'.repeat(64), recipientKey: 'R'.repeat(64) };
  const mat = await t.dispatch('chat-selected-signing-material', { identity: id }, {}, nativeRequest);
  assert.equal(mat.signingFingerprint, 'S'.repeat(64));
  const sig = await t.dispatch('chat-sign-digest', { review: mat.review, requestId: '1'.repeat(64), digest: 'D'.repeat(86) + '==', signingFingerprint: id.signingFingerprint }, {}, nativeRequest);
  assert.equal(sig.mldsa65, 'BB==');

  // Replay of consumed signing ticket must fail (no retry/no fallback)
  await assert.rejects(
    t.dispatch('chat-sign-digest', { review: mat.review, requestId: '1'.repeat(64) }, {}, nativeRequest),
    /Expired or unknown/
  );

  // Decapsulation ticket + decapsulate flow via smartcard
  const dmat = await t.dispatch('chat-selected-decryption-material', { identity: id }, {}, nativeRequest);
  const shares = await t.dispatch('chat-decapsulate-components', { review: dmat.review, requestId: '2'.repeat(64) }, {}, nativeRequest);
  assert.equal(shares.mlkemShare, 'CC==');

  // Vault material + classical ECDH via smartcard
  const vmat = await t.dispatch('chat-vault-material', {}, {}, nativeRequest);
  assert.equal(vmat.serial, '41088108');
  assert.equal(vmat.classical.slot, '9d');
  assert.equal(vmat.classical.algorithm, 'ECDH-P256');
  const ecdh = await t.dispatch('chat-vault-ecdh', { peer: 'AA==', fingerprint: 'fp1' }, {}, nativeRequest);
  assert.equal(ecdh.secret, 'EE==');

  // Unsupported native-only op fails explicitly without silent fallback
  await assert.rejects(
    t.dispatch('chat-certificate-migration', {}, {}, nativeRequest),
    /requires the Native helper/
  );

  console.log('PASS hardware-transport dual-mode routing, ticket single-use, and no-fallback tests');
})();
