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
    async decapsulateComponentsViaSmartCard(req) { pivCalls.push('decap:' + req.requestId); return { requestId: req.requestId, mlkemSecret: 'CC==', x25519Secret: 'DD==' }; },
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

  // New installations default to direct Web Smart Card; saved native choices persist.
  assert.equal(t.getMode(), 'smartcard');
  t.setMode('native');
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
  const id = {version:6,profile:'level3',bundleHash:'b'.repeat(64), serial: '41088108', fingerprint: 'F'.repeat(64), certificateHash: 'a'.repeat(64), email: 'u@example.test', certificate: 'CERT', signingFingerprint: 'S'.repeat(64), recipientKey: 'R'.repeat(64) };
  const auth={authorizeIdentity:async()=>id,assertIdentity:async()=>{},signingInput:async()=> 'MU'};
  const originalDispatch=t.dispatch; t.dispatch=(op,data,opt,native,context)=>originalDispatch(op,data,opt,native,{...auth,...context});
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
  const shares = await t.dispatch('chat-decapsulate-components', { review: dmat.review, requestId: '2'.repeat(64), recipientKey:id.recipientKey }, {}, nativeRequest);
  assert.equal(shares.mlkemSecret, 'CC==');

  // Locked-vault hybrid operations use verified public material rather than
  // the account-selected message identity. Tickets cannot change purpose.
  let vaultActive=true;
  const vaultCtx={prepareVault:async serial=>{assert.equal(serial,'41088108');return {identity:id};},assertVault:()=>{if(!vaultActive)throw Error('Vault operation ended');}};
  const vd=await t.dispatch('chat-decryption-material',{service:'Vault',serial:'41088108',recipientKey:id.recipientKey},{},nativeRequest,vaultCtx);
  await assert.rejects(t.dispatch('chat-decapsulate-components',{review:vd.review,service:'Chat',recipientKey:id.recipientKey},{},nativeRequest,vaultCtx),/purpose changed/);
  vaultActive=false;
  await assert.rejects(t.dispatch('chat-decryption-material',{service:'Vault',serial:'41088108',recipientKey:id.recipientKey},{},nativeRequest,vaultCtx),/operation ended/);

  // Vault material + classical ECDH via smartcard
  const vmat = await t.dispatch('chat-vault-material', {}, {}, nativeRequest,{prepareVault:()=>fakePiv.readVaultMaterialViaSmartCard()});
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

  // Requiring SCP forbids the unprotected native path and native FIDO PRF,
  // while unrelated Google API brokerage still works.
  ctx.SequoiaSecureChannel={isRequired:()=>true};
  t.setMode('native');
  const before=nativeCalls.length;
  await assert.rejects(t.dispatch('chat-vault-ecdh',{}, {},nativeRequest),/requires Web Smart Card/);
  await assert.rejects(t.dispatch('vault-prf',{}, {},nativeRequest),/requires Web Smart Card/);
  assert.equal(nativeCalls.length,before);
  await t.dispatch('google-oauth-test',{}, {},nativeRequest);
  assert.equal(nativeCalls.length,before+1);

  // Exercise the production PIN dialog through its actual submission handler.
  // The modal must stay open with a cleared PIN all the way into the card call.
  const elements = new Map();
  for(const id of ['dialog','entry','wait','status','title','detail','input','ok','cancel']){
    elements.set('smartcard-pin-'+id,Object.assign(new EventTarget(),{
      hidden:id==='wait',open:false,value:'',focus(){},
      showModal(){this.open=true;},close(){this.open=false;},
    }));
  }
  const element=id=>elements.get('smartcard-pin-'+id);
  ctx.document={getElementById:id=>elements.get(id)};
  Object.assign(ctx,{setTimeout,clearTimeout,requestAnimationFrame:cb=>queueMicrotask(cb)});
  const browserTransport=createHardwareTransport({storage,piv:{
    async openLevel5VaultViaSmartCard(data,prompt){
      const submitted=prompt({title:'PIV PIN',detail:'Test'});
      assert.equal(element('dialog').open,true);
      element('input').value='123456';
      element('ok').dispatchEvent(new Event('click'));
      assert.equal(await submitted,'123456');
      assert.equal(element('dialog').open,true);
      assert.equal(element('input').value,'');
      assert.equal(element('entry').hidden,true);
      assert.equal(element('wait').hidden,false);
      assert.match(element('status').textContent,/Touch YubiKey SN# 123/);
      throw Error('Card declined the command (bare SW=6982) [INS=87 P1=E7 P2=9D, final command, SW=6982]');
    },
  }});
  browserTransport.setMode('smartcard');
  await assert.rejects(browserTransport.dispatch('chat-vault-level5-open',{serial:'123'},{},nativeRequest,{assertVault(){}}),/declined the operation.*touch the key promptly.*INS=87 P1=E7 P2=9D/);
  assert.equal(element('dialog').open,false);
  assert.equal(element('entry').hidden,false);
  assert.equal(element('wait').hidden,true);

  console.log('PASS hardware-transport dual-mode routing, ticket single-use, and no-fallback tests');
})();
