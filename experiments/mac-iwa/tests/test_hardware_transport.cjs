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

// Exercise the actual browser prompt's event handlers without a physical card.
async function testBrowserPinValidation() {
  const ids = ['dialog', 'title', 'detail', 'input', 'ok', 'cancel', 'hint'];
  const elements = Object.fromEntries(ids.map(id => ['smartcard-pin-' + id, new EventTarget()]));
  const el = id => elements['smartcard-pin-' + id];
  const dialog = el('dialog'), input = el('input'), ok = el('ok');
  dialog.showModal = () => { dialog.open = true; };
  dialog.close = () => { dialog.open = false; };
  input.focus = () => {};
  ctx.document = { getElementById: id => elements[id] };
  const transport = createHardwareTransport();
  let submissions = 0;
  const pending = transport.promptPin({}, () => { submissions++; });
  assert.equal(ok.disabled, true);
  function enter(options = {}) {
    const event = new Event('keydown', {cancelable: true});
    Object.assign(event, {key: 'Enter', ...options});
    input.dispatchEvent(event);
  }
  for (const pin of ['', '1', '12345', '123456789', '12345é']) {
    input.value = pin;
    input.dispatchEvent(new Event('input'));
    enter();
    ok.dispatchEvent(new Event('click'));
    assert.equal(submissions, 0);
    assert.equal(ok.disabled, true);
    assert.equal(dialog.open, true);
    assert.match(el('hint').textContent, /6 to 8/);
    assert.equal(input.value, pin);
  }
  input.value = '12345678';
  input.dispatchEvent(new Event('input'));
  assert.equal(ok.disabled, false);
  enter({repeat: true});
  enter({isComposing: true});
  assert.equal(submissions, 0);
  enter();
  ok.dispatchEvent(new Event('click'));
  assert.equal(await pending, '12345678');
  assert.equal(submissions, 1);
  assert.equal(input.value, '');
  delete ctx.document;
}
(async () => {
  await testBrowserPinValidation();
  const pivCalls = [];
  const fakePiv = {
    async listYubiKeys() { pivCalls.push('listYubiKeys'); return [{ serial: '41088108', version: '0.0.1', reader: 'YubiKey' }]; },
    async hardwareAuditViaSmartCard(id) { pivCalls.push('audit:' + id.serial); return { format: 'sequoia-iwa-hardware-audit', version: 1 }; },
    async signDigestViaSmartCard(req) { pivCalls.push('sign:' + req.requestId); return { requestId: req.requestId, ed25519: 'AA==', mldsa65: 'BB==' }; },
    async decapsulateComponentsViaSmartCard(req, identity, _prompt, options) { if(req.service==='Vault')assert.equal(options?.vaultUnlock,true); pivCalls.push('decap:' + req.requestId); return { requestId: req.requestId, mlkemSecret: 'CC==', x25519Secret: 'DD==' }; },
    async readPublicSnapshotViaSmartCard(serial, includeBundle, inspectBundle) {
      if(includeBundle)assert.equal(typeof inspectBundle,'function');
      pivCalls.push('snapshot:' + serial + ':' + includeBundle);
      return { format: 'sequoia-iwa-public-snapshot', version: 1, serial: serial || '41088108', slots: [], warnings: [], ...(includeBundle ? { bundle: 'UFFNWklQMDE=', generation: 4 } : {}) };
    },
    async readVaultMaterialViaSmartCard() {
      pivCalls.push('vault-material');
      return { serial: '41088108', classical: { serial: '41088108', slot: '9d', algorithm: 'ECDH-P256', public: 'SPKI==', fingerprint: 'fp1' }, classicalSlots: [] };
    },
    async ecdhViaSmartCard(req) { pivCalls.push('ecdh'); return { secret: 'EE==', fingerprint: req.fingerprint }; },
  };

  const t = createHardwareTransport({ piv: fakePiv, promptPin: async () => '123456' });
  const st = await t.dispatch('status');
  assert.equal(st.connected, true);
  assert.equal(st.serial, '41088108');

  // Device discovery returns strict {serial}-only objects required by identities/devices.js
  const devs = await t.dispatch('chat-identity-devices', {}, {});
  assert.equal(JSON.stringify(devs), JSON.stringify({ devices: [{ serial: '41088108' }] }));
  assert.equal(Object.keys(devs.devices[0]).join(), 'serial');

  // Bundle read & key snapshot via smartcard
  await assert.rejects(t.dispatch('chat-identity-bundle-read', {serial:'41088108'}, {}),/verification unavailable/);
  const bsnap = await t.dispatch('chat-identity-bundle-read', { serial: '41088108' }, {},{inspectPublicBundle:async()=>{}});
  assert.equal(bsnap.generation, 4);
  const ksnap = await t.dispatch('chat-identity-key-snapshot', { serial: '41088108' }, {});
  assert.equal(ksnap.format, 'sequoia-iwa-public-snapshot');

  // Signing ticket + signDigest flow via smartcard
  const id = {version:6,profile:'level3',bundleHash:'b'.repeat(64), serial: '41088108', fingerprint: 'F'.repeat(64), certificateHash: 'a'.repeat(64), email: 'u@example.test', certificate: 'CERT', signingFingerprint: 'S'.repeat(64), recipientKey: 'R'.repeat(64) };
  const auth={authorizeIdentity:async()=>id,assertIdentity:async()=>{},signingInput:async()=> 'MU'};
  const originalDispatch=t.dispatch; t.dispatch=(op,data,opt,context)=>originalDispatch(op,data,opt,{...auth,...context});
  const mat = await t.dispatch('chat-selected-signing-material', { identity: id }, {});
  assert.equal(mat.signingFingerprint, 'S'.repeat(64));
  const sig = await t.dispatch('chat-sign-digest', { review: mat.review, requestId: '1'.repeat(64), digest: 'D'.repeat(86) + '==', signingFingerprint: id.signingFingerprint }, {});
  assert.equal(sig.mldsa65, 'BB==');

  // Replay of consumed signing ticket must fail (no retry/no fallback)
  await assert.rejects(
    t.dispatch('chat-sign-digest', { review: mat.review, requestId: '1'.repeat(64) }, {}),
    /Expired or unknown/
  );

  // Decapsulation ticket + decapsulate flow via smartcard
  const dmat = await t.dispatch('chat-selected-decryption-material', { identity: id }, {});
  const shares = await t.dispatch('chat-decapsulate-components', { review: dmat.review, requestId: '2'.repeat(64), recipientKey:id.recipientKey }, {});
  assert.equal(shares.mlkemSecret, 'CC==');

  // Locked-vault hybrid operations use verified public material rather than
  // the account-selected message identity. Tickets cannot change purpose.
  let vaultActive=true;
  const vaultCtx={prepareLevel3VaultUnlock:async (serial,recipientKey,progress)=>{assert.equal(serial,'41088108');assert.equal(recipientKey,id.recipientKey);progress?.({stage:'prepare'});return id;},assertVault:()=>{if(!vaultActive)throw Error('Vault operation ended');}};
  const progress=[];
  const vd=await t.dispatch('chat-decryption-material',{service:'Vault',serial:'41088108',recipientKey:id.recipientKey},{vaultProgress:event=>progress.push(event)},vaultCtx);
  assert.deepEqual(progress,[{stage:'prepare'}]);
  await assert.rejects(t.dispatch('chat-decapsulate-components',{review:vd.review,service:'Chat',recipientKey:id.recipientKey},{},vaultCtx),/purpose changed/);
  const actual=await t.dispatch('chat-decryption-material',{service:'Vault',serial:'41088108',recipientKey:id.recipientKey},{},vaultCtx);
  await t.dispatch('chat-decapsulate-components',{review:actual.review,service:'Vault',recipientKey:id.recipientKey},{},vaultCtx);
  vaultActive=false;
  await assert.rejects(t.dispatch('chat-decryption-material',{service:'Vault',serial:'41088108',recipientKey:id.recipientKey},{},vaultCtx),/operation ended/);

  // Vault material + classical ECDH via smartcard
  const vmat = await t.dispatch('chat-vault-material', {}, {},{prepareVault:()=>fakePiv.readVaultMaterialViaSmartCard()});
  assert.equal(vmat.serial, '41088108');
  assert.equal(vmat.classical.slot, '9d');
  assert.equal(vmat.classical.algorithm, 'ECDH-P256');
  const ecdh = await t.dispatch('chat-vault-ecdh', { peer: 'AA==', fingerprint: 'fp1' }, {});
  assert.equal(ecdh.secret, 'EE==');

  // Retired routes and saved preferences cannot invoke a native transport.
  ctx.localStorage = {getItem: () => 'native'};
  assert.equal((await createHardwareTransport({piv:fakePiv}).dispatch('status')).serial,'41088108');
  for(const op of ['chat-certificate-migration','chat-identity-current','vault-prf','chat-identity-companion-read'])
    await assert.rejects(t.dispatch(op), /not supported over Web Smart Card/);
  for(const profile of [{...id,version:4},{...id,version:5},{...id,profile:'level5'},{...id,companion:{}}]){
    assert.equal(t.supportsIdentity(profile),false);
    await assert.rejects(t.dispatch('chat-selected-signing-material',{}, {},{authorizeIdentity:async()=>profile}), /require a Level 3 RFC 9980/);
  }
  ctx.SequoiaSecureChannel={isRequired:()=>true};

  // Exercise the production PIN dialog through its actual submission handler.
  // The modal must stay open with a cleared PIN all the way into the card call.
  const elements = new Map();
  for(const id of ['dialog','entry','wait','status','hint','title','detail','input','ok','cancel']){
    elements.set('smartcard-pin-'+id,Object.assign(new EventTarget(),{
      hidden:id==='wait',open:false,value:'',focus(){},
      showModal(){this.open=true;},close(){this.open=false;},
    }));
  }
  const element=id=>elements.get('smartcard-pin-'+id);
  ctx.document={getElementById:id=>elements.get(id)};
  Object.assign(ctx,{setTimeout,clearTimeout,requestAnimationFrame:cb=>queueMicrotask(cb)});
  const browserTransport=createHardwareTransport({piv:{
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
  await assert.rejects(browserTransport.dispatch('chat-vault-level5-open',{serial:'123'},{},{assertVault(){}}),/declined the operation.*touch the key promptly.*INS=87 P1=E7 P2=9D/);
  assert.equal(element('dialog').open,false);
  assert.equal(element('entry').hidden,false);
  assert.equal(element('wait').hidden,true);

  console.log('PASS hardware-transport Web Smart Card routing, ticket single-use, and no-fallback tests');
})();
