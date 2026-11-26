// Dual-mode hardware transport selector: explicit choice between
// 'native' (scoped extension -> Native Messaging -> PKCS#11) and
// 'smartcard' (direct browser navigator.smartCard -> macOS PCSC.framework).
// Never silently falls back between transports.
(function(global){
'use strict';

const STORAGE_KEY = 'sequoia_hardware_transport';
const VALID_MODES = new Set(['native', 'smartcard']);
const TICKET_TTL_MS = 10 * 60 * 1000;

// Extension-only (non-PIV) operations still pass through even in smartcard mode.
const EXTENSION_PASSTHROUGH_OPS = new Set([
  'vault-prf',
  'google-oauth-test', 'google-oauth-services',
  'google-chat-upload', 'google-chat-download',
]);

function createHardwareTransport(deps = {}){
  const piv = deps.piv || global.SequoiaSmartCardPiv;
  const storage = deps.storage ?? global.localStorage;
  const tickets = new Map();

  function randomHex(bytesLen){
    const buf = new Uint8Array(bytesLen);
    crypto.getRandomValues(buf);
    return Array.from(buf, b=>b.toString(16).padStart(2,'0')).join('');
  }

  function getMode(){
    try{
      const saved = storage?.getItem?.(STORAGE_KEY);
      if(VALID_MODES.has(saved)) return saved;
    }catch(_){}
    return 'smartcard';
  }

  function setMode(mode){
    if(!VALID_MODES.has(mode)) throw Error('Unsupported hardware transport: ' + mode);
    tickets.clear();
    try{ storage?.setItem?.(STORAGE_KEY, mode); }catch(_){}
    return mode;
  }

  function pruneTickets(){
    const now = Date.now();
    for(const [k, v] of tickets){
      if(now - v.created > TICKET_TTL_MS) tickets.delete(k);
    }
  }

  function promptPinInBrowser({title, detail}){
    if(deps.promptPin) return deps.promptPin({title, detail});
    const dialog = document.getElementById('smartcard-pin-dialog');
    const titleEl = document.getElementById('smartcard-pin-title');
    const detailEl = document.getElementById('smartcard-pin-detail');
    const inputEl = document.getElementById('smartcard-pin-input');
    const okBtn = document.getElementById('smartcard-pin-ok');
    const cancelBtn = document.getElementById('smartcard-pin-cancel');
    if(!dialog || !inputEl || !okBtn || !cancelBtn){
      return Promise.reject(Error('Web Smart Card PIN dialog is unavailable.'));
    }
    titleEl.textContent = title || 'Enter YubiKey PIV PIN';
    detailEl.textContent = detail || '';
    inputEl.value = '';
    return new Promise((resolve, reject)=>{
      const cleanup = ()=>{
        okBtn.removeEventListener('click', onOk);
        cancelBtn.removeEventListener('click', onCancel);
        dialog.removeEventListener('cancel', onCancel);
        inputEl.removeEventListener('keydown', onKeyDown);
        inputEl.value = '';
        if(dialog.open) dialog.close();
      };
      const onOk = ()=>{
        const pin = inputEl.value;
        cleanup();
        if(!/^[\x20-\x7e]{6,8}$/.test(pin)){
          reject(Error('PIV PIN must be 6 to 8 printable ASCII characters.'));
          return;
        }
        resolve(pin);
      };
      const onKeyDown = (ev)=>{
        if(ev.key === 'Enter'){ ev.preventDefault(); onOk(); }
      };
      const onCancel = ()=>{
        cleanup();
        reject(Error('PIV PIN entry cancelled; no card operation was attempted.'));
      };
      okBtn.disabled = false;
      cancelBtn.disabled = false;
      okBtn.addEventListener('click', onOk);
      cancelBtn.addEventListener('click', onCancel);
      dialog.addEventListener('cancel', onCancel);
      inputEl.addEventListener('keydown', onKeyDown);
      dialog.showModal();
      inputEl.focus();
    });
  }

  // Resolve a revision-checked selection and authenticate the card's current
  // bundle before issuing a ticket. Stored UI fields are never slot authority.
  async function resolveIdentity(identityRef, ctx){
    if(typeof ctx.authorizeIdentity !== 'function') throw Error('Hardware identity authorization unavailable.');
    const identity = await ctx.authorizeIdentity(identityRef);
    if(identity.version !== 6 || identity.profile !== 'level3' || identity.companion)
      throw Error('Direct Web Smart Card currently supports native Level 3 v6 only. Select Native helper for this profile.');
    return identity;
  }

  // Recheck account/vault/revision after the asynchronous PIN dialog and before
  // submitting PIN bytes. Locking while a dialog is open revokes the operation.
  function checkedPrompt(identity, ctx){
    return async details => {
      const pin = await promptPinInBrowser(details);
      if(ctx.signal?.aborted||getMode()!=='smartcard')throw Error('Hardware operation cancelled; no PIN submitted.');
      await ctx.assertIdentity(identity);
      return pin;
    };
  }

  // The main login screen and vault enrollment share these card operations.
  // Show the same touch guidance in both paths after the PIN field is cleared.
  async function withVaultTouch(serial, ctx, perform){
    const prompt = checkedPrompt(null,{...ctx,assertIdentity:ctx.assertVault});
    const dialog = global.document?.getElementById('smartcard-touch-dialog');
    const status = global.document?.getElementById('smartcard-touch-status');
    // A card command already in progress cannot be cancelled safely from
    // this dialog. Keep the touch instruction visible until it settles.
    const preventCancel = event => event.preventDefault();
    try{
      return await perform(async details=>{
        const pin = await prompt(details);
        const instruction = serial ? `Touch YubiKey SN# ${serial}` : 'Touch your YubiKey';
        if(dialog && status){
          status.textContent = `${instruction} promptly when it flashes. Keep it connected until the operation finishes.`;
          dialog.addEventListener('cancel',preventCancel);
          dialog.showModal();
          // Allow a paint before the card starts waiting for touch.
          await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
        }
        if(ctx.signal?.aborted||getMode()!=='smartcard')throw Error('Hardware operation cancelled; no PIN submitted.');
        await ctx.assertVault();
        return pin;
      });
    }finally{
      dialog?.removeEventListener('cancel',preventCancel);
      if(dialog?.open)dialog.close();
      if(status)status.textContent='';
    }
  }

  async function dispatchSmartCard(op, data, ctx){
    if(!piv) throw Error('Web Smart Card PIV module is not loaded.');
    if(!global.navigator?.smartCard && !deps.piv){
      throw Error('Web Smart Card (navigator.smartCard) is unavailable in this browser. Switch Hardware transport to Native helper (PKCS#11) or launch Chromium with --enable-features=SmartCard.');
    }
    pruneTickets();

    if(op === 'status'){
      const devices = await piv.listYubiKeys();
      if(!devices.length){
        return {connected: false, serial: '', backend: 'Web Smart Card (navigator.smartCard)'};
      }
      return {connected: true, serial: devices[0].serial, backend: 'Web Smart Card (navigator.smartCard)'};
    }

    if(op === 'chat-identity-devices'){
      const devices = await piv.listYubiKeys();
      const serials = [...new Set(devices.map(d=>String(d.serial)).filter(s=>/^[1-9][0-9]{0,9}$/.test(s)))].sort();
      return {devices: serials.map(serial=>({serial}))};
    }

    if(op === 'chat-identity-bundle-read'){
      ctx.say?.('Reading public certificate bundle and all 24 PIV slots via Web Smart Card (no PIN required)…');
      return piv.readPublicSnapshotViaSmartCard(data.serial || null, true);
    }

    if(op === 'chat-identity-key-snapshot'){
      ctx.say?.('Reading all 24 PIV public keys via Web Smart Card (no PIN required)…');
      return piv.readPublicSnapshotViaSmartCard(data.serial || null, false);
    }

    if(op === 'chat-hardware-audit'){
      ctx.say?.('Reading all 24 PIV slots twice via Web Smart Card (no PIN required)…');
      return piv.hardwareAuditViaSmartCard(data.identity);
    }

    if(op === 'chat-selected-signing-material'){
      const identity = await resolveIdentity(data.identity, ctx);
      if(!identity?.certificate || !identity?.signingFingerprint){
        throw Error('Select a saved hardware identity with a restored certificate before signing.');
      }
      const rid = randomHex(24);
      tickets.set(rid, {kind: 'sign', created: Date.now(), identity});
      return {
        review: rid,
        senderCertificate: identity.certificate,
        senderEmail: identity.email,
        signingFingerprint: identity.signingFingerprint,
        identity: {
          serial: String(identity.serial),
          bundleHash: identity.bundleHash,
          fingerprint: identity.fingerprint,
          certificateHash: identity.certificateHash,
          email: identity.email,
        },
        hardwareProfile: identity.profile,
      };
    }

    if(op === 'chat-sign-digest'){
      const t = tickets.get(data.review);
      if(!t || t.kind !== 'sign') throw Error('Expired or unknown Web Smart Card signing ticket.');
      tickets.delete(data.review);
      await ctx.assertIdentity?.(t.identity);
      if(data.signingFingerprint !== t.identity.signingFingerprint) throw Error('Signing key changed.');
      const mu = await ctx.signingInput(t.identity, data);
      return piv.signDigestViaSmartCard({...data, mu}, t.identity, checkedPrompt(t.identity, ctx));
    }

    if(op === 'chat-selected-decryption-material' || op === 'chat-decryption-material'){
      const vaultOperation=op==='chat-decryption-material'&&data.service==='Vault';
      let identity;
      if(vaultOperation){
        await ctx.assertVault();
        const material=await ctx.prepareVault(data.serial);
        identity=material.identity;
        if(!identity||identity.recipientKey!==data.recipientKey)throw Error('Hybrid vault recipient changed');
      }else identity=await resolveIdentity(data.identity, ctx);
      if(!identity?.certificate || !identity?.recipientKey){
        throw Error('Select a saved hardware identity with a restored certificate before decrypting.');
      }
      const rid = randomHex(24);
      tickets.set(rid, {kind: 'decrypt', created: Date.now(), identity, vaultOperation});
      return {
        review: rid,
        recipientCertificate: identity.certificate,
        recipientKey: identity.recipientKey,
        identity: {
          serial: String(identity.serial),
          bundleHash: identity.bundleHash,
          fingerprint: identity.fingerprint,
          certificateHash: identity.certificateHash,
          email: identity.email,
        },
        hardwareProfile: identity.profile,
      };
    }

    if(op === 'chat-decapsulate-components'){
      const t = tickets.get(data.review);
      if(!t || t.kind !== 'decrypt') throw Error('Expired or unknown Web Smart Card decryption ticket.');
      tickets.delete(data.review);
      if(t.vaultOperation){if(data.service!=='Vault')throw Error('Vault ticket purpose changed');await ctx.assertVault();}else await ctx.assertIdentity?.(t.identity);
      if(data.recipientKey !== t.identity.recipientKey) throw Error('Recipient key changed.');
      if(t.vaultOperation)return withVaultTouch(t.identity.serial,ctx,prompt=>piv.decapsulateComponentsViaSmartCard(data,t.identity,prompt));
      return piv.decapsulateComponentsViaSmartCard(data,t.identity,checkedPrompt(t.identity,ctx));
    }

    if(op === 'chat-vault-material'){
      ctx.say?.('Restoring verified public bundle and selecting vault protection…');
      if(!ctx.prepareVault)throw Error('Vault hardware policy unavailable');
      return ctx.prepareVault(data.serial);
    }

    if(op === 'chat-vault-level5-open'){
      await ctx.assertVault();
      if(!global.SequoiaSecureChannel?.isRequired())throw Error('Level 5 vault requires SCP11b.');
      return withVaultTouch(data.serial,ctx,prompt=>piv.openLevel5VaultViaSmartCard(data,prompt));
    }

    if(op === 'chat-vault-ecdh'){
      return withVaultTouch(data.serial,ctx,prompt=>piv.ecdhViaSmartCard(data,data.slot||null,data.serial||null,prompt));
    }

    throw Error(`Operation "${op}" requires the Native helper (PKCS#11). Switch Hardware transport to Native helper to use it.`);
  }

  function dispatch(op, data = {}, options = {}, nativeRequest, ctx = {}){
    const mode = getMode();
    if(!global.SequoiaSecureChannel && global.document?.getElementById('secure-yubikey-connection'))return Promise.reject(Error('Secure-channel policy is not ready'));
    // Secure mode must not silently route card work through an unprotected
    // native implementation. Google-only broker operations are unaffected.
    if(global.SequoiaSecureChannel?.isRequired() && (op==='vault-prf' || mode==='native' && !EXTENSION_PASSTHROUGH_OPS.has(op)))return Promise.reject(Error('Secure YubiKey connection requires Web Smart Card; native SCP is not implemented.'));
    if(options.signal?.aborted) return Promise.reject(Error('Operation cancelled; no retry.'));
    if(mode === 'native' || EXTENSION_PASSTHROUGH_OPS.has(op)){
      return nativeRequest(op, data, options);
    }
    return dispatchSmartCard(op, data, {...ctx,signal:options.signal});
  }

  return {getMode, setMode, dispatch, promptPin:promptPinInBrowser};
}

const transport = createHardwareTransport();
global.createHardwareTransport = createHardwareTransport;
global.hardwareTransport = transport;
if(typeof module !== 'undefined' && module.exports){
  module.exports = {createHardwareTransport, hardwareTransport: transport};
}

if(typeof document !== 'undefined'){
  const select = document.getElementById('hardware-transport');
  if(select){
    select.value = transport.getMode();
    select.addEventListener('change', ()=>{
      const mode = transport.setMode(select.value);
      const statusEl = document.getElementById('result');
      if(statusEl){
        statusEl.textContent = mode === 'smartcard'
          ? 'Hardware transport set to Web Smart Card (navigator.smartCard). No native helper or PKCS#11 will be used for PIV operations.'
          : 'Hardware transport set to Native helper (PKCS#11).';
      }
    });
  }
}
})(typeof globalThis !== 'undefined' ? globalThis : window);
