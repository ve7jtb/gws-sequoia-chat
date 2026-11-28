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

  function promptPinInBrowser({title, detail}, onSubmitted, onShown){
    if(deps.promptPin){
      const result=deps.promptPin({title, detail});
      onShown?.();
      return result;
    }
    const dialog = document.getElementById('smartcard-pin-dialog');
    const titleEl = document.getElementById('smartcard-pin-title');
    const detailEl = document.getElementById('smartcard-pin-detail');
    const inputEl = document.getElementById('smartcard-pin-input');
    const hint = document.getElementById('smartcard-pin-hint');
    const okBtn = document.getElementById('smartcard-pin-ok');
    const cancelBtn = document.getElementById('smartcard-pin-cancel');
    if(!dialog || !inputEl || !okBtn || !cancelBtn || !hint){
      return Promise.reject(Error('Web Smart Card PIN dialog is unavailable.'));
    }
    titleEl.textContent = title || 'Enter YubiKey PIV PIN';
    detailEl.textContent = detail || '';
    inputEl.value = '';
    return new Promise((resolve, reject)=>{
      const validPin = value=>/^[\x20-\x7e]{6,8}$/.test(value);
      const updatePin = (showError=false)=>{
        const valid = validPin(inputEl.value);
        okBtn.disabled = !valid;
        hint.textContent = !valid && (showError === true || inputEl.value)
          ? 'Enter 6 to 8 printable ASCII characters.' : '';
        return valid;
      };
      const cleanup = (close=true)=>{
        okBtn.removeEventListener('click', onOk);
        cancelBtn.removeEventListener('click', onCancel);
        dialog.removeEventListener('cancel', onCancel);
        inputEl.removeEventListener('keydown', onKeyDown);
        inputEl.removeEventListener('input', updatePin);
        inputEl.value = '';
        hint.textContent = '';
        if(close && dialog.open) dialog.close();
      };
      const onOk = ()=>{
        // Both Enter and the button validate locally, including pasted
        // overlong input. Invalid input keeps the operation at the dialog.
        if(!updatePin(true)) return;
        const pin = inputEl.value;
        cleanup(!onSubmitted);
        try{
          onSubmitted?.();
          resolve(pin);
        }catch(error){
          if(dialog.open)dialog.close();
          reject(error);
        }
      };
      const onKeyDown = (ev)=>{
        if(ev.key === 'Enter' && !ev.isComposing){
          ev.preventDefault();
          if(!ev.repeat) onOk();
        }
      };
      const onCancel = ()=>{
        cleanup();
        reject(Error('PIV PIN entry cancelled; no card operation was attempted.'));
      };
      updatePin();
      cancelBtn.disabled = false;
      okBtn.addEventListener('click', onOk);
      cancelBtn.addEventListener('click', onCancel);
      dialog.addEventListener('cancel', onCancel);
      inputEl.addEventListener('keydown', onKeyDown);
      inputEl.addEventListener('input', updatePin);
      try{
        dialog.showModal();
        onShown?.();
        inputEl.focus();
      }catch(error){
        cleanup();
        reject(error);
      }
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
  function checkedPrompt(identity, ctx, onSubmitted, onShown){
    return async details => {
      const pin = await promptPinInBrowser(details,onSubmitted,onShown);
      if(ctx.signal?.aborted||getMode()!=='smartcard')throw Error('Hardware operation cancelled; no PIN submitted.');
      await ctx.assertIdentity(identity);
      return pin;
    };
  }

  // The main login screen and vault enrollment share these card operations.
  // Show the same touch guidance in both paths after the PIN field is cleared.
  async function withVaultTouch(serial, ctx, perform, retry='start a fresh unlock',certificate=false){
    const doc = global.document;
    const dialog = doc?.getElementById('smartcard-pin-dialog');
    const entry = doc?.getElementById('smartcard-pin-entry');
    const waiting = doc?.getElementById('smartcard-pin-wait');
    const status = doc?.getElementById('smartcard-pin-status');
    const title = doc?.getElementById('smartcard-pin-title');
    if(doc && (!dialog || !entry || !waiting || !status || !title))
      throw Error('The YubiKey touch dialog is unavailable. Close and reopen the app.');
    const paintTouchPrompt=()=>new Promise(resolve=>{
      const fallback=setTimeout(resolve,900);
      requestAnimationFrame(()=>requestAnimationFrame(()=>{
        clearTimeout(fallback);
        setTimeout(resolve,500);
      }));
    });
    const key=serial?'YubiKey SN# '+serial:'your YubiKey';
    let showing = false;
    // Keep the PIN dialog open. Replacing it with a second modal can leave
    // the login screen visible while the browser changes modal focus.
    const preventCancel = event => event.preventDefault();
    const submitted = dialog && entry && waiting && status && title ? ()=>{
      dialog.addEventListener('cancel',preventCancel);
      showing = true;
      entry.hidden = true;
      waiting.hidden = false;
      title.textContent = certificate?'Checking YubiKey':'Waiting for YubiKey';
      status.textContent = certificate?'PIN submitted. Keep '+key+' connected while the secure session is checked.':
        'PIN submitted. Touch '+key+' promptly when it flashes. Keep it connected until the operation finishes.';
      waiting.focus();
    } : undefined;
    // Record presentation only after showModal succeeds. No PIN data
    // crosses this callback, and the elapsed measurement excludes user input.
    const prompt = checkedPrompt(null,{...ctx,assertIdentity:ctx.assertVault},submitted,
      ctx.vaultProgress?()=>ctx.vaultProgress({stage:'pin-shown',scpRequired:global.SequoiaSecureChannel?.isRequired()===true}):undefined);
    try{
      return await perform(async details=>{
        const pin = await prompt(details);
        // Start the card's touch window only after the instruction has had
        // time to appear. A timer works when animation frames are throttled.
        if(showing&&!certificate)await paintTouchPrompt();
        if(ctx.signal?.aborted||getMode()!=='smartcard')throw Error('Hardware operation cancelled; no PIN submitted.');
        await ctx.assertVault();
        return pin;
      },certificate?async ({slot,algorithm,touchPolicy})=>{
        if(!showing)return;
        const touch=touchPolicy==='always'||touchPolicy==='cached';
        title.textContent=touch?'Waiting for YubiKey':'Signing certificate';
        status.textContent='PIN verified for slot '+slot.toUpperCase()+' ('+algorithm+'). '+
          (touch?'Touch '+key+' promptly when it flashes.':'Keep '+key+' connected.');
        if(touch)await paintTouchPrompt();
      }:undefined,certificate?({instruction,count})=>{
        if(!showing)return;
        title.textContent='YubiKey response pending';
        status.textContent='Still waiting for '+instruction+' (frame '+count+'). If the key has stopped flashing or never flashed, remove it to end this attempt.';
      }:undefined);
    }catch(error){
      // Chromium may preserve only the message from a transaction callback.
      const header=/\[INS=([0-9A-F]{2}) P1=([0-9A-F]{2}) P2=([0-9A-F]{2}), (command fragment|GET RESPONSE|final command), SW=6982\]/i.exec(error.message);
      const fromMessage=header&&{
        ins:parseInt(header[1],16),p1:parseInt(header[2],16),
        p2:parseInt(header[3],16),stage:header[4],sw:0x6982,
      };
      const command=error.scpCommand??error.cause?.scpCommand??fromMessage;
      if(command?.sw!==0x6982)throw error;
      const hex=n=>n.toString(16).padStart(2,'0').toUpperCase();
      const name=command.ins===0x20?'PIV PIN verification':command.ins===0x87?'PIV private operation':'PIV card command';
      const diagnostic=`INS=${hex(command.ins)} P1=${hex(command.p1)} P2=${hex(command.p2)}, ${command.stage}, SW=6982`;
      const touch=command.ins===0x87&&command.stage==='final command';
      const summary=touch
        ?'YubiKey declined the operation. If you missed the flash, '+retry+' and touch the key promptly.'
        :`${name} was declined. Start a fresh unlock to open a new secure card session.`;
      const timing=/\[PIN verified; signing command [0-9]+ ms\]/.exec(error.message)?.[0];
      throw Error(summary+' Diagnostic: '+diagnostic+' (unauthenticated status).'+(timing?' '+error.message.slice(error.message.indexOf(timing)):''),{cause:error});
    }finally{
      if(showing){
        dialog.removeEventListener('cancel',preventCancel);
        if(dialog.open)dialog.close();
        status.textContent='';
        waiting.hidden=true;
        entry.hidden=false;
      }
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
      // The signed bundle identifies every slot needed for restore. Empty
      // Beta 0 slots can return bare errors, which SCP11b must still reject.
      if(typeof ctx.inspectPublicBundle!=='function')throw Error('Public bundle verification unavailable.');
      ctx.say?.('Reading public certificate bundle and checking its mapped slots via Web Smart Card (no PIN required)…');
      return piv.readPublicSnapshotViaSmartCard(data.serial || null, true,ctx.inspectPublicBundle);
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
        identity=await ctx.prepareLevel3VaultUnlock(data.serial,data.recipientKey,ctx.vaultProgress);
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
      if(t.vaultOperation)return withVaultTouch(t.identity.serial,ctx,prompt=>piv.decapsulateComponentsViaSmartCard(data,t.identity,prompt,{vaultUnlock:true,vaultProgress:ctx.vaultProgress}));
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
    return dispatchSmartCard(op, data, {...ctx,signal:options.signal,vaultProgress:options.vaultProgress});
  }

  return {getMode, setMode, dispatch, promptPin:promptPinInBrowser,
   withCertificateTouch:(serial,guard,perform)=>withVaultTouch(serial,{assertVault:guard},perform,'resume certificate signing',true)};
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
