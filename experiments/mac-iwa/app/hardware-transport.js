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
  'google-oauth-token',
  'google-oauth-clear',
  'chat-media-upload',
  'chat-media-download',
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
    return 'native';
  }

  function setMode(mode){
    if(!VALID_MODES.has(mode)) throw Error('Unsupported hardware transport: ' + mode);
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
      const onCancel = ()=>{
        cleanup();
        reject(Error('PIV PIN entry cancelled; no card operation was attempted.'));
      };
      okBtn.addEventListener('click', onOk);
      cancelBtn.addEventListener('click', onCancel);
      dialog.addEventListener('cancel', onCancel);
      dialog.showModal();
      inputEl.focus();
    });
  }

  async function resolveIdentity(identityRef, identityStore){
    if(!identityRef) return null;
    if(identityRef.certificate && (identityRef.signingFingerprint || identityRef.recipientKey)){
      return identityRef;
    }
    if(identityStore?.list){
      const listed = await identityStore.list();
      const rows = Array.isArray(listed) ? listed : (listed?.identities || listed?.choices || []);
      const found = rows.find(r=>
        (identityRef.fingerprint && r.fingerprint === identityRef.fingerprint) &&
        (!identityRef.serial || String(r.serial) === String(identityRef.serial))
      );
      if(found) return found;
    }
    return identityRef;
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
      return {devices: devices.map(d=>({serial: d.serial, version: d.version, reader: d.reader}))};
    }

    if(op === 'chat-hardware-audit'){
      ctx.say?.('Reading all 24 PIV slots twice via Web Smart Card (no PIN required)…');
      return piv.hardwareAuditViaSmartCard(data.identity);
    }

    if(op === 'chat-selected-signing-material'){
      const identity = await resolveIdentity(data.identity, ctx.identityStore);
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
          fingerprint: identity.fingerprint,
          certificateHash: identity.certificateHash,
          email: identity.email,
        },
        hardwareProfile: identity.hardwareProfile || 'level3',
      };
    }

    if(op === 'chat-sign-digest'){
      const t = tickets.get(data.review);
      if(!t || t.kind !== 'sign') throw Error('Expired or unknown Web Smart Card signing ticket.');
      tickets.delete(data.review);
      return piv.signDigestViaSmartCard(data, t.identity, promptPinInBrowser);
    }

    if(op === 'chat-selected-decryption-material' || op === 'chat-decryption-material'){
      const identity = await resolveIdentity(data.identity, ctx.identityStore);
      if(!identity?.certificate || !identity?.recipientKey){
        throw Error('Select a saved hardware identity with a restored certificate before decrypting.');
      }
      const rid = randomHex(24);
      tickets.set(rid, {kind: 'decrypt', created: Date.now(), identity});
      return {
        review: rid,
        recipientCertificate: identity.certificate,
        recipientKey: identity.recipientKey,
        identity: {
          serial: String(identity.serial),
          fingerprint: identity.fingerprint,
          certificateHash: identity.certificateHash,
          email: identity.email,
        },
        hardwareProfile: identity.hardwareProfile || 'level3',
      };
    }

    if(op === 'chat-decapsulate-components'){
      const t = tickets.get(data.review);
      if(!t || t.kind !== 'decrypt') throw Error('Expired or unknown Web Smart Card decryption ticket.');
      tickets.delete(data.review);
      return piv.decapsulateComponentsViaSmartCard(data, t.identity, promptPinInBrowser);
    }

    if(op === 'chat-vault-ecdh'){
      return piv.ecdhViaSmartCard(data, data.slot || '9d', data.serial || null, promptPinInBrowser);
    }

    throw Error(`Operation "${op}" requires the Native helper (PKCS#11). Switch Hardware transport to Native helper to use it.`);
  }

  function dispatch(op, data = {}, options = {}, nativeRequest, ctx = {}){
    const mode = getMode();
    if(mode === 'native' || EXTENSION_PASSTHROUGH_OPS.has(op)){
      return nativeRequest(op, data, options);
    }
    return dispatchSmartCard(op, data, ctx);
  }

  return {getMode, setMode, dispatch};
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
