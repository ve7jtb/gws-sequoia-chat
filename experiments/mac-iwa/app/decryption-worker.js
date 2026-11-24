// All recipient-packet parsing, the RFC 9980 combiner, session-key recovery,
// AEAD decryption and signature verification remain in this disposable worker.
// Neither the full message nor an OpenPGP session key reaches the native host.
import init, {prepare_decryption, finalize_decryption, cancel_decryption,
  verify_detached, companion_complete} from './wasm/sequoia_iwa_verify.js';
import {readMessage} from './message-mime.js';
import {completeCompanion} from './companion/complete.js';

let phase = 'new', requestId, purpose, verification, vault, certificate, componentRequest;
self.onmessage = async ({data}) => {
  try {
    if (!data || JSON.stringify(data).length > 800000) throw Error('Request limit');
    if (phase === 'new' && data.type === 'prepare') {
      phase = 'initializing'; requestId = data.requestId; purpose = data.purpose;
      verification = data.verification; vault = data.vault; certificate = data.recipientCertificate;
      await init();
      if (phase !== 'initializing') throw Error('Cancelled');
      const request = componentRequest = JSON.parse(prepare_decryption(JSON.stringify({requestId,
        cipher: data.cipher, recipientCertificate: data.recipientCertificate,
        recipientKey: data.recipientKey, purpose})));
      phase = 'waiting';
      self.postMessage({type: 'component-request', requestId, request});
      return;
    }
    if (phase === 'waiting' && data.type === 'finalize' && data.requestId === requestId) {
      phase = 'finalizing';
      let opened;
      try {
        // A wrapped companion is decrypted only inside this one-operation worker.
        // Its authenticated manifest binds software components to this exact
        // certificate and the card's freshly checked public keys.
        const completed = await completeCompanion('decapsulate', certificate, componentRequest, data.result, companion_complete);
        if (phase !== 'finalizing') throw Error('Cancelled operation');
        try { opened = JSON.parse(finalize_decryption(JSON.stringify(completed))); }
        finally { delete completed.mlkemSecret; delete completed.x25519Secret; }
      }
      finally {
        if (data.result) { delete data.result.mlkemSecret; delete data.result.x25519Secret; delete data.result.companionShared; }
      }
      if (opened.requestId !== requestId) throw Error('Operation mismatch');
      let result;
      if (purpose === 'vault') {
        // Vault envelopes are unsigned. They cannot enter the message reader,
        // and their authenticated purpose and IDs must match the exact wrapper.
        if (!vault || typeof opened.raw !== 'string' || opened.raw.length > 1400) throw Error('Vault limit');
        const raw = Uint8Array.from(atob(opened.raw), c => c.charCodeAt(0));
        const value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(raw)); raw.fill(0);
        if (value.purpose !== 'sequoia-iwa-vault-wrap-v1' || value.vaultId !== vault.vaultId ||
            value.wrapperId !== vault.wrapperId || typeof value.secret !== 'string' ||
            !/^[A-Za-z0-9+/]{43}=$/.test(value.secret) || atob(value.secret).length !== 32)
          throw Error('Vault binding mismatch');
        result = {secret: value.secret}; delete value.secret; delete opened.raw;
      } else {
        if (!verification) throw Error('Missing verification policy');
        const {material, expectedEmail, expectedFingerprint, recipient} = verification;
        result = await readMessage({...opened, expectedEmail, expectedFingerprint, recipient}, material,
          request => JSON.parse(verify_detached(JSON.stringify(request))));
      }
      phase = 'done'; verification = vault = certificate = componentRequest = undefined;
      self.postMessage({type: 'complete', requestId, result}); self.close(); return;
    }
    throw Error('Unexpected decryption phase');
  } catch (_) {
    phase = 'failed'; verification = vault = certificate = componentRequest = undefined;
    try { cancel_decryption(); } catch (_) {}
    self.postMessage({type: 'error', requestId}); self.close();
  }
};
