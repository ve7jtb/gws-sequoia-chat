// All OpenPGP framing, v6 salt generation and hashing stay in this worker.
// Only the prepared digest leaves it for hardware signing. A fresh worker is
// created for each message and destroyed on success, cancellation or failure.
import init, {prepare_signing, finalize_signing, cancel_signing, encrypt_signed} from './wasm/sequoia_iwa_verify.js';
import {composeMime} from './message-mime.js';

let stage = 'new', requestId, material;
self.onmessage = async ({data}) => {
  try {
    if (!data || JSON.stringify(data).length > 800000) throw Error('Request limit');
    if (stage === 'new' && data.type === 'prepare') {
      // Mark the worker occupied before asynchronous module initialization.
      // A duplicate prepare cannot replace its pending payload or v6 salt.
      stage = 'preparing';
      requestId = data.requestId;
      if (!/^[A-F0-9]{64}$/.test(requestId)) throw Error('Invalid operation');
      material = data.material;
      const compose = data.compose;
      if (!material || !compose || compose.sender !== material.senderEmail ||
          compose.recipient !== material.recipientEmail || compose.subject !== material.subject ||
          !/^[a-f0-9]{48}$/.test(material.review)) throw Error('Compose binding mismatch');
      const payload = composeMime(compose);
      // Encryption's input includes both the clear payload and its signed
      // packet stream. Reject a worst-case oversized envelope before asking
      // the hardware for a signature, rather than failing after PIN/touch.
      const bytes = Math.floor(payload.length / 4) * 3;
      const signingOverhead = 8192;
      const envelopeBound = payload.length + Math.ceil((bytes + signingOverhead) / 3) * 4 +
        material.senderCertificate.length + material.recipientCertificate.length + 4096;
      if (envelopeBound > 800000) throw Error('Signed encryption envelope limit');
      await init();
      // Another queued malformed request may have cancelled this operation
      // while init yielded. Such cancellation must not create signing state.
      if (stage !== 'preparing') throw Error('Cancelled operation');
      const request = JSON.parse(prepare_signing(JSON.stringify({
        senderCertificate: material.senderCertificate, senderEmail: material.senderEmail,
        payload, requestId
      })));
      if (request.signingFingerprint !== material.signingFingerprint) throw Error('Selected signing key changed');
      stage = 'waiting';
      self.postMessage({type: 'sign-request', requestId, request});
      return;
    }
    if (stage === 'waiting' && data.type === 'finalize' && data.requestId === requestId) {
      // Finalization consumes the stored state, checks both returned signature
      // components, and verifies the exact retained payload before release.
      stage = 'finalizing';
      const signed = JSON.parse(finalize_signing(JSON.stringify(data.signature)));
      if (signed.requestId !== requestId) throw Error('Operation mismatch');
      // Pass only encryption inputs: the detached signature and operation
      // metadata are not part of encrypt_signed's contract or size budget.
      const encrypted = JSON.parse(encrypt_signed(JSON.stringify({
        senderCertificate: signed.senderCertificate, signed: signed.signed, payload: signed.payload,
        recipientCertificate: material.recipientCertificate,
        recipientFingerprint: material.recipientFingerprint, recipientEmail: material.recipientEmail
      })));
      stage = 'done'; material = undefined;
      self.postMessage({type: 'complete', requestId, cipher: encrypted.cipher});
      self.close();
      return;
    }
    throw Error('Unexpected signing phase');
  } catch (_) {
    stage = 'failed'; material = undefined;
    // init may have failed before the export exists. Regardless, closing this
    // worker drops all state and never falls back to native packet construction.
    try {cancel_signing();} catch (_) {}
    self.postMessage({type: 'error', requestId});
    self.close();
  }
};
