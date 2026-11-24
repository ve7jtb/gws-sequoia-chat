// All OpenPGP framing, v6 salt generation and hashing stay in this worker.
// Only the prepared digest leaves it for hardware signing. A fresh worker is
// created for each message and destroyed on success, cancellation or failure.
import init, {prepare_signing, finalize_signing, cancel_signing, encrypt_signed, inspect_public, companion_complete} from './wasm/sequoia_iwa_verify.js';
import {composeMime} from './message-mime.js';
import {completeCompanion} from './companion/complete.js';
import {signingFailurePhase} from './signing-phases.js';

let stage = 'new', requestId, material, componentRequest, failurePhase = 'signing-preparation';
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
      // The optional LibrePGP v5 wire mode is isolated from RFC 9580 in
      // this increment. Inspect the actual certificates before requesting a
      // private signature; UI labels cannot authorize a mixed-format message.
      const own = JSON.parse(inspect_public(JSON.stringify({certificate:material.senderCertificate})));
      const peer = JSON.parse(inspect_public(JSON.stringify({certificate:material.recipientCertificate})));
      if ((own.version===5)!==(peer.version===5)) throw Error('Select v5 certificates for both ends of LibrePGP compatibility');
      const request = componentRequest = JSON.parse(prepare_signing(JSON.stringify({
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
      // Companion unwrapping and software components exist only in this disposable
      // worker. The native host contributes card operations; it never receives
      // plaintext .p12 bytes, and no software key can replace a required card key.
      let signature;
      try {
        // These labels describe boundaries only; no thrown WASM/native text is
        // retained. A successful native return does not yet prove the software
        // companion restored or the complete OpenPGP signature verified.
        failurePhase = data.signature?.companion ? 'companion-completion' : 'signature-finalization';
        signature = await completeCompanion('sign', material.senderCertificate, componentRequest, data.signature, companion_complete);
        if (stage !== 'finalizing') throw Error('Cancelled operation');
      } finally { if (data.signature) delete data.signature.companionShared; }
      failurePhase = 'signature-finalization';
      const signed = JSON.parse(finalize_signing(JSON.stringify(signature)));
      if (signed.requestId !== requestId) throw Error('Operation mismatch');
      // Pass only encryption inputs: the detached signature and operation
      // metadata are not part of encrypt_signed's contract or size budget.
      failurePhase = 'recipient-encryption';
      const encrypted = JSON.parse(encrypt_signed(JSON.stringify({
        senderCertificate: signed.senderCertificate, signed: signed.signed, payload: signed.payload,
        recipientCertificate: material.recipientCertificate,
        recipientFingerprint: material.recipientFingerprint, recipientEmail: material.recipientEmail
      })));
      stage = 'done'; material = componentRequest = undefined;
      self.postMessage({type: 'complete', requestId, cipher: encrypted.cipher});
      self.close();
      return;
    }
    failurePhase = 'signing-protocol';
    throw Error('Unexpected signing phase');
  } catch (_) {
    stage = 'failed'; material = componentRequest = undefined;
    // init may have failed before the export exists. Regardless, closing this
    // worker drops all state and never falls back to native packet construction.
    try {cancel_signing();} catch (_) {}
    self.postMessage({type: 'error', requestId, failurePhase: signingFailurePhase(failurePhase)});
    self.close();
  }
};
