// One worker owns the recipient packet, ciphertext and transient component
// secrets. Only the fixed, bounded hardware inputs cross Native Messaging.
// A cancelled operation is consumed, never retried or resumed with old shares.
export async function decryptWithHardware({cipher, service, purpose = 'message',
  recipientKey, verification, vault, identity, validateMaterial, native, createWorker, gate = async () => {},
  signal, timeoutMs = 240000}) {
  if (!['Gmail', 'Chat', 'Vault'].includes(service) ||
      !['message', 'vault'].includes(purpose) || (purpose === 'vault') !== (service === 'Vault'))
    throw Error('Invalid decryption purpose.');
  if(purpose==='message'&&(!identity||typeof validateMaterial!=='function'))
    throw Error('A matched saved identity is required for message decryption.');
  // Independently bind the hardware request to these immutable ciphertext
  // bytes, rather than trusting a worker-provided digest by itself. This also
  // protects the fixed vault path, which does not use the message matcher.
  const cipherHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',
    Uint8Array.from(atob(cipher), value => value.charCodeAt(0)))),
    value => value.toString(16).padStart(2, '0')).join('');
  const controller = new AbortController();
  const check = async () => {
    if (controller.signal.aborted || signal?.aborted) throw Error('Decryption cancelled; no retry.');
    await gate();
    if (controller.signal.aborted || signal?.aborted) throw Error('Decryption cancelled; no retry.');
  };
  let worker, timer, phase = 'metadata', finished = false, material;
  return new Promise((resolve, reject) => {
    const finish = (error, result) => {
      if (finished) return;
      finished = true; phase = 'done'; clearTimeout(timer);
      signal?.removeEventListener('abort', cancel);
      controller.abort(); worker?.terminate(); material = undefined;
      error ? reject(error) : resolve(result);
    };
    const cancel = () => finish(Error('Decryption cancelled; no retry.'));
    signal?.addEventListener('abort', cancel, {once: true});
    timer = setTimeout(() => finish(Error('Decryption timed out; no retry.')), timeoutMs);
    if (signal?.aborted) { cancel(); return; }
    (async () => {
      await check();
      // Vault enrollment retains its existing fixed key. Messages use only the
      // recipient-matched saved identity; a failure never falls back to that
      // fixed key. Native code authenticates the selected live card bundle.
      material = await native(purpose==='vault'?'chat-decryption-material':'chat-selected-decryption-material',
        purpose==='vault'?{service}:{service,identity}, {signal: controller.signal});
      await check();
      if(purpose==='message'){await validateMaterial(material);await check();}
      if (!material || !/^[a-f0-9]{48}$/.test(material.review) ||
          !/^[A-F0-9]{64}$/.test(material.recipientKey) ||
          typeof material.recipientCertificate !== 'string' || material.recipientCertificate.length > 90000 ||
          (recipientKey && recipientKey !== material.recipientKey))
        throw Error('Configured decryption identity changed.');
      worker = createWorker();
      const requestId = Array.from(crypto.getRandomValues(new Uint8Array(32)),
        n => n.toString(16).padStart(2, '0')).join('').toUpperCase();
      worker.onerror = () => finish(Error('WASM decryption failed; no native fallback.'));
      worker.onmessage = ({data}) => {
        if (finished) return;
        (async () => {
          if (data?.type === 'component-request' && phase === 'preparing' && data.requestId === requestId) {
            // Claim the phase before awaiting a trust/vault recheck. A duplicate
            // worker request cannot trigger a second PIN prompt or card call.
            phase = 'hardware'; await check();
            const r = data.request;
            if (!r || Object.keys(r).sort().join(',') !== 'cipherHash,mlkemCiphertext,recipientKey,requestId,x25519Ephemeral' ||
                r.requestId !== requestId || r.recipientKey !== material.recipientKey ||
                r.cipherHash !== cipherHash)
              throw Error('Invalid WASM hardware request.');
            let result;
            try {
              result = await native('chat-decapsulate-components',
                {...r, review: material.review, service}, {signal: controller.signal});
              await check();
              if (finished || phase !== 'hardware') throw Error('Stale hardware result.');
              phase = 'finalizing';
              worker.postMessage({type: 'finalize', requestId, result});
            } finally {
              // Structured cloning gives the disposable worker its own copy.
              // Drop main-page references promptly; JS cannot promise erasure.
              if (result) { delete result.mlkemSecret; delete result.x25519Secret; }
            }
          } else if (data?.type === 'complete' && phase === 'finalizing' && data.requestId === requestId) {
            phase = 'checking'; await check(); finish(null, data.result);
          } else {
            throw Error('WASM decryption rejected this operation; no retry.');
          }
        })().catch(error => finish(error));
      };
      phase = 'preparing';
      worker.postMessage({type: 'prepare', requestId, cipher, purpose,
        recipientCertificate: material.recipientCertificate, recipientKey: material.recipientKey,
        verification, vault});
    })().catch(error => finish(error));
  });
}
