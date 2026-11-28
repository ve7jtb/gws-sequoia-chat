// Coordinate a single disposable signing worker. It alone owns the MIME bytes,
// v6 salt, signature template and pending digest. The main page relays a bounded
// digest request to the fixed native signer; it never receives a private key.
import {signingFailure,signingFailurePhase} from './signing-phases.js';
export async function signAndEncrypt(material, compose, signDigest, options = {}) {
  const createWorker = options.createWorker || (() => new Worker('/signing-worker.js', {type: 'module'}));
  const timeoutMs = options.timeoutMs ?? 360000;
  const signal = options.signal;
  if (signal?.aborted) throw signingFailure('Signing cancelled; no retry.','signing-cancelled');
  const random = crypto.getRandomValues(new Uint8Array(32));
  const requestId = Array.from(random, b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  let worker, timer, rejectResult, finishResult, failure, inFlight, stage = 'preparing';
  const result = new Promise((resolve, reject) => {finishResult = resolve; rejectResult = reject;});
  const fail = (message,phase='signing-protocol') => {
    if (stage === 'done' || failure) return;
    failure = signingFailure(message,phase);
    // Termination discards the pending signing state. The native operation may
    // already be waiting for touch; cancellation must not retry or replace it.
    worker?.terminate();
    rejectResult(failure);
  };
  const cancel = () => fail('Signing cancelled; no retry.','signing-cancelled');
  try {
    worker = createWorker();
    timer = setTimeout(() => fail('Browser signing timed out; check the card operation before trying again.','signing-timeout'), timeoutMs);
    signal?.addEventListener('abort', cancel, {once: true});
    worker.onerror = () => fail('Browser signing failed; no native fallback.','signing-worker');
    worker.onmessage = ({data}) => {
      if (failure || stage === 'done') return;
      if (!data || data.requestId !== requestId) {fail('Signing response belongs to a different operation.'); return;}
      // The worker may report only a known phase code. Its message, stack and
      // other properties are deliberately ignored, including on malformed data.
      if (data.type === 'error') {fail('Browser signing rejected this message; no retry.',signingFailurePhase(data.failurePhase)); return;}
      if (data.type === 'sign-request' && stage === 'preparing') {
        const r = data.request;
        // Reconstruct the allowed shape instead of forwarding arbitrary worker
        // fields. PINs, paths, slots, MIME and backend options cannot enter it.
        if (!r || r.requestId !== requestId || r.hashAlgorithm !== 10 ||
            !/^(?:[A-F0-9]{40}|[A-F0-9]{64})$/.test(r.signingFingerprint) ||
            typeof r.digest !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(r.digest)) {
          fail('Invalid hardware signing request.'); return;
        }
        // Only a publicly validated v5 profile may request its second literal-
        // metadata-bound signature. Native code independently checks the live
        // selected certificate before accepting that additional digest.
        const v5=(material.softwareProfile||material.hardwareProfile)==='level3-v5-hybrid';
        const extra=v5?{inlineDigest:r.inlineDigest}:{};
        if(v5?typeof r.inlineDigest!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(r.inlineDigest):Object.hasOwn(r,'inlineDigest')){
          fail('Invalid compatibility signing request.');return;
        }
        stage = 'signing';
        inFlight = (async () => {
          try {
            const signature = await signDigest({review: material.review, requestId,
              signingFingerprint: r.signingFingerprint, hashAlgorithm: 10, digest: r.digest,...extra});
            try {
              if (failure) return; // A late native reply can never revive a worker.
              stage = 'finalizing';
              worker.postMessage({type: 'finalize', requestId, signature});
            } catch (_) {
              // A browser handoff failure is distinct from a failed native
              // signature; neither outcome permits retrying the card operation.
              fail('Browser signing handoff failed; no retry.','signing-worker');
            } finally {
              // A companion wrapping share is transient secret material. The
              // disposable worker owns the structured clone after posting; no
              // page-level operation may retain or reuse the native response.
              if (signature) delete signature.companionShared;
            }
          } catch (_) {fail('Hardware signing did not complete; no retry.','native-signature');}
        })();
        return;
      }
      if (data.type === 'complete' && stage === 'finalizing' &&
          typeof data.cipher === 'string' && data.cipher.length > 0 && data.cipher.length <= 349528) {
        stage = 'done'; finishResult({cipher: data.cipher}); return;
      }
      fail('Unexpected signing response; no retry.');
    };
    worker.postMessage({type: 'prepare', requestId, material, compose});
    return await result;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', cancel);
    worker?.terminate();
    // Keep the caller's operation lock until an already-started native request
    // settles, even if the worker times out. This prevents a second PIN/signing
    // request while the first operation's outcome is still uncertain.
    await inFlight;
  }
}
