// Only imported by the existing disposable signing/decryption workers. The
// native bridge never receives a decrypted P12; no seed, password or shared
// secret is persisted. The owner terminates this worker on every outcome.
import {companion_complete} from '../wasm/sequoia_iwa_verify.js';

export async function completeCompanion(operation, certificate, request, response, complete = companion_complete) {
  if (!response || typeof response !== 'object') throw Error('Missing component response');
  if (!response.companion) {
    if ('companionShared' in response) throw Error('Unbound companion shared secret');
    return response;
  }
  if (!['sign', 'decapsulate'].includes(operation)) throw Error('Unsupported companion operation');
  // Wide/baseline workers pass the binding from their own initialized module.
  // This avoids initializing a second WASM instance with separate state.
  try {
    return JSON.parse(complete(JSON.stringify({operation, certificate, request, response})));
  } finally {
    // JS strings cannot promise erasure, so release references promptly and
    // rely on the one-operation worker's termination in addition to Rust wipes.
    response.companionShared = '';
    delete response.companion;
  }
}
