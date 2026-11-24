// Run the actual browser worker in Node without exposing a network or native
// bridge. Only its exact local WASM URL can be fetched; tests provide component
// shares from disposable fixtures or an explicitly authorized hardware harness.
import {parentPort} from 'node:worker_threads';
import fs from 'node:fs';
const wasm = new URL('../app/wasm/sequoia_iwa_verify_bg.wasm', import.meta.url);
globalThis.fetch = async input => {
  if (String(input) !== wasm.href) throw Error('Unexpected test fetch');
  return new Response(fs.readFileSync(wasm), {headers: {'Content-Type': 'application/wasm'}});
};
globalThis.self = {postMessage: value => parentPort.postMessage(value), close: () => parentPort.close()};
await import('../app/decryption-worker.js');
parentPort.on('message', data => self.onmessage({data}));
