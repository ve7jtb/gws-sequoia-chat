// Node-only Web Worker compatibility shim for the actual bundled browser worker.
// The sole fetch permitted here loads the fixed local WASM asset. The worker
// cannot reach a native bridge, account, network endpoint or hardware device.
import {parentPort} from 'node:worker_threads';
import fs from 'node:fs';
const wasm=new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url);
globalThis.fetch=async input=>{
  if(String(input)!==wasm.href)throw Error('Unexpected test fetch');
  return new Response(fs.readFileSync(wasm),{headers:{'Content-Type':'application/wasm'}});
};
globalThis.self={postMessage:message=>parentPort.postMessage(message),close:()=>parentPort.close()};
await import('../app/signing-worker.js');
parentPort.on('message',data=>self.onmessage({data}));
