// Run the actual public-only worker with its exact bundled WASM URL. No network,
// native helper, card, account or browser storage is available in this harness.
import {parentPort} from 'node:worker_threads';
import fs from 'node:fs';
const wasm=new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url);
globalThis.fetch=async input=>{
 if(String(input)!==wasm.href)throw Error('Unexpected test fetch');
 return new Response(fs.readFileSync(wasm),{headers:{'Content-Type':'application/wasm'}});
};
globalThis.self={postMessage:value=>parentPort.postMessage(value)};
await import('../app/identities/worker.js');
parentPort.on('message',data=>self.onmessage({data}));
