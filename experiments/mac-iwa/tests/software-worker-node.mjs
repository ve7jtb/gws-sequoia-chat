// Test-only Node bridge for the shipped browser workers. No network, native
// extension, account storage or physical authenticator is exposed. The wide
// variant changes only the fixed WASM import directory; worker source and
// messages remain those shipped in the browser application.
import {parentPort,workerData} from 'node:worker_threads';
import fs from 'node:fs';
const entries=new Set(['software/worker.js','identities/worker.js','signing-worker.js','decryption-worker.js']);
if(!entries.has(workerData.entry)||!['baseline','wide'].includes(workerData.variant))throw Error('Invalid worker fixture');
const entry=new URL('../app/'+workerData.entry,import.meta.url),directory=workerData.variant==='wide'?'wasm-wide':'wasm';
const wasm=new URL('../app/'+directory+'/sequoia_iwa_verify_bg.wasm',import.meta.url);
globalThis.fetch=async input=>{
 if(String(input)!==wasm.href)throw Error('Unexpected test fetch');
 return new Response(fs.readFileSync(wasm),{headers:{'Content-Type':'application/wasm'}});
};
globalThis.self={postMessage:value=>parentPort.postMessage(value),close:()=>parentPort.close()};
// Resolve relative static imports exactly as the browser would, replacing only
// the known baseline WASM directory for the separately shipped wide build.
const source=fs.readFileSync(entry,'utf8').replace(/from\s+(['"])(\.{1,2}\/[^'"]+)\1/g,(all,quote,relative)=>{
 const resolved=new URL(relative,entry);
 if(resolved.pathname.endsWith('/wasm/sequoia_iwa_verify.js'))resolved.pathname=resolved.pathname.replace('/wasm/','/'+directory+'/');
 return 'from '+JSON.stringify(resolved.href);
});
await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
parentPort.on('message',data=>self.onmessage({data}));
