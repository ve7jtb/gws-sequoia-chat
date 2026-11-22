// Separate experimental UI: ordinary Gmail verification still uses the proven
// native path. Test expectations are assertions supplied by a fixture, not trust.
const output=document.getElementById('wasm-results');
let running=false;
// IWAs enforce Trusted Types even for Worker script URLs. Permit exactly this
// bundled worker; never convert user input, remote URLs or HTML into trusted code.
const workerPolicy=globalThis.trustedTypes?.createPolicy('sequoia-wasm-worker',{
 createScriptURL(value){if(!['/wasm-worker.js','/wasm-benchmark-worker.js'].includes(value))throw TypeError('Unexpected worker URL');return value;}
});
async function run(vectors){
 if(running)throw Error('A WASM test is already running');
 running=true;output.textContent='Running Sequoia verification inside a browser worker…';
 let worker,timer;
 try{
  const result=await new Promise((resolve,reject)=>{
   worker=new Worker(workerPolicy?workerPolicy.createScriptURL('/wasm-worker.js'):'/wasm-worker.js',{type:'module'});
   timer=setTimeout(()=>reject(Error('Verification timed out')),30000);
   worker.onerror=()=>reject(Error('WASM worker failed; no native fallback'));
   worker.onmessage=({data})=>data.ok?resolve(data):reject(Error(data.error));
   worker.postMessage(vectors);
  });
  output.textContent=(result.passed?'PASS':'FAIL')+' — browser WebAssembly, RustCrypto backend\n'+result.rows.map(r=>(r.passed?'PASS ':'FAIL ')+r.name+': '+r.signatures.map(s=>s.status+' · '+(s.algorithm||'no key')).join(', ')+' · '+r.milliseconds+' ms').join('\n')+'\nPublic signature validity only. Saved trust is independent and is not read or changed by this test. MIME extraction remains native.';
 }finally{clearTimeout(timer);worker?.terminate();running=false;}
}
for(const [id,load] of [
 ['wasm-baseline',async()=>{const r=await fetch('/wasm-fixtures.json');if(!r.ok)throw Error('Fixtures missing');return r.json();}],
 ['wasm-local',async()=>{const f=document.getElementById('wasm-vectors').files[0];if(!f||f.size>2000000)throw Error('Select verification vectors up to 2 MB');return JSON.parse(await f.text());}]
])document.getElementById(id).addEventListener('click',async()=>{try{await run(await load());}catch(e){output.textContent='STOPPED: '+e.message;}});

// Benchmarks run in a fresh worker and use the selected public vectors, or the
// bundled synthetic fixtures if no local file is selected. No trust mutation.
document.getElementById('wasm-benchmark').addEventListener('click',async()=>{
 if(running)return;
 let worker,timer;running=true;
 output.textContent='Benchmarking baseline versus wide arithmetic (warm-up, alternating order)…';
 try{
  const f=document.getElementById('wasm-vectors').files[0];
  if(f&&f.size>2000000)throw Error('Vectors exceed 2 MB');
  const vectors=f?JSON.parse(await f.text()):await (await fetch('/wasm-fixtures.json')).json();
  const result=await new Promise((resolve,reject)=>{
   const url='/wasm-benchmark-worker.js';
   worker=new Worker(workerPolicy?workerPolicy.createScriptURL(url):url,{type:'module'});
   timer=setTimeout(()=>reject(Error('Benchmark timed out')),120000);
   worker.onerror=()=>reject(Error('Benchmark worker failed'));
   worker.onmessage=({data})=>data.ok?resolve(data):reject(Error(data.error));
   worker.postMessage(vectors);
  });
  output.textContent='PASS — baseline and wide arithmetic agree on every verification\n21 alternating rounds × 5 verifications after 5 warm-ups per case. Median ms/call (lower is faster); ratio = baseline/wide.\n'+result.rows.map(r=>r.name+': baseline '+r.baseline.median.toFixed(3)+' ms, wide '+r.wide.median.toFixed(3)+' ms, ratio '+r.ratio.toFixed(2)+'×').join('\n')+'\nModule bytes: baseline '+result.baselineBytes+', wide '+result.wideBytes+'\n'+result.userAgent+'\nNo native crypto fallback. No key, message or trust changes.';
  // Public timing report only. Saving is explicit and contains no message bytes.
  const link=document.getElementById('wasm-report');
  if(link.dataset.url)URL.revokeObjectURL(link.dataset.url);
  link.href=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));
  link.dataset.url=link.href;link.hidden=false;
 }catch(e){output.textContent='STOPPED: '+e.message;}
 finally{clearTimeout(timer);worker?.terminate();running=false;}
});
