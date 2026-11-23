// Signing uses its own fixed worker because it must retain the v6 template and
// salt across an asynchronous hardware request. Neither policy accepts URLs
// supplied by a message, certificate, native response or user setting.
const signingWorkerPolicy=globalThis.trustedTypes?.createPolicy('sequoia-signing-worker',{createScriptURL:url=>{if(url!=='/signing-worker.js')throw Error('Unexpected signing worker');return url;}});
function signingWorkerURL(){return signingWorkerPolicy?signingWorkerPolicy.createScriptURL('/signing-worker.js'):'/signing-worker.js';}
// A fresh worker per message bounds lifetime and drops decrypted content on
// completion. A timeout never retries hardware or falls back to native verify.
const messageWorkerPolicy=globalThis.trustedTypes?.createPolicy('sequoia-message-worker',{createScriptURL:url=>{if(url!=='/message-worker.js')throw Error('Unexpected worker');return url;}});
// The unadorned worker RPC also serves certificate actions inside an already
// locked UI operation. Re-verification uses the captured message bytes, never
// a UI-supplied claim that a certificate signed the message.
function runMessageWorker(packet,material,compose,encrypt){return new Promise((resolve,reject)=>{
 let worker,timer,finished=false;
 const finish=(error,result)=>{
  if(finished)return;finished=true;clearTimeout(timer);worker?.terminate();error?reject(Error(error)):resolve(result);
 };
 try{
  worker=new Worker(messageWorkerPolicy?messageWorkerPolicy.createScriptURL('/message-worker.js'):'/message-worker.js',{type:'module'});
  timer=setTimeout(()=>finish('Browser verification timed out; no retry.'),30000);
  worker.onerror=()=>finish('Browser verifier failed; no fallback.');
  worker.onmessage=({data})=>finish(data.ok?null:data.error,data.result);
  worker.postMessage({packet,material,compose,encrypt});
  // Structured cloning has transferred the operation to the disposable worker.
  // Drop the main-page reference; JS strings cannot promise secure zeroization.
  if(packet?.sessionKey)delete packet.sessionKey;
 }catch(_){finish('Browser verifier could not start; no fallback.');}
});}
async function processMessage(packet,material,compose,encrypt){
 if(busy)throw Error('An operation is already running.');
 operationBusy(true);
 try{return await runMessageWorker(packet,material,compose,encrypt);}
 finally{operationBusy(false);}
}
