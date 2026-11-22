// A fresh worker per message bounds lifetime and drops decrypted content on
// completion. A timeout never retries hardware or falls back to native verify.
const messageWorkerPolicy=globalThis.trustedTypes?.createPolicy('sequoia-message-worker',{createScriptURL:url=>{if(url!=='/message-worker.js')throw Error('Unexpected worker');return url;}});
function processMessage(packet,material,compose){return new Promise((resolve,reject)=>{
 if(busy){reject(Error('An operation is already running.'));return;}
 busy=true;document.querySelectorAll('button').forEach(b=>b.disabled=true);$('transport').disabled=true;$('busy').hidden=false;
 let worker,timer,finished=false;
 const finish=(error,result)=>{
  if(finished)return;finished=true;clearTimeout(timer);worker?.terminate();busy=false;
  document.querySelectorAll('button').forEach(b=>b.disabled=false);$('transport').disabled=false;$('busy').hidden=true;
  $('newer').disabled=page===0;$('older').disabled=!next;error?reject(Error(error)):resolve(result);
 };
 try{
  worker=new Worker(messageWorkerPolicy?messageWorkerPolicy.createScriptURL('/message-worker.js'):'/message-worker.js',{type:'module'});
  timer=setTimeout(()=>finish('Browser verification timed out; no retry.'),30000);
  worker.onerror=()=>finish('Browser verifier failed; no fallback.');
  worker.onmessage=({data})=>finish(data.ok?null:data.error,data.result);
  worker.postMessage({packet,material,compose});
 }catch(_){finish('Browser verifier could not start; no fallback.');}
});}
