// Every software operation uses a new, fixed worker. The only long-lived input
// supplied to it is already password-encrypted OpenPGP secret material. Worker
// termination on completion, lock or cancellation bounds private-key lifetime;
// JavaScript/IPC copies still cannot be promised to have been physically erased.
const policy=globalThis.trustedTypes?.createPolicy('sequoia-software-worker',{
 createScriptURL:url=>{if(url!=='/software/worker.js')throw Error('Unexpected software worker');return url;}
});
export function createSoftwareClient({createWorker=()=>new Worker(policy?policy.createScriptURL('/software/worker.js'):'/software/worker.js',{type:'module'}),timeoutMs=90000}={}){
 return async function software(op,input,{signal}={}){
  if(!['inspect','sign','decapsulate','generate','export','import-p12'].includes(op))throw Error('Unsupported software operation.');
  if(JSON.stringify(input).length>(op==='import-p12'?1500000:400000))throw Error('Software identity request is too large.');
  return new Promise((resolve,reject)=>{
   let worker,timer,finished=false;const id=crypto.randomUUID();
   const finish=(error,result)=>{
    if(finished)return;finished=true;clearTimeout(timer);signal?.removeEventListener('abort',cancel);worker?.terminate();worker=null;
    // Drop this task's references. The caller separately discards the password
    // and encrypted source copies after the worker has settled.
    input=null;error?reject(Error(error)):resolve(result);
   };
   const cancel=()=>finish('Software identity operation cancelled; no retry.');
   try{
    if(signal?.aborted){cancel();return;}
    signal?.addEventListener('abort',cancel,{once:true});worker=createWorker();
    timer=setTimeout(()=>finish('Software identity operation timed out; no retry.'),op==='import-p12'?Math.max(timeoutMs,180000):timeoutMs);
    worker.onerror=()=>finish('Software cryptography failed; no hardware fallback.');
    worker.onmessage=({data})=>{
     if(!data||data.id!==id||typeof data.ok!=='boolean')return finish('Software response belongs to a different operation.');
     // Never reflect a worker's raw error/exception: parser failures may include
     // imported bytes or a password. All user-visible failures are fixed text.
     if(!data.ok)return finish('Software identity or password rejected; no data was changed.');
     if(Object.keys(data).sort().join(',')!=='id,ok,result')return finish('Invalid software response.');
     finish(null,data.result);
    };
    worker.postMessage({id,op,input});
   }catch(_){finish('Could not start software identity operation.');}
  });
 };
}
export const softwareCrypto=createSoftwareClient();
