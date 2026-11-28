const url='/local-files/worker.js';
const policy=globalThis.trustedTypes?.createPolicy('sequoia-local-files-worker',{
 createScriptURL(value){if(value!==url)throw Error('Unexpected file worker.');return value;},
});

export function localFileCrypto(operation,input,{signal}={}){
 return new Promise((resolve,reject)=>{
  let worker,timer;
  const finish=(error,result)=>{
   clearTimeout(timer);
   signal?.removeEventListener('abort',abort);
   worker?.terminate();
   if(error)reject(Error(error));else resolve(result);
  };
  const abort=()=>finish('Local file operation cancelled.');
  try{
   if(signal?.aborted){abort();return;}
   worker=new Worker(policy?policy.createScriptURL(url):url,{type:'module'});
   signal?.addEventListener('abort',abort,{once:true});
   timer=setTimeout(()=>finish('Local file encryption or decryption timed out.'),30000);
   worker.onerror=()=>finish('Local file cryptography failed.');
   worker.onmessage=({data})=>data?.ok?finish(null,data.result):finish('Local file encryption or authentication failed.');
   worker.postMessage({operation,input},input.plain?[input.plain.buffer]:[]);
  }catch{finish('Could not start local file cryptography.');}
 });
}
