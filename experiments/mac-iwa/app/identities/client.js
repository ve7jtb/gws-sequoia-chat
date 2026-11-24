// Fixed worker loading keeps public certificates from selecting executable code
// or requesting native hardware access. Every call gets isolated WASM state.
const policy=globalThis.trustedTypes?.createPolicy('sequoia-identity-worker',{
 createScriptURL:url=>{if(url!=='/identities/worker.js')throw Error('Unexpected identity worker');return url;}
});
function request(op,value,{signal}={}){
 return new Promise((resolve,reject)=>{
  let worker,timer,finished=false;
  const finish=(error,result)=>{
   if(finished)return;finished=true;clearTimeout(timer);signal?.removeEventListener('abort',cancel);worker?.terminate();
   error?reject(Error(error)):resolve(result);
  };
  const cancel=()=>finish('Public identity inspection cancelled.');
  try{
   if(signal?.aborted){cancel();return;}
   signal?.addEventListener('abort',cancel,{once:true});
   worker=new Worker(policy?policy.createScriptURL('/identities/worker.js'):'/identities/worker.js',{type:'module'});
   timer=setTimeout(()=>finish('Public identity inspection timed out; no native fallback.'),30000);
   worker.onerror=()=>finish('Public identity inspector unavailable; no native fallback.');
   worker.onmessage=({data})=>finish(data?.ok?null:'Public identity or recipient matching rejected.',data?.result);
   worker.postMessage({op,value});
  }catch(_){finish('Could not start public identity inspection.');}
 });
}

/** Inspect a public identity; supported means current Level 3 v6 key capability,
 * not a proof that this browser owns it or can use a particular hardware slot.
 */
export function inspectIdentity(certificate,options){return request('inspect',{certificate},options);}

/** Authenticate a compressed public bundle without contacting any hardware.
 * The result deliberately claims no live-key match. Hardware evidence is joined
 * separately, and native private-operation authorization remains independent.
 */
export function inspectBundle(bundle,options){return request('bundle',{bundle},options);}

/** Return every exact saved-certificate match, never an arbitrary first match.
 * A message's recipient packet is not yet authenticated plaintext. The caller
 * must bind the chosen identity/cipher hash again before requesting private ops.
 */
export function matchRecipients({cipher,candidates},options){return request('match',{cipher,candidates},options);}
