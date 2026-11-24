// Public own-identity inspection and recipient matching run in a disposable
// worker. It has no native bridge, PIN, private-key API or storage mutation.
import init,{inspect_identity,match_recipients} from '../wasm/sequoia_iwa_verify.js';

self.onmessage=async({data})=>{
 try{
  if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).sort().join(',')!=='op,value')throw Error();
  const functions={'inspect':inspect_identity,'match':match_recipients},operation=functions[data.op];
  if(typeof operation!=='function'||!Object.hasOwn(functions,data.op))throw Error();
  // The outer worker limit is separate from Rust's packet/count bounds. No
  // attacker-selected URL, script or backend is accepted by either boundary.
  const input=JSON.stringify(data.value);
  if(input.length>(data.op==='inspect'?360000:1800000))throw Error();
  await init();
  self.postMessage({ok:true,result:JSON.parse(operation(input))});
 }catch(_){self.postMessage({ok:false,error:'Public identity or recipient matching rejected.'});}
};
