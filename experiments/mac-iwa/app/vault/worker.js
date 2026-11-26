// One-shot WASM worker: PIV envelope creation/opening never touches a private key.
import init,{wrap_vault_key,unwrap_vault_key,vault_mlkem1024_encapsulate} from '../wasm/sequoia_iwa_verify.js';
self.onmessage=async({data})=>{try{await init();const fn=data.op==='wrap'?wrap_vault_key:data.op==='unwrap'?unwrap_vault_key:data.op==='level5-encapsulate'?vault_mlkem1024_encapsulate:null;if(!fn)throw Error();const result=JSON.parse(fn(JSON.stringify(data.input)));self.postMessage({ok:true,result});}catch(_){self.postMessage({ok:false,error:'PIV vault envelope rejected.'});}};
