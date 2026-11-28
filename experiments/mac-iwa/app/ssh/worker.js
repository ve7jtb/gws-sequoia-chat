// One worker per SSH connection or one-shot software signature. Destroying it
// on vault lock removes protocol/session/private-key state from the JS realm.
// A static module import loads the bundled Go runtime without a dynamic
// importScripts URL assignment under the IWA's Trusted Types policy.
import './wasm_exec.js';
let socket,reader,writer,started=false,sequence=0,timer;
const pending=new Map();
const fail=message=>{postMessage({type:'error',message});shutdown();};
function shutdown(){clearTimeout(timer);reader?.cancel().catch(()=>{});socket?.close().catch(()=>{});close();}
const rpc=(type,data)=>new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});postMessage({type,id,...data});});
globalThis.sshRead=async()=>{const r=await reader.read();return r.done?null:r.value;};
globalThis.sshWrite=async bytes=>writer.write(bytes);
globalThis.sshClose=()=>{postMessage({type:'closed'});shutdown();};
globalThis.sshOutput=data=>postMessage({type:'output',data});
globalThis.sshSign=data=>rpc('sign',{data});
globalThis.sshVerifyHost=(algorithm,data)=>rpc('host',{algorithm,data});
globalThis.sshFailure=fail;
globalThis.sshReady=()=>{clearTimeout(timer);postMessage({type:'ready'});};
globalThis.onmessage=async({data})=>{
 try{
  if(data.type==='reply'){const p=pending.get(data.id);if(!p)return;pending.delete(data.id);data.error?p.reject(Error('SSH authorization rejected')):p.resolve(data.result);return;}
  if(data.type==='input'){if(started)globalThis.sshInput(data.data);return;}
  if(data.type==='resize'){if(started)globalThis.sshResize(data.rows,data.cols);return;}
  if(started)throw Error('SSH worker already used');started=true;
  const go=new globalThis.Go(),wasm=await WebAssembly.instantiateStreaming(fetch('./engine.wasm'),go.importObject);
  go.run(wasm.instance).catch(()=>fail('SSH engine stopped.'));
  if(data.type==='software-sign'){
   try{const signature=globalThis.sshSignSeeds(data.ml,data.ed,data.publicKey,data.message);if(!signature)throw Error('SSH software signature failed');postMessage({type:'signature',signature});}
   finally{data.ml.fill(0);data.ed.fill(0);shutdown();}return;
  }
  if(data.type!=='connect')throw Error('Invalid SSH worker request');
  timer=setTimeout(()=>fail('SSH connection timed out.'),120000);
  socket=new TCPSocket(data.host,data.port);socket.closed.catch(()=>{});
  const streams=await socket.opened;reader=streams.readable.getReader();writer=streams.writable.getWriter();
  globalThis.sshStart({publicKey:data.publicKey,address:data.host+':'+data.port,username:data.username});
 }catch(e){fail(e.message||'SSH operation failed.');}
};
