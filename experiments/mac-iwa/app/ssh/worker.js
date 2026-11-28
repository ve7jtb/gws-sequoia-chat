// One worker per SSH connection or one-shot software signature. Destroying it
// on vault lock removes protocol/session/private-key state from the JS realm.
// A static module import loads the bundled Go runtime without a dynamic
// importScripts URL assignment under the IWA's Trusted Types policy.
import './wasm_exec.js';
let socket,reader,writer,started=false,ready=false,finished=false,sequence=0,timer;
const pending=new Map();
function closeTransport(){
 const connection=socket;socket=null;
 if(!connection)return;
 if(reader){reader.cancel().catch(()=>{});reader.releaseLock();}
 writer?.releaseLock();
 connection.close().catch(()=>{});
}
function finish(event){
 if(finished)return;
 finished=true;clearTimeout(timer);
 if(event)postMessage(event);
 closeTransport();close();
}
const fail=message=>finish({type:'error',message});
const rpc=(type,data)=>new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});postMessage({type,id,...data});});
globalThis.sshRead=async()=>{const r=await reader.read();return r.done?null:r.value;};
globalThis.sshWrite=async bytes=>writer.write(bytes);
globalThis.sshClose=()=>{
 closeTransport();
 // Go closes net.Conn before returning a handshake or authentication error.
 // Keep the worker alive so sshFailure can report that error to the caller.
 if(ready)finish({type:'closed',message:'SSH session ended.'});
};
globalThis.sshOutput=data=>postMessage({type:'output',data});
globalThis.sshSign=data=>rpc('sign',{data});
globalThis.sshPassword=algorithms=>rpc('password',{algorithms});
globalThis.sshVerifyHost=(algorithm,data)=>rpc('host',{algorithm,data});
globalThis.sshFailure=fail;
globalThis.sshAuthorized=algorithms=>finish({type:'authorized',algorithms});
globalThis.sshReady=keyExchange=>{
 if(!socket){fail('SSH server closed the session before the terminal was ready.');return;}
 ready=true;clearTimeout(timer);postMessage({type:'ready',keyExchange});
};
globalThis.onmessage=async({data})=>{
 try{
  if(data.type==='reply'){const p=pending.get(data.id);if(!p)return;pending.delete(data.id);data.error?p.reject(Error('SSH authorization rejected')):p.resolve(data.result);return;}
  if(data.type==='input'){if(started)globalThis.sshInput(data.data);return;}
  if(data.type==='resize'){if(started)globalThis.sshResize(data.rows,data.cols);return;}
  if(started)throw Error('SSH worker already used');started=true;
  const go=new globalThis.Go(),wasm=await WebAssembly.instantiateStreaming(fetch('./engine.wasm'),go.importObject);
  go.run(wasm.instance).catch(()=>fail('SSH engine stopped.'));
  if(data.type==='import-ed25519'){
   let result;
   try{result=globalThis.sshImportEd25519(data.file,data.passphrase);}
   finally{data.file.fill(0);data.passphrase.fill(0);}
   if(result.error)throw Error(result.error);
   try{finish({type:'imported',seed:result.seed,publicKey:result.publicKey});}
   finally{result.seed.fill(0);}
   return;
  }
  if(data.type==='software-sign'){
   let signature;
   try{signature=globalThis.sshSignSeeds(data.ml,data.ed,data.publicKey,data.message);if(!signature)throw Error('SSH software signature failed.');}
   finally{data.ml.fill(0);data.ed.fill(0);}
   finish({type:'signature',signature});return;
  }
  if(data.type!=='connect')throw Error('Invalid SSH worker request');
  timer=setTimeout(()=>fail('SSH connection timed out.'),120000);
  socket=new TCPSocket(data.host,data.port);socket.closed.catch(()=>{});
  const streams=await socket.opened;reader=streams.readable.getReader();writer=streams.writable.getWriter();
  globalThis.sshStart({publicKey:data.publicKey,additionalPublicKey:data.additionalPublicKey,address:data.host+':'+data.port,username:data.username,authorizeKey:data.authorizeKey===true});
 }catch(e){fail(e.message||'SSH operation failed.');}
};
