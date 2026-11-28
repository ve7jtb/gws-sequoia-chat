import {endpoint,sshUsername} from './transport.js';
import {UnknownSshHostError,verifyHost} from './host-verifier.js';
import {usesHybridSshKex} from './kex-probe.js';
const b64=b=>btoa(String.fromCharCode(...b));
const sshWorkerPath='/ssh/worker.js';
const sshWorkerPolicy=globalThis.trustedTypes?.createPolicy('sequoia-ssh-worker',{
 createScriptURL(url){
  if(url!==sshWorkerPath)throw Error('Unexpected SSH worker URL.');
  return url;
 },
});
// Both SSH paths run the same fixed, bundled module worker. Chromium's IWA
// policy requires a TrustedScriptURL even for same-origin Worker URLs.
function createSshWorker(WorkerClass=Worker){
 const url=sshWorkerPolicy?sshWorkerPolicy.createScriptURL(sshWorkerPath):sshWorkerPath;
 return new WorkerClass(url,{type:'module'});
}
// The UI receives no private key. The injected signer checks its vault revision
// on both sides of signing; trust must pass before any sign callback is accepted.
export function connectSsh({host,port,username,publicKey,additionalPublicKey,entries,getEntries,acceptUnknownHost,requestPassword,authorizeKey=false,sign,guard,signal,onOutput,onStatus,WorkerClass=Worker}){
 const target=endpoint(host,port);guard();
 sshUsername(username);
 if(authorizeKey&&typeof requestPassword!=='function')throw Error('Password prompt is unavailable.');
 const worker=createSshWorker(WorkerClass),lifetime=new AbortController();
 let fileRequest=null,transferID=0;
 let closed=false,hostAccepted=false,ready=false,signing=false,authUsed=false,reviewedAlgorithms,hostKey=null,resizeTimer;
 const close=()=>{if(closed)return;closed=true;clearTimeout(resizeTimer);lifetime.abort();fileRequest?.finish(Error('SSH connection closed.'));worker.terminate();signal?.removeEventListener('abort',close);};
 const check=()=>{if(closed)throw Error('SSH connection closed.');guard();};
 const verify=async candidate=>verifyHost({entries:getEntries?await getEntries():entries,...candidate,guard:check});
 signal?.addEventListener('abort',close,{once:true});if(signal?.aborted){close();throw Error('SSH cancelled.');}
 worker.onerror=()=>{if(!closed){onStatus('SSH engine failed.','error');close();}};
 worker.onmessage=async({data})=>{
  if(closed)return;
  try{
   guard();
   if(data.type==='host'){
    if(hostKey)throw Error('Unexpected SSH host verification request.');
    hostKey={...target,type:data.algorithm,key:b64(data.data)};
    try{await verify(hostKey);}
    catch(error){
     if(!(error instanceof UnknownSshHostError)||!acceptUnknownHost)throw error;
     check();await acceptUnknownHost(hostKey,check,lifetime.signal);
     await verify(hostKey);
    }
    check();hostAccepted=true;
    if(!closed)worker.postMessage({type:'reply',id:data.id,result:true});
   }else if(data.type==='sign'){
    if(authorizeKey||!hostAccepted||signing||ready||authUsed)throw Error('Unexpected SSH authentication request.');signing=true;authUsed=true;
    try{await verify(hostKey);check();const result=await sign(data.data);check();worker.postMessage({type:'reply',id:data.id,result});}finally{signing=false;}
   }else if(data.type==='password'){
    if(!authorizeKey||!hostAccepted||reviewedAlgorithms)throw Error('Unexpected SSH password request.');
    const algorithms=data.algorithms;
    if(!Array.isArray(algorithms)||!algorithms.length||algorithms.length>2||new Set(algorithms).size!==algorithms.length||algorithms.some(a=>a!=='ssh-ed25519'&&a!=='ssh-mldsa44-ed25519'))throw Error('Invalid SSH key authorization review.');
    reviewedAlgorithms=algorithms;let secret;
    try{
     await verify(hostKey);check();
     secret=await requestPassword({...target,username,algorithms},lifetime.signal);
     if(!(secret instanceof Uint8Array)||!secret.length||secret.length>1024)throw Error('Invalid SSH password length.');
     await verify(hostKey);check();
     // postMessage copies the bytes to the disposable authentication worker.
     worker.postMessage({type:'reply',id:data.id,result:secret});
    }finally{if(secret instanceof Uint8Array)secret.fill(0);}
   }else if(data.type==='authorized'){
    if(!authorizeKey||!hostAccepted||!reviewedAlgorithms||JSON.stringify(data.algorithms)!==JSON.stringify(reviewedAlgorithms))throw Error('Unexpected SSH authorization result.');
    const description=reviewedAlgorithms.includes('ssh-mldsa44-ed25519')?'SSH public key authorization confirmed: '+reviewedAlgorithms.join(', ')+'.':'SSH public key authorized: Ed25519 only.';
    onStatus(description,'success');close();
   }else if(data.type==='ready'){
    if(authorizeKey||!hostAccepted||signing||ready)throw Error('Unexpected SSH connection result.');
    ready=true;
    const credential=authUsed?data.credential:'';
    const login=credential==='ssh-mldsa44-ed25519'?'Post-quantum hybrid login: ML-DSA-44 + Ed25519.':
     credential==='ssh-ed25519'?'Warning: classical Ed25519 login credential.':
     'Warning: no post-quantum login credential was confirmed.';
    const transport=usesHybridSshKex(data.keyExchange)?'Hybrid key exchange: '+data.keyExchange+'.':
     data.keyExchange?'Warning: classical key exchange: '+data.keyExchange+'.':'Key exchange unreported.';
    onStatus('SSH connected. '+login+' '+transport,'ready',{login,transport});
   }
   else if(data.type==='transfer-result'){
    if(fileRequest?.id===data.id)fileRequest.finish(data.error?Error(data.error):null,data.result);
   }
   else if(data.type==='output'){if(hostAccepted)onOutput(data.data);}
   else if(data.type==='error'||data.type==='closed'){onStatus(data.message||'SSH disconnected.',data.type);close();}
  }catch(e){if(!closed){onStatus(e.message,'error');close();}}
 };
 worker.postMessage({type:'connect',...target,username,publicKey,additionalPublicKey,authorizeKey});
 return {
  close,
  async transfer(op,fields,signal){
   check();signal?.throwIfAborted();
   if(!ready||authorizeKey||!hostAccepted)throw Error('Connect SSH before transferring files.');
   await verify(hostKey);check();signal?.throwIfAborted();
   if(fileRequest)throw Error('Another file operation is in progress.');
   return new Promise((resolve,reject)=>{
    const id=++transferID;
    const finish=(error,result)=>{
     clearTimeout(timer);signal?.removeEventListener('abort',cancel);
     fileRequest=null;error?reject(error):resolve(result);
    };
    const cancel=()=>{
     if(!closed)worker.postMessage({type:'transfer-cancel',id});
     finish(Error('SFTP operation cancelled or timed out.'));
    };
    const timer=setTimeout(cancel,65000);
    fileRequest={id,finish};signal?.addEventListener('abort',cancel,{once:true});
    try{worker.postMessage({...fields,type:'transfer',op,id},fields.bytes?[fields.bytes.buffer]:[]);}
    catch(error){finish(error);}
   });
  },
  input(data){guard();if(!closed&&ready)worker.postMessage({type:'input',data});},
  resize(rows,cols){
   guard();
   if(closed||!ready)return;
   // Window dragging generates many geometry events. Send the latest size
   // once the layout settles so the remote PTY can keep up.
   clearTimeout(resizeTimer);
   resizeTimer=setTimeout(()=>{
    try{check();worker.postMessage({type:'resize',rows,cols});}
    catch(error){if(!closed){onStatus(error.message,'error');close();}}
   },80);
  },
 };
}
// Signing workers are short-lived and receive a copy of the selected seeds only.
// No raw key is returned to UI code or persisted outside the encrypted vault.
function oneShot(data,reply,timeoutMs,signal){
 return new Promise((resolve,reject)=>{
  const worker=createSshWorker();let settled=false;
  const finish=(error,result)=>{if(settled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);worker.terminate();error?reject(error):resolve(result);};
  const abort=()=>finish(Error('SSH key operation cancelled.'));
  const timer=setTimeout(()=>finish(Error('SSH key operation timed out.')),timeoutMs);
  signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted){abort();return;}
  worker.onerror=()=>finish(Error('SSH key worker failed.'));
  worker.onmessage=({data})=>data.type===reply?finish(null,data):data.type==='error'&&finish(Error(data.message));
  worker.postMessage(data);
 });
}

export async function signSoftwareSsh({ml,ed,publicKey,message,signal}){
 return (await oneShot({type:'software-sign',ml,ed,publicKey,message},'signature',30000,signal)).signature;
}

export function openEd25519File(file,passphrase,signal){
 return oneShot({type:'import-ed25519',file,passphrase},'imported',90000,signal);
}
