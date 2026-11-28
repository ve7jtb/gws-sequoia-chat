import {endpoint} from './transport.js';
import {UnknownSshHostError,verifyHost} from './host-verifier.js';
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
export function connectSsh({host,port,username,publicKey,entries,getEntries,acceptUnknownHost,requestPassword,authorizeKey=false,sign,guard,signal,onOutput,onStatus,WorkerClass=Worker}){
 const target=endpoint(host,port);guard();
 if(typeof username!=='string'||!username||username.length>256||/[\x00-\x20\x7f]/.test(username))throw Error('Enter a valid SSH username.');
 if(authorizeKey&&typeof requestPassword!=='function')throw Error('Password prompt is unavailable.');
 const worker=createSshWorker(WorkerClass),lifetime=new AbortController();
 let closed=false,hostAccepted=false,ready=false,signing=false,authUsed=false,passwordUsed=false,hostKey=null;
 const close=()=>{if(closed)return;closed=true;lifetime.abort();worker.terminate();signal?.removeEventListener('abort',close);};
 const check=()=>{if(closed)throw Error('SSH connection closed.');guard();};
 const verify=async candidate=>verifyHost({entries:getEntries?await getEntries():entries,...candidate,guard:check});
 signal?.addEventListener('abort',close,{once:true});if(signal?.aborted){close();throw Error('SSH cancelled.');}
 worker.onerror=()=>{onStatus('SSH engine failed.');close();};
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
    if(!authorizeKey||!hostAccepted||passwordUsed)throw Error('Unexpected SSH password request.');
    passwordUsed=true;let secret;
    try{
     await verify(hostKey);check();
     secret=await requestPassword({...target,username},lifetime.signal);
     if(!(secret instanceof Uint8Array)||!secret.length||secret.length>1024)throw Error('Invalid SSH password length.');
     await verify(hostKey);check();
     // postMessage copies the bytes to the disposable authentication worker.
     worker.postMessage({type:'reply',id:data.id,result:secret});
    }finally{if(secret instanceof Uint8Array)secret.fill(0);}
   }else if(data.type==='authorized'){
    if(!authorizeKey||!hostAccepted||!passwordUsed)throw Error('Unexpected SSH authorization result.');
    onStatus('SSH public key authorized.');close();
   }else if(data.type==='ready'){ready=true;onStatus('SSH authenticated.');}
   else if(data.type==='output'){if(hostAccepted)onOutput(data.data);}
   else if(data.type==='error'||data.type==='closed'){onStatus(data.message||'SSH disconnected.');close();}
  }catch(e){if(!closed){onStatus(e.message);close();}}
 };
 worker.postMessage({type:'connect',...target,username,publicKey,authorizeKey});
 return {close,input(data){guard();if(!closed&&ready)worker.postMessage({type:'input',data});},resize(rows,cols){guard();if(!closed&&ready)worker.postMessage({type:'resize',rows,cols});}};
}
// Signing workers are short-lived and receive a copy of the selected seeds only.
// No raw key is returned to UI code or persisted outside the encrypted vault.
export function signSoftwareSsh({ml,ed,publicKey,message,signal}){
 return new Promise((resolve,reject)=>{
  const worker=createSshWorker();let settled=false;
  const finish=(error,result)=>{if(settled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);worker.terminate();error?reject(error):resolve(result);};
  const abort=()=>finish(Error('SSH signing cancelled.'));
  const timer=setTimeout(()=>finish(Error('SSH signing timed out.')),30000);
  signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted){abort();return;}
  worker.onerror=()=>finish(Error('SSH signing worker failed.'));
  worker.onmessage=({data})=>data.type==='signature'?finish(null,data.signature):data.type==='error'&&finish(Error(data.message));
  worker.postMessage({type:'software-sign',ml,ed,publicKey,message});
 });
}
