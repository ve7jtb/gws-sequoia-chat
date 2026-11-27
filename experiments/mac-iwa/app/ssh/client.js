import {endpoint} from './transport.js';
import {verifyHost} from './host-verifier.js';
const b64=b=>btoa(String.fromCharCode(...b));
// The UI receives no private key. The injected signer checks its vault revision
// on both sides of signing; trust must pass before any sign callback is accepted.
export function connectSsh({host,port,username,publicKey,entries,getEntries,sign,guard,signal,onOutput,onStatus,WorkerClass=Worker}){
 const target=endpoint(host,port);guard();
 if(typeof username!=='string'||!username||username.length>256||/[\x00-\x20\x7f]/.test(username))throw Error('Enter a valid SSH username.');
 const worker=new WorkerClass(new URL('./worker.js',import.meta.url));let closed=false,hostAccepted=false,ready=false,signing=false,authUsed=false,hostKey=null;
 const close=()=>{if(closed)return;closed=true;worker.terminate();signal?.removeEventListener('abort',close);};
 signal?.addEventListener('abort',close,{once:true});if(signal?.aborted){close();throw Error('SSH cancelled.');}
 worker.onerror=()=>{onStatus('SSH engine failed.');close();};
 worker.onmessage=async({data})=>{
  if(closed)return;
  try{
   guard();
   if(data.type==='host'){
    hostKey={type:data.algorithm,key:b64(data.data)};
    await verifyHost({entries:getEntries?await getEntries():entries,host:target.host,port:target.port,...hostKey,guard});guard();hostAccepted=true;
    if(!closed)worker.postMessage({type:'reply',id:data.id,result:true});
   }else if(data.type==='sign'){
    if(!hostAccepted||signing||ready||authUsed)throw Error('Unexpected SSH authentication request.');signing=true;authUsed=true;
    try{await verifyHost({entries:getEntries?await getEntries():entries,host:target.host,port:target.port,...hostKey,guard});const result=await sign(data.data);guard();if(!closed)worker.postMessage({type:'reply',id:data.id,result});}finally{signing=false;}
   }else if(data.type==='ready'){ready=true;onStatus('SSH authenticated.');}
   else if(data.type==='output'){if(hostAccepted)onOutput(data.data);}
   else if(data.type==='error'||data.type==='closed'){onStatus(data.message||'SSH disconnected.');close();}
  }catch(e){onStatus(e.message);close();}
 };
 worker.postMessage({type:'connect',...target,username,publicKey});
 return {close,input(data){guard();if(!closed&&ready)worker.postMessage({type:'input',data});},resize(rows,cols){guard();if(!closed&&ready)worker.postMessage({type:'resize',rows,cols});}};
}
// Signing workers are short-lived and receive a copy of the selected seeds only.
// No raw key is returned to UI code or persisted outside the encrypted vault.
export function signSoftwareSsh({ml,ed,publicKey,message,signal}){
 return new Promise((resolve,reject)=>{
  const worker=new Worker(new URL('./worker.js',import.meta.url));let settled=false;
  const finish=(error,result)=>{if(settled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);worker.terminate();error?reject(error):resolve(result);};
  const abort=()=>finish(Error('SSH signing cancelled.'));
  const timer=setTimeout(()=>finish(Error('SSH signing timed out.')),30000);
  signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted){abort();return;}
  worker.onerror=()=>finish(Error('SSH signing worker failed.'));
  worker.onmessage=({data})=>data.type==='signature'?finish(null,data.signature):data.type==='error'&&finish(Error(data.message));
  worker.postMessage({type:'software-sign',ml,ed,publicKey,message});
 });
}
