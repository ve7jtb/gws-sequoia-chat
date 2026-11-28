import {maxBytes} from '../local-files/storage.js';

// All plaintext stays between the vault service and this terminal's worker.
// The popup receives file names, sizes and operation status only.
export function createFileTransfer({session,store,guard,reply}){
 let active;
 function cancel(){active?.abort();}
 async function request(data){
  if(active||!Number.isSafeInteger(data.id))return;
  active=new AbortController();
  const {signal}=active;
  let plain;
  try{
   guard();
   const files=store(),ssh=session();
   if(!ssh||!files)throw Error('Connect SSH and unlock the vault first.');
   const call=async(op,fields)=>{
    const result=await ssh.transfer(op,fields,signal);
    if(op==='get'&&result instanceof Uint8Array)plain=result;
    guard();signal.throwIfAborted();
    return result;
   };
   let result;
   if(data.op==='local')result=(await files.list(signal)).filter(file=>!file.unreadable);
   else if(data.op==='browse')result=await call('browse',{directory:data.directory});
   else if(data.op==='get'){
    const bytes=await call('get',{directory:data.directory,name:data.name});
    if(!(bytes instanceof Uint8Array)||bytes.length>maxBytes)throw Error('Invalid downloaded file.');
    // The vault writer encrypts before committing anything to IndexedDB.
    await files.add(new File([bytes],data.name),signal);
   }else if(data.op==='put'){
    const file=await files.open(data.fileId,signal);
    plain=file.plain;
    guard();signal.throwIfAborted();
    await call('put',{directory:data.directory,name:file.name,bytes:plain});
   }else throw Error('Unknown file transfer.');
   guard();signal.throwIfAborted();
   reply(data.id,{result});
  }catch(error){
   if(!signal.aborted)reply(data.id,{error:error.message});
  }finally{
   if(plain?.byteLength)plain.fill(0);
   active=null;
  }
 }
 return {request,cancel};
}
