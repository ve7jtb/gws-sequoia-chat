// Files live outside the credential vault so ciphertext does not count
// against the vault's 2 MB limit. Each IndexedDB row is an atomic envelope.
export const localFileDatabase='sequoia-iwa-local-files';
export const maxBytes=16*1024*1024;
export const maxFiles=32;

function database(){
 return new Promise((resolve,reject)=>{
  const request=indexedDB.open(localFileDatabase,1);
  request.onupgradeneeded=()=>{
   const rows=request.result.createObjectStore('files',{keyPath:['vaultId','id']});
   rows.createIndex('vault','vaultId');
  };
  request.onsuccess=()=>resolve(request.result);
  request.onerror=()=>reject(Error('Could not open local file storage.'));
 });
}

export function createLocalFileStorage(){
 async function transact(mode,signal,operate){
  const db=await database();
  try{
   return await new Promise((resolve,reject)=>{
    signal?.throwIfAborted();
    const transaction=db.transaction('files',mode);
    const stop=()=>{try{transaction.abort();}catch{ /* The transaction already finished. */ }};
    signal?.addEventListener('abort',stop,{once:true});
    let result,failure;
    transaction.oncomplete=()=>{
     signal?.removeEventListener('abort',stop);
     resolve(result);
    };
    transaction.onabort=()=>{
     signal?.removeEventListener('abort',stop);
     reject(Error(failure||'The local file operation was cancelled or storage is full.'));
    };
    operate(transaction.objectStore('files'),value=>{result=value;},message=>{failure=message;transaction.abort();});
   });
  }finally{db.close();}
 }
 return {
  list:(vaultId,signal)=>transact('readonly',signal,(rows,done)=>{
   const request=rows.index('vault').getAll(vaultId,maxFiles+1);
   request.onsuccess=()=>done(request.result);
  }),
  read:(vaultId,id,signal)=>transact('readonly',signal,(rows,done)=>{
   const request=rows.get([vaultId,id]);
   request.onsuccess=()=>done(request.result);
  }),
  add:(row,signal)=>transact('readwrite',signal,(rows,_done,fail)=>{
   // Count and insert share one transaction, also across open windows.
   const count=rows.index('vault').count(row.vaultId);
   count.onsuccess=()=>{
    if(count.result>=maxFiles){fail('The local file store can hold up to '+maxFiles+' files.');return;}
    rows.add(row);
   };
  }),
  remove:(vaultId,id,signal)=>transact('readwrite',signal,rows=>{rows.delete([vaultId,id]);}),
 };
}
