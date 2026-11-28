import {localFileCrypto} from './client.js';
import {createLocalFileStorage,maxBytes} from './storage.js';

const kind='Local file encryption key';
const slot=state=>state.items.filter(item=>item.kind===kind);

export function createLocalFileStore(access,{storage=createLocalFileStorage(),operate=localFileCrypto}={}){
 async function context(signal){
  const state=access.snapshot();
  if(!state.unlocked)throw Error('Unlock the vault first.');
  const check=async()=>{
   signal?.throwIfAborted();
   await access.assertCurrent(state);
   signal?.throwIfAborted();
  };
  await check();
  const found=slot(state);
  if(found.length>1)throw Error('More than one local file key is recorded in this vault.');
  const key=found[0];
  if(key&&(key.version!==1||typeof key.publicKey!=='string'||typeof key.seed!=='string'))throw Error('Invalid local file key.');
  return {state,key,check,vaultId:state.vaultId};
 }
 return Object.freeze({
  async list(signal){
   const {vaultId,key,check}=await context(signal);
   const records=await storage.list(vaultId,signal);
   await check();
   if(!records.length)return [];
   if(!key)throw Error('Restore the vault containing this local file store key.');
   const rows=records.map(({fileBox,...header})=>header);
   const result=await operate('list',{vaultId,keyId:key.id,publicKey:key.publicKey,seed:key.seed,rows},{signal});
   await check();
   return result;
  },
  async add(file,signal){
   if(!file||!Number.isSafeInteger(file.size)||file.size<0||file.size>maxBytes)throw Error('Choose a file up to 16 MiB.');
   let current=await context(signal);
   const {vaultId}=current;
   if(!current.key){
    // Commit the recovery key first. A cancelled or failed write may leave
    // an unused key, but cannot leave ciphertext whose key was never saved.
    if((await storage.list(vaultId,signal)).length)throw Error('Restore the existing local file store key first.');
    const id=crypto.randomUUID();
    const pair=await operate('generate',{vaultId,keyId:id},{signal});
    const item={kind,id,name:'Local files · ML-KEM-1024 + X448',version:1,...pair};
    await current.check();
    await access.replaceItems([...current.state.items,item],current.state,{signal,change:'local-file-key'});
    current=await context(signal);
    if(current.vaultId!==vaultId||current.key?.id!==id)throw Error('The file encryption key changed.');
   }
   const {key,check}=current;
   const plain=new Uint8Array(await file.arrayBuffer());
   try{
    await check();
    const sealed=await operate('seal',{vaultId,keyId:key.id,publicKey:key.publicKey,id:crypto.randomUUID(),name:file.name,plain},{signal});
    await check();
    // A Blob keeps the encrypted contents lazy when reading the file list.
    await storage.add({...sealed,fileBox:new Blob([sealed.fileBox])},signal);
    await check();
   }finally{
    // The browser worker may already own the transferred buffer.
    if(plain.byteLength)plain.fill(0);
   }
  },
  async open(id,signal){
   const {vaultId,key,check}=await context(signal);
   if(!key)throw Error('Restore the vault containing this local file store key.');
   const row=await storage.read(vaultId,id,signal);
   if(!row||row.id!==id)throw Error('Local file is unavailable.');
   if(!(row.fileBox instanceof Blob)||row.fileBox.size>maxBytes+16)throw Error('Invalid encrypted file size.');
   const fileBox=new Uint8Array(await row.fileBox.arrayBuffer());
   await check();
   const result=await operate('open',{vaultId,keyId:key.id,publicKey:key.publicKey,seed:key.seed,row:{...row,fileBox}},{signal});
   try{await check();return result;}
   catch(error){result.plain.fill(0);throw error;}
  },
  async remove(id,signal){
   const {vaultId,check}=await context(signal);
   await storage.remove(vaultId,id,signal);
   await check();
  },
 });
}
