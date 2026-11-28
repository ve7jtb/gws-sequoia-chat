import {b64,bytes} from '../vault/core.js';
import {openEd25519File} from './client.js';

const kind='SSH Ed25519 identity';
const pkcs8Prefix=Uint8Array.of(0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20);

function ed25519PublicLine(raw){
 if(raw.length!==32)throw Error('Invalid Ed25519 public key.');
 const blob=new Uint8Array(51),view=new DataView(blob.buffer);
 view.setUint32(0,11);
 blob.set(new TextEncoder().encode('ssh-ed25519'),4);
 view.setUint32(15,32);blob.set(raw,19);
 return 'ssh-ed25519 '+b64(blob);
}

export function createImportedSshStore(access,{openFile=openEd25519File}={}){
 function current(){
  const state=access.snapshot();
  if(!state?.unlocked)throw Error('Unlock the credential vault first.');
  return state;
 }
 const marker=state=>[state.vaultId,state.epoch,state.revision].join(':');
 async function check(state){
  await access.assertCurrent(state);
  if(marker(current())!==marker(state))throw Error('SSH identity vault changed.');
 }
 const rows=state=>state.items.filter(item=>item.kind===kind);
 const snapshot=(state,item)=>({id:'ssh-ed25519:'+item.id,name:item.name,algorithm:'ssh-ed25519',hasSsh:true,hasSshPublic:true,publicKey:ed25519PublicLine(bytes(item.publicKey)),vaultId:state.vaultId,epoch:state.epoch,revision:state.revision});
 async function records(){
  const state=current();await check(state);
  return rows(state).map(item=>snapshot(state,item));
 }
 async function get(id){
  const item=(await records()).find(row=>row.id===id);
  if(!item)throw Error('Select an imported Ed25519 key.');
  return item;
 }
 async function assert(selected){
  if(JSON.stringify(await get(selected.id))!==JSON.stringify(selected))throw Error('SSH identity changed.');
 }
 return Object.freeze({
  records,get,assert,
  async importKey(name,file,passphrase,signal){
   name=name.trim();
   if(!name||name.length>80||/[\x00-\x1f\x7f]/.test(name))throw Error('Enter an SSH identity name up to 80 characters.');
   if(!(file instanceof Uint8Array)||!file.length||file.length>32768||!(passphrase instanceof Uint8Array)||passphrase.length>1024)throw Error('Choose an OpenSSH key file up to 32 KiB and a passphrase up to 1,024 bytes.');
   const state=current();await check(state);
   const imported=await openFile(file,passphrase,signal);
   try{
    if(imported.seed.length!==32||imported.publicKey.length!==32)throw Error('Invalid imported Ed25519 key.');
    await check(state);
    if(signal?.aborted)throw Error('SSH import cancelled.');
    const publicKey=b64(imported.publicKey);
    const duplicate=rows(state).find(item=>item.publicKey===publicKey);
    if(duplicate)return snapshot(state,duplicate);
    if(rows(state).length>=32)throw Error('Maximum 32 imported SSH identities per vault.');
    const item={id:crypto.randomUUID(),kind,name,publicKey,seed:b64(imported.seed)};
    await access.replaceItems([...state.items,item],state,{signal});
    return get('ssh-ed25519:'+item.id);
   }finally{imported.seed.fill(0);}
  },
  async signSsh(selected,message){
   if(!(message instanceof Uint8Array)||message.length<32||message.length>65536)throw Error('Invalid SSH transcript.');
   const state=current();await assert(selected);await check(state);
   const item=rows(state).find(record=>'ssh-ed25519:'+record.id===selected.id);
   const seed=bytes(item.seed),encoded=new Uint8Array(pkcs8Prefix.length+32);
   try{
    if(seed.length!==32)throw Error('Invalid imported SSH key.');
    encoded.set(pkcs8Prefix);encoded.set(seed,pkcs8Prefix.length);
    const privateKey=await crypto.subtle.importKey('pkcs8',encoded,'Ed25519',false,['sign']);
    await check(state);
    const signature=new Uint8Array(await crypto.subtle.sign('Ed25519',privateKey,message));
    await check(state);
    // The SSH engine also verifies against the selected public key before sending.
    return signature;
   }finally{seed.fill(0);encoded.fill(0);}
  },
 });
}
