// The encapsulations, recipient public keys and file identifiers bind the
// fixed-width KEM secrets to this envelope. Separate HKDF contexts derive
// independent AES-256-GCM keys for the name and contents.
import {b64,bytes,random} from '../vault/core.js';
import {maxBytes,maxFiles} from './storage.js';

const encode=new TextEncoder(),decode=new TextDecoder('utf-8',{fatal:true});
const capsuleBytes=1568+56;
const uuid=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const label='Sequoia IWA local file v1, ML-KEM-1024 + X448';
const nameValid=name=>typeof name==='string'&&name.length>0&&name.length<=255&&name!=='.'&&name!=='..'&&!/[\\/\x00-\x1f\x7f]/.test(name);
const join=(a,b)=>{const out=new Uint8Array(a.length+b.length);out.set(a);out.set(b,a.length);return out;};

function check(row,vaultId,keyId){
 if(row?.version!==1||row.vaultId!==vaultId||row.keyId!==keyId||!uuid.test(row.id)||
    !(row.capsule instanceof Uint8Array)||row.capsule.length!==capsuleBytes||
    !(row.nameIv instanceof Uint8Array)||row.nameIv.length!==12||
    !(row.fileIv instanceof Uint8Array)||row.fileIv.length!==12||
    !(row.nameBox instanceof Uint8Array)||row.nameBox.length<17||row.nameBox.length>16+255*4||
    !Number.isInteger(row.size)||row.size<0||row.size>maxBytes)throw Error('Invalid local file envelope.');
}

async function keys(shared,publicKey,row){
 const material=await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveKey']);
 const salt=await crypto.subtle.digest('SHA-384',join(publicKey,row.capsule));
 return async (part,usage)=>{
  const aad=encode.encode(JSON.stringify([label,row.vaultId,row.keyId,row.id,row.size,part]));
  const key=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-384',salt,info:aad},material,{name:'AES-GCM',length:256},false,[usage]);
  const params={name:'AES-GCM',iv:part==='name'?row.nameIv:row.fileIv,additionalData:aad,tagLength:128};
  return [params,key];
 };
}

export async function operateLocalFile(wasm,operation,input){
 const {vaultId,keyId}=input;
 if(!uuid.test(vaultId)||!uuid.test(keyId))throw Error('Invalid local file key binding.');
 if(operation==='generate'){
  const seed=random(120);
  try{return {seed:b64(seed),publicKey:b64(wasm.local_file_public(seed))};}
  finally{seed.fill(0);}
 }
 const publicKey=bytes(input.publicKey);
 if(publicKey.length!==capsuleBytes)throw Error('Invalid file-store public key.');
 if(operation==='seal'){
  const {id,name,plain}=input;
  if(!uuid.test(id)||!nameValid(name)||!(plain instanceof Uint8Array)||plain.length>maxBytes)throw Error('Invalid local file.');
  const raw=wasm.local_file_encapsulate(publicKey);
  try{
   if(raw.length!==capsuleBytes+88)throw Error('Invalid hybrid encapsulation.');
   const row={version:1,vaultId,keyId,id,size:plain.length,capsule:raw.slice(0,capsuleBytes),nameIv:random(12),fileIv:random(12)};
   const derive=await keys(raw.subarray(capsuleBytes),publicKey,row);
   const nameBox=new Uint8Array(await crypto.subtle.encrypt(...await derive('name','encrypt'),encode.encode(name)));
   const fileBox=new Uint8Array(await crypto.subtle.encrypt(...await derive('file','encrypt'),plain));
   return {...row,nameBox,fileBox};
  }finally{raw.fill(0);plain.fill(0);}
 }
 const seed=bytes(input.seed);
 try{
  if(seed.length!==120)throw Error('Invalid local file key.');
  const open=async row=>{
   check(row,vaultId,keyId);
   const shared=wasm.local_file_decapsulate(seed,row.capsule);
   try{
    if(shared.length!==88)throw Error('Invalid hybrid decapsulation.');
    const derive=await keys(shared,publicKey,row);
    const name=decode.decode(await crypto.subtle.decrypt(...await derive('name','decrypt'),row.nameBox));
    if(!nameValid(name))throw Error('Invalid encrypted filename.');
    return {name,derive};
   }finally{shared.fill(0);}
  };
  if(operation==='list'){
   if(!Array.isArray(input.rows)||input.rows.length>maxFiles)throw Error('Invalid local file index.');
   const files=[];
   for(const row of input.rows){
    if(!uuid.test(row?.id))throw Error('Invalid local file identifier.');
    try{const {name}=await open(row);files.push({id:row.id,name,size:row.size});}
    catch{files.push({id:row.id,unreadable:true});}
   }
   return files;
  }
  if(operation==='open'){
   const {row}=input;
   const {name,derive}=await open(row);
   if(!(row.fileBox instanceof Uint8Array)||row.fileBox.length!==row.size+16)throw Error('Invalid encrypted file length.');
   const plain=new Uint8Array(await crypto.subtle.decrypt(...await derive('file','decrypt'),row.fileBox));
   return {name,plain};
  }
  throw Error('Unknown local file operation.');
 }finally{seed.fill(0);}
}
