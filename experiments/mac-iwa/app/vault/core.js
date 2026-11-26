// Versioned envelope encryption shared by PIV and FIDO PRF. Only sealed records
// are persisted. A random 256-bit content key never depends on a user's PIN.
const enc=new TextEncoder(),dec=new TextDecoder();
export const random=n=>crypto.getRandomValues(new Uint8Array(n));
export const b64=a=>{let s='';for(const b of new Uint8Array(a))s+=String.fromCharCode(b);return btoa(s);};
export const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const json=v=>enc.encode(JSON.stringify(v));
const fail=()=>{throw Error('Vault authentication failed. No data was changed.');};
export function validate(v){
 if(!v||v.format!=='sequoia-iwa-vault'||v.version!==1||!/^[-a-f0-9]{36}$/.test(v.id)||!Number.isSafeInteger(v.revision)||v.revision<1||!Array.isArray(v.wrappers)||!v.wrappers.length||v.wrappers.length>16||JSON.stringify(v).length>4000000)fail();
 const ids=new Set();for(const w of v.wrappers){if(!w||!['piv','prf'].includes(w.type)||!/^[-a-f0-9]{36}$/.test(w.id)||ids.has(w.id)||typeof w.name!=='string'||!w.name.trim()||w.name.length>80||!w.binding||!w.box)fail();ids.add(w.id);}
 if(!ids.has(v.default))fail();return v;
}
async function seal(key,value,aad){
 const iv=random(12),k=await crypto.subtle.importKey('raw',key,'AES-GCM',false,['encrypt']);
 return {iv:b64(iv),cipher:b64(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:json(aad),tagLength:128},k,json(value)))};
}
async function open(key,box,aad){
 try{if(bytes(box.iv).length!==12)fail();const k=await crypto.subtle.importKey('raw',key,'AES-GCM',false,['decrypt']);return JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(box.iv),additionalData:json(aad),tagLength:128},k,bytes(box.cipher))));}catch(_){fail();}
}
// Domain separation binds each wrap to its vault, method, hardware/credential
// identifier and encapsulation. Relabelling does not change cryptographic identity.
const context=(v,w)=>['Sequoia IWA vault wrap',1,v.id,w.id,w.type,w.binding];
async function wrappingKey(v,w,secret){
 if(secret.length!==32)fail();const material=await crypto.subtle.importKey('raw',secret,'HKDF',false,['deriveBits']);
 // The Level 5 public transcript exceeds some Web Crypto HKDF info limits.
 // Hash its context while preserving the original derivation for old wrappers.
 const serialized=json(context(v,w));
 const info=w.type==='piv'&&w.binding.kind==='mlkem1024-p384-v1'
  ?await crypto.subtle.digest('SHA-384',serialized):serialized;
 return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:enc.encode(v.id),info},material,256));
}
export class Vault {
 constructor(){this.lock();}
 lock(){this.epoch=(this.epoch||0)+1;this.key?.fill(0);this.key=null;this.data=null;this.record=null;}
 // A WebCrypto promise can resolve after lock/navigation. Its result must not
 // recreate an unlocked vault or commit an older content revision.
 assertLive(epoch,key,record){if(this.epoch!==epoch||this.key!==key||this.record!==record||!this.unlocked)throw Error('Vault operation cancelled by locking or changing the vault.');}
 get unlocked(){return !!this.key;}
 async create(w,secret,id=crypto.randomUUID()){
  if(this.unlocked)throw Error('Lock the current vault first.');
  this.key=random(32);this.data={items:[]};this.record={format:'sequoia-iwa-vault',version:1,id,revision:0,wrappers:[],default:w.id};
  try{await this.add(w,secret);return this.record;}catch(e){this.lock();throw e;}
 }
 async unlock(record,id,secret){
  this.lock();validate(record);record=structuredClone(record);const epoch=this.epoch,w=record.wrappers.find(w=>w.id===id);if(!w)fail();let wrap;
  try{wrap=await wrappingKey(record,w,secret);const value=await open(wrap,w.box,context(record,w));const key=bytes(value.key);if(key.length!==32)fail();
   try{const data=await open(key,record.body,['Sequoia IWA vault content',1,record.id,record.revision]);if(!Array.isArray(data.items))fail();
    if(this.epoch!==epoch)throw Error('Vault unlock cancelled.');this.key=key;this.data=data;this.record=record;
   }catch(e){key.fill(0);throw e;}
  }finally{wrap?.fill(0);}
 }
 // Backup cryptography stays inside the vault object; callers receive only
 // ciphertext or authenticated snapshots, never the raw content key. Locking
 // during WebCrypto work invalidates the result through the usual epoch guard.
 async sealBackup(snapshot,header){
  if(!this.unlocked)throw Error('Unlock the vault first');
  const epoch=this.epoch,key=this.key,record=this.record;
  const box=await seal(key,snapshot,['Sequoia IWA complete backup',2,header]);
  this.assertLive(epoch,key,record);return box;
 }
 async openBackup(box,header){
  if(!this.unlocked)throw Error('Unlock the backup vault first');
  const epoch=this.epoch,key=this.key,record=this.record;
  const value=await open(key,box,['Sequoia IWA complete backup',2,header]);
  this.assertLive(epoch,key,record);return value;
 }
 async add(w,secret){
  if(!this.unlocked)throw Error('Unlock the vault before enrolling another method.');
  if(this.record.wrappers.length>=16||this.record.wrappers.some(x=>x.type===w.type&&JSON.stringify(x.binding)===JSON.stringify(w.binding)))throw Error('Unlock method already enrolled or limit reached.');
  const epoch=this.epoch,key=this.key,record=this.record,k=await wrappingKey(record,w,secret);
  try{this.assertLive(epoch,key,record);w={...w,box:await seal(k,{key:b64(key)},context(record,w))};}finally{k.fill(0);}
  this.assertLive(epoch,key,record);this.record.wrappers.push(w);
  // Enrolling a PIV key makes it the default, without removing existing PRF wraps.
  if(w.type==='piv')this.record.default=w.id;
  return this.save();
 }
 async save(){
  if(!this.unlocked)throw Error('Unlock the vault first.');
  if(JSON.stringify(this.data).length>2000000)throw Error('Vault exceeds 2 MB.');
  const epoch=this.epoch,key=this.key,record=this.record,previous=record.revision;
  const body=await seal(key,structuredClone(this.data),['Sequoia IWA vault content',1,record.id,previous+1]);
  this.assertLive(epoch,key,record);if(record.revision!==previous)throw Error('Concurrent vault update rejected.');
  record.revision=previous+1;record.body=body;validate(record);return record;
 }
 async remove(id){if(!this.unlocked)throw Error('Unlock first.');if(this.record.wrappers.length<=1)throw Error('Cannot remove the last unlock method.');this.record.wrappers=this.record.wrappers.filter(w=>w.id!==id);if(this.record.default===id)this.record.default=(this.record.wrappers.find(w=>w.type==='piv')||this.record.wrappers[0]).id;return this.save();}
 async rename(id,name){if(!this.unlocked||!name.trim()||name.length>80)throw Error('Enter a name of 1–80 characters.');this.record.wrappers.find(w=>w.id===id).name=name.trim();return this.save();}
}
// IndexedDB compare-and-swap prevents a second open window from silently
// overwriting a newer vault. Failed writes must lock the in-memory instance.
export function database(){return new Promise((resolve,reject)=>{const r=indexedDB.open('sequoia-iwa-vault',1);r.onupgradeneeded=()=>r.result.createObjectStore('vault');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});}
export async function load(){const db=await database();return new Promise((resolve,reject)=>{const t=db.transaction('vault'),r=t.objectStore('vault').get('current');r.onsuccess=()=>resolve(r.result||null);r.onerror=()=>reject(r.error);t.oncomplete=()=>db.close();});}
export async function persist(record,expected,{signal,guard=()=>{}}={}){
 validate(record);guard();if(signal?.aborted)throw Error('Vault write cancelled.');const db=await database();
 return new Promise((resolve,reject)=>{
  let t,finished=false;
  const finish=error=>{if(finished)return;finished=true;signal?.removeEventListener('abort',cancel);db.close();error?reject(error):resolve();};
  const cancel=()=>{try{t?.abort();}catch(_){}finish(Error('Vault write cancelled.'));};
  try{
   guard();if(signal?.aborted){cancel();return;}signal?.addEventListener('abort',cancel,{once:true});
   t=db.transaction('vault','readwrite');const s=t.objectStore('vault'),r=s.get('current');
   r.onsuccess=()=>{
    try{guard();if(signal?.aborted)throw Error();const old=r.result;
     if((old?.revision??0)!==expected||(old&&old.id!==record.id)){t.abort();return;}
     // Guard and put run synchronously in the same transaction callback. A
     // lock before commit aborts that transaction through the signal above.
     s.put(structuredClone(record),'current');
    }catch(_){try{t.abort();}catch(_){}finish(Error('Vault changed or write cancelled.'));}
   };
   t.oncomplete=()=>finish();t.onabort=t.onerror=()=>finish(Error('Vault changed in another window or could not be saved. Unlock the latest copy.'));
  }catch(_){finish(Error('Vault could not be saved.'));}
 });
}
