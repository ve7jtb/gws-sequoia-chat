// Complete migration is deliberately separate from the live mail application.
// No hardware APIs, account connections or private-key operations run here.
import {validate as validateVault} from './vault/core.js';
import {localFileDatabase} from './local-files/storage.js';
export const DATABASES=[['sequoia-iwa-vault','vault'],['sequoia-iwa-identities','state'],['sequoia-iwa-certificates','state']];
export const PENDING='sequoia-complete-restore-pending';
// Connection trust belongs to the receiving device. A backup must neither
// disable required SCP nor enable a beta anchor or switch hardware transports.
export const LOCAL_CONNECTION_SETTINGS=new Set(['sequoia_secure_yubikey_connection','sequoia_secure_yubikey_beta_pin','sequoia_hardware_transport']);
const LIMIT=12*1024*1024,enc=new TextEncoder();
const fail=m=>{throw Error(m);};
const canonical=v=>JSON.stringify(v,(_,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x);
const b64=b=>{let s='';for(const x of new Uint8Array(b))s+=String.fromCharCode(x);return btoa(s);};
export const digest=async v=>b64(await crypto.subtle.digest('SHA-256',enc.encode(canonical(v))));
export function validateSnapshot(s,origin){
 if(!s||s.format!=='sequoia-complete-state'||s.version!==1||s.origin!==origin||!Array.isArray(s.databases)||s.databases.length!==3||!Array.isArray(s.settings)||canonical(s).length>LIMIT)fail('Invalid backup or different app origin');
 for(let i=0;i<3;i++){
  const r=s.databases[i];if(r.name!==DATABASES[i][0]||r.store!==DATABASES[i][1])fail('Unexpected database');
  if(r.value!==null){if(i===0)validateVault(r.value);else if(r.value.version!==1||r.value.format!==['','sequoia-iwa-identities','sequoia-iwa-certificates'][i])fail('Invalid public database');}
 }
 const names=new Set();for(const pair of s.settings){if(!Array.isArray(pair)||pair.length!==2||typeof pair[0]!=='string'||typeof pair[1]!=='string'||pair[0]===PENDING||names.has(pair[0])||pair[0].length>1024||pair[1].length>LIMIT)fail('Invalid settings');names.add(pair[0]);}
 return s;
}
// The complete snapshot uses the already-random vault content key. A fresh
// nonce and distinct AAD prevent cross-protocol substitution with vault bodies.
// The recovery vault is ciphertext plus existing authenticator key wrappers;
// it contains no unwrapped key and requires the same authenticator after export.
export async function seal(snapshot,vault){
 validateSnapshot(snapshot,snapshot.origin);
 if(!vault.unlocked||canonical(snapshot.databases[0].value)!==canonical(vault.record))fail('Unlock the current source vault first');
 const header={format:'sequoia-complete-backup',version:2,origin:snapshot.origin,recoveryVault:structuredClone(vault.record)};
 const box=await vault.sealBackup(snapshot,header);
 return {...header,...box};
}
export function recoveryVault(box,origin){
 if(!box||box.format!=='sequoia-complete-backup'||box.version!==2||box.origin!==origin||canonical(box).length>LIMIT*2)fail('Invalid backup header or app origin');
 validateVault(box.recoveryVault);return structuredClone(box.recoveryVault);
}
export async function unseal(box,vault,origin){
 recoveryVault(box,origin);
 const {iv,cipher,...header}=box;
 if(canonical(vault.record)!==canonical(box.recoveryVault))fail('Unlock this backup with its enrolled authenticator');
 const result=validateSnapshot(await vault.openBackup({iv,cipher},header),origin);
 if(canonical(result.databases[0].value)!==canonical(box.recoveryVault))fail('Backup recovery vault mismatch');
 return result;
}
// Capture persisted settings and credential databases. Local files are
// intentionally device-local: their key is already in the vault, while their
// ciphertext stays in its own database. Unknown databases still fail closed.
export function browserStorage(factory=indexedDB,settings=localStorage){
 async function database(name,store){return new Promise((resolve,reject)=>{const r=factory.open(name,1);r.onupgradeneeded=()=>r.result.createObjectStore(store);r.onerror=()=>reject(r.error);r.onblocked=()=>reject(Error('Close other app windows'));r.onsuccess=()=>{const db=r.result;if(db.objectStoreNames.length!==1||!db.objectStoreNames.contains(store)){db.close();reject(Error('Unknown database schema'));}else resolve(db);};});}
 return {
  settings,
  async names(){return (await factory.databases()).map(x=>x.name);},
  async read(name,store){const db=await database(name,store);try{return await new Promise((resolve,reject)=>{const t=db.transaction(store),s=t.objectStore(store),r=s.getAllKeys();let value=null;r.onsuccess=()=>{if(r.result.some(k=>k!=='current')){t.abort();return;}const q=s.get('current');q.onsuccess=()=>value=q.result??null;};t.oncomplete=()=>resolve(value);t.onerror=t.onabort=()=>reject(Error('Unexpected database records or read failure'));});}finally{db.close();}},
  // Compare and write in one transaction. Restoration can only populate an
  // empty database, or confirm identical data from an interrupted restore.
  async put(name,store,value){const db=await database(name,store);try{await new Promise((resolve,reject)=>{const t=db.transaction(store,'readwrite'),s=t.objectStore(store),r=s.get('current');r.onsuccess=()=>{if(r.result!==undefined&&canonical(r.result)!==canonical(value)){t.abort();return;}if(value!==null)s.put(structuredClone(value),'current');};t.oncomplete=resolve;t.onabort=t.onerror=()=>reject(Error('Conflicting database; nothing overwritten'));});}finally{db.close();}}
 };
}
export async function capture(storage,origin){
 const names=await storage.names();if(names.some(n=>n!==localFileDatabase&&!DATABASES.some(d=>d[0]===n)))fail('Unknown database: cannot guarantee a complete backup');
 const databases=[];for(const [name,store] of DATABASES)databases.push({name,store,value:await storage.read(name,store)});
 const settings=[];for(let i=0;i<storage.settings.length;i++){const k=storage.settings.key(i);if(k!==PENDING)settings.push([k,storage.settings.getItem(k)]);}settings.sort((a,b)=>a[0].localeCompare(b[0]));
 return validateSnapshot({format:'sequoia-complete-state',version:1,origin,databases,settings},origin);
}
export async function restore(storage,snapshot,origin,{guard=()=>{}}={}){
 guard();
 validateSnapshot(snapshot,origin);const hash=await digest(snapshot),pending=storage.settings.getItem(PENDING);
 if(pending&&pending!==hash)fail('A different restore is pending');
 const before=await capture(storage,origin);guard();
 // Validate *all* destinations before the first write. Never merge trust into
 // an unrelated installation. The only supported target is empty or identical.
 for(let i=0;i<3;i++)if(before.databases[i].value!==null&&canonical(before.databases[i].value)!==canonical(snapshot.databases[i].value))fail('Existing database differs; restore refused');
 // Project the authenticated snapshot onto this device's connection policy.
 // Missing local values stay missing (normal defaults); imported values never
 // silently opt a new host into beta trust. Keep the original snapshot digest
 // as the recovery marker so interrupted restores still bind to one backup.
 const expected=structuredClone(snapshot);
 expected.settings=[...snapshot.settings.filter(([k])=>!LOCAL_CONNECTION_SETTINGS.has(k)),...before.settings.filter(([k])=>LOCAL_CONNECTION_SETTINGS.has(k))].sort((a,b)=>a[0].localeCompare(b[0]));
 const incoming=new Map(expected.settings);for(const [k,v] of before.settings)if(!incoming.has(k)||incoming.get(k)!==v)fail('Existing settings differ; restore refused (setting: '+k+')');
 // IndexedDB cannot atomically commit across three databases and localStorage.
 // A durable marker blocks app startup until an idempotent retry verifies all
 // records. It contains only a digest; no password or decrypted vault content.
 storage.settings.setItem(PENDING,hash);
 for(const r of snapshot.databases){guard();await storage.put(r.name,r.store,r.value);}
 guard();
 // Never write device-local policy, even with an identical value: another
 // window changing it must cause readback failure, not be silently undone.
 for(const [k,v] of expected.settings)if(!LOCAL_CONNECTION_SETTINGS.has(k))storage.settings.setItem(k,v);
 if(await digest(await capture(storage,origin))!==await digest(expected))fail('Restore readback failed; reopen backup to resume');
 guard();storage.settings.removeItem(PENDING);return hash;
}
