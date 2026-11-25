import {Vault,load,persist,validate,random,b64,bytes} from './vault/core.js';
import {classicalWrap,classicalOpen} from './vault/piv.js';
import {createSoftwareIdentityStore} from './software/store.js';
import {softwareCrypto} from './software/client.js';
import {inspectIdentity} from './identities/client.js';
const engine=new Vault();let record=null,revision=0,active=false,epoch=0,timer;
const el=id=>document.getElementById(id),tell=s=>el('vault-status').textContent=s;
const workerPolicy=globalThis.trustedTypes?.createPolicy('sequoia-vault-worker',{createScriptURL:u=>{if(u!=='/vault/worker.js')throw Error();return u;}});
function wasm(op,input){return new Promise((resolve,reject)=>{const w=new Worker(workerPolicy?workerPolicy.createScriptURL('/vault/worker.js'):'/vault/worker.js',{type:'module'});const t=setTimeout(()=>{w.terminate();reject(Error('Vault cryptography timed out.'));},30000);w.onmessage=({data})=>{clearTimeout(t);w.terminate();data.ok?resolve(data.result):reject(Error(data.error));};w.onerror=()=>{clearTimeout(t);w.terminate();reject(Error('Vault cryptography failed.'));};w.postMessage({op,input});});}
function lock(){softwareIdentities.cancel();epoch++;engine.lock();clearTimeout(timer);el('vault-password').value='';el('vault-file').value='';el('vault-secret').value='';render();window.dispatchEvent(new Event('iwa-vault-locked'));}
function render(){
 // Unlock completes after its component request releases the general UI lock.
 // Refresh this control here too, so it becomes usable immediately on success.
 el('vault-lock').disabled=!engine.unlocked;
 el('vault-unlocked').hidden=!engine.unlocked;el('vault-unlock').hidden=!record||engine.unlocked;
 el('vault-methods').replaceChildren();for(const w of record?.wrappers||[]){const o=document.createElement('option');o.value=w.id;o.textContent=w.name+' · '+(w.type==='piv'?'PIV':'FIDO PRF')+(w.id===record.default?' (default)':'');el('vault-methods').append(o);}if(record)el('vault-methods').value=record.default;
 el('vault-method-list').replaceChildren();if(engine.unlocked)for(const w of record.wrappers){const row=document.createElement('div');row.textContent=w.name+' · '+w.type+(w.type==='piv'?' · '+w.binding.serial:'');for(const [label,fn] of [['Rename',async()=>{const name=prompt('Name for this unlock method',w.name);if(name!==null){await engine.rename(w.id,name);await commit();}}],['Remove',async()=>{if(confirm('Remove this vault unlock method? This does not delete any credential or token key.')){await engine.remove(w.id);await commit();}}]]){const b=document.createElement('button');b.textContent=label;b.onclick=()=>run(fn);row.append(b);}el('vault-method-list').append(row);}
 el('vault-items').replaceChildren();if(engine.unlocked)for(const item of engine.data.items){const row=document.createElement('p');row.textContent=item.name+' · '+item.kind+' (encrypted at rest)';el('vault-items').append(row);}
 el('vault-state').textContent=record?(engine.unlocked?'Unlocked — auto-locks after five minutes of inactivity.':'Locked — choose an enrolled method.'):'No IWA vault yet. Use PIV by default, or FIDO PRF for software-only credentials.';
 el('vault-add-piv').textContent=record?'Add PIV unlock method':'Create vault with PIV (default)';el('vault-add-prf').textContent=record?'Add FIDO PRF unlock method':'Create software-only vault with FIDO PRF';
}
async function commit(options={}){try{options.guard?.();const candidate=engine.record;await persist(candidate,revision,options);options.guard?.();record=structuredClone(candidate);revision=record.revision;}catch(e){lock();record=await load();revision=record?.revision||0;throw e;}render();touch();window.dispatchEvent(new Event('iwa-software-identities-changed'));}
function touch(){clearTimeout(timer);if(engine.unlocked)timer=setTimeout(()=>{lock();tell('Vault locked after inactivity.');},300000);}
// The service below is the sole software-identity path into the unlocked
// vault. UI code receives public snapshots and operations, never the raw vault
// object, content key or password-bearing item list. Persistence remains the
// same encrypted IndexedDB record and compare-and-swap revision used by PIV/PRF.
const sameVault=expected=>engine.unlocked&&engine.record?.id===expected.vaultId&&revision===expected.revision&&epoch===expected.epoch;
const softwareIdentities=createSoftwareIdentityStore({
 inspectPublic:inspectIdentity,cryptoCall:softwareCrypto,
 changed:()=>window.dispatchEvent(new Event('iwa-software-identities-changed')),
 access:{
  snapshot:()=>({unlocked:engine.unlocked,vaultId:engine.record?.id,revision,epoch,items:engine.data?.items||[]}),
  async assertCurrent(expected){
   if(!sameVault(expected))throw Error('Software identity vault changed.');const latest=await load();
   if(!sameVault(expected))throw Error('Software identity vault locked or changed.');
   if(!latest||latest.id!==expected.vaultId||latest.revision!==expected.revision){lock();throw Error('Vault changed in another window; unlock the latest copy.');}
  },
  async replaceItems(items,expected,{signal}={}){
   if(active)throw Error('Finish the current vault operation first.');active=true;
   const guard=()=>{if(!sameVault(expected)||signal?.aborted)throw Error('Software identity write cancelled.');};
   try{
    guard();const latest=await load();guard();if(!latest||latest.id!==expected.vaultId||latest.revision!==expected.revision)throw Error('Vault changed in another window.');
    engine.data={...engine.data,items};await engine.save();guard();await commit({guard,signal});
   }catch(e){if(engine.unlocked)lock();throw e;}finally{active=false;}
  }
 }
});
window.softwareIdentities=Object.freeze(softwareIdentities);
async function run(fn){if(active||busy){tell('Finish the current operation first.');return;}active=true;const token=epoch;try{await fn(()=>{if(token!==epoch)throw Error('Vault operation cancelled by locking.');});touch();}catch(e){tell(e.message);window.directFido?.complete(e.message,false);}finally{active=false;render();}}
async function pivSecret(w){
 if(w.binding.kind==='ecdh')return classicalOpen(w.binding,call);
 // Reuse the message component boundary, but authenticate a distinct unsigned
 // vault purpose inside WASM. The native helper never sees the vault envelope.
 const started=epoch;
 const v=await decryptInIwa({cipher:w.binding.cipher,recipientKey:w.binding.recipientKey,
  service:'Vault',purpose:'vault',vault:{vaultId:record?.id||w.vaultId,wrapperId:w.id},
  gate:async()=>{if(started!==epoch)throw Error('Vault operation cancelled by locking.');}});
 try{return bytes(v.secret);}finally{delete v.secret;}
}
async function prf(w){if(w.binding.rpId&&w.binding.rpId!==('chrome-extension://'+EXTENSION_ID)&&globalThis.hardwareTransport?.getMode()!=='smartcard')throw Error('This wrapper requires direct Web Smart Card for its original RP.');const r=globalThis.hardwareTransport?.getMode()==='smartcard'?await window.directFido.prf(w.binding):await call('vault-prf',{name:w.name,salt:w.binding.salt,credentialId:w.binding.credentialId||''});if(w.binding.credentialId&&r.credentialId!==w.binding.credentialId)throw Error('Wrong passkey');w.binding.credentialId=r.credentialId;try{return bytes(r.secret);}finally{delete r.secret;}}
async function enroll(type,check,create=false){
 if(record&&!engine.unlocked)throw Error('Unlock the existing vault before adding another method.');
 const name=el('vault-name').value.trim();if(!name||name.length>80)throw Error('Enter an unlock-method name (1–80 characters).');
 const vaultId=record?.id||crypto.randomUUID(),w={id:crypto.randomUUID(),name,type,binding:{}};let secret;
 try{
  if(type==='piv'){
   const material=await call('chat-vault-material');
   if(el('vault-classical').checked){if(!material.classical)throw Error('No classical PIV vault key configured. Configure an existing public key and slot first; no keys will be generated.');if(!confirm('Classical ECDH protects this vault. Its encrypted backup is not post-quantum resistant. Continue?'))return;const result=await classicalWrap(material.classical);w.binding=result.binding;try{secret=await classicalOpen(w.binding,call);if(!secret.every((b,i)=>b===result.secret[i]))throw Error('PIV ECDH enrollment verification failed.');}finally{result.secret.fill(0);}
   }else{
    if(!material.certificate)throw Error('No Level 3 OpenPGP certificate saved for hybrid PIV vault. Restore your identity bundle first, or check "Use configured classical PIV ECDH key" for a P-256/P-384 PIV slot.');
    const seed=random(32);try{const out=await wasm('wrap',{certificate:material.certificate,secret:b64(seed),vaultId,wrapperId:w.id});w.binding={kind:'hybrid',cipher:out.cipher,recipientKey:out.recipientKey,serial:material.serial};w.vaultId=vaultId;secret=await pivSecret(w);delete w.vaultId;if(!secret.every((b,i)=>b===seed[i]))throw Error('PIV enrollment verification failed.');}finally{seed.fill(0);}
   }
   if(record?.wrappers.some(x=>x.type==='piv'&&x.binding.kind===w.binding.kind&&(x.binding.recipientKey||x.binding.fingerprint)===(w.binding.recipientKey||w.binding.fingerprint)))throw Error('This PIV key already unlocks the vault.');
  }else{w.binding={salt:b64(random(32)),credentialId:'',...(globalThis.hardwareTransport?.getMode()==='smartcard'?window.directFido.enrollmentBinding():{})};if(create){const r=await window.directFido.create(w.binding,name,vaultId);w.binding=r.binding;try{secret=bytes(r.secret);}finally{delete r.secret;}}else secret=await prf(w);if(record?.wrappers.some(x=>x.type==='prf'&&x.binding.credentialId===w.binding.credentialId))throw Error('This passkey already unlocks the vault.');}
  check();if(record)await engine.add(w,secret);else await engine.create(w,secret,vaultId);check();await commit();if(create)window.directFido.creationSaved();tell('Unlock method verified and saved. The same vault can use PIV or FIDO PRF.');if(type==='prf')window.directFido?.complete('FIDO PRF unlock method saved. You may remove the key. Lock the vault to test a fresh unlock.');
 }finally{secret?.fill(0);}
}
el('vault-create-prf').onclick=()=>run(c=>enroll('prf',c,true));
el('vault-add-piv').onclick=()=>run(c=>enroll('piv',c));el('vault-add-prf').onclick=()=>run(c=>enroll('prf',c));
el('vault-unlock').onclick=()=>run(async check=>{const fresh=await load();if(fresh){record=fresh;revision=fresh.revision;}validate(record);const w=structuredClone(record.wrappers.find(w=>w.id===el('vault-methods').value));if(!w)throw Error('Select an unlock method.');let secret;try{secret=w.type==='piv'?await pivSecret(w):await prf(w);check();await engine.unlock(record,w.id,secret);check();tell('Vault unlocked.');if(w.type==='prf')window.directFido?.complete('Vault unlocked successfully with FIDO PRF. You may remove the key.');window.dispatchEvent(new Event('iwa-vault-unlocked'));}finally{secret?.fill(0);}});
el('vault-lock').onclick=()=>{lock();tell('Vault locked.');};
el('vault-store').onclick=()=>run(async check=>{if(!engine.unlocked)throw Error('Unlock first.');const file=el('vault-file').files[0],name=el('vault-item-name').value.trim();if(!name||name.length>100)throw Error('Enter an item name.');let item;if(file){if(!/\.(p12|pfx)$/i.test(file.name)||file.size>1000000)throw Error('Choose a .p12/.pfx up to 1 MB.');item={id:crypto.randomUUID(),name,kind:'password-protected .p12',file:b64(await file.arrayBuffer()),password:el('vault-password').value};if(!item.password)throw Error('Enter the existing .p12 password.');}else{const value=el('vault-secret').value;if(!value||value.length>65536)throw Error('Enter a secret up to 64 KiB.');item={id:crypto.randomUUID(),name,kind:'secret setting',value};}check();engine.data.items.push(item);await engine.save();await commit();el('vault-password').value=el('vault-secret').value=el('vault-file').value='';tell('Saved encrypted in the IWA vault. This does not select a software signing identity or change gws credentials.');});
el('vault-export').onclick=()=>run(async()=>{if(!record)throw Error('Create a vault first.');const url=URL.createObjectURL(new Blob([JSON.stringify(record)],{type:'application/json'})),a=document.createElement('a');a.href=url;a.download='sequoia-vault.encrypted.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);tell('Exported encrypted vault only. Keep an enrolled authenticator available.');});
el('vault-import').onchange=()=>run(async()=>{if(record)throw Error('A vault already exists. Import never overwrites it.');const f=el('vault-import').files[0];if(!f||f.size>4000000)throw Error('Choose a vault backup up to 4 MB.');record=validate(JSON.parse(await f.text()));revision=0;tell('Backup loaded temporarily. Unlock and choose Save restored vault before it is stored.');});
el('vault-restore').onclick=()=>run(async()=>{if(revision||!engine.unlocked)throw Error('Unlock the imported backup first.');await persist(record,0);revision=record.revision;tell('Encrypted backup restored.');});
window.vaultGate=()=>{if(record&&!engine.unlocked)throw Error('Unlock the credential vault first (Vault tab).');};
window.addEventListener('pagehide',lock);for(const e of ['pointerdown','keydown'])document.addEventListener(e,touch,{passive:true});
record=await load();revision=record?.revision||0;if(record)validate(record);render();

// Read-only gate for the experimental in-memory Google session.
window.vaultIsUnlocked=()=>engine.unlocked;
