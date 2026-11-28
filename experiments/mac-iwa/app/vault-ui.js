import {createBackupVaultAccess,registerBackupVaultSession} from './vault/backup-session.js';
import {createLocalFileStore} from './local-files/store.js';
import {createSshTrustStore} from './ssh/trust.js';
import {createSshAddressBook} from './ssh/address-book.js';
import {createImportedSshStore} from './ssh/imported-keys.js';
import {verifyProvisioningRecovery} from './vault/provisioning-recovery.js';
import {wrapLevel5} from './vault/level5.js';
import {unlockMethodLabel} from './vault/labels.js';
import {confirmUnlockEnrollment,discoverOrCreate,hasMatchingPiv,requireAttachedUnlockMethod} from './vault/enrollment.js';
import {Vault,load,persist,validate,random,b64,bytes} from './vault/core.js';
import {classicalWrap} from './vault/piv.js';
import {openPivWrapper} from './vault/open-piv.js';
import {showVaultUnlockProgress} from './vault/unlock-progress.js';
import {attachedUnlockAlternatives,reviewAlternateUnlock} from './vault/alternate-unlock.js';
import {createSoftwareIdentityStore} from './software/store.js';
import {softwareCrypto} from './software/client.js';
import {operateImportedKey} from './piv-import.js';
import {inspectIdentity} from './identities/client.js';
import {discoverIdentityDevices} from './identities/devices.js';
let engine=new Vault(),record=null,revision=0,active=false,epoch=0,timer;
const el=id=>document.getElementById(id),tell=s=>el('vault-status').textContent=s;
const workerPolicy=globalThis.trustedTypes?.createPolicy('sequoia-vault-worker',{createScriptURL:u=>{if(u!=='/vault/worker.js')throw Error();return u;}});
function wasm(op,input){return new Promise((resolve,reject)=>{const w=new Worker(workerPolicy?workerPolicy.createScriptURL('/vault/worker.js'):'/vault/worker.js',{type:'module'});const t=setTimeout(()=>{w.terminate();reject(Error('Vault cryptography timed out.'));},30000);w.onmessage=({data})=>{clearTimeout(t);w.terminate();data.ok?resolve(data.result):reject(Error(data.error));};w.onerror=()=>{clearTimeout(t);w.terminate();reject(Error('Vault cryptography failed.'));};w.postMessage({op,input});});}
function lock(){window.sshTrust?.cancel();softwareIdentities.cancel();epoch++;engine.lock();clearTimeout(timer);el('vault-password').value='';el('vault-file').value='';el('vault-secret').value='';render();window.dispatchEvent(new Event('iwa-vault-locked'));}
function render(){
 // Publish only presentation state; the startup screen never receives vault secrets.
 window.vaultStartupState=()=>({exists:!!record,unlocked:engine.unlocked&&revision>0,methods:(record?.wrappers||[]).map(w=>({id:w.id,name:w.name,type:w.type,...(w.type==='piv'?{serial:w.binding.serial}:{})})),defaultId:record?.default,status:el('vault-status').textContent});
 // Unlock completes after its component request releases the general UI lock.
 // Refresh this control here too, so it becomes usable immediately on success.
 el('vault-lock').disabled=!engine.unlocked;
 el('vault-unlocked').hidden=!engine.unlocked;el('vault-unlock').hidden=!record||engine.unlocked;
 el('vault-methods').replaceChildren();for(const w of record?.wrappers||[]){const o=document.createElement('option');o.value=w.id;o.textContent=(w.type==='piv'?unlockMethodLabel(w):w.name+' · FIDO PRF')+(w.id===record.default?' (default)':'');el('vault-methods').append(o);}if(record)el('vault-methods').value=record.default;
 el('vault-method-list').replaceChildren();if(engine.unlocked)for(const w of record.wrappers){const row=document.createElement('div');row.textContent=unlockMethodLabel(w);for(const [label,fn] of [['Rename',async()=>{const name=prompt('Name for this unlock method',w.name);if(name!==null){await engine.rename(w.id,name);await commit();}}],['Remove',async()=>{if(confirm('Remove this vault unlock method? This does not delete any credential or token key.')){await engine.remove(w.id);await commit();}}]]){const b=document.createElement('button');b.textContent=label;b.onclick=()=>run(fn);row.append(b);}el('vault-method-list').append(row);}
 el('vault-items').replaceChildren();if(engine.unlocked)for(const item of engine.data.items){const row=document.createElement('p');row.textContent=item.name+' · '+item.kind+' (encrypted at rest)';el('vault-items').append(row);}
 el('vault-state').textContent=record?(engine.unlocked?'Unlocked — auto-locks after five minutes of inactivity.':'Locked — choose an enrolled method.'):'No IWA vault yet. Use PIV by default, or FIDO PRF for software-only credentials.';
 window.dispatchEvent(new Event('iwa-vault-state'));
 el('vault-add-piv').textContent=record?'Add PIV unlock method':'Create vault with PIV (default)';el('vault-add-prf').textContent=record?'Add FIDO PRF unlock method':'Create software-only vault with FIDO PRF';
}
async function commit(options={}){try{options.guard?.();const candidate=engine.record;await persist(candidate,revision,options);options.guard?.();record=structuredClone(candidate);revision=record.revision;}catch(e){lock();record=await load();revision=record?.revision||0;throw e;}render();touch();window.dispatchEvent(new CustomEvent('iwa-software-identities-changed',{detail:options.change}));}
function touch(){clearTimeout(timer);if(engine.unlocked)timer=setTimeout(()=>{lock();tell('Vault locked after inactivity.');},300000);}
// The service below is the sole software-identity path into the unlocked
// vault. UI code receives public snapshots and operations, never the raw vault
// object, content key or password-bearing item list. Persistence remains the
// same encrypted IndexedDB record and compare-and-swap revision used by PIV/PRF.
const sameVault=expected=>engine.unlocked&&engine.record?.id===expected.vaultId&&revision===expected.revision&&epoch===expected.epoch;
const identityVaultAccess={
  snapshot:()=>({unlocked:engine.unlocked,vaultId:engine.record?.id,revision,epoch,items:engine.data?.items||[]}),
  async assertCurrent(expected){
   if(!sameVault(expected))throw Error('Software identity vault changed.');const latest=await load();
   if(!sameVault(expected))throw Error('Software identity vault locked or changed.');
   if(!latest||latest.id!==expected.vaultId||latest.revision!==expected.revision){lock();throw Error('Vault changed in another window; unlock the latest copy.');}
  },
  async verifyRecovery(recovery,item,targetSerial){
   if(!engine.unlocked||!record)throw Error('Unlock the vault first.');
   try{
    await verifyProvisioningRecovery({...recovery,item,targetSerial,sourceRecord:record,assertPrf:prf});
    window.directFido?.complete('Recovery backup verified with the separate YubiKey.');
   }catch(error){
    window.directFido?.complete(error.message,false);
    throw error;
   }
  },
  async replaceItems(items,expected,{signal,change}={}){
   if(active)throw Error('Finish the current vault operation first.');active=true;
   const guard=()=>{if(!sameVault(expected)||signal?.aborted)throw Error('Software identity write cancelled.');};
   try{
    guard();const latest=await load();guard();if(!latest||latest.id!==expected.vaultId||latest.revision!==expected.revision)throw Error('Vault changed in another window.');
    engine.data={...engine.data,items};await engine.save();guard();await commit({guard,signal,change});
   }catch(e){if(engine.unlocked)lock();throw e;}finally{active=false;}
  }
 };
const softwareIdentities=createSoftwareIdentityStore({
 inspectPublic:inspectIdentity,cryptoCall:softwareCrypto,hardwareCall:operateImportedKey,entropyCollector:options=>window.directFido.entropy(options),
 changed:()=>window.dispatchEvent(new Event('iwa-software-identities-changed')),
 access:identityVaultAccess
});
window.sshTrust= createSshTrustStore(identityVaultAccess);
window.sshAddressBook=createSshAddressBook(identityVaultAccess);
window.localFiles=createLocalFileStore(identityVaultAccess);
window.importedSshKeys=createImportedSshStore(identityVaultAccess);
window.softwareIdentities=Object.freeze(softwareIdentities);
async function run(fn){if(active||busy){tell('Finish the current operation first.');return;}active=true;const token=epoch;try{await fn(()=>{if(token!==epoch)throw Error('Vault operation cancelled by locking.');});touch();}catch(e){tell(e.message);if(e.code!=='YUBIKEY_NOT_FOUND')window.directFido?.complete(e.message,false);}finally{active=false;render();}}
async function pivSecret(w,vaultProgress){
 const started=epoch;
 return openPivWrapper(record,w,{request:(op,data,options)=>hardwareRequest(op,data,{...options,vaultProgress}),vaultRequest:call,decrypt:decryptInIwa,
  guard:()=>{if(started!==epoch)throw Error('Vault operation cancelled by locking.');}});
}
async function prf(w,options){if(w.binding.rpId&&w.binding.rpId!==('chrome-extension://'+EXTENSION_ID)&&globalThis.hardwareTransport?.getMode()!=='smartcard')throw Error('This wrapper requires direct Web Smart Card for its original RP.');const r=globalThis.hardwareTransport?.getMode()==='smartcard'?await window.directFido.prf(w.binding,options):await call('vault-prf',{name:w.name,salt:w.binding.salt,credentialId:w.binding.credentialId||''});if(w.binding.credentialId&&r.credentialId!==w.binding.credentialId)throw Error('Wrong passkey');w.binding.credentialId=r.credentialId;try{return bytes(r.secret);}finally{delete r.secret;}}
async function checkExistingUnlockDevice(check){
 check();
 if(!record)return;
 await requireAttachedUnlockMethod(record.wrappers,()=>discoverIdentityDevices(call,{allowEmpty:true}));
 check();
}
async function enroll(type,check,{create=false,expectedSerial=null,
 name=el('vault-name').value.trim(),makeDefault=type==='piv',requireHybrid=false,
 confirmCreate=()=>confirm('No FIDO credential exists for this IWA on the selected key. Create a new discoverable PRF credential?')}={}){
 if(record&&!engine.unlocked)throw Error('Unlock the existing vault before adding another method.');
 if(!name||name.length>80)throw Error('Enter an unlock-method name (1–80 characters).');
 await checkExistingUnlockDevice(check);
 const vaultId=record?.id||crypto.randomUUID(),w={id:crypto.randomUUID(),name,type,binding:{}};let secret;
 try{
  if(type==='piv'){
   const material=await call('chat-vault-material',expectedSerial?{serial:expectedSerial}:{});
   check();
   if(requireHybrid&&material.classicalAllowed)throw Error('Expected a verified hybrid vault key.');
   if(expectedSerial&&String(material.serial)!==String(expectedSerial))throw Error('Wrong YubiKey for PIV enrollment.');
   if(material.classicalAllowed){
    if(!material.classical)throw Error('No classical PIV vault wrapping key is available.');
    if(!await confirmUnlockEnrollment(document,window,{
     title:'Use classical PIV protection?',
     detail:'This YubiKey uses classical ECDH. A vault backup protected by this method is not post-quantum resistant.',
     action:'Use classical protection',
    }))return;
    check();
    const result=await classicalWrap(material.classical);
    w.binding=result.binding;
    try{
     check();
     secret=await classicalOpen(w.binding,call);
     if(!secret.every((byte,index)=>byte===result.secret[index]))throw Error('PIV ECDH enrollment verification failed.');
    }finally{result.secret.fill(0);}
   }else if(material.level5){
    const result=await wrapLevel5(material,input=>wasm('level5-encapsulate',input));
    w.binding=result.binding;
    try{
     check();secret=await pivSecret(w);
     if(!secret.every((byte,index)=>byte===result.secret[index]))throw Error('Level 5 vault verification failed.');
    }finally{result.secret.fill(0);}
   }else{
    if(!material.certificate)throw Error('No verified supported hybrid vault certificate is available. YK6 setup never falls back to classical wrapping.');
    const seed=random(32);try{const out=await wasm('wrap',{certificate:material.certificate,secret:b64(seed),vaultId,wrapperId:w.id});w.binding={kind:'hybrid',cipher:out.cipher,recipientKey:out.recipientKey,serial:material.serial};w.vaultId=vaultId;check();secret=await pivSecret(w);delete w.vaultId;if(!secret.every((b,i)=>b===seed[i]))throw Error('PIV enrollment verification failed.');}finally{seed.fill(0);}
   }
   if(record?.wrappers.some(x=>x.type==='piv'&&x.binding.kind===w.binding.kind&&(x.binding.recipientKey||x.binding.fingerprint||x.binding.kemPublic)===(w.binding.recipientKey||w.binding.fingerprint||w.binding.kemPublic)))throw Error('This PIV key already unlocks the vault.');
  }else{w.binding={salt:b64(random(32)),credentialId:'',...(globalThis.hardwareTransport?.getMode()==='smartcard'?window.directFido.enrollmentBinding(expectedSerial):{})};if(create){
    // Discover first under this exact RP and serial; never turn cancellation,
    // wrong PIN, transport loss or unsupported PRF into credential creation.
    const found=await discoverOrCreate({
     assertExisting:async()=>({secret:await prf(w)}),
     confirmCreate,
     createNew:async()=>{await checkExistingUnlockDevice(check);const r=await window.directFido.create(w.binding,name,vaultId);w.binding=r.binding;try{return {secret:bytes(r.secret)};}finally{delete r.secret;}}
    });secret=found.result.secret;create=found.created;
   }else secret=await prf(w);if(record?.wrappers.some(x=>x.type==='prf'&&x.binding.credentialId===w.binding.credentialId))throw Error('This passkey already unlocks the vault.');}
  // Authenticator prompts can outlast a USB swap. Recheck immediately
  // before storing the wrapper, while there is still nothing to persist.
  await checkExistingUnlockDevice(check);
  if(record)await engine.add(w,secret,{makeDefault});else await engine.create(w,secret,vaultId);
  check();await commit();if(create)window.directFido.creationSaved();tell('Unlock method verified and saved. The same vault can use PIV or FIDO PRF.');if(type==='prf')window.directFido?.complete('FIDO PRF unlock method saved. You may remove the key. Lock the vault to test a fresh unlock.');
 }finally{secret?.fill(0);}
}
// Run after provisioning has released the general UI lock. Enrollment is a
// separate, optional transaction with its own vault epoch and card check.
window.offerProvisionedVaultUnlock=async({serial,type})=>{
 if(typeof serial!=='string'||!/^[1-9][0-9]{5,9}$/.test(serial)||!['piv','prf'].includes(type))
  throw Error('Invalid provisioned YubiKey.');
 if(!record||!engine.unlocked)throw Error('Unlock the vault to add a method.');
 if(active||busy)throw Error('Finish the current vault operation first.');
 const label=type==='piv'?'hybrid PIV':'FIDO PRF';
 const name='YubiKey SN# '+serial;
 let enrolled=false,failure,credentialDeclined=false;
 await run(async checkEpoch=>{
  const check=()=>{
   checkEpoch();
   if(window.hardwareTransport?.getMode()!=='smartcard')throw Error('Use Web Smart Card to enroll the reviewed YubiKey.');
  };
  if(!await confirmUnlockEnrollment(document,window,{
   title:'Add '+name+' as a vault unlock method?',
   detail:label+' will unlock this vault alongside its existing methods. Keep an enrolled YubiKey connected. Your current default stays selected.',
   action:'Add unlock method',
  }))return;
  try{
   check();
   await enroll(type,check,{expectedSerial:serial,name,create:type==='prf',makeDefault:false,requireHybrid:type==='piv',
    async confirmCreate(){
     check();
     // The previous FIDO operation ended with NO_CREDENTIALS. Dismiss its
     // status so this separate credential-creation consent is visible.
     el('fido-pin-dialog').close();
     const approved=await confirmUnlockEnrollment(document,window,{
      title:'Create a FIDO PRF credential on '+name+'?',
      detail:'This card has no discoverable credential for this IWA. Creating one requires a separate PIN and touch.',
      action:'Create FIDO credential',
     });
     check();
     credentialDeclined=!approved;
     return approved;
    },
   });
   enrolled=true;
  }catch(error){if(!credentialDeclined)failure=error;}
 });
 if(failure)throw failure;
 return enrolled;
};
el('vault-create-prf').onclick=()=>run(c=>enroll('prf',c,{create:true}));
async function enrollConnectedPiv(check,requestedSerial){
 // The native helper has a configured identity. Web Smart Card can enroll
 // an unknown connected device after independently authenticating its keys.
 if(window.hardwareTransport?.getMode()!=='smartcard')return enroll('piv',check);
 let serial=requestedSerial;
 if(!serial){
  const devices=await discoverIdentityDevices(call);
  check();
  serial=await confirmUnlockEnrollment(document,window,{
   title:'Add a PIV vault unlock method',
   detail:'Choose a connected YubiKey. Keep an enrolled YubiKey connected while adding a method.',
   action:'Continue with this YubiKey',devices,
  });
  if(!serial)return;
 }
 const checkTransport=()=>{
  check();
  if(window.hardwareTransport?.getMode()!=='smartcard')throw Error('Use Web Smart Card to enroll the selected YubiKey.');
 };
 checkTransport();
 return enroll('piv',checkTransport,{expectedSerial:serial});
}
el('vault-add-piv').onclick=()=>run(c=>enrollConnectedPiv(c));
el('vault-add-prf').onclick=()=>run(c=>enroll('prf',c));
async function unlockWithMethod(method,check){
 const w=structuredClone(method);
 const showProgress=w.type==='piv'&&w.binding.kind==='hybrid'&&window.hardwareTransport?.getMode()==='smartcard';
 const progressPanel=el(el('startup').hidden?'vault-unlock-progress':'startup-vault-progress');
 const progress=showProgress?showVaultUnlockProgress(progressPanel,w.binding.serial):null;
 let secret;
 try{
  secret=w.type==='piv'?await pivSecret(w,event=>{check();progress?.update(event);}):await prf(w,{quietMissing:true});
  check();
  await engine.unlock(record,w.id,secret);
  check();
  tell('Vault unlocked.');
  if(w.type==='prf')window.directFido?.complete('Vault unlocked successfully with FIDO PRF. You may remove the key.');
  window.dispatchEvent(new Event('iwa-vault-unlocked'));
 }finally{progress?.close();secret?.fill(0);}
}
el('vault-unlock').onclick=()=>run(async check=>{
 const fresh=await load();
 if(fresh){record=fresh;revision=fresh.revision;}
 validate(record);
 const selected=record.wrappers.find(w=>w.id===el('vault-methods').value);
 if(!selected)throw Error('Select an unlock method.');
 try{await unlockWithMethod(selected,check);}
 catch(error){
  const methods=attachedUnlockAlternatives(record,selected,error);
  if(!methods.length)throw error;
  check();
  const current=record,transport=window.hardwareTransport;
  const requireScp=window.SequoiaSecureChannel?.isRequired();
  const id=await reviewAlternateUnlock(document,window,selected.binding.serial,methods);
  check();
  if(!id){tell(error.message+' Unlock cancelled.');return;}
  const latest=await load();
  check();
  if(transport?.getMode()!=='smartcard'||window.SequoiaSecureChannel?.isRequired()!==requireScp)
   throw Error('YubiKey connection settings changed. Start a fresh unlock.');
  if(!latest||latest.id!==current.id||latest.revision!==current.revision)
   throw Error('The vault changed. Start a fresh unlock.');
  const alternate=latest.wrappers.find(w=>w.id===id);
  if(!alternate)throw Error('The alternate method is no longer enrolled.');
  // Consent applies to exactly one method. A removed card or rejected PIN
  // ends this operation without offering or trying another credential.
  await unlockWithMethod(alternate,check);
 }
});
el('vault-lock').onclick=()=>{lock();tell('Vault locked.');};
el('vault-store').onclick=()=>run(async check=>{if(!engine.unlocked)throw Error('Unlock first.');const file=el('vault-file').files[0],name=el('vault-item-name').value.trim();if(!name||name.length>100)throw Error('Enter an item name.');let item;if(file){if(!/\.(p12|pfx)$/i.test(file.name)||file.size>1000000)throw Error('Choose a .p12/.pfx up to 1 MB.');item={id:crypto.randomUUID(),name,kind:'password-protected .p12',file:b64(await file.arrayBuffer()),password:el('vault-password').value};if(!item.password)throw Error('Enter the existing .p12 password.');}else{const value=el('vault-secret').value;if(!value||value.length>65536)throw Error('Enter a secret up to 64 KiB.');item={id:crypto.randomUUID(),name,kind:'secret setting',value};}check();engine.data.items.push(item);await engine.save();await commit();el('vault-password').value=el('vault-secret').value=el('vault-file').value='';tell('Saved encrypted in the IWA vault. This does not select a software signing identity or change gws credentials.');});
el('vault-export').onclick=()=>run(async()=>{if(!record)throw Error('Create a vault first.');const url=URL.createObjectURL(new Blob([JSON.stringify(record)],{type:'application/json'})),a=document.createElement('a');a.href=url;a.download='sequoia-vault.encrypted.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);tell('Exported encrypted vault only. Keep an enrolled authenticator available.');});
el('vault-import').onchange=()=>run(async()=>{if(record)throw Error('A vault already exists. Import never overwrites it.');const f=el('vault-import').files[0];if(!f||f.size>4000000)throw Error('Choose a vault backup up to 4 MB.');record=validate(JSON.parse(await f.text()));revision=0;tell('Backup loaded temporarily. Unlock and choose Save restored vault before it is stored.');});
el('vault-restore').onclick=()=>run(async()=>{if(revision||!engine.unlocked)throw Error('Unlock the imported backup first.');await persist(record,0);revision=record.revision;tell('Encrypted backup restored.');});
window.vaultGate=()=>{if(record&&!engine.unlocked)throw Error('Unlock the credential vault first (Vault tab).');};
window.addEventListener('pagehide',lock);for(const e of ['pointerdown','keydown'])document.addEventListener(e,touch,{passive:true});
record=await load();revision=record?.revision||0;if(record)validate(record);render();
// Keep the vault key inside the active engine even when changing screens.
registerBackupVaultSession(createBackupVaultAccess({
 current:()=>({engine,epoch,revision,active}),
 load,settings:localStorage,origin:location.origin,touch,
 activate(candidate,saved,restored){
  if(engine!==candidate)engine.lock();
  engine=candidate;
  record=saved;revision=saved.revision;epoch++;
  tell(restored?'Restored vault unlocked.':'Vault unlocked.');
  render();touch();
  if(restored)window.dispatchEvent(new Event('iwa-vault-restored'));
  window.dispatchEvent(new Event('iwa-vault-unlocked'));
 },
}));

// Read-only gate for the experimental in-memory Google session.
window.vaultIsUnlocked=()=>engine.unlocked;
// Locked-vault decryption is allowed only inside an explicit active vault operation.
window.vaultOperationActive=()=>active;

// Dedicated onboarding entry point. Never overwrite a saved/imported vault and
// never infer permission to create a credential from an assertion failure.
window.createStartupVault=async({name,serial,method,classical=false})=>{
 if(record||await load())throw Error('A vault already exists. Return to login.');
 if(!['existing-prf','new-prf','existing-piv'].includes(method))throw Error('Choose an unlock method.');
 if(!name||name.length>80)throw Error('Enter a vault name.');
 if(method!=='existing-piv'&&!/^[1-9][0-9]{0,9}$/.test(serial))throw Error('Enter the connected YubiKey serial.');
 el('vault-name').value=name;el('fido-serial').value=serial;el('vault-classical').checked=classical;
 return run(async check=>{
  if(method==='existing-piv')await enrollConnectedPiv(check,serial);
  else await enroll('prf',check,{create:method==='new-prf'});
  if(method==='existing-piv'||!engine.unlocked)return;
  // The read-only probe follows successful FIDO protection. Failure leaves
  // that verified vault intact and never attempts PIV provisioning or login.
  let material;try{material=await call('chat-vault-material',{serial});check();}
  catch(error){tell('FIDO vault saved. PIV availability could not be checked: '+error.message);return;}
  if(!hasMatchingPiv(material,serial))return;
  if(!confirm('This YubiKey already has a usable PIV wrapping key. Also configure PIV unlocking for this vault? No keys will be created or changed.'))return;
  el('vault-classical').checked=!!material.classicalAllowed;
  await enroll('piv',check,{expectedSerial:serial});
 });
};
