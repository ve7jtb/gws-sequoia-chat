// Load the same required-SCP policy before any backup PRF assertion.
import './secure-channel-ui.js';
import {Vault,load} from './vault/core.js';
import {evaluate} from './ctap2-smartcard.js';
import {capture,unseal,digest,restore,browserStorage,recoveryVault,PENDING} from './complete-backup.js';
import {createBackupDrive,DRIVE_SCOPE} from './backup-drive.js';
import {runLoopbackPkceOAuth,getLoopbackClientId,getLoopbackClientSecret} from './google-loopback-oauth.js';
import {backupVaultSession} from './vault/backup-session.js';
import {backupUnlockChoices,unlockBackup} from './vault/backup-unlock.js';
import {detailedUnlockMethodLabel} from './vault/labels.js';
import {prepareLevel3VaultUnlock} from './vault/hardware.js';
import {showVaultUnlockProgress} from './vault/unlock-progress.js';
import {createVaultPresenceMonitor,monitoredVaultSerial} from './vault/presence.js';
import {decryptWithHardware} from './decryption-session.js';
const workerPath='/decryption-worker.js';
const workerPolicy=globalThis.trustedTypes?.createPolicy('sequoia-backup-decryption-worker',{
 createScriptURL:url=>{if(url!==workerPath)throw Error('Unexpected backup worker');return url;}
});
const el=id=>document.getElementById('backup-'+id),storage=browserStorage(),drive=createBackupDrive();
const screen=el('screen'),application=document.getElementById('application-screen');
let verificationVault=new Vault(),source;
const securityIds=['secure-yubikey-connection','secure-yubikey-beta','secure-yubikey-status','hardware-transport'];
const security=[document.querySelector('label[for=hardware-transport]'),...securityIds.map(id=>document.getElementById(id))].map((node,i)=>{
 const control=i===1||i===2?node.closest('label'):node;
 const home=document.createComment('security control home');control.before(home);
 return {control,home};
});
function show(){
 application.hidden=true;screen.hidden=false;
 for(const {control} of security)el('security-controls').append(control);
}
function hide(){
 for(const {control,home} of security)home.after(control);
 screen.hidden=true;application.hidden=false;
}
window.openEncryptedBackup=async()=>{
 show();
 history.replaceState(null,'','/#backup');
 source=await load();methods(source,'source-methods');updateSourceActions();
 if(localStorage.getItem(PENDING))tell('Finish the interrupted restore with the same encrypted backup.');
 else tell(backupVaultSession?.unlocked()?'Using your unlocked vault for backup.':'');
};
document.getElementById('backup-link').onclick=event=>{event.preventDefault();window.openEncryptedBackup().catch(error=>tell(error.message));};

let box=null,review=null,busy=false,page='',controller,timer,unlockAbort;
const tell=s=>el('status').textContent=s;
const verificationPresence=createVaultPresenceMonitor({
 probe:serial=>window.SequoiaSmartCardPiv.verifyVaultKeyPresence(serial),
 onTimeout:serial=>{
  clear();
  tell('Backup verification locked. Could not verify unlock key SN# '+serial+' over SCP11b for 30 seconds.');
 },
});
window.addEventListener('focus',verificationPresence.refresh);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)void verificationPresence.refresh();});
document.addEventListener('freeze',()=>{if(verificationPresence.serial)clearBackup();});
function clear(){verificationPresence.stop();el('restore-success').hidden=true;el('restore').textContent='Restore into empty instance';box=null;review=null;verificationVault.lock();el('restore').disabled=true;el('save').disabled=true;el('upload').disabled=true;el('review').textContent='';el('approve').checked=false;methods(null);}
function disconnect(){controller?.abort();drive.disconnect();clearTimeout(timer);el('auth').hidden=true;}
function touch(){if(screen.hidden)return;clearTimeout(timer);timer=setTimeout(()=>{clearBackup();tell('Backup session cleared after inactivity.');},300000);}
async function run(fn){if(busy)return;busy=true;try{await fn();touch();}catch(e){tell(e.message);}finally{busy=false;}}
function select(value){clear();box=value;const record=recoveryVault(box,location.origin);methods(record);el('save').disabled=false;}
function save(){const url=URL.createObjectURL(new Blob([JSON.stringify(box)],{type:'application/octet-stream'}));const a=document.createElement('a');a.href=url;a.download='sequoia-complete.encrypted.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function methods(record,id='methods'){
 const list=el(id),{methods,selected}=backupUnlockChoices(record,list.value);
 list.replaceChildren(...methods.map(w=>{
  const option=document.createElement('option');
  option.value=w.id;
  option.textContent=detailedUnlockMethodLabel(w)+(w.id===record.default?' (default)':'');
  return option;
 }));
 list.value=selected||'';
 list.disabled=!methods.length;
 if(id==='methods')el('verify').disabled=!methods.length;
}
function updateSourceActions(){
 const pending=!!localStorage.getItem(PENDING),unlocked=!!backupVaultSession?.unlocked();
 el('source-unlock').hidden=pending||unlocked||!source;
 el('export').disabled=pending||!unlocked;
 el('back').disabled=pending;
}

// Only reader-discovery failures show this reminder. Never automatically retry
// an assertion: other failures may occur after a PIN has reached the key.
function showMissingKey(wrapper){
 const dialog=el('insert-dialog');
 el('insert-details').textContent='No key found. Connect '+detailedUnlockMethodLabel(wrapper)+' to this computer, then select Unlock again. No PIN was submitted.';
 el('insert-close').onclick=()=>dialog.close();
 dialog.showModal();el('insert-close').focus();
}
async function unlock(record,vault,methodId){
 verificationPresence.stop();
 vault.lock();
 const w=record?.wrappers.find(w=>w.id===methodId);
 if(!w)throw Error('Select an enrolled unlock method.');
 tell('Checking '+detailedUnlockMethodLabel(w)+' — keep the key connected.');
 const abort=new AbortController(),dialog=el('pin-dialog');unlockAbort=abort;
 const guard=()=>abort.signal.throwIfAborted();
 const mode=window.hardwareTransport.getMode();
 const progress=w.type==='piv'&&w.binding.kind==='hybrid'&&mode==='smartcard'
  ?showVaultUnlockProgress(el('vault-progress'),w.binding.serial):null;
 const vaultProgress=event=>{guard();progress?.update(event);};
 const request=(op,data,options={})=>{
  guard();
  // Allow only the read and unwrap operations needed before the app unlocks.
  if(!['chat-identity-devices','vault-prf','chat-vault-ecdh','chat-vault-level5-open',
   'chat-decryption-material','chat-decapsulate-components'].includes(op))throw Error('Unsupported backup unlock operation.');
  if(['chat-decryption-material','chat-decapsulate-components'].includes(op)&&data?.service!=='Vault')
   throw Error('Backup recovery requires a vault operation.');
  return window.hardwareTransport.dispatch(op,data,{signal:abort.signal,...options,vaultProgress},
   (op,data,options)=>requestCompanion(op,data,{...options,progress:tell}),{
    say:tell,assertVault:guard,
    prepareLevel3VaultUnlock:async(serial,recipientKey,progress)=>{
     const {inspectBundle,inspectIdentity}=await import('./identities/client.js');
     const identity=await prepareLevel3VaultUnlock({serial,recipientKey,piv:window.SequoiaSmartCardPiv,inspectBundle,inspectIdentity,progress});
     guard();
     return identity;
    },
   });
 };
 const promptPin=details=>new Promise((resolve,reject)=>{
  el('pin-details').textContent='Key '+details.serial+' · RP '+details.rpId+' · '+details.retries+' PIN tries remaining';el('pin').value='';el('pin-progress').textContent='';el('pin').hidden=false;el('pin-ok').hidden=false;
  const cancelled=()=>{cleanup();reject(Error('Cancelled; no automatic retry'));};
  const cancel=()=>abort.abort();
  const ok=()=>{const value=el('pin').value,length=new TextEncoder().encode(value).length;
   if(value.length<4||length>63){el('pin-progress').textContent='Enter a FIDO PIN of at least four characters and at most 63 UTF-8 bytes.';return;}
   cleanup();el('pin').hidden=true;el('pin-ok').hidden=true;el('pin-progress').textContent='Touch the key when it flashes. Keep it connected.';resolve(value);};
  const key=e=>{if(e.key==='Enter'&&!e.repeat&&!e.isComposing){e.preventDefault();ok();}};
  const cleanup=()=>{el('pin').value='';el('pin-ok').onclick=null;el('pin').removeEventListener('keydown',key);abort.signal.removeEventListener('abort',cancelled);};
  abort.signal.addEventListener('abort',cancelled,{once:true});
  el('pin-ok').onclick=ok;el('pin').addEventListener('keydown',key);el('pin-cancel').onclick=cancel;dialog.oncancel=e=>{e.preventDefault();cancel();};dialog.showModal();el('pin').focus();
 });
 try{
  const authenticated=await unlockBackup(record,w.id,vault,{
   request,evaluate,promptPin,
   decrypt:options=>decryptWithHardware({...options,signal:abort.signal,
    createWorker:()=>new Worker(workerPolicy?workerPolicy.createScriptURL(workerPath):workerPath,{type:'module'})}),
   mode,legacyRp:'chrome-extension://'+EXTENSION_ID,
   expectedSerial:localStorage.getItem('iwa-fido-expected-serial'),signal:abort.signal,
   progress:m=>el('pin-progress').textContent=m,
  });
  verificationPresence.start(monitoredVaultSerial(authenticated.serial,authenticated.mode));
  tell('Authenticator unlocked the vault. Keep the unlock key connected.');
 }catch(e){
  if(/No PC\/SC smart card readers detected/i.test(e.message)){
   showMissingKey(w);throw Error('Connect the selected key and retry. No reader was detected; no PIN was submitted.');
  }
  throw e;
 }finally{progress?.close();unlockAbort=null;el('pin').value='';if(dialog.open)dialog.close();}
}
el('unlock').onclick=()=>run(async()=>{
 source=await load();methods(source,'source-methods');
 if(!backupVaultSession)throw Error('Finish restoring the backup before unlocking the app.');
 await unlock(source,verificationVault,el('source-methods').value);
 try{await backupVaultSession.adopt(verificationVault,{presence:verificationPresence.snapshot});}
 catch(error){verificationVault.lock();throw error;}
 finally{verificationPresence.stop();}
 verificationVault=new Vault();
 updateSourceActions();
 tell('Authenticator unlocked the vault. Keep the unlock key connected.');
});
el('export').onclick=()=>run(async()=>{
 clear();const snapshot=await capture(storage,location.origin);
 if(!backupVaultSession)throw Error('Unlock the current source vault first.');
 const candidate=await backupVaultSession.create(snapshot);
 if(await digest(snapshot)!==await digest(await capture(storage,location.origin))||!backupVaultSession.unlocked())
  throw Error('App data changed during export. Close other windows and retry.');
 select(candidate);el('upload').disabled=false;tell('Authenticator-protected backup verified against all source records. Save it before migration.');
});
el('save').onclick=()=>{if(box)save();};
el('file').onchange=()=>run(async()=>{clear();const f=el('file').files[0];if(!f||f.size>24*1024*1024)throw Error('Invalid backup file size');select(JSON.parse(await f.text()));tell('File loaded. Use its enrolled authenticator to verify.');});
el('verify').onclick=()=>run(async()=>{
 const selected=box,verified=verificationVault;
 review=null;el('review').textContent='';el('restore-success').hidden=true;el('restore').textContent='Restore into empty instance';
 el('restore').disabled=true;el('approve').checked=false;
 await unlock(recoveryVault(selected,location.origin),verified,el('methods').value);
 let snapshot,hash;
 try{
  snapshot=await unseal(selected,verified,location.origin);
  hash=await digest(snapshot);
  verificationPresence.check();
  if(box!==selected||!verified.unlocked)throw Error('Backup review expired. Verify the file again.');
 }catch(error){verificationPresence.stop();verified.lock();throw error;}
 review=snapshot;
 el('review').textContent=JSON.stringify({origin:review.origin,databases:review.databases.map(r=>({name:r.name,present:r.value!==null})),settings:review.settings.length,preservedLocalSettings:['SCP requirement','beta SD pin selection','hardware transport'],sha256:hash},null,2);
 el('restore').disabled=false;tell('Backup authenticated. This device’s SCP, beta-pin and hardware transport settings will be preserved. Other conflicting data is refused.');
});
el('restore').onclick=()=>run(async()=>{if(!review||!el('approve').checked)throw Error('Review and explicitly approve trust restoration');el('restore').disabled=true;el('restore').textContent='Restoring and verifying…';
 const verified=verificationVault,entry=review;
 try{
  await restore(storage,entry,location.origin,{guard:()=>{
   verificationPresence.check();
   if(review!==entry||!verified.unlocked)throw Error('Backup review expired. Verify the file again.');
  }});
  await window.startIwaApplicationAfterRestore();
  await backupVaultSession.adopt(verified,{restored:true,presence:verificationPresence.snapshot});
  verificationPresence.stop();
  source=verified.record;methods(source,'source-methods');
  verificationVault=new Vault();
 }catch(e){el('restore').disabled=!review;el('restore').textContent='Restore into empty instance';updateSourceActions();throw e;}
 el('restore').textContent='Restore complete';el('restore-success').hidden=false;el('restore-success').focus();
 tell('Restore complete. Keep the unlock key connected to continue using the vault.');review=null;el('restore').disabled=true;updateSourceActions();});
el('connect').onclick=()=>run(async()=>{disconnect();controller=new AbortController();const clientId=getLoopbackClientId();const session=await runLoopbackPkceOAuth({clientId,clientSecret:getLoopbackClientSecret(clientId),scopes:[DRIVE_SCOPE],signal:controller.signal,onAuthUrl:url=>{el('auth').href=url;el('auth').hidden=false;}});drive.connect(session);el('auth').hidden=true;tell('Drive connected for app-created files only. No backup uploaded yet.');});
el('disconnect').onclick=()=>{disconnect();tell('Drive session cleared.');};
el('upload').onclick=()=>run(async()=>{if(!box)throw Error('Create a backup first');const result=await drive.upload(box);tell('Encrypted snapshot uploaded: '+result.name);});
async function list(more=false){const result=await drive.list(more?page:'');if(!more)el('files').replaceChildren();for(const f of result.files||[]){const o=document.createElement('option');o.value=f.id;o.textContent=f.name+' · '+f.modifiedTime;el('files').append(o);}page=result.nextPageToken||'';el('more').hidden=!page;tell('Only backups accessible to this OAuth application are listed.');}
el('list').onclick=()=>run(()=>list());el('more').onclick=()=>run(()=>list(true));
el('download').onclick=()=>run(async()=>{select(await drive.download(el('files').value));save();tell('Encrypted file downloaded. Unlock with its enrolled authenticator and verify before restoring.');});
function clearBackup(){
 unlockAbort?.abort();disconnect();clear();el('file').value='';
}
function returnToApp(){
 if(busy||localStorage.getItem(PENDING))return;
 clearBackup();hide();history.replaceState(null,'','/');
}
el('back').onclick=el('continue').onclick=returnToApp;
window.addEventListener('iwa-vault-locked',()=>{clearBackup();updateSourceActions();});
window.addEventListener('iwa-vault-unlocked',updateSourceActions);
window.addEventListener('pagehide',clearBackup);for(const e of ['pointerdown','keydown'])document.addEventListener(e,touch,{passive:true});
