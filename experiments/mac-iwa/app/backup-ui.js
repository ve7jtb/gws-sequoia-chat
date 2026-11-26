// Load the same required-SCP policy before any backup PRF assertion.
import './secure-channel-ui.js';
import {Vault,load,bytes,b64} from './vault/core.js';
import {evaluate} from './ctap2-smartcard.js';
import {capture,seal,unseal,digest,restore,browserStorage,recoveryVault} from './complete-backup.js';
import {createBackupDrive,DRIVE_SCOPE} from './backup-drive.js';
import {runLoopbackPkceOAuth,getLoopbackClientId,getLoopbackClientSecret} from './google-loopback-oauth.js';
const el=id=>document.getElementById(id),storage=browserStorage(),drive=createBackupDrive();
const vault=new Vault();let source=await load();
let box=null,review=null,busy=false,page='',controller,timer;
const tell=s=>el('status').textContent=s;
function clear(){el('restore-success').hidden=true;el('restore').textContent='Restore into empty instance';box=null;review=null;el('restore').disabled=true;el('save').disabled=true;el('upload').disabled=true;el('review').textContent='';el('approve').checked=false;}
function disconnect(){controller?.abort();drive.disconnect();clearTimeout(timer);el('auth').hidden=true;}
function touch(){clearTimeout(timer);timer=setTimeout(()=>{disconnect();clear();vault.lock();tell('Backup session cleared after inactivity.');},300000);}
async function run(fn){if(busy)return;busy=true;try{await fn();touch();}catch(e){tell(e.message);}finally{busy=false;}}
function select(value){clear();box=value;methods(recoveryVault(box,location.origin));el('save').disabled=false;}
function save(){const url=URL.createObjectURL(new Blob([JSON.stringify(box)],{type:'application/octet-stream'}));const a=document.createElement('a');a.href=url;a.download='sequoia-complete.encrypted.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
// PRF assertions only: never create credentials or change authenticator policy.
function methods(record){el('methods').replaceChildren();for(const w of record?.wrappers||[]){if(w.type!=='prf'||!w.binding.rpId||!w.binding.serial)continue;const o=document.createElement('option');o.value=w.id;o.textContent=w.name;el('methods').append(o);}}
methods(source);
// Only reader-discovery failures show this reminder. Never automatically retry
// an assertion: other failures may occur after a PIN has reached the key.
function showMissingKey(wrapper){
 const dialog=el('insert-dialog');
 el('insert-details').textContent='No key found. Connect '+wrapper.name+' (YubiKey '+wrapper.binding.serial+') to this computer, then select Unlock again. No PIN was submitted.';
 el('insert-close').onclick=()=>dialog.close();
 dialog.showModal();el('insert-close').focus();
}
async function unlock(record){
 vault.lock();if(!record)throw Error('No source vault. Download or choose a backup first');
 const w=record.wrappers.find(w=>w.id===el('methods').value&&w.type==='prf');if(!w)throw Error('This preview requires an enrolled FIDO PRF method with Web Smart Card metadata');
 tell('Checking YubiKey '+w.binding.serial+' — keep it connected.');
 const abort=new AbortController(),dialog=el('pin-dialog');
 const promptPin=details=>new Promise((resolve,reject)=>{
  el('pin-details').textContent='Key '+details.serial+' · RP '+details.rpId+' · '+details.retries+' PIN tries remaining';el('pin').value='';el('pin-progress').textContent='';el('pin').hidden=false;el('pin-ok').hidden=false;
  const cancel=()=>{abort.abort();cleanup();reject(Error('Cancelled; no automatic retry'));};
  const ok=()=>{const value=el('pin').value;cleanup();el('pin').hidden=true;el('pin-ok').hidden=true;el('pin-progress').textContent='Touch the key when it flashes. Keep it connected.';resolve(value);};
  const key=e=>{if(e.key==='Enter'&&!e.repeat&&!e.isComposing){e.preventDefault();ok();}};
  const cleanup=()=>{el('pin').value='';el('pin-ok').onclick=null;el('pin').removeEventListener('keydown',key);};
  el('pin-ok').onclick=ok;el('pin').addEventListener('keydown',key);el('pin-cancel').onclick=cancel;dialog.oncancel=e=>{e.preventDefault();cancel();};dialog.showModal();el('pin').focus();
 });
 let result;try{
  result=await evaluate({serial:w.binding.serial,rpId:w.binding.rpId,credentialId:bytes(w.binding.credentialId),salt:bytes(w.binding.salt)},promptPin,{signal:abort.signal,progress:m=>el('pin-progress').textContent=m});
  if(b64(result.credentialId)!==w.binding.credentialId)throw Error('Unexpected credential');
  await vault.unlock(record,w.id,result.secret);tell('Authenticator unlocked the vault. You may remove the key.');
 }catch(e){
  if(/No PC\/SC smart card readers detected/i.test(e.message)){showMissingKey(w);throw Error('Insert YubiKey '+w.binding.serial+' into this computer, then click Unlock again. No reader was detected; no PIN was submitted.');}
  throw e;
 }finally{result?.secret.fill(0);el('pin').value='';dialog.close();}
}
el('unlock').onclick=()=>run(()=>unlock(source));
el('export').onclick=()=>run(async()=>{
 clear();const snapshot=await capture(storage,location.origin),candidate=await seal(snapshot,vault);
 const checked=await unseal(candidate,vault,location.origin);
 if(await digest(snapshot)!==await digest(checked)||await digest(snapshot)!==await digest(await capture(storage,location.origin)))throw Error('App data changed during export; close other windows and retry');
 select(candidate);el('upload').disabled=false;tell('Authenticator-protected backup verified against all source records. Save it before migration.');
});
el('save').onclick=()=>{if(box)save();};
el('file').onchange=()=>run(async()=>{clear();const f=el('file').files[0];if(!f||f.size>24*1024*1024)throw Error('Invalid backup file size');select(JSON.parse(await f.text()));tell('File loaded. Use its enrolled authenticator to verify.');});
el('verify').onclick=()=>run(async()=>{review=null;el('restore-success').hidden=true;el('restore').textContent='Restore into empty instance';el('restore').disabled=true;el('approve').checked=false;await unlock(recoveryVault(box,location.origin));review=await unseal(box,vault,location.origin);el('review').textContent=JSON.stringify({origin:review.origin,databases:review.databases.map(r=>({name:r.name,present:r.value!==null})),settings:review.settings.length,preservedLocalSettings:['SCP requirement','beta SD pin selection','hardware transport'],sha256:await digest(review)},null,2);el('restore').disabled=false;tell('Backup authenticated. This device’s SCP, beta-pin and hardware transport settings will be preserved. Other conflicting data is refused.');});
el('restore').onclick=()=>run(async()=>{if(!review||!el('approve').checked)throw Error('Review and explicitly approve trust restoration');el('restore').disabled=true;el('restore').textContent='Restoring and verifying…';
 try{await restore(storage,review,location.origin);}catch(e){el('restore').disabled=false;el('restore').textContent='Restore into empty instance';throw e;}
 el('restore').textContent='Restore complete';el('restore-success').hidden=false;el('restore-success').focus();
 tell('Restore complete; records verified and this device’s SCP, beta-pin and hardware transport settings preserved. Return to the app and unlock with your existing authenticator.');review=null;el('restore').disabled=true;});
el('connect').onclick=()=>run(async()=>{disconnect();controller=new AbortController();const clientId=getLoopbackClientId();const session=await runLoopbackPkceOAuth({clientId,clientSecret:getLoopbackClientSecret(clientId),scopes:[DRIVE_SCOPE],signal:controller.signal,onAuthUrl:url=>{el('auth').href=url;el('auth').hidden=false;}});drive.connect(session);el('auth').hidden=true;tell('Drive connected for app-created files only. No backup uploaded yet.');});
el('disconnect').onclick=()=>{disconnect();tell('Drive session cleared.');};
el('upload').onclick=()=>run(async()=>{if(!box)throw Error('Create a backup first');const result=await drive.upload(box);tell('Encrypted snapshot uploaded: '+result.name);});
async function list(more=false){const result=await drive.list(more?page:'');if(!more)el('files').replaceChildren();for(const f of result.files||[]){const o=document.createElement('option');o.value=f.id;o.textContent=f.name+' · '+f.modifiedTime;el('files').append(o);}page=result.nextPageToken||'';el('more').hidden=!page;tell('Only backups accessible to this OAuth application are listed.');}
el('list').onclick=()=>run(()=>list());el('more').onclick=()=>run(()=>list(true));
el('download').onclick=()=>run(async()=>{select(await drive.download(el('files').value));save();tell('Encrypted file downloaded. Unlock with its enrolled authenticator and verify before restoring.');});
window.addEventListener('pagehide',()=>{disconnect();clear();vault.lock();});for(const e of ['pointerdown','keydown'])document.addEventListener(e,touch,{passive:true});
