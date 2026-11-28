import {signCardSsh} from './card-signer.js';
import {connectSsh} from './client.js';
import {probe} from './transport.js';
import {sshHostFingerprint} from './trust.js';
import {promptSshPassword} from './password-dialog.js';
// The module receives no private seeds. Unlock grants access to public identity
// choices only; a future SSH engine must request narrowly scoped signatures.
export function initializeSsh({window,document}){
 const $=id=>document.getElementById(id);let controller=null,epoch=0,trustReview=null,session=null,terminal=null;
 let identities=[],connecting=false,authorizing=false;
 let importing;
 const gate=()=>{if(!window.vaultIsUnlocked?.())throw Error('Unlock the credential vault first.');};
 const authorizationStatus=$('ssh-authorize-status'),authorizeButton=$('ssh-authorize');
 function finishAuthorization(message){
  authorizing=false;authorizeButton.disabled=false;authorizationStatus.textContent=message;
 }
 function updateCardPicker(){
  const checkbox=$('ssh-use-card'),picker=$('ssh-card-serial');
  const identity=identities.find(row=>row.id===$('ssh-identities').value);
  const serials=identity?.sshCardSerials||[];
  checkbox.disabled=identity?.algorithm==='ssh-ed25519';
  if(checkbox.disabled)checkbox.checked=false;
  $('ssh-fallback-picker').hidden=!identity||checkbox.disabled||!identities.some(row=>row.algorithm==='ssh-ed25519');
  const previous=picker.value;
  $('ssh-card-picker').hidden=!checkbox.checked;
  picker.replaceChildren();
  if(serials.length!==1){
   const placeholder=document.createElement('option');
   placeholder.value='';placeholder.disabled=true;
   placeholder.textContent=serials.length?'Choose a YubiKey':'No YubiKey provisioned for this SSH identity';
   picker.append(placeholder);
  }
  for(const serial of serials){
   const option=document.createElement('option');
   option.value=serial;option.textContent='YubiKey · SN# '+serial;
   picker.append(option);
  }
  picker.value=serials.includes(previous)?previous:serials.length===1?serials[0]:'';
  picker.disabled=!checkbox.checked||!serials.length;
 }
 async function refresh(){
  controller?.abort();session?.close();session=null;
  if(authorizing)finishAuthorization('SSH key authorization cancelled.');
  const started=++epoch,chooser=$('ssh-identities'),previous=chooser.value;
  identities=[];chooser.replaceChildren();
  $('ssh-tab').hidden=!window.vaultIsUnlocked?.();
  if($('ssh-tab').hidden){updateCardPicker();return;}
  const [rows,imported]=await Promise.all([window.softwareIdentities?.records()||[],window.importedSshKeys?.records()||[]]);
  if(started!==epoch||!window.vaultIsUnlocked?.())return;
  identities=[...rows.filter(row=>row.hasSshPublic),...imported];
  for(const row of identities){
   const option=document.createElement('option');option.value=row.id;option.textContent=row.name+(row.algorithm==='ssh-ed25519'?' — Ed25519 (software)':' — ML-DSA-44 + Ed25519');chooser.append(option);
  }
  const fallback=$('ssh-fallback-ed25519'),previousFallback=fallback.value;
  const none=document.createElement('option');none.value='';none.textContent='None';
  fallback.replaceChildren(none);
  for(const row of imported){
   const option=document.createElement('option');option.value=row.id;option.textContent=row.name;fallback.append(option);
  }
  fallback.value=imported.some(row=>row.id===previousFallback)?previousFallback:'';
  chooser.value=identities.some(row=>row.id===previous)?previous:identities[0]?.id||'';
  $('ssh-public').disabled=!identities.length;
  updateCardPicker();
 }
 $('ssh-identities').onchange=updateCardPicker;
 $('ssh-use-card').onchange=updateCardPicker;
 const importDialog=$('ssh-import-dialog'),importPassphrase=$('ssh-import-passphrase');
 function clearImport(){
  importing?.abort();importPassphrase.value='';$('ssh-import-file').value='';
  if(importDialog.open)importDialog.close();
 }
 $('ssh-import').onclick=()=>{
  try{gate();if(importing||importDialog.open)return;importPassphrase.value='';$('ssh-import-status').textContent='';importDialog.showModal();}
  catch(error){$('ssh-status').textContent=error.message;}
 };
 $('ssh-import-cancel').onclick=clearImport;
 importDialog.oncancel=event=>{event.preventDefault();clearImport();};
 $('ssh-import-form').onsubmit=async event=>{
  event.preventDefault();if(importing)return;
  importing=new AbortController();
  const signal=importing.signal,status=$('ssh-import-status'),button=$('ssh-import-save');
  const password=new TextEncoder().encode(importPassphrase.value);
  importPassphrase.value='';let file;
  try{
   gate();
   const source=$('ssh-import-file').files[0];
   if(!source||source.size<1||source.size>32768)throw Error('Choose an OpenSSH private-key file up to 32 KiB.');
   button.disabled=true;status.textContent='Opening the Ed25519 key…';
   file=new Uint8Array(await source.arrayBuffer());
   const selected=await window.importedSshKeys.importKey($('ssh-import-name').value,file,password,signal);
   if(signal.aborted)return;
   clearImport();await refresh();gate();
   $('ssh-identities').value=selected.id;updateCardPicker();
   $('ssh-status').textContent='OpenSSH Ed25519 key saved in the encrypted vault.';
  }catch(error){if(!signal.aborted)status.textContent=error.message;}
  finally{file?.fill(0);password.fill(0);button.disabled=false;importing=null;}
 };
 $('ssh-probe').onclick=async()=>{
  if(controller)return;
  const started=epoch,button=$('ssh-probe'),cancel=$('ssh-cancel'),status=$('ssh-probe-status');
  const label=button.textContent;
  try{
   gate();controller=new AbortController();
   button.disabled=true;button.textContent='Checking…';cancel.disabled=false;
   status.textContent='Checking SSH transport…';
   const result=await probe({host:$('ssh-host').value,port:$('ssh-port').value,signal:controller.signal,guard:()=>{gate();if(started!==epoch)throw Error('SSH context changed.');}});
   if(started!==epoch)return;
   const cipher=result.clientToServer===result.serverToClient?result.clientToServer:
    result.clientToServer+' (to server), '+result.serverToClient+' (from server)';
   const security=result.postQuantum?'Hybrid post-quantum key exchange available.':
    'Warning: this connection would use classical key exchange. No compatible post-quantum key exchange was advertised.';
   status.textContent='Expected encryption: '+cipher+'. Key exchange: '+result.keyExchange+'. '+security+
    ' The server advertised these settings. Its identity is verified when you connect.';
  }catch(e){if(started===epoch)status.textContent=e.message;}
  finally{controller=null;button.disabled=false;button.textContent=label;cancel.disabled=true;}
 };
 $('ssh-cancel').onclick=()=>controller?.abort();
 $('ssh-public').onclick=async()=>{
  const started=epoch;
  try{gate();const {publicLine}=await readIdentity($('ssh-identities').value);
   gate();if(started!==epoch)throw Error('SSH context changed.');
   $('ssh-public-text').textContent=publicLine;
  }catch(e){$('ssh-status').textContent=e.message;}
 };
 async function readIdentity(id){
  if(id.startsWith('ssh-ed25519:')){
   const store=window.importedSshKeys,selected=await store.get(id);
   return {store,selected,publicLine:selected.publicKey,imported:true,hasSsh:true};
  }
  const store=window.softwareIdentities,row=(await store.records()).find(r=>r.hasSshPublic&&r.id===id);
  if(!row)throw Error('Select an SSH identity.');
  const selected=await store.get(row.id,row.emails[0]);
  const info=await store.provisioningCertificates(selected);
  if(!info?.ssh?.publicKey)throw Error('The selected identity has no SSH public key.');
  return {store,selected,publicLine:info.ssh.publicKey,imported:false,hasSsh:row.hasSsh};
 }
 $('ssh-trust-review').onclick=async()=>{
  const started=epoch;trustReview=null;$('ssh-trust-import').disabled=true;
  try{gate();const file=$('ssh-trust-file').files[0];if(!file||file.size>1048576)throw Error('Choose a known_hosts file up to 1 MiB.');
   const text=await file.text();gate();if(started!==epoch)throw Error('SSH context changed.');
   const review=await window.sshTrust.review(text);gate();if(started!==epoch)throw Error('SSH context changed.');trustReview=review;
   const summary=await Promise.all(review.entries.map(async e=>(e.marker||'host key')+' '+e.hosts+' '+e.type+' '+await sshHostFingerprint(e.key)));
   gate();if(started!==epoch)throw Error('SSH context changed.');$('ssh-trust-summary').textContent=summary.join('\n');$('ssh-trust-import').disabled=false;
  }catch(e){$('ssh-status').textContent=e.message;}
 };
 $('ssh-trust-import').onclick=async()=>{
  try{gate();if(!trustReview)throw Error('Review a trust file first.');const reviewed=trustReview;trustReview=null;$('ssh-trust-import').disabled=true;
   const n=await window.sshTrust.import(reviewed);gate();$('ssh-status').textContent='Imported '+n+' reviewed host trust entries into the encrypted vault.';
  }catch(e){$('ssh-status').textContent=e.message;}
 };
 async function openSsh(authorizeKey){
  const status=authorizeKey?authorizationStatus:$('ssh-status');
  if(connecting||session){if(!authorizing||!authorizeKey)status.textContent='Disconnect the current SSH connection first.';return;}
  connecting=true;
  if(authorizeKey){
   authorizing=true;authorizeButton.disabled=true;status.textContent='Verifying SSH host…';
  }
  const started=epoch;
  try{
   gate();
   const identityId=$('ssh-identities').value,serial=$('ssh-card-serial').value,useCard=!authorizeKey&&$('ssh-use-card').checked;
   const trustFirstUse=$('ssh-trust-first-use').checked;
   const fallbackId=$('ssh-fallback-ed25519').value;
   if(useCard&&!serial)throw Error('Choose a YubiKey provisioned for this SSH identity.');
   if(useCard&&window.hardwareTransport?.getMode()!=='smartcard')throw Error('Select Web Smart Card hardware transport first.');
   let {store,selected,publicLine,imported,hasSsh}=await readIdentity(identityId);
   if(!authorizeKey&&!useCard&&!hasSsh)throw Error('Select the provisioned YubiKey for this identity.');
   if(useCard&&imported)throw Error('Imported Ed25519 keys sign in software.');
   const entries=await window.sshTrust.list();
   const keyBlob=line=>Uint8Array.from(atob(line.split(' ')[1]),c=>c.charCodeAt(0));
   const publicKey=keyBlob(publicLine);
   const additionalPublicKey=authorizeKey&&!imported&&fallbackId?keyBlob((await window.importedSshKeys.get(fallbackId)).publicKey):undefined;
   const card=useCard?await store.sshHardware(selected,serial):null;
   const guard=()=>{gate();if(started!==epoch||(authorizeKey&&!authorizing))throw Error('SSH context changed.');};guard();
   if(!authorizeKey){terminal?.dispose();terminal=new window.Terminal({cols:80,rows:24,scrollback:1000,disableStdin:false,allowProposedApi:false});terminal.open($('ssh-terminal'));}
   // xterm renders terminal controls without HTML or link/clipboard addons.
   // Scrollback is memory-only and is disposed when the vault locks.
   session=connectSsh({host:$('ssh-host').value,port:$('ssh-port').value,username:$('ssh-username').value,
    publicKey,additionalPublicKey,entries,getEntries:()=>window.sshTrust.list(),guard,authorizeKey,
    requestPassword:authorizeKey?async(target,signal)=>{
     status.textContent='Waiting for the SSH account password…';
     const password=await promptSshPassword({document,...target,compositeSelected:!imported,signal});
     if(authorizing)status.textContent='Authorizing the SSH public key…';
     return password;
    }:undefined,
    acceptUnknownHost:trustFirstUse?async(candidate,check,signal)=>{
     const fingerprint=await sshHostFingerprint(candidate.key);check();
     const endpoint=(candidate.host.includes(':')?'['+candidate.host+']':candidate.host)+':'+candidate.port;
     if(!window.confirm('Trust this SSH host and connect?\n\n'+endpoint+'\n'+candidate.type+'  '+fingerprint+'\n\nCompare this fingerprint with a trusted source. If you continue, the key will be saved in your encrypted vault and required on future connections.'))throw Error('SSH host trust declined.');
     await store.assert(selected);check();
     await window.sshTrust.pinFirstUse({...candidate,guard:check,signal});check();
     // Pinning rewrites the vault. Refresh only the revision on the exact
     // same identity before permitting any software signature or card PIN.
     const refreshed=await store.get(selected.id,selected.email);check();
     const {revision:oldRevision,...previousIdentity}=selected;
     const {revision:newRevision,...currentIdentity}=refreshed;
     if(JSON.stringify(previousIdentity)!==JSON.stringify(currentIdentity))throw Error('SSH identity changed while saving host trust. Connect again.');
     selected=refreshed;
    }:undefined,
    sign:async data=>{await store.assert(selected);if(card){const signature=await signCardSsh({identity:card,publicKey,message:data,piv:window.SequoiaSmartCardPiv,promptPin:window.hardwareTransport.promptPin,guard,onProgress:text=>{status.textContent=text;}});await store.assert(selected);return signature;}return store.signSsh(selected,data);},
    onOutput:data=>{if(!authorizeKey)terminal.write(data);},
    onStatus:(text,result)=>{
     if(result!=='ready')session=null;
     if(authorizeKey)finishAuthorization((result==='success'?'Success: ':'Error: ')+text);
     else status.textContent=text;
    }});
   if(!authorizeKey){terminal.onData(text=>{try{session?.input(new TextEncoder().encode(text));}catch(e){status.textContent=e.message;}});terminal.focus();status.textContent='Connecting and verifying SSH host…';}
  }catch(e){
   if(started===epoch){
    if(authorizeKey){if(authorizing)finishAuthorization('Error: '+e.message);}
    else status.textContent=e.message;
   }
   session?.close();session=null;
  }
  finally{connecting=false;}
 }
 $('ssh-connect').onclick=()=>openSsh(false);
 authorizeButton.onclick=()=>openSsh(true);
 $('ssh-disconnect').onclick=()=>{
  session?.close();session=null;
  if(authorizing)finishAuthorization('SSH key authorization cancelled.');
  else $('ssh-status').textContent='SSH disconnected.';
 };
 const clear=()=>{clearImport();session?.close();session=null;finishAuthorization('');terminal?.dispose();terminal=null;trustReview=null;$('ssh-trust-import').disabled=true;$('ssh-trust-summary').textContent='';$('ssh-trust-file').value='';epoch++;controller?.abort();$('ssh').hidden=true;$('ssh-tab').hidden=true;$('ssh-host').value='';$('ssh-username').value='';$('ssh-use-card').checked=false;$('ssh-trust-first-use').checked=false;$('ssh-fallback-ed25519').replaceChildren();$('ssh-port').value='22';$('ssh-public-text').textContent='';$('ssh-probe-status').textContent='';$('ssh-status').textContent='';$('ssh-identities').replaceChildren();identities=[];updateCardPicker();};
 window.addEventListener('iwa-vault-locked',clear);window.addEventListener('pagehide',clear);
 for(const event of ['iwa-vault-unlocked','iwa-software-identities-changed'])window.addEventListener(event,change=>{
  // The first-use pin advances the vault revision without editing identities.
  // The waiting handshake revalidates its identity before it can continue.
  if(change.detail!=='ssh-first-use')refresh().catch(()=>{});
 });
 return {refresh};
}
