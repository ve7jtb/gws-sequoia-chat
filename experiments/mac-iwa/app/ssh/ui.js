import {createFileTransfer} from './file-transfer.js';
import {signCardSsh} from './card-signer.js';
import {connectSsh} from './client.js';
import {endpoint,probe,sshUsername} from './transport.js';
import {sshHostFingerprint} from './trust.js';
import {promptSshPassword} from './password-dialog.js';
import {openTerminalWindow} from './terminal-window.js';
// The module receives no private seeds. Unlock grants access to public identity
// choices only; a future SSH engine must request narrowly scoped signatures.
export function initializeSsh({window,document}){
 const $=id=>document.getElementById(id);let controller=null,epoch=0,trustReview=null;
 let identities=[],authorizing=false,pending=null;
 // Each detached window owns a connection. Only the handshake is serialized,
 // since PIN and first-use prompts share the main window.
 const connections=new Set();
 let importing,editingHost=false,savedHosts=[],hostDraft=null;
 const gate=()=>{if(!window.vaultIsUnlocked?.())throw Error('Unlock the credential vault first.');};
 const authorizationStatus=$('ssh-authorize-status'),authorizeButton=$('ssh-authorize');
 function finishAuthorization(message){
  authorizing=false;authorizeButton.disabled=false;authorizationStatus.textContent=message;
 }
 function closeConnection(connection){
  connections.delete(connection);
  if(pending===connection)pending=null;
  connection.files?.cancel();
  connection.cancelCardAttention?.();
  connection.session?.close();
  connection.view?.dispose();
  updateHostButtons();
 }
 function closeConnections(){
  for(const connection of connections)closeConnection(connection);
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
 const hostChooser=$('ssh-saved-hosts'),hostName=$('ssh-host-name'),hostStatus=$('ssh-saved-host-status');
 const saveHost=$('ssh-save-host'),removeHost=$('ssh-remove-host');
 const savedHost=()=>savedHosts.find(row=>row.id===hostChooser.value);
 function updateHostButtons(){
  const draft=hostDraft!==null,selected=!!savedHost();
  $('ssh-host-editor').hidden=!draft;
  $('ssh-connection-actions').hidden=!draft&&!selected;
  $('ssh-add-host').disabled=draft||editingHost;
  $('ssh-edit-host').disabled=draft||editingHost||!selected;
  saveHost.textContent=hostDraft?'Update saved host':'Save host';
  saveHost.disabled=editingHost||!identities.length;
  $('ssh-cancel-host').disabled=editingHost;
  removeHost.disabled=draft||editingHost||!selected;
  hostChooser.disabled=draft||editingHost;
  $('ssh-connect').disabled=editingHost||!!pending||(!draft&&!selected);
  $('ssh-disconnect').disabled=!connections.size;
 }
 function renderSavedHosts(rows,selected=hostChooser.value){
  savedHosts=rows;
  const empty=document.createElement('option');
  empty.value='';empty.textContent=rows.length?'Choose a saved host':'No saved hosts';
  hostChooser.replaceChildren(empty);
  for(const row of rows){
   const option=document.createElement('option');
   const host=row.host.includes(':')?'['+row.host+']':row.host;
   option.value=row.id;option.textContent=row.name+' · '+row.username+' @ '+host+':'+row.port;
   hostChooser.append(option);
  }
  hostChooser.value=rows.some(row=>row.id===selected)?selected:'';
  updateHostButtons();
 }
 function applySavedHost(row){
  $('ssh-host').value=row.host;
  $('ssh-port').value=String(row.port);
  $('ssh-username').value=row.username;
  const identity=identities.find(item=>item.id===row.identityId);
  const serialAvailable=!row.serial||(identity?.algorithm!=='ssh-ed25519'&&identity?.sshCardSerials?.includes(row.serial));
  // A missing identity or card copy requires a new explicit selection.
  // Never silently connect with a different credential.
  $('ssh-identities').value=identity&&serialAvailable?identity.id:'';
  $('ssh-use-card').checked=!!row.serial;
  updateCardPicker();
  $('ssh-card-serial').value=serialAvailable?row.serial:'';
  hostStatus.textContent=!identity?'The saved SSH identity is unavailable. Edit the saved host to choose an identity.':
   !serialAvailable?'The saved YubiKey is unavailable for this identity. Edit the saved host to choose a YubiKey.':'';
 }
 function clearHostFields(){
  hostName.value='';
  $('ssh-host').value='';
  $('ssh-port').value='22';
  $('ssh-username').value='';
  $('ssh-identities').value=identities[0]?.id||'';
  $('ssh-use-card').checked=false;
  $('ssh-card-serial').value='';
  $('ssh-fallback-ed25519').value='';
  $('ssh-public-text').textContent='';
  updateCardPicker();
 }
 function showSelectedHost(){
  hostDraft=null;
  hostStatus.textContent='';
  clearHostFields();
  const row=savedHost();
  if(row){hostName.value=row.name;applySavedHost(row);}
  updateHostButtons();
 }
 hostChooser.onchange=()=>{
  $('ssh-trust-first-use').checked=false;
  showSelectedHost();
 };
 $('ssh-add-host').onclick=()=>{
  hostDraft='';
  clearHostFields();
  $('ssh-trust-first-use').checked=false;
  hostStatus.textContent='';
  updateHostButtons();
  $('ssh-host').focus();
 };
 $('ssh-edit-host').onclick=()=>{
  const row=savedHost();
  if(!row)return;
  hostDraft=row.id;
  updateHostButtons();
  $('ssh-host').focus();
 };
 $('ssh-cancel-host').onclick=()=>{
  $('ssh-trust-first-use').checked=false;
  showSelectedHost();
  (savedHost()?hostChooser:$('ssh-add-host')).focus();
 };
 async function editSavedHost(remove){
  if(editingHost)return;
  if(pending){
   hostStatus.textContent='Wait for SSH authentication to finish before changing saved hosts.';
   return;
  }
  const started=epoch;
  let saved=false;
  editingHost=true;updateHostButtons();
  try{
   gate();
   const book=window.sshAddressBook;
   const id=remove?hostChooser.value:hostDraft;
   if(id===null)return;
   let selected='';
   if(remove)await book.remove(id);
   else{
    const identityId=$('ssh-identities').value;
    const identity=identities.find(row=>row.id===identityId);
    if(!identity)throw Error('Select an SSH identity for this host.');
    const serial=$('ssh-card-serial').value;
    const useCard=$('ssh-use-card').checked;
    if(useCard&&!identity.sshCardSerials?.includes(serial))throw Error('Choose a YubiKey provisioned for this SSH identity.');
    selected=await book.save({
     id,name:hostName.value,host:$('ssh-host').value,port:$('ssh-port').value,
     username:$('ssh-username').value,identityId,serial:useCard?serial:'',
    });
   }
   if(started!==epoch||!window.vaultIsUnlocked?.())return;
   const rows=await book.list();
   if(started!==epoch||!window.vaultIsUnlocked?.())return;
   renderSavedHosts(rows,selected);
   showSelectedHost();
   hostStatus.textContent=remove?'Saved host removed.':'Host saved in the encrypted vault.';
   saved=true;
  }catch(error){if(started===epoch)hostStatus.textContent=error.message;}
  finally{
   editingHost=false;updateHostButtons();
   if(saved)(savedHosts.length?hostChooser:$('ssh-add-host')).focus();
  }
 }
 saveHost.onclick=()=>editSavedHost(false);
 removeHost.onclick=()=>editSavedHost(true);
 async function refresh(){
  controller?.abort();closeConnections();
  if(authorizing)finishAuthorization('SSH key authorization cancelled.');
  const started=++epoch,chooser=$('ssh-identities'),previous=chooser.value;
  const previousSerial=$('ssh-card-serial').value,previousHost=hostChooser.value;
  identities=[];chooser.replaceChildren();
  $('ssh-tab').hidden=!window.vaultIsUnlocked?.();
  if($('ssh-tab').hidden){updateCardPicker();return;}
  const [rows,imported,hosts]=await Promise.all([
   window.softwareIdentities?.records()||[],window.importedSshKeys?.records()||[],window.sshAddressBook?.list()||[],
  ]);
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
  chooser.value=identities.some(row=>row.id===previous)?previous:hostChooser.value?'':identities[0]?.id||'';
  $('ssh-public').disabled=!identities.length;
  updateCardPicker();
  renderSavedHosts(hosts);
  if(hostDraft===null&&previousHost)showSelectedHost();
  if(hostDraft!==null&&!chooser.value)hostStatus.textContent='Choose an available SSH identity to connect.';
  if(hostDraft!==null&&$('ssh-use-card').checked&&$('ssh-card-serial').value!==previousSerial){
   $('ssh-card-serial').value='';
   hostStatus.textContent='Choose an available YubiKey to connect.';
  }
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
 // The detached terminal may be frontmost when SSH asks for a signature.
 // Chromium's reader access belongs to the opener. Require a foreground click
 // in that window before its first live-key read, which still precedes the PIN.
 function requestCardAttention(connection,host,serial){
  const dialog=$('ssh-card-attention'),proceed=$('ssh-card-attention-continue'),cancel=$('ssh-card-attention-cancel');
  return new Promise((resolve,reject)=>{
   const finish=error=>{
    connection.cancelCardAttention=null;
    proceed.onclick=cancel.onclick=dialog.oncancel=null;
    $('ssh-card-attention-detail').textContent='';
    if(dialog.open)dialog.close();
    error?reject(error):resolve();
   };
   connection.cancelCardAttention=()=>finish(Error('YubiKey SSH login cancelled.'));
   proceed.onclick=()=>finish();
   cancel.onclick=connection.cancelCardAttention;
   dialog.oncancel=event=>{event.preventDefault();connection.cancelCardAttention?.();};
   $('ssh-card-attention-detail').textContent='Authorize SSH login to '+host+' with YubiKey SN# '+serial+'. Chromium needs this window in front to access the reader.';
   try{dialog.showModal();window.focus();}
   catch(error){finish(error);}
  });
 }
 async function openSsh(authorizeKey){
  const status=authorizeKey?authorizationStatus:$('ssh-status');
  if(editingHost){status.textContent='Wait for the saved host update to finish.';return;}
  if(pending){if(!authorizing||!authorizeKey)status.textContent='Wait for the current SSH authentication to finish.';return;}
  const connection={view:null,session:null};
  connections.add(connection);
  pending=connection;
  updateHostButtons();
  if(authorizeKey){
   authorizing=true;authorizeButton.disabled=true;status.textContent='Verifying SSH host…';
  }
  const started=epoch;
  let view,dimensions;
  const guard=()=>{
   gate();
   if(started!==epoch||!connections.has(connection))throw Error('SSH context changed.');
  };
  function input(text){
   try{connection.session?.input(new TextEncoder().encode(text));}
   catch(error){status.textContent=error.message;view?.status(error.message,'error');}
  }
  try{
   gate();
   const host=$('ssh-host').value,port=$('ssh-port').value,username=$('ssh-username').value;
   const identityId=$('ssh-identities').value,serial=$('ssh-card-serial').value,useCard=!authorizeKey&&$('ssh-use-card').checked;
   const trustFirstUse=$('ssh-trust-first-use').checked;
   const fallbackId=$('ssh-fallback-ed25519').value;
   const identity=identities.find(row=>row.id===identityId);
   if(!identity)throw Error('Select an SSH identity.');
   if(useCard&&!identity.sshCardSerials?.includes(serial))throw Error('Choose a YubiKey provisioned for this SSH identity.');
   endpoint(host,port);sshUsername(username);
   if(!authorizeKey){
    // Open during the user's click. Waiting for the vault or network first
    // could lose browser activation and leave the popup blocked.
    connection.files=createFileTransfer({
     session:()=>connection.session,store:()=>window.localFiles,guard,
     reply:(id,detail)=>view?.transferResult(id,detail),
    });
    view=openTerminalWindow({window,onInput:input,onTransfer:connection.files.request,onResize:(rows,cols)=>{
     dimensions=[rows,cols];
     if(connections.has(connection)&&window.vaultIsUnlocked?.())connection.session?.resize(rows,cols);
    },onClose:()=>{
     if(!connections.has(connection))return;
     closeConnection(connection);
     status.textContent='SSH terminal window closed.';
    }});
    connection.view=view;
    await view.ready;guard();
    view.status('Verifying SSH host…','progress');
   }
   let {store,selected,publicLine,imported,hasSsh}=await readIdentity(identityId);
   if(!authorizeKey&&!useCard&&!hasSsh)throw Error('Select the provisioned YubiKey for this identity.');
   if(useCard&&imported)throw Error('Imported Ed25519 keys sign in software.');
   const entries=await window.sshTrust.list();
   const keyBlob=line=>Uint8Array.from(atob(line.split(' ')[1]),c=>c.charCodeAt(0));
   const publicKey=keyBlob(publicLine);
   const additionalPublicKey=authorizeKey&&!imported&&fallbackId?keyBlob((await window.importedSshKeys.get(fallbackId)).publicKey):undefined;
   const card=useCard?await store.sshHardware(selected,serial):null;
   guard();
   connection.session=connectSsh({host,port,username,
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
     if(view){view.status('Review the server fingerprint in the main window.','progress');window.focus();}
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
    sign:async data=>{
     await store.assert(selected);
     if(!card)return store.signSsh(selected,data);
     status.textContent='Continue with YubiKey in this window.';
     view?.status('In the main window, choose Continue with YubiKey.','progress');
     await requestCardAttention(connection,host,serial);
     guard();await store.assert(selected);guard();
     const signature=await signCardSsh({
      identity:card,publicKey,message:data,piv:window.SequoiaSmartCardPiv,guard,
      promptPin:details=>{
       if(view){view.status('Enter the YubiKey PIN in the main window.','progress');window.focus();}
       return window.hardwareTransport.promptPin(details);
      },
      onProgress:text=>{status.textContent=text;view?.status(text,'progress');},
     });
     await store.assert(selected);
     return signature;
    },
    onOutput:data=>view?.write(data),
    onStatus:(text,result,negotiated)=>{
     if(!connections.has(connection))return;
     if(pending===connection)pending=null;
     if(result!=='ready'){
      connection.session=null;
      connection.files?.cancel();
      connection.cancelCardAttention?.();
     }
     if(authorizeKey){
      closeConnection(connection);
      finishAuthorization((result==='success'?'Success: ':'Error: ')+text);
     }else{
      status.textContent=text;
      view.status(result==='ready'?'Connected to '+username+' @ '+host+'.':text,result,negotiated);
      if(result==='ready'&&dimensions)connection.session?.resize(...dimensions);
      updateHostButtons();
     }
    }});
   if(!authorizeKey)status.textContent='Connecting and verifying SSH host…';
  }catch(e){
   if(!connections.has(connection))return;
   if(pending===connection)pending=null;
   if(started===epoch){
    if(authorizeKey){if(authorizing)finishAuthorization('Error: '+e.message);}
    else{
     status.textContent=e.message;
     view?.status(e.message,'error');
    }
   }
   // Keep an initialized terminal open to show its error. A failure before
   // opening a window or during authorization has no view to retain.
   if(!view)closeConnection(connection);
   updateHostButtons();
  }
 }
 $('ssh-connect').onclick=()=>openSsh(false);
 authorizeButton.onclick=()=>openSsh(true);
 $('ssh-disconnect').onclick=()=>{
  closeConnections();
  if(authorizing)finishAuthorization('SSH key authorization cancelled.');
  $('ssh-status').textContent='SSH disconnected.';
 };
 const clear=()=>{
  clearImport();closeConnections();finishAuthorization('');trustReview=null;
  $('ssh-trust-import').disabled=true;$('ssh-trust-summary').textContent='';$('ssh-trust-file').value='';
  epoch++;controller?.abort();$('ssh').hidden=true;$('ssh-tab').hidden=true;
  $('ssh-trust-first-use').checked=false;$('ssh-fallback-ed25519').replaceChildren();
  $('ssh-public-text').textContent='';$('ssh-probe-status').textContent='';$('ssh-status').textContent='';
  $('ssh-identities').replaceChildren();identities=[];
  renderSavedHosts([],'');showSelectedHost();
 };
 updateHostButtons();
 window.addEventListener('iwa-vault-locked',clear);window.addEventListener('pagehide',clear);
 for(const event of ['iwa-vault-unlocked','iwa-software-identities-changed'])window.addEventListener(event,change=>{
  // These vault writes leave SSH identities intact. An in-flight signer
  // still validates the vault revision before using any key.
  if(!['ssh-first-use','ssh-address-book','local-file-key'].includes(change.detail))refresh().catch(()=>{});
 });
 return {refresh};
}
