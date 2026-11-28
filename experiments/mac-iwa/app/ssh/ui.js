import {signCardSsh} from './card-signer.js';
import {connectSsh} from './client.js';
import {probe} from './transport.js';
import {sshHostFingerprint} from './trust.js';
// The module receives no private seeds. Unlock grants access to public identity
// choices only; a future SSH engine must request narrowly scoped signatures.
export function initializeSsh({window,document}){
 const $=id=>document.getElementById(id);let controller=null,epoch=0,trustReview=null,session=null,terminal=null;
 let identities=[];
 const gate=()=>{if(!window.vaultIsUnlocked?.())throw Error('Unlock the credential vault first.');};
 function updateCardPicker(){
  const checkbox=$('ssh-use-card'),picker=$('ssh-card-serial');
  const serials=identities.find(row=>row.id===$('ssh-identities').value)?.sshCardSerials||[];
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
  const started=++epoch,chooser=$('ssh-identities'),previous=chooser.value;
  identities=[];chooser.replaceChildren();
  $('ssh-tab').hidden=!window.vaultIsUnlocked?.();
  if($('ssh-tab').hidden){updateCardPicker();return;}
  const rows=await window.softwareIdentities?.records()||[];
  if(started!==epoch||!window.vaultIsUnlocked?.())return;
  identities=rows.filter(row=>row.hasSshPublic);
  for(const row of identities){
   const option=document.createElement('option');option.value=row.id;option.textContent=row.name+' — ML-DSA-44 + Ed25519';chooser.append(option);
  }
  chooser.value=identities.some(row=>row.id===previous)?previous:identities[0]?.id||'';
  $('ssh-public').disabled=!identities.length;
  updateCardPicker();
 }
 $('ssh-identities').onchange=updateCardPicker;
 $('ssh-use-card').onchange=updateCardPicker;
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
  try{gate();const store=window.softwareIdentities,row=(await store.records()).find(r=>r.hasSshPublic&&r.id===$('ssh-identities').value);if(!row)throw Error('Select an SSH identity.');const selected=await store.get(row.id,row.emails[0]);
   const info=await store.provisioningCertificates(selected);gate();if(started!==epoch)throw Error('SSH context changed.');
   if(!info?.ssh?.publicKey)throw Error('The selected identity has no SSH public key.');
   $('ssh-public-text').textContent=info.ssh.publicKey;
  }catch(e){$('ssh-status').textContent=e.message;}
 };
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
 $('ssh-connect').onclick=async()=>{
  const started=epoch;
  try{
   gate();if(session)throw Error('Disconnect the current SSH session first.');
   const identityId=$('ssh-identities').value,serial=$('ssh-card-serial').value,useCard=$('ssh-use-card').checked;
   const trustFirstUse=$('ssh-trust-first-use').checked;
   const store=window.softwareIdentities,row=(await store.records()).find(r=>r.hasSshPublic&&r.id===identityId);
   if(!row)throw Error('Select an SSH identity.');
   if(!useCard&&!row.hasSsh)throw Error('Select the provisioned YubiKey for this identity.');
   if(useCard&&!serial)throw Error('Choose a YubiKey provisioned for this SSH identity.');
   if(useCard&&window.hardwareTransport?.getMode()!=='smartcard')throw Error('Select Web Smart Card hardware transport first.');
   let selected=await store.get(row.id,row.emails[0]);
   const info=await store.provisioningCertificates(selected),entries=await window.sshTrust.list();
   if(!info?.ssh?.publicKey)throw Error('The selected identity has no SSH public key.');
   const publicKey=Uint8Array.from(atob(info.ssh.publicKey.split(' ')[1]),c=>c.charCodeAt(0));
   const card=useCard?await store.sshHardware(selected,serial):null;
   const guard=()=>{gate();if(started!==epoch)throw Error('SSH context changed.');};guard();
   terminal?.dispose();terminal=new window.Terminal({cols:80,rows:24,scrollback:1000,disableStdin:false,allowProposedApi:false});terminal.open($('ssh-terminal'));
   // xterm renders terminal controls without HTML or link/clipboard addons.
   // Scrollback is memory-only and is disposed when the vault locks.
   session=connectSsh({host:$('ssh-host').value,port:$('ssh-port').value,username:$('ssh-username').value,
    publicKey,entries,getEntries:()=>window.sshTrust.list(),guard,
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
    sign:async data=>{await store.assert(selected);if(card){const signature=await signCardSsh({identity:card,publicKey,message:data,piv:window.SequoiaSmartCardPiv,promptPin:window.hardwareTransport.promptPin,guard,onProgress:text=>{$('ssh-status').textContent=text;}});await store.assert(selected);return signature;}return store.signSsh(selected,data);},onOutput:data=>terminal.write(data),onStatus:text=>{$('ssh-status').textContent=text;if(text!=='SSH authenticated.')session=null;}});
   terminal.onData(text=>{try{session?.input(new TextEncoder().encode(text));}catch(e){$('ssh-status').textContent=e.message;}});terminal.focus();$('ssh-status').textContent='Connecting and verifying SSH host…';
  }catch(e){$('ssh-status').textContent=e.message;session?.close();session=null;}
 };
 $('ssh-disconnect').onclick=()=>{session?.close();session=null;$('ssh-status').textContent='SSH disconnected.';};
 const clear=()=>{session?.close();session=null;terminal?.dispose();terminal=null;trustReview=null;$('ssh-trust-import').disabled=true;$('ssh-trust-summary').textContent='';$('ssh-trust-file').value='';epoch++;controller?.abort();$('ssh').hidden=true;$('ssh-tab').hidden=true;$('ssh-host').value='';$('ssh-username').value='';$('ssh-use-card').checked=false;$('ssh-trust-first-use').checked=false;$('ssh-port').value='22';$('ssh-public-text').textContent='';$('ssh-probe-status').textContent='';$('ssh-status').textContent='';$('ssh-identities').replaceChildren();identities=[];updateCardPicker();};
 window.addEventListener('iwa-vault-locked',clear);window.addEventListener('pagehide',clear);
 for(const event of ['iwa-vault-unlocked','iwa-software-identities-changed'])window.addEventListener(event,change=>{
  // The first-use pin advances the vault revision without editing identities.
  // The waiting handshake revalidates its identity before it can continue.
  if(change.detail!=='ssh-first-use')refresh().catch(()=>{});
 });
 return {refresh};
}
