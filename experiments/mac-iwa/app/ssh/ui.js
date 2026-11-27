import {signCardSsh} from './card-signer.js';
import {connectSsh} from './client.js';
import {probe} from './transport.js';
// The module receives no private seeds. Unlock grants access to public identity
// choices only; a future SSH engine must request narrowly scoped signatures.
export function initializeSsh({window,document}){
 const $=id=>document.getElementById(id);let controller=null,epoch=0,trustReview=null,session=null,terminal=null;
 const gate=()=>{if(!window.vaultIsUnlocked?.())throw Error('Unlock the credential vault first.');};
 async function refresh(){
  controller?.abort();session?.close();session=null;const started=++epoch;$('ssh-identities').replaceChildren();
  $('ssh-tab').hidden=!window.vaultIsUnlocked?.();
  if($('ssh-tab').hidden)return;
  const rows=await window.softwareIdentities?.records()||[];
  if(started!==epoch||!window.vaultIsUnlocked?.())return;
  for(const row of rows.filter(r=>r.hasSshPublic||(r.version===4&&r.signingAlgorithm?.includes('Ed25519')&&!r.hardware?.privateRemoved))){
   const option=document.createElement('option');option.value=row.id;option.textContent=row.name+(row.hasSshPublic?' — ML-DSA-44 + Ed25519':' — classical Ed25519 (OpenPGP compatibility)');$('ssh-identities').append(option);
  }
  $('ssh-public').disabled=!$('ssh-identities').children.length;
 }
 $('ssh-probe').onclick=async()=>{
  if(controller)return;const started=epoch;
  try{
   gate();controller=new AbortController();$('ssh-status').textContent='Checking SSH transport…';
   const result=await probe({host:$('ssh-host').value,port:$('ssh-port').value,signal:controller.signal,guard:()=>{gate();if(started!==epoch)throw Error('SSH context changed.');}});
   $('ssh-status').textContent=result.identification+' — TCP/SSH identification received. Server identity is not authenticated; no PIN, signature or login was sent.';
  }catch(e){if(started===epoch)$('ssh-status').textContent=e.message;}
  finally{controller=null;}
 };
 $('ssh-cancel').onclick=()=>controller?.abort();
 $('ssh-public').onclick=async()=>{
  const started=epoch;
  try{gate();const store=window.softwareIdentities,row=(await store.records()).find(r=>r.id===$('ssh-identities').value);if(!row)throw Error('Select an SSH identity.');const selected=await store.get(row.id,row.emails[0]);
   const info=await store.provisioningCertificates(selected);gate();if(started!==epoch)throw Error('SSH context changed.');
   if(info?.ssh?.publicKey)$('ssh-public-text').textContent=info.ssh.publicKey;else{const compatibility=await store.sshCompatibility(selected);gate();if(started!==epoch)throw Error('SSH context changed.');$('ssh-public-text').textContent='ssh-ed25519 '+btoa(String.fromCharCode(...compatibility.publicKey));}
  }catch(e){$('ssh-status').textContent=e.message;}
 };
 $('ssh-trust-review').onclick=async()=>{
  const started=epoch;trustReview=null;$('ssh-trust-import').disabled=true;
  try{gate();const file=$('ssh-trust-file').files[0];if(!file||file.size>1048576)throw Error('Choose a known_hosts file up to 1 MiB.');
   const text=await file.text();gate();if(started!==epoch)throw Error('SSH context changed.');
   const review=await window.sshTrust.review(text);gate();if(started!==epoch)throw Error('SSH context changed.');trustReview=review;
   const summary=await Promise.all(review.entries.map(async e=>{const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',Uint8Array.from(atob(e.key),c=>c.charCodeAt(0))));return (e.marker||'host key')+' '+e.hosts+' '+e.type+' SHA256:'+btoa(String.fromCharCode(...digest)).replace(/=+$/,'');}));
   gate();if(started!==epoch)throw Error('SSH context changed.');$('ssh-trust-summary').textContent=summary.join('\n');$('ssh-trust-import').disabled=false;
  }catch(e){$('ssh-status').textContent=e.message;}
 };
 $('ssh-trust-import').onclick=async()=>{
  try{gate();if(!trustReview)throw Error('Review a trust file first.');const reviewed=trustReview;trustReview=null;$('ssh-trust-import').disabled=true;
   const n=await window.sshTrust.import(reviewed);gate();$('ssh-status').textContent='Imported '+n+' reviewed host trust entries into the encrypted vault.';
  }catch(e){$('ssh-status').textContent=e.message;}
 };
 $('ssh-import-pgp').onclick=()=>{gate();document.querySelector('[data-tab="identities"]').click();$('software-file').focus();};
 $('ssh-connect').onclick=async()=>{
  const started=epoch;
  try{
   gate();if(session)throw Error('Disconnect the current SSH session first.');
   const store=window.softwareIdentities,row=(await store.records()).find(r=>r.id===$('ssh-identities').value);
   if(!row)throw Error('Select an SSH identity.');
   const classical=!row.hasSshPublic,useCard=$('ssh-use-card').checked;
   if(classical&&useCard)throw Error('Imported classical SSH currently uses software custody.');
   if(!classical&&!useCard&&!row.hasSsh)throw Error('Select the provisioned YubiKey for this identity.');
   if(useCard&&window.hardwareTransport?.getMode()!=='smartcard')throw Error('Select Web Smart Card hardware transport first.');
   if(classical&&!window.confirm('Use this standalone OpenPGP Ed25519 key for classical SSH authentication? This is not post-quantum resistant. It does not upgrade or alter the server’s authorized keys.'))return;
   const selected=await store.get(row.id,row.emails[0]),info=await store.provisioningCertificates(selected),entries=await window.sshTrust.list();
   const compatibility=classical?await store.sshCompatibility(selected):null;
   const card=useCard?await store.sshHardware(selected,$('ssh-card-serial').value.trim()):null;
   const guard=()=>{gate();if(started!==epoch)throw Error('SSH context changed.');};guard();
   terminal?.dispose();terminal=new window.Terminal({cols:80,rows:24,scrollback:1000,disableStdin:false,allowProposedApi:false});terminal.open($('ssh-terminal'));
   // xterm renders terminal controls without HTML or link/clipboard addons.
   // Scrollback is memory-only and is disposed when the vault locks.
   session=connectSsh({host:$('ssh-host').value,port:$('ssh-port').value,username:$('ssh-username').value,
    publicKey:compatibility?.publicKey||Uint8Array.from(atob(info.ssh.publicKey.split(' ')[1]),c=>c.charCodeAt(0)),entries,getEntries:()=>window.sshTrust.list(),guard,
    sign:async data=>{await store.assert(selected);if(card){const signature=await signCardSsh({identity:card,publicKey:Uint8Array.from(atob(info.ssh.publicKey.split(' ')[1]),c=>c.charCodeAt(0)),message:data,piv:window.SequoiaSmartCardPiv,promptPin:window.hardwareTransport.promptPin,guard});await store.assert(selected);return signature;}return classical?(await store.sshCompatibility(selected,data)).signature:store.signSsh(selected,data);},onOutput:data=>terminal.write(data),onStatus:text=>{$('ssh-status').textContent=text;if(text!=='SSH authenticated.')session=null;}});
   terminal.onData(text=>{try{session?.input(new TextEncoder().encode(text));}catch(e){$('ssh-status').textContent=e.message;}});terminal.focus();$('ssh-status').textContent='Connecting and verifying SSH host…';
  }catch(e){$('ssh-status').textContent=e.message;session?.close();session=null;}
 };
 $('ssh-disconnect').onclick=()=>{session?.close();session=null;$('ssh-status').textContent='SSH disconnected.';};
 const clear=()=>{session?.close();session=null;terminal?.dispose();terminal=null;trustReview=null;$('ssh-trust-import').disabled=true;$('ssh-trust-summary').textContent='';$('ssh-trust-file').value='';epoch++;controller?.abort();$('ssh').hidden=true;$('ssh-tab').hidden=true;$('ssh-host').value='';$('ssh-username').value='';$('ssh-card-serial').value='';$('ssh-use-card').checked=false;$('ssh-port').value='22';$('ssh-public-text').textContent='';$('ssh-status').textContent='';$('ssh-identities').replaceChildren();};
 window.addEventListener('iwa-vault-locked',clear);window.addEventListener('pagehide',clear);
 for(const event of ['iwa-vault-unlocked','iwa-software-identities-changed'])window.addEventListener(event,()=>refresh().catch(()=>{}));
 return {refresh};
}
