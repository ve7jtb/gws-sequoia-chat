import {createBackupUi} from './piv-backup-ui.js';
// Creation/import/export are explicit local actions. The form's password is passed only to the
// vault software provider, cleared on every completion, and never logged. Own
// certificate import does not grant trust to a recipient or change a card.
export function initializeSoftwareUi({isBusy,setBusy,say,account,changed,test}){
 const $=id=>document.getElementById(id),provider=()=>window.softwareIdentities;
 const backup=createBackupUi({provider,account,test,say,changed});
 const bytes64=bytes=>{let s='';for(const byte of bytes)s+=String.fromCharCode(byte);return btoa(s);};
 const download=(data,name,type)=>{const url=URL.createObjectURL(new Blob([data],{type})),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
 let reviewReport=null,generation=0,renderTicket=0,importController=null,exportSelection=null;
 const clearExport=()=>{exportSelection=null;$('software-export-password').value='';$('software-export-repeat').value='';$('software-export-dialog').close?.();};
 const invalidate=()=>{generation++;importController?.abort();$('software-password').value='';$('software-file').value='';clearExport();};
 const warning=row=>row.pqSigning===false?'Classical signing — not post-quantum resistant.'+(row.pqEncryption===false?' Classical encryption — not post-quantum resistant.':' Hybrid encryption remains post-quantum resistant.'):'';
 async function refresh(){
  // Vault commits and store events can request overlapping inventories. Only
  // the newest request may paint; an older promise must not append duplicates
  // or replace rows after a later remove/import has already been rendered.
  const started=generation,ticket=++renderTicket;
  const target=$('software-identities');target.replaceChildren();
  if(!window.vaultIsUnlocked?.()){$('software-status').textContent='Unlock the vault to create, restore or use software identities.';return;}
  if(!provider()){$('software-status').textContent='Software identity service is starting.';return;}
  const rows=await provider().records();
  // A lock can occur while reading encrypted storage or validating policy.
  if(started!==generation||ticket!==renderTicket||!window.vaultIsUnlocked?.())return;
  $('software-status').textContent=rows.length?'Software keys are encrypted in the vault; hardware-only entries retain public bindings.':'No software OpenPGP identities in this vault.';
  for(const row of rows){
   const box=document.createElement('div');box.className='contact';const text=document.createElement('p');
   text.textContent=row.name+(row.hardware?.privateRemoved?' · YubiKey '+row.hardware.serial+' (vault public binding) · OpenPGP v':' · Software (experimental) · OpenPGP v')+(row.version||6)+'\n'+(row.signingAlgorithm||'ML-DSA-65 + Ed25519')+' signing · '+(row.encryptionAlgorithm||'ML-KEM-768 + X25519')+' encryption\n'+row.fingerprint+'\n'+(row.emails||[]).join(', ')+'\n'+warning(row);box.append(text);
   const button=(label,fn)=>{const b=document.createElement('button');b.textContent=label;b.onclick=()=>run(fn);box.append(b);};
   if(row.profile==='level3'&&!row.hardware?.privateRemoved)button(row.hardware?'Verify hardware backup / remove software keys…':'Back up existing keys to empty YubiKey…',async()=>{await backup(row);await refresh();});
   button('Export public certificate…',async()=>{const current=(await provider().records()).find(x=>x.id===row.id);if(!current)throw Error('Identity removed or vault locked.');download(Uint8Array.from(atob(current.certificate),c=>c.charCodeAt(0)),'software-openpgp-'+current.fingerprint.slice(-16)+'.pgp','application/pgp-keys');});
   if(!row.hardware?.privateRemoved)button('Export encrypted identity…',async()=>{
    const current=await provider().get(row.id,account());clearExport();exportSelection={identity:current,generation,account:account()};
    $('software-export-details').textContent=current.name+' · OpenPGP v'+current.version+'\n'+current.fingerprint+'\n'+warning(current);
    $('software-export-save').textContent=current.version===5?'Export encrypted .pqidentity file':'Export encrypted .pgp file';
    $('software-export-help').textContent=current.version===5?'This encrypted v5 identity backup restores in the IWA. Your existing certificate fingerprint stays unchanged.':'This portable OpenPGP secret-key file is encrypted with the new export password. Your certificate fingerprint stays unchanged.';
    $('software-export-dialog').showModal();$('software-export-password').focus?.();
   });
   button('Test signing and decryption — no email',async()=>{
    reviewReport=null;$('software-test-export').disabled=true;const started=generation,email=account();
    const current=await provider().get(row.id,email);
    const report=await test(current,message=>{if(started===generation)$('software-test-result').textContent=message;});
    if(started!==generation||email!==account()||!window.vaultIsUnlocked?.())throw Error('Software test context changed; result discarded.');
    reviewReport=report;$('software-test-result').textContent='PASS — signing, decryption and exact text/HTML/attachment verified. No email sent. '+warning(current);$('software-test-export').disabled=false;
   });
   button(row.hardware?.privateRemoved?'Forget hardware identity…':'Remove software identity…',async()=>{if(!confirm('Remove '+row.name+' from this encrypted vault? Keep your original encrypted OpenPGP backup. No YubiKey or recipient trust is changed.'))return;await provider().remove(row);await changed();await refresh();});
   target.append(box);
  }
 }
 async function run(fn){
  if(isBusy())return say('Finish the current operation first.',true);
  setBusy(true);try{window.vaultGate?.();if(!window.vaultIsUnlocked?.())throw Error('Unlock or create the encrypted vault first.');await fn();}
  catch(error){say(error.message,true);$('software-test-result').textContent='Operation stopped. No automatic retry.';}
  finally{setBusy(false);$('software-test-export').disabled=!reviewReport;}
 }
 $('software-import').onclick=()=>run(async()=>{
  const started=generation;let password='';importController=new AbortController();
  try{
   const file=$('software-file').files[0],name=$('software-name').value.trim(),email=account();
   if(!email)throw Error('Configure your account first.');
   if(!$('software-custody-confirm').checked)throw Error('Review and acknowledge software key custody first.');
   const p12=/\.(p12|pfx)$/i.test(file?.name||'');
   if(!file||!file.size||file.size>(p12?1048576:262144)||!(/\.(pgp|gpg|asc|pqidentity)$/i.test(file.name)||p12))throw Error('Select an encrypted OpenPGP secret-key file up to 256 KiB or a PQ Mail OpenPGP .p12 up to 1 MiB.');
   if(!name||name.length>80)throw Error('Enter an identity name of 1–80 characters.');
   password=$('software-password').value;$('software-password').value='';
   const encryptedSecret=bytes64(new Uint8Array(await file.arrayBuffer()));
   // A delayed file read cannot start an import in a new account or a later
   // unlock session. Do not leave the password in a hidden DOM form during KDF.
   if(started!==generation||email!==account()||!window.vaultIsUnlocked?.())throw Error('Software import context changed; select the file again.');
   if(p12)await provider().importP12({name,p12:encryptedSecret,password},email,{signal:importController.signal});
   else await provider().import({name,encryptedSecret,password},email,{signal:importController.signal});
   if(started!==generation||email!==account()||!window.vaultIsUnlocked?.())throw Error('Software import context changed; review the vault before continuing.');
   await changed();await refresh();say('Software OpenPGP identity saved in the encrypted vault. Select it in Compose. Recipient trust is unchanged.');
  }finally{password='';importController=null;$('software-password').value='';$('software-file').value='';}
 });
 $('software-create').onclick=()=>run(async()=>{
  const started=generation,email=account(),name=$('software-name').value.trim(),profile=$('software-create-profile').value;importController=new AbortController();
  try{
   if(!email)throw Error('Configure your account first.');if(!$('software-custody-confirm').checked)throw Error('Review and acknowledge software key custody first.');
   if(!name||name.length>80)throw Error('Enter an identity name of 1–80 characters.');
   if(profile.includes('-v4-')||profile.includes('-v5-')){
    const message='This optional compatibility identity has classical signing, which is not post-quantum resistant.'+(profile.endsWith('-classical')?' Its encryption is also classical.':' Its encryption is hybrid and remains post-quantum resistant.')+' Create it for older recipients? V6 remains the default.';
    if(!confirm(message))return;
   }
   await provider().create({name,profile,entropy:$('software-hardware-entropy')?.checked===true},email,{signal:importController.signal});
   if(started!==generation||email!==account()||!window.vaultIsUnlocked?.())throw Error('Software creation context changed; review the vault before continuing.');
   await changed();await refresh();say('Software identity created in the encrypted vault. Use Export encrypted identity to make a portable backup. No hardware keys or recipient trust changed.');
  }finally{importController=null;}
 });
 // Per-identity export uses a new password only for the portable file. It does
 // not reveal the random password stored by the vault or overwrite that source.
 // The dialog and every late result are tied to the same account/vault epoch.
 $('software-export-cancel').onclick=clearExport;
 $('software-export-dialog').addEventListener?.('cancel',clearExport);
 $('software-export-save').onclick=()=>run(async()=>{
  const selected=exportSelection;let password=$('software-export-password').value,repeat=$('software-export-repeat').value;
  $('software-export-password').value='';$('software-export-repeat').value='';importController=new AbortController();
  try{
   if(!selected||selected.generation!==generation||selected.account!==account())throw Error('Encrypted export context changed; select the identity again.');
   if(password!==repeat)throw Error('Export passwords do not match.');
   const result=await provider().export(selected.identity,password,{signal:importController.signal});
   if(selected!==exportSelection||selected.generation!==generation||selected.account!==account()||!window.vaultIsUnlocked?.())throw Error('Encrypted export context changed; result discarded.');
   download(Uint8Array.from(atob(result.encryptedSecret),c=>c.charCodeAt(0)),'software-openpgp-v'+result.version+'-'+result.fingerprint.slice(-16)+'-encrypted.'+(result.version===5?'pqidentity':'pgp'),result.version===5?'application/octet-stream':'application/pgp-keys');
   clearExport();say('Password-encrypted identity exported. Restore it with Import / restore software identity; its certificate fingerprint is unchanged.');
  }finally{password='';repeat='';importController=null;}
 });
 $('software-test-export').onclick=()=>{if(reviewReport&&!isBusy())download(JSON.stringify(reviewReport,null,2)+'\n','sequoia-iwa-software-test-'+reviewReport.id+'.json','application/json');};
 for(const name of ['iwa-software-identities-changed','iwa-vault-unlocked'])window.addEventListener(name,()=>refresh().catch(error=>say(error.message,true)));
 window.addEventListener('iwa-vault-locked',()=>{invalidate();$('software-identities').replaceChildren();reviewReport=null;$('software-test-export').disabled=true;$('software-test-result').textContent='';$('software-status').textContent='Unlock the vault to create, restore or use software identities.';});
 window.addEventListener('iwa-account-changed',invalidate);
 window.addEventListener('pagehide',()=>{invalidate();reviewReport=null;});
 return {refresh,hasReport:()=>!!reviewReport};
}
