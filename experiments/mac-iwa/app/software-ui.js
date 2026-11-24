// Import is an explicit local action. The form's password is passed only to the
// vault software provider, cleared on every completion, and never logged. Own
// certificate import does not grant trust to a recipient or change a card.
export function initializeSoftwareUi({isBusy,setBusy,say,account,changed,test}){
 const $=id=>document.getElementById(id),provider=()=>window.softwareIdentities;
 const bytes64=bytes=>{let s='';for(const byte of bytes)s+=String.fromCharCode(byte);return btoa(s);};
 const download=(data,name,type)=>{const url=URL.createObjectURL(new Blob([data],{type})),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
 let reviewReport=null,generation=0,importController=null;
 const invalidate=()=>{generation++;importController?.abort();$('software-password').value='';$('software-file').value='';};
 async function refresh(){
  const started=generation;
  const target=$('software-identities');target.replaceChildren();
  if(!window.vaultIsUnlocked?.()){$('software-status').textContent='Unlock the vault to view or import software identities.';return;}
  if(!provider()){$('software-status').textContent='Software identity service is starting.';return;}
  const rows=await provider().records();
  // A lock can occur while reading encrypted storage or validating policy.
  if(started!==generation||!window.vaultIsUnlocked?.())return;
  $('software-status').textContent=rows.length?'Software private keys are encrypted in the vault.':'No software OpenPGP identities in this vault.';
  for(const row of rows){
   const box=document.createElement('div');box.className='contact';const text=document.createElement('p');
   text.textContent=row.name+' · Software (experimental)\n'+row.fingerprint+'\n'+(row.emails||[]).join(', ');box.append(text);
   const button=(label,fn)=>{const b=document.createElement('button');b.textContent=label;b.onclick=()=>run(fn);box.append(b);};
   button('Export public certificate…',async()=>{const current=(await provider().records()).find(x=>x.id===row.id);if(!current)throw Error('Identity removed or vault locked.');download(Uint8Array.from(atob(current.certificate),c=>c.charCodeAt(0)),'software-openpgp-'+current.fingerprint.slice(-16)+'.pgp','application/pgp-keys');});
   button('Test signing and decryption — no email',async()=>{
    reviewReport=null;$('software-test-export').disabled=true;const started=generation,email=account();
    const current=await provider().get(row.id,email);
    const report=await test(current,message=>{if(started===generation)$('software-test-result').textContent=message;});
    if(started!==generation||email!==account()||!window.vaultIsUnlocked?.())throw Error('Software test context changed; result discarded.');
    reviewReport=report;$('software-test-result').textContent='PASS — software hybrid signing, decryption and exact text/HTML/attachment verified. No native calls or email.';$('software-test-export').disabled=false;
   });
   button('Remove software identity…',async()=>{if(!confirm('Remove '+row.name+' from this encrypted vault? Keep your original encrypted OpenPGP backup. No YubiKey or recipient trust is changed.'))return;await provider().remove(row);await changed();await refresh();});
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
   if(!file||!file.size||file.size>262144||!/\.(pgp|gpg|asc)$/i.test(file.name))throw Error('Select an encrypted OpenPGP secret-key file up to 256 KiB.');
   if(!name||name.length>80)throw Error('Enter an identity name of 1–80 characters.');
   password=$('software-password').value;$('software-password').value='';
   const encryptedSecret=bytes64(new Uint8Array(await file.arrayBuffer()));
   // A delayed file read cannot start an import in a new account or a later
   // unlock session. Do not leave the password in a hidden DOM form during KDF.
   if(started!==generation||email!==account()||!window.vaultIsUnlocked?.())throw Error('Software import context changed; select the file again.');
   await provider().import({name,encryptedSecret,password},email,{signal:importController.signal});
   if(started!==generation||email!==account()||!window.vaultIsUnlocked?.())throw Error('Software import context changed; review the vault before continuing.');
   await changed();await refresh();say('Software OpenPGP identity saved in the encrypted vault. Select it in Compose. Recipient trust is unchanged.');
  }finally{password='';importController=null;$('software-password').value='';$('software-file').value='';}
 });
 $('software-test-export').onclick=()=>{if(reviewReport&&!isBusy())download(JSON.stringify(reviewReport,null,2)+'\n','sequoia-iwa-software-test-'+reviewReport.id+'.json','application/json');};
 for(const name of ['iwa-software-identities-changed','iwa-vault-unlocked'])window.addEventListener(name,()=>refresh().catch(error=>say(error.message,true)));
 window.addEventListener('iwa-vault-locked',()=>{invalidate();$('software-identities').replaceChildren();reviewReport=null;$('software-test-export').disabled=true;$('software-test-result').textContent='';$('software-status').textContent='Unlock the vault to view or import software identities.';});
 window.addEventListener('iwa-account-changed',invalidate);
 window.addEventListener('pagehide',()=>{invalidate();reviewReport=null;});
 return {refresh,hasReport:()=>!!reviewReport};
}
