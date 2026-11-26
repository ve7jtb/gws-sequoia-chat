// UI composition for reviewed backup. No operation runs on startup. The first
// click is public discovery; a second confirmation binds the detected serial.
import {createProvisioning} from './piv-provisioning.js';
import {createPivImporter} from './piv-import.js';
export function managementPrompt(length){
 const dialog=document.getElementById('piv-management-dialog'),input=document.getElementById('piv-management-value');
 document.getElementById('piv-management-help').textContent='Enter the existing '+length+'-byte PIV management key in hex. This is not your PIN; it is never saved. No PIN or management key will be changed.';
 input.value='';dialog.showModal();input.focus();
 return new Promise((resolve,reject)=>{
  const ok=document.getElementById('piv-management-ok'),cancel=document.getElementById('piv-management-cancel');
  function finish(accepted){const value=input.value;input.value='';dialog.close();ok.removeEventListener('click',yes);cancel.removeEventListener('click',no);dialog.removeEventListener('cancel',no);input.removeEventListener('keydown',enter);accepted?resolve(value):reject(Error('Management authentication cancelled.'));}
  const yes=()=>finish(true),no=e=>{e?.preventDefault();finish(false);},enter=e=>{if(e.key==='Enter'){e.preventDefault();yes();}};
  ok.addEventListener('click',yes);cancel.addEventListener('click',no);dialog.addEventListener('cancel',no);input.addEventListener('keydown',enter);
 });
}
// Read the file the user actually saved and list only its independent PRF
// methods. The store repeats all checks before it can remove private keys.
async function recoveryPrompt(targetSerial){
 const dialog=document.createElement('dialog');
 const title=document.createElement('h2');title.textContent='Verify a separate recovery YubiKey';
 const help=document.createElement('p');help.textContent='Choose the encrypted vault-only backup containing this identity. Export it from Vault first if needed.';
 const file=document.createElement('input');file.type='file';file.accept='.json';file.setAttribute('aria-label','Encrypted vault backup');
 const methods=document.createElement('select');methods.setAttribute('aria-label','Recovery YubiKey');
 const status=document.createElement('p');status.setAttribute('role','status');
 const verify=document.createElement('button');verify.textContent='Verify and remove software copy';verify.disabled=true;
 const cancel=document.createElement('button');cancel.textContent='Keep software copy';
 dialog.append(title,help,file,methods,status,cancel,verify);document.body.append(dialog);
 try{
  return await new Promise(resolve=>{
   let chosen;
   file.onchange=async()=>{
    const current=file.files[0];chosen=null;verify.disabled=true;methods.replaceChildren();
    try{
     if(!current||current.size>4_000_000)throw Error('Choose an encrypted vault backup.');
     const backup=JSON.parse(await current.text());
     if(file.files[0]!==current)return;
     for(const w of backup.wrappers||[]){
      if(w.type!=='prf'||!w.binding?.credentialId||!w.binding.rpId||
         !/^[1-9][0-9]{5,9}$/.test(w.binding.serial)||String(w.binding.serial)===String(targetSerial))continue;
      const option=document.createElement('option');option.value=w.id;option.textContent=w.name+' · SN# '+w.binding.serial;methods.append(option);
     }
     if(!methods.options.length)throw Error('This file has no separate FIDO PRF recovery YubiKey.');
     status.textContent='Connect the selected recovery YubiKey to verify the saved file.';
     chosen=current;verify.disabled=false;
    }catch(error){if(file.files[0]===current)status.textContent=error.message;}
   };
   verify.onclick=()=>{if(chosen&&methods.value)resolve({file:chosen,methodId:methods.value});};
   cancel.onclick=()=>resolve(null);
   dialog.oncancel=event=>{event.preventDefault();resolve(null);};
   dialog.showModal();
  });
 }finally{dialog.remove();}
}
export function createBackupUi({provider,account,test,say,changed}){
 return async row=>{
  const store=provider(),identity=await store.get(row.id,account());
  // A later removal repeats real hardware tests. A persisted success label alone
  // cannot authorize deleting the last working software copy after a restart.
  if(identity.hardware){
   const binding={...identity.hardware,certificate:identity.certificate};
   await test(identity,m=>say(m),binding);await store.assert(identity);
   const recovery=await recoveryPrompt(identity.hardware.serial);
   if(recovery){await store.removePrivate(identity,{identity},recovery);await changed();say('Software private keys removed; public certificate and verified YubiKey mapping retained.');}
   return;
  }
  const card=createPivImporter({promptManagement:managementPrompt});
  const journal={save:async record=>localStorage.setItem('sequoia-piv-provisioning-journal-v1',JSON.stringify(record))};
  const controller=createProvisioning({card:{...card,verify:async(plan,selected)=>{
   const slots=card.getSlots(),binding={serial:plan.serial,slots,certificate:selected.certificate};
   const report=await test(selected,m=>say(m),binding);
   return {publicKeysMatch:true,signingVerified:report.signatureVerified===true,decryptionVerified:report.decryptionVerified===true,slots};
  }},vault:{assert:store.assert,material:store.backupMaterial,saveHardware:store.saveHardware,assertHardware:store.assertHardware,removePrivate:store.removePrivate},journal});
  say('Reading all 24 PIV slots and certificates; no PIN or writes.');
  const review=await controller.discover(identity);
  const summary=review.plan.keys.map(k=>k.slot.toUpperCase()+': '+k.component+' ('+k.role+'), PIN always, touch '+k.touch).join('\n');
  if(!confirm('Detected empty YubiKey '+review.plan.serial+'\n\nImport the EXISTING Level 3 software keys (no new keys generated):\n'+summary+'\n\nFingerprint: '+identity.fingerprint+'\n\nThis writes six empty slots. An interrupted import must not be blindly retried. Keep the software copy until verification passes. Proceed?'))return;
  try{
   await controller.provision(review.id,{confirmed:true});await changed();
   say('Hardware backup verified. Export an encrypted vault backup before using Verify hardware backup / remove software keys.');
  }catch(error){say('Provisioning stopped. Keep the software keys and journal; do not reset or repeat after partial writes. '+error.message,true);throw error;}
 };
}
