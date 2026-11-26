// UI composition for reviewed backup. No operation runs on startup. The first
// click is public discovery; a second confirmation binds the detected serial.
import {createProvisioning} from './piv-provisioning.js';
import {createPivImporter} from './piv-import.js';
function managementPrompt(length){
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
export function createBackupUi({provider,account,test,say,changed}){
 return async row=>{
  const store=provider(),identity=await store.get(row.id,account());
  const confirmRemoval=()=>confirm('Hardware signing and decryption passed. Remove the software private keys from this vault? Public certificates and YubiKey slot mappings will remain. Previously exported encrypted backups may still contain private keys. Cancel keeps the software copy.');
  // A later removal repeats real hardware tests. A persisted success label alone
  // cannot authorize deleting the last working software copy after a restart.
  if(identity.hardware){
   const binding={...identity.hardware,certificate:identity.certificate};
   await test(identity,m=>say(m),binding);await store.assert(identity);
   if(confirmRemoval()){await store.removePrivate(identity,{identity});await changed();say('Software private keys removed; public certificate and verified YubiKey mapping retained.');}
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
   const result=await controller.provision(review.id,{confirmed:true});await changed();
   say('Hardware backup verified. The software keys remain encrypted in the vault.');
   if(confirmRemoval()){await controller.removeSoftwareKeys(result.id,{confirmed:true});await changed();say('Software private keys removed; public certificate and verified YubiKey mapping retained.');}
  }catch(error){say('Provisioning stopped. Keep the software keys and journal; do not reset or repeat after partial writes. '+error.message,true);throw error;}
 };
}
