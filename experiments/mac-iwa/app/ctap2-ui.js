import {batch} from './preview-pgp.js';
import initPreviewSequoia,{inspect_public,verify_detached} from './wasm/sequoia_iwa_verify.js';
import {derive,verify,point,digest} from './preview-sign.js';
// Browser-only FIDO controls. This module never logs PINs, assertions or PRF
// outputs. Only GetInfo's public capability summary is rendered/exportable.
import {getInfo,evaluate,collectEntropy,createCredential,createPreviewSign,signPreview,encode,decode,extensionRp,packageRp} from './ctap2-smartcard.js';
import {b64,bytes} from './vault/core.js';
const el=id=>document.getElementById(id);
let active=null;
const say=s=>{el('fido-status').textContent=s;};
// Keep the modal visible through PIN submission, touch and vault validation.
// Receiving PRF bytes is not yet proof that the encrypted vault unlocked.
function stage(title,message,finished=false){
 el('fido-pin-title').textContent=title;el('fido-pin-progress').textContent=message;
 el('fido-pin-entry').hidden=true;el('fido-pin-ok').hidden=true;
 el('fido-pin-wait').hidden=finished;el('fido-pin-done').hidden=!finished;
 el('fido-pin-cancel').hidden=finished;
}
function complete(message,ok=true){
 if(!el('fido-pin-dialog').open){if(ok)return;el('fido-pin-detail').textContent='';el('fido-pin-dialog').showModal();}
 stage(ok?'YubiKey operation complete':'YubiKey operation stopped',message,true);
 el('fido-pin-done').focus();
}
el('fido-pin-done').onclick=()=>el('fido-pin-dialog').close();
const progress=s=>{say(s);if(el('fido-pin-dialog').open)stage(/touch/i.test(s)?'Touch your YubiKey':'YubiKey is processing',s);};

const cancel=()=>active?.abort();
window.addEventListener('iwa-vault-locked',cancel);
window.addEventListener('pagehide',cancel);
el('fido-cancel').onclick=cancel;
el('fido-rp').options[0].value=packageRp();
el('fido-rp').options[0].textContent='IWA package — '+packageRp();
el('fido-rp').options[1].value=extensionRp();
el('fido-rp').options[1].textContent='Legacy Sequoia extension — '+extensionRp();
// Serial is public routing metadata; private operations still verify the card.
el('fido-serial').value=localStorage.getItem('iwa-fido-expected-serial')||'';
el('fido-serial').addEventListener('change',()=>{const v=el('fido-serial').value.trim();if(/^[1-9][0-9]{0,9}$/.test(v))localStorage.setItem('iwa-fido-expected-serial',v);});
function selectedSerial(){const serial=el('fido-serial').value.trim();if(!/^[1-9][0-9]{0,9}$/.test(serial))throw Error('Enter the expected YubiKey serial in Vault → FIDO enrollment settings.');localStorage.setItem('iwa-fido-expected-serial',serial);return serial;}
async function run(fn,{quietMissing=false}={}){
 if(active)throw Error('A FIDO operation is already running.');
 const controller=new AbortController();active=controller;
 try{return await fn({signal:controller.signal,progress});}
 catch(e){if(!quietMissing||e.code!=='YUBIKEY_NOT_FOUND')complete(e.message+' No automatic retry was performed.',false);throw e;}
 finally{active=null;el('fido-pin-input').value='';}
}
function promptPin({serial,rpId,retries,purpose},signal,creating=false){
 const dialog=el('fido-pin-dialog'),input=el('fido-pin-input');
 el('fido-pin-title').textContent=purpose|| (creating?'FIDO PIN — create IWA credential':'FIDO PIN — vault access');
 el('fido-pin-ok').textContent=creating?'Create credential':'Authorize vault access';
 el('fido-pin-entry').hidden=false;el('fido-pin-ok').hidden=false;el('fido-pin-cancel').hidden=false;
 el('fido-pin-wait').hidden=true;el('fido-pin-done').hidden=true;el('fido-pin-progress').textContent='';
 el('fido-pin-detail').textContent=`YubiKey · SN# ${serial} · RP ${rpId} · ${retries} FIDO PIN tries remaining. This is the FIDO PIN, not the PIV PIN. Touch the key after submitting.`;
 return new Promise((resolve,reject)=>{
  let settled=false;
  const finish=(error,pin)=>{if(settled)return;settled=true;input.removeEventListener('keydown',onKeyDown);input.value='';if(error)dialog.close();else stage('Touch your YubiKey','PIN submitted. Keep the key connected and touch it when it flashes.');el('fido-pin-ok').removeEventListener('click',ok);el('fido-pin-cancel').removeEventListener('click',abort);dialog.removeEventListener('cancel',abort);signal.removeEventListener('abort',abort);if(!error){el('fido-pin-cancel').onclick=()=>{cancel();stage('Cancelling','Waiting for the card operation to stop…');};dialog.oncancel=e=>{e.preventDefault();cancel();};}error?reject(error):resolve(pin);};
  const abort=()=>finish(Error('FIDO PIN entry cancelled. No retry.'));
  const ok=()=>{if(signal.aborted)return abort();finish(null,input.value);};
  // Enter follows the same authorization path as the visible button for every
  // FIDO use (vault, enrollment and previewSign). Ignore IME composition and
  // held-key repeats; remove the listener before waiting for authenticator touch.
  const onKeyDown=e=>{if(e.key==='Enter'&&!e.isComposing&&!e.repeat){e.preventDefault();ok();}};
  input.addEventListener('keydown',onKeyDown);
  el('fido-pin-ok').addEventListener('click',ok);el('fido-pin-cancel').addEventListener('click',abort);dialog.addEventListener('cancel',abort);signal.addEventListener('abort',abort,{once:true});
  if(signal.aborted)return abort();el('fido-pin-cancel').onclick=null;dialog.oncancel=null;input.value='';if(!dialog.open)dialog.showModal();input.focus();
 });
}
el('fido-getinfo').onclick=async()=>{try{const result=await run(options=>getInfo(selectedSerial(),options));say('PASS: CTAP2 GetInfo (no PIN, no credential changes)\n'+JSON.stringify(result,null,2));}catch(e){say('STOPPED: '+e.message);}};
// New local wrappers may enroll an EXISTING discoverable credential. This
// assertion-only path deliberately has no makeCredential fallback.
window.directFido=Object.freeze({
 complete,
 async entropy({signal,guard,serial:reviewedSerial}){
  if(!globalThis.SequoiaSecureChannel?.isRequired())throw Error('Enable secure YubiKey connection for entropy collection.');
  const serial=reviewedSerial===undefined?selectedSerial():reviewedSerial;
  if(typeof serial!=='string'||!/^[1-9][0-9]{0,9}$/.test(serial))
   throw Error('Invalid FIDO entropy serial.');
  return run(async options=>{
   const abort=()=>active?.abort();signal?.addEventListener('abort',abort,{once:true});
   try{
    if(signal?.aborted)throw Error('Entropy collection cancelled');await guard();
    el('fido-pin-detail').textContent='YubiKey · SN# '+serial+' · One temporary non-resident credential. Existing credentials and PIV keys are unchanged.';
    if(!el('fido-pin-dialog').open)el('fido-pin-dialog').showModal();
    stage('Collecting key-generation entropy','Preparing authenticator touch…');
    el('fido-pin-cancel').onclick=abort;el('fido-pin-dialog').oncancel=e=>{e.preventDefault();abort();};
    const output=await collectEntropy(serial,details=>promptPin(details,options.signal,true),{...options,guard});
    complete('Touch complete. Mixing authenticator output with fresh OS randomness for software key generation.');return output;
   }finally{signal?.removeEventListener('abort',abort);}
  });
 },
 // Only public recovery metadata is persisted; never PINs or PRF outputs.
 async create(binding,name,vaultId){
  if(binding.rpId!==packageRp())throw Error('New FIDO credentials require the IWA package RP.');
  const key='iwa-fido-creation-recovery:'+packageRp();let pending=JSON.parse(localStorage.getItem(key)||'null');
  if(pending&&(pending.vaultId!==vaultId||pending.binding.serial!==binding.serial))throw Error('An unfinished credential enrollment belongs to another vault/key.');
  if(pending&&!pending.binding.credentialId){
   // Never repeat uncertain makeCredential. First ask the same physical key
   // for a discoverable assertion; only CTAP NO_CREDENTIALS clears the marker.
   try{const r=await this.prf(pending.binding);pending.binding.credentialId=r.credentialId;localStorage.setItem(key,JSON.stringify(pending));return {...r,binding:pending.binding};}
   catch(e){if(e.ctapStatus===0x2e){localStorage.removeItem(key);throw Error('The key confirmed no credential exists for this IWA. Recovery is cleared. Click Create new discoverable IWA PRF credential again to create it.');}throw e;}
  }
  if(pending){const r=await this.prf(pending.binding);return {...r,binding:pending.binding};}
  pending={vaultId,binding,userId:b64(crypto.getRandomValues(new Uint8Array(32)))};
  return run(async options=>{
   // Record uncertainty immediately before transmission, not at PIN entry.
   // Cancelling the PIN dialog must not leave a false partial-creation marker.
   const r=await createCredential({...binding,salt:bytes(binding.salt),userId:bytes(pending.userId),name},details=>promptPin(details,options.signal,true),{...options,beforeCreate:()=>localStorage.setItem(key,JSON.stringify(pending)),created:id=>{pending.binding.credentialId=b64(id);localStorage.setItem(key,JSON.stringify(pending));}});
   try{return {binding:pending.binding,credentialId:b64(r.credentialId),secret:b64(r.secret)};}finally{r.secret.fill(0);}
  });
 },
 creationSaved(){localStorage.removeItem('iwa-fido-creation-recovery:'+packageRp());},
 // Provisioning binds a specific device and uses the current IWA RP. The
 // manual vault controls still use their selected serial and RP settings.
 enrollmentBinding:(serial=null)=>serial
  ?{rpId:packageRp(),serial}
  :{rpId:el('fido-rp').value,serial:selectedSerial()},
 async prf(binding,options){
  return run(async options=>{
   let serial=binding.serial;
   if(!serial){
    // Old extension-RP wrappers may only record the credential ID. Preserve
    // that RP and credential, and require an unambiguous physical card.
    serial=el('fido-serial').value.trim();
    if(serial)serial=selectedSerial();
    else{
     const devices=await window.SequoiaSmartCardPiv.listYubiKeys();
     if(devices.length!==1)throw Error('Connect only the YubiKey for this FIDO unlock method or enter its serial under FIDO enrollment settings.');
     serial=String(devices[0].serial);
    }
   }
   const r=await evaluate({serial,rpId:binding.rpId||extensionRp(),credentialId:binding.credentialId?bytes(binding.credentialId):null,salt:bytes(binding.salt)},details=>promptPin(details,options.signal),options);
   try{progress('PRF received. Checking the encrypted vault…');return {credentialId:b64(r.credentialId),secret:b64(r.secret),serial};}
   finally{r.secret.fill(0);}
  },options);
 }
});

// Test setup is explicit and separate from the PRF vault. A non-discoverable
// credential avoids consuming another discoverable-credential slot. Persist the
// opaque handles and public keys only, so the same test can be repeated.
const previewStore=()=> 'iwa-preview-sign:'+packageRp()+':'+selectedSerial();
const previewSay=message=>{el('preview-status').textContent=message;};
el('preview-create').onclick=async()=>{
 try{
  if(previewBatchActive)throw Error('Finish the ten-key test first.');
  const key=previewStore();if(localStorage.getItem(key))throw Error('Test setup already exists or is incomplete. Do not create a duplicate.');
  const serial=selectedSerial();
  const result=await run(options=>createPreviewSign({serial,rpId:packageRp(),userId:crypto.getRandomValues(new Uint8Array(32)),name:'IWA previewSign diagnostic'},details=>promptPin(details,options.signal,true),{...options,beforeCreate:()=>localStorage.setItem(key,JSON.stringify({pending:true,serial,rpId:packageRp()}))}));
  localStorage.setItem(key,JSON.stringify({serial,rpId:packageRp(),credentialId:b64(result.credentialId),credentialKey:b64(encode(result.credentialKey)),keyHandle:b64(result.keyHandle),publicKey:b64(encode(result.publicKey))}));
  previewSay('Setup complete. Test credential saved locally. Choose Sign and verify synthetic message.');complete('previewSign test credential created. You may remove the key.');
 }catch(e){previewSay(e.message);complete(e.message,false);}
};
el('preview-sign').onclick=async()=>{
 try{
  if(previewBatchActive)throw Error('Finish the ten-key test first.');
  const saved=JSON.parse(localStorage.getItem(previewStore())||'null');if(!saved||saved.pending)throw Error('Create the separate previewSign test credential first; incomplete setup must be inspected before retrying.');
  const ikm=crypto.getRandomValues(new Uint8Array(32));let derived;
  try{derived=derive(decode(bytes(saved.publicKey)),ikm,new TextEncoder().encode('Sequoia IWA previewSign test'));}finally{ikm.fill(0);}
  const message=new TextEncoder().encode('Synthetic previewSign diagnostic '+crypto.randomUUID());
  const start=performance.now();
  const result=await run(options=>signPreview({serial:saved.serial,rpId:saved.rpId,credentialId:bytes(saved.credentialId),preview:{keyHandle:bytes(saved.keyHandle),digest:digest(message),args:derived.args}},details=>promptPin(details,options.signal),options));
  // Verify both the extension signature and the ordinary FIDO assertion. The
  // latter binds extension output to the exact credential registered at setup.
  const joined=new Uint8Array(result.authData.length+result.clientHash.length);joined.set(result.authData);joined.set(result.clientHash,result.authData.length);
  if(!verify(result.assertionSignature,joined,point(decode(bytes(saved.credentialKey))).toBytes(false)))throw Error('FIDO assertion signature did not verify');
  if(!verify(result.signature,message,derived.publicKey))throw Error('previewSign signature did not verify');
  if(verify(result.signature,new Uint8Array([...message,0]),derived.publicKey))throw Error('Tampered message unexpectedly verified');
  const report={result:'PASS',algorithm:'Experimental ARKG-P256 (-65539)',rpId:saved.rpId,serial:saved.serial,signatureVerified:true,assertionVerified:true,tamperedMessageRejected:true,elapsedIncludingPinAndTouchMs:Math.round(performance.now()-start)};
  previewSay(JSON.stringify(report,null,2));complete('previewSign signature and FIDO assertion verified. Altered message rejected. You may remove the key.');
 }catch(e){previewSay(e.message);complete(e.message,false);}
};

let previewBatchActive=false;
el('preview-pgp').onclick=async()=>{
 if(previewBatchActive){previewSay('Finish the current ten-key test first.');return;}
 previewBatchActive=true;const urls=[];
 try{
  const saved=JSON.parse(localStorage.getItem(previewStore())||'null');
  if(!saved||saved.pending)throw Error('Complete previewSign test setup first.');
  previewSay('Preparing ten ARKG-derived OpenPGP identities. Expect 20 PIN/touch operations; no email is sent.');
  el('preview-downloads').replaceChildren();await initPreviewSequoia();
  const sign=async(derived,hash,purpose)=>{
   previewSay(purpose+' — enter FIDO PIN, then touch the key.');
   const result=await run(options=>signPreview({serial:saved.serial,rpId:saved.rpId,credentialId:bytes(saved.credentialId),preview:{keyHandle:bytes(saved.keyHandle),digest:hash,args:derived.args}},details=>promptPin({...details,purpose},options.signal),options));
   const signed=new Uint8Array(result.authData.length+result.clientHash.length);signed.set(result.authData);signed.set(result.clientHash,result.authData.length);
   if(!verify(result.assertionSignature,signed,point(decode(bytes(saved.credentialKey))).toBytes(false)))throw Error('FIDO assertion verification failed');
   return result.signature;
  };
  const download=(name,data)=>{const a=document.createElement('a'),url=URL.createObjectURL(new Blob([data],{type:'application/octet-stream'}));urls.push(url);a.href=url;a.download=name;a.textContent=name;const row=document.createElement('p');row.append(a);el('preview-downloads').append(row);};
  const report=await batch(decode(bytes(saved.publicKey)),sign,
   certificate=>JSON.parse(inspect_public(JSON.stringify({certificate}))),
   request=>JSON.parse(verify_detached(JSON.stringify(request))),
   row=>{previewSay('PASS '+row.index+'/10 — self-certificate and message verified by Sequoia; altered message rejected.');download('arkg-'+row.index+'-certificate.pgp',bytes(row.certificate));download('arkg-'+row.index+'-message.pgp',bytes(row.signedMessage));});
  download('previewSign-openpgp-report.json',JSON.stringify(report,null,2));
  previewSay('PASS: 10 distinct ARKG public keys, 10 self-certified OpenPGP certificates, 10 signed messages. Sequoia verified all; all altered messages rejected.');
  complete('All ten OpenPGP certificates and messages passed Sequoia verification. You may remove the key.');
 }catch(e){previewSay('STOPPED: '+e.message+' Completed public artifacts remain available below. No automatic retry.');complete(e.message,false);}
 finally{previewBatchActive=false;}
 // Public download URLs live until navigation; no PIN or private material is
 // included. The diagnostic never imports these certificates into trust stores.
 window.addEventListener('pagehide',()=>urls.forEach(url=>URL.revokeObjectURL(url)),{once:true});
};
