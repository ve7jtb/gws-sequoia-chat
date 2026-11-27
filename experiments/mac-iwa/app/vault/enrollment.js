// A failed assertion is not permission to create a credential. Only the
// authenticator's explicit NO_CREDENTIALS response permits a separate offer.
export async function discoverOrCreate({assertExisting,createNew,confirmCreate}){
 try{return {result:await assertExisting(),created:false};}
 catch(error){
  if(error.ctapStatus!==0x2e)throw error;
  if(!await confirmCreate())throw Error('No existing credential found. Creation cancelled.');
  return {result:await createNew(),created:true};
 }
}
// A public PIV probe must belong to the same physical key as FIDO enrollment.
// Finding arbitrary signing certificates alone does not establish a usable
// vault unlock key: require the existing wrapping material as well.
export function hasMatchingPiv(material,serial){
 return String(material?.serial)===String(serial)&&!!(material?.certificate||material?.classical||material?.level5);
}

// Presence is checked against the current vault's device bindings, independently
// of the serial selected for the new method. A legacy method without a serial
// cannot prove which attached card belongs to it.
export async function requireAttachedUnlockMethod(wrappers,discover){
 const enrolled=new Set(wrappers.map(wrapper=>String(wrapper.binding?.serial??''))
  .filter(serial=>/^[1-9][0-9]{0,9}$/.test(serial)));
 if(!enrolled.size)throw Error('No enrolled unlock method identifies its YubiKey by serial.');
 const devices=await discover();
 if(!devices.some(({serial})=>enrolled.has(serial)))
  throw Error('Keep a YubiKey already enrolled to unlock this vault connected while adding an unlock method.');
}

// Use an in-app dialog because Chromium can suppress confirm() in an IWA.
// Locking or leaving the vault dismisses a pending offer before any card call.
export function confirmUnlockEnrollment(doc,win,{title,detail,action,devices}){
 const el=id=>doc.getElementById('provisioned-unlock-'+id);
 const dialog=el('dialog'),cancel=el('cancel'),submit=el('add');
 const chooser=el('serial'),serials=devices?.map(device=>device.serial);
 el('choice').hidden=!devices;
 if(devices){
  chooser.replaceChildren();
  const append=(serial,label)=>{
   const option=doc.createElement('option');option.value=serial;option.textContent=label;chooser.append(option);
  };
  if(serials.length>1)append('','Select a connected YubiKey');
  for(const serial of serials)append(serial,'SN# '+serial);
  chooser.value=serials.length===1?serials[0]:'';
 }
 const selection=()=>serials?serials.find(serial=>serial===chooser.value):true;
 const update=()=>{submit.disabled=!selection();};
 update();
 el('title').textContent=title;
 el('detail').textContent=detail;
 submit.textContent=action;
 dialog.showModal();
 cancel.focus();
 return new Promise(resolve=>{
  const skip=()=>finish(false);
  const finish=approved=>{
   cancel.onclick=null;submit.onclick=null;chooser.onchange=null;dialog.oncancel=null;dialog.onclose=null;
   submit.disabled=false;
   win.removeEventListener('iwa-vault-locked',skip);
   win.removeEventListener('pagehide',skip);
   if(dialog.open)dialog.close();
   resolve(approved);
  };
  cancel.onclick=skip;
  submit.onclick=()=>{const selected=selection();if(selected)finish(selected);};
  chooser.onchange=update;
  dialog.oncancel=event=>{event.preventDefault();skip();};
  dialog.onclose=()=>{if(!dialog.open)skip();};
  win.addEventListener('iwa-vault-locked',skip);
  win.addEventListener('pagehide',skip);
 });
}
