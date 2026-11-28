import {detailedUnlockMethodLabel} from './labels.js';

// Discovery establishes presence only. Each candidate is routed through its
// original enrolled wrapper and must pass the usual live checks and PIN flow.
export function attachedUnlockAlternatives(record,selected,error){
 const missing=selected.binding?.serial;
 if(!missing||error?.code!=='YUBIKEY_NOT_FOUND'||error.expectedSerial!==missing||
    !Array.isArray(error.attachedSerials)||error.attachedSerials.includes(missing))return [];
 const attached=new Set(error.attachedSerials);
 return record.wrappers.filter(method=>method.id!==selected.id&&
  /^[1-9][0-9]{0,9}$/.test(method.binding?.serial)&&attached.has(method.binding.serial));
}

export function reviewAlternateUnlock(doc,win,missing,methods){
 const el=id=>doc.getElementById('alternate-unlock-'+id);
 const dialog=el('dialog'),input=el('method'),use=el('use'),cancel=el('cancel');
 const single=methods.length===1;
 el('message').textContent='Authenticator SN# '+missing+' not found. '+(single
  ?'Authenticator SN# '+methods[0].binding.serial+' is attached. Would you like to use this one?'
  :'Other enrolled authenticators are attached. Would you like to use one of them?');
 el('choice').hidden=single;
 input.replaceChildren();
 const prompt=doc.createElement('option');
 prompt.textContent='Choose an enrolled unlock method';
 prompt.value='';
 input.append(prompt);
 for(const method of methods){
  const option=doc.createElement('option');
  option.textContent=detailedUnlockMethodLabel(method);
  option.value=method.id;
  input.append(option);
 }
 input.value=single?methods[0].id:'';
 use.textContent=single?'Use '+(methods[0].type==='prf'?'FIDO PRF':'PIV')+' on SN# '+methods[0].binding.serial:'Use selected authenticator';
 const selection=()=>methods.find(method=>method.id===input.value)?.id||null;
 const update=()=>{use.disabled=!selection();};
 update();
 dialog.showModal();
 cancel.focus();
 return new Promise(resolve=>{
  const dismiss=()=>finish(null);
  const finish=id=>{
   use.onclick=cancel.onclick=input.onchange=dialog.oncancel=dialog.onclose=null;
   win.removeEventListener('iwa-vault-locked',dismiss);
   win.removeEventListener('pagehide',dismiss);
   if(dialog.open)dialog.close();
   resolve(id);
  };
  use.onclick=()=>{const id=selection();if(id)finish(id);};
  cancel.onclick=dismiss;
  input.onchange=update;
  dialog.oncancel=event=>{event.preventDefault();dismiss();};
  // A close event from a previous use can arrive after a new modal opens.
  dialog.onclose=()=>{if(!dialog.open)dismiss();};
  win.addEventListener('iwa-vault-locked',dismiss);
  win.addEventListener('pagehide',dismiss);
 });
}
