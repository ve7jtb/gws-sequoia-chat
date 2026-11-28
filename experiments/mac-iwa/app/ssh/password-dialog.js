// This prompt is reachable only through the verified SSH authorization
// connection. The password is never a vault item or terminal input.
export function promptSshPassword({document,host,port,username,algorithms=[],compositeSelected=false,signal}){
 const dialog=document.getElementById('ssh-password-dialog');
 const form=document.getElementById('ssh-password-form');
 const input=document.getElementById('ssh-password-input');
 const detail=document.getElementById('ssh-password-target');
 const status=document.getElementById('ssh-password-status');
 const plan=document.getElementById('ssh-password-plan');
 const cancel=document.getElementById('ssh-password-cancel');
 if(signal?.aborted)return Promise.reject(Error('SSH key authorization cancelled.'));
 if(dialog.open)return Promise.reject(Error('An SSH password prompt is already open.'));
 const endpoint=(host.includes(':')?'['+host+']':host)+':'+port;
 return new Promise((resolve,reject)=>{
  const finish=(error,secret)=>{
   form.removeEventListener('submit',submit);
   dialog.removeEventListener('cancel',decline);
   cancel.removeEventListener('click',decline);
   signal?.removeEventListener('abort',decline);
   input.value='';detail.textContent='';plan.textContent='';status.textContent='';
   if(dialog.open)dialog.close();
   if(error)reject(error);else resolve(secret);
  };
  const decline=event=>{event?.preventDefault();finish(Error('SSH key authorization cancelled.'));};
  const submit=event=>{
   event.preventDefault();
   const secret=new TextEncoder().encode(input.value);
   if(!secret.length||secret.length>1024){
    secret.fill(0);status.textContent='Enter a password up to 1,024 UTF-8 bytes.';return;
   }
   finish(null,secret);
  };
  input.value='';status.textContent='';
  detail.textContent=username+' @ '+endpoint;
  plan.textContent=compositeSelected&&!algorithms.includes('ssh-mldsa44-ed25519')
   ?'Warning: The server supports only Ed25519 among the selected keys. The composite key will be skipped.'
   :'Keys to authorize: '+algorithms.join(', ')+'.';
  form.addEventListener('submit',submit);
  dialog.addEventListener('cancel',decline);
  cancel.addEventListener('click',decline);
  signal?.addEventListener('abort',decline,{once:true});
  try{dialog.showModal();input.focus();}
  catch(error){finish(error);}
 });
}
