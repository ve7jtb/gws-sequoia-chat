import test from 'node:test';
import assert from 'node:assert/strict';
import {promptSshPassword} from '../app/ssh/password-dialog.js';

test('SSH authorization prompt clears the input on submit and cancellation',async()=>{
 const nodes=new Map();
 const document={getElementById(id){
  if(!nodes.has(id))nodes.set(id,new EventTarget());
  return nodes.get(id);
 }};
 const dialog=document.getElementById('ssh-password-dialog');
 const input=document.getElementById('ssh-password-input');
 const form=document.getElementById('ssh-password-form');
 dialog.showModal=()=>{dialog.open=true;};
 dialog.close=()=>{dialog.open=false;};
 input.focus=()=>{};
 const abort=new AbortController();
 const options={document,host:'::1',port:22,username:'fixture',algorithms:['ssh-ed25519'],compositeSelected:true,signal:abort.signal};
 const submitted=promptSshPassword(options);
 assert.equal(document.getElementById('ssh-password-target').textContent,'fixture @ [::1]:22');
 assert.match(document.getElementById('ssh-password-plan').textContent,/Warning:.*only Ed25519/);
 input.value=' disposable password ';
 form.dispatchEvent(new Event('submit',{cancelable:true}));
 assert.equal(new TextDecoder().decode(await submitted),' disposable password ');
 assert.equal(input.value,'');assert.equal(dialog.open,false);
 const cancelled=promptSshPassword(options);
 input.value='must be cleared';abort.abort();
 await assert.rejects(cancelled,/cancelled/);
 assert.equal(input.value,'');assert.equal(dialog.open,false);
});
