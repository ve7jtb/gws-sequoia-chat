import test from 'node:test';import assert from 'node:assert/strict';
import {initializeSsh} from '../app/ssh/ui.js';
function fakeDocument(){
 const nodes=new Map();
 return {getElementById(id){if(!nodes.has(id))nodes.set(id,{hidden:false,value:'',textContent:'',children:[],replaceChildren(){this.children=[];},append(x){this.children.push(x);}});return nodes.get(id);},createElement(){return {};}};
}
// Exercise unlock/lock races without any browser, network or card access.
test('SSH only offers dedicated SSH identities and clears public state on lock',async()=>{
 const document=fakeDocument();
 const window=new EventTarget();let unlocked=false,reads=0;
 window.vaultIsUnlocked=()=>unlocked;window.softwareIdentities={records:async()=>{reads++;return [
  {id:'pgp',name:'OpenPGP test',version:4,signingAlgorithm:'Ed25519'},
  {id:'test',name:'SSH test',hasSshPublic:true},
 ];}};
 const ui=initializeSsh({window,document});await ui.refresh();assert(document.getElementById('ssh-tab').hidden);assert.equal(reads,0);
 unlocked=true;await ui.refresh();assert(!document.getElementById('ssh-tab').hidden);
 const chooser=document.getElementById('ssh-identities');
 assert.deepEqual(chooser.children.map(option=>option.value),['test']);
 chooser.value='pgp';
 await document.getElementById('ssh-public').onclick();
 assert.equal(document.getElementById('ssh-status').textContent,'Select an SSH identity.');
 await document.getElementById('ssh-connect').onclick();
 assert.equal(document.getElementById('ssh-status').textContent,'Select an SSH identity.');
 document.getElementById('ssh-public-text').textContent='public data';unlocked=false;window.dispatchEvent(new Event('iwa-vault-locked'));
 assert(document.getElementById('ssh-tab').hidden);assert.equal(document.getElementById('ssh-public-text').textContent,'');assert.equal(document.getElementById('ssh-identities').children.length,0);
});

test('SSH transport check displays progress and the validation error beside its controls',async()=>{
 const document=fakeDocument(),window=new EventTarget();
 window.vaultIsUnlocked=()=>true;
 const check=document.getElementById('ssh-probe'),cancel=document.getElementById('ssh-cancel');
 const status=document.getElementById('ssh-probe-status');
 check.textContent='Check SSH transport';
 initializeSsh({window,document});
 const pending=check.onclick();
 assert.equal(check.textContent,'Checking…');
 assert.equal(check.disabled,true);
 assert.equal(cancel.disabled,false);
 assert.equal(status.textContent,'Checking SSH transport…');
 await pending;
 assert.match(status.textContent,/Enter a hostname or IP address/);
 assert.equal(check.textContent,'Check SSH transport');
 assert.equal(check.disabled,false);
 assert.equal(cancel.disabled,true);
});

test('the hardware picker lists only the selected identity’s verified SSH copies',async()=>{
 const document=fakeDocument(),window=new EventTarget();
 window.vaultIsUnlocked=()=>true;
 window.softwareIdentities={records:async()=>[
  {id:'both',name:'Two SSH copies',hasSshPublic:true,sshCardSerials:['12345678','87654321']},
  {id:'one',name:'One SSH copy',hasSshPublic:true,sshCardSerials:['13572468']},
  {id:'mail-only-card',name:'SSH in software',hasSshPublic:true,cardSerials:['24681357'],sshCardSerials:[]},
 ]};
 const ui=initializeSsh({window,document});
 const chooser=document.getElementById('ssh-identities'),checkbox=document.getElementById('ssh-use-card');
 const group=document.getElementById('ssh-card-picker'),picker=document.getElementById('ssh-card-serial');
 await ui.refresh();
 assert.equal(group.hidden,true);
 checkbox.checked=true;checkbox.onchange();
 assert.equal(group.hidden,false);
 assert.deepEqual(picker.children.map(option=>option.value),['','12345678','87654321']);
 assert.equal(picker.value,'');
 await document.getElementById('ssh-connect').onclick();
 assert.match(document.getElementById('ssh-status').textContent,/Choose a YubiKey provisioned/);
 picker.value='87654321';await ui.refresh();
 assert.equal(picker.value,'87654321');
 chooser.value='one';chooser.onchange();
 assert.equal(picker.value,'13572468');
 chooser.value='mail-only-card';chooser.onchange();
 assert.equal(picker.value,'');
 assert.equal(picker.disabled,true);
 assert.equal(picker.children[0].textContent,'No YubiKey provisioned for this SSH identity');
 window.dispatchEvent(new Event('iwa-vault-locked'));
 assert.equal(group.hidden,true);
 assert.equal(picker.value,'');
});

test('first-use confirmation keeps the handshake alive across the vault revision change',async t=>{
 const document=fakeDocument(),window=new EventTarget(),previousWorker=globalThis.Worker;
 t.after(()=>{if(previousWorker===undefined)delete globalThis.Worker;else globalThis.Worker=previousWorker;});
 let worker,revision=4,approvals=0,entries=[],signatures=0,approved=false;
 globalThis.Worker=class{
  constructor(){worker=this;this.messages=[];}
  postMessage(message){this.messages.push(message);}
  terminate(){this.closed=true;}
  emit(data){return this.onmessage({data});}
 };
 window.vaultIsUnlocked=()=>true;
 window.Terminal=class{open(){} onData(){} focus(){} dispose(){}};
 window.confirm=message=>{
  approvals++;assert.match(message,/server\.invalid:2222\nssh-ed25519  SHA256:/);
  assert.equal(signatures,0);return approved;
 };
 const identity={id:'identity',name:'SSH test',email:'ssh@example.invalid',emails:['ssh@example.invalid'],hasSsh:true,hasSshPublic:true};
 window.softwareIdentities={
  records:async()=>[identity],get:async()=>({...identity,revision}),
  provisioningCertificates:async()=>({ssh:{publicKey:'ssh-mldsa44-ed25519 AQID'}}),
  assert:async selected=>assert.equal(selected.revision,revision),
  signSsh:async selected=>{assert.equal(selected.revision,revision);signatures++;return Uint8Array.of(7);},
 };
 window.sshTrust={
  list:async()=>entries,
  pinFirstUse:async({host,port,type,key})=>{
   entries=[{hosts:`[${host}]:${port}`,type,key,marker:''}];
   revision++;
   window.dispatchEvent(new CustomEvent('iwa-software-identities-changed',{detail:'ssh-first-use'}));
  },
 };
 const ui=initializeSsh({window,document});await ui.refresh();
 document.getElementById('ssh-host').value='server.invalid';
 document.getElementById('ssh-port').value='2222';
 document.getElementById('ssh-username').value='user';
 document.getElementById('ssh-trust-first-use').checked=true;
 const connect=()=>document.getElementById('ssh-connect').onclick();
 const hostMessage={type:'host',id:1,algorithm:'ssh-ed25519',data:Uint8Array.of(1,2,3)};
 await connect();await worker.emit(hostMessage);
 assert(worker.closed);assert.equal(entries.length,0);
 approved=true;
 await connect();await worker.emit(hostMessage);
 assert(!worker.closed);assert.equal(entries.length,1);assert.equal(signatures,0);
 await worker.emit({type:'sign',id:2,data:Uint8Array.of(1,2,3)});
 assert.equal(signatures,1);assert.equal(approvals,2);
 assert.deepEqual(worker.messages.at(-1),{type:'reply',id:2,result:Uint8Array.of(7)});
});
