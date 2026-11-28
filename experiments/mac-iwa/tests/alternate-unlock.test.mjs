import test from 'node:test';
import assert from 'node:assert/strict';
import {attachedUnlockAlternatives,reviewAlternateUnlock} from '../app/vault/alternate-unlock.js';

const method=(id,serial,type='piv')=>({id,name:'My key',type,binding:{serial}});
const selected=method('selected','100');
const attachedPiv=method('piv','101');
const attachedPrf=method('prf','102','prf');
const record={default:selected.id,wrappers:[selected,attachedPiv,attachedPrf,method('absent','103'),method('legacy',undefined,'prf')]};
const missing={code:'YUBIKEY_NOT_FOUND',expectedSerial:'100',attachedSerials:['101','102','105']};

test('an absent selected key offers only methods explicitly enrolled for discovered serials',()=>{
 assert.deepEqual(attachedUnlockAlternatives(record,selected,missing),[attachedPiv,attachedPrf]);
 assert.equal(record.default,selected.id);
 for(const error of [new Error('Incorrect PIV PIN'),new Error('SCP11b MAC failed'),
  {...missing,expectedSerial:'105'},{...missing,attachedSerials:['100','101']},
  {...missing,attachedSerials:['999']}])
  assert.deepEqual(attachedUnlockAlternatives(record,selected,error),[]);
});

function dialogFixture(){
 const nodes=Object.fromEntries(['dialog','method','use','cancel','message','choice'].map(key=>[key,{}]));
 Object.assign(nodes.dialog,{showModal(){this.open=true;},close(){this.open=false;}});
 Object.assign(nodes.method,{options:[],replaceChildren(){this.options=[];},append(option){this.options.push(option);}});
 nodes.cancel.focus=()=>{};
 const doc={getElementById:id=>nodes[id.replace('alternate-unlock-','')],createElement:()=>({})};
 return {nodes,doc,win:new EventTarget()};
}

test('single attached method is offered with both serials and requires explicit consent',async()=>{
 const {nodes,doc,win}=dialogFixture();
 const choice=reviewAlternateUnlock(doc,win,'100',[attachedPrf]);
 assert.match(nodes.message.textContent,/SN# 100 not found.*SN# 102 is attached/);
 assert.match(nodes.use.textContent,/FIDO PRF on SN# 102/);
 assert.equal(nodes.dialog.open,true);
 nodes.use.onclick();
 assert.equal(await choice,'prf');
 assert.equal(nodes.dialog.open,false);
});

test('multiple methods have no preselection, and locking dismisses the offer',async()=>{
 const {nodes,doc,win}=dialogFixture();
 const choice=reviewAlternateUnlock(doc,win,'100',[attachedPiv,attachedPrf]);
 assert.equal(nodes.use.disabled,true);
 assert.equal(nodes.choice.hidden,false);
 nodes.method.value='piv';
 nodes.method.onchange();
 assert.equal(nodes.use.disabled,false);
 win.dispatchEvent(new Event('iwa-vault-locked'));
 assert.equal(await choice,null);
 assert.equal(nodes.dialog.open,false);
});
