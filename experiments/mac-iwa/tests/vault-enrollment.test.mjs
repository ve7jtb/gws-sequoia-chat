import test from 'node:test';
import assert from 'node:assert/strict';
import {confirmUnlockEnrollment,discoverOrCreate,hasMatchingPiv,requireAttachedUnlockMethod} from '../app/vault/enrollment.js';
test('existing credential is reused without creation or confirmation',async()=>{
 const r=await discoverOrCreate({assertExisting:async()=>42,createNew:()=>assert.fail(),confirmCreate:()=>assert.fail()});assert.deepEqual(r,{result:42,created:false});
});
test('only explicit no-credential and approval permit creation',async()=>{
 const r=await discoverOrCreate({assertExisting:async()=>{throw {ctapStatus:0x2e};},confirmCreate:()=>true,createNew:async()=>7});assert.equal(r.created,true);
 await assert.rejects(discoverOrCreate({assertExisting:async()=>{throw {ctapStatus:0x2e};},confirmCreate:()=>false,createNew:()=>assert.fail()}),/cancelled/);
});
test('PIN errors and transport errors never create',async()=>{
 for(const error of [Object.assign(Error('PIN'),{ctapStatus:0x31}),Error('transport'),Error('cancelled')])await assert.rejects(discoverOrCreate({assertExisting:async()=>{throw error;},confirmCreate:()=>assert.fail(),createNew:()=>assert.fail()}));
});
test('PIV offer requires wrapping material on the matching key',()=>{
 assert.equal(hasMatchingPiv({serial:'123',classical:{}},'123'),true);
 assert.equal(hasMatchingPiv({serial:'456',classical:{}},'123'),false);
 assert.equal(hasMatchingPiv({serial:'123'},'123'),false);
});


function openOffer(options={}){
 const nodes=new Map(),win=new EventTarget();
 const doc={
  getElementById(id){
   if(!nodes.has(id))nodes.set(id,{children:[],focus(){},showModal(){this.open=true;},close(){this.open=false;},
    replaceChildren(){this.children=[];},append(node){this.children.push(node);}});
   return nodes.get(id);
  },
  createElement:()=>({}),
 };
 const el=id=>doc.getElementById('provisioned-unlock-'+id);
 const pending=confirmUnlockEnrollment(doc,win,{title:'Add unlock method?',detail:'A separate unlock method',action:'Continue',...options});
 return {el,pending,win};
}
test('optional enrollment approves explicitly, and skip, lock and navigation dismiss it',async()=>{
 for(const choice of ['add','cancel','iwa-vault-locked','pagehide']){
  const f=openOffer();
  assert.equal(f.el('dialog').open,true);
  if(choice==='add'||choice==='cancel')f.el(choice).onclick();
  else f.win.dispatchEvent(new Event(choice));
  assert.equal(await f.pending,choice==='add');
  assert.equal(f.el('dialog').open,false);
  assert.equal(f.el('add').onclick,null);
 }
});
test('manual PIV review returns only an explicitly selected connected serial',async()=>{
 const devices=[{serial:'12345678'},{serial:'87654321'}],f=openOffer({devices});
 assert.equal(f.el('add').disabled,true);
 f.el('serial').value='99999999';f.el('serial').onchange();
 f.el('add').onclick();
 assert.equal(f.el('dialog').open,true);
 f.el('serial').value='87654321';f.el('serial').onchange();
 assert.equal(f.el('add').disabled,false);
 f.el('add').onclick();
 assert.equal(await f.pending,'87654321');
});


test('an attached enrolled device is required and removal is detected on a fresh check',async()=>{
 const wrappers=[{type:'prf',binding:{serial:'12345678'}},{type:'piv',binding:{serial:'87654321'}}];
 const newlyProvisioned={serial:'99999999'};
 let attached=[newlyProvisioned,{serial:'87654321'}];
 const discover=async()=>attached;
 await requireAttachedUnlockMethod(wrappers,discover);
 attached=[newlyProvisioned];
 await assert.rejects(requireAttachedUnlockMethod(wrappers,discover),/already enrolled/);
 attached=[];
 await assert.rejects(requireAttachedUnlockMethod(wrappers,discover),/already enrolled/);
 attached=[newlyProvisioned,{serial:'12345678'}];
 await requireAttachedUnlockMethod(wrappers,discover);
});
test('legacy wrappers without a serial cannot vouch for an attached key by name',async()=>{
 await assert.rejects(requireAttachedUnlockMethod([{type:'prf',name:'YubiKey 12345678',binding:{}}],
  ()=>assert.fail('No serial binding means no attachment can be proven')),/identifies its YubiKey by serial/);
});
