import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';import {createCipheriv,createDecipheriv} from 'node:crypto';
import {createPivImporter} from '../app/piv-import.js';import {planPivBackup,USER_PIV_SLOTS} from '../app/piv-backup-plan.js';
function harness({occupied,wrongManagement=false,wrongPublic=false}={}){
 const context={Uint8Array,TextEncoder,TextDecoder,atob,btoa,crypto};context.globalThis=context;vm.createContext(context);vm.runInContext(fs.readFileSync(new URL('../app/smartcard-piv.js',import.meta.url),'utf8'),context);
 const p=context.SequoiaSmartCardPiv,t=p.encodeBerTlv,join=(...a)=>new Uint8Array(a.flatMap(x=>[...x]));
 const imports=[],key=Buffer.alloc(24,5),plain=Buffer.alloc(16,9),slots=new Map();let prompt=0;
 const crypt=(v,decrypt=false)=>{const c=(decrypt?createDecipheriv:createCipheriv)('aes-192-ecb',key,null);c.setAutoPadding(false);return new Uint8Array(Buffer.concat([c.update(v),c.final()]));};
 const material=['86','87','9c','84','9d','85'].map((slot,i)=>{const algorithm=['ML-DSA-65','Ed25519','ML-DSA-65','Ed25519','ML-KEM-768','X25519'][i];return {slot,algorithm,seed:new Uint8Array(algorithm==='ML-KEM-768'?64:32).fill(i+1),publicKey:new Uint8Array(algorithm==='ML-DSA-65'?1952:algorithm==='ML-KEM-768'?1184:32).fill(i+10)};});
 const inspect=async()=>({serial:'12345678',version:'6.0.0',slots:USER_PIV_SLOTS.map(slot=>({slot,keyPresent:false,certificatePresent:false}))});
 const meta=id=>{const k=material.find(k=>parseInt(k.slot,16)===id),a=slots.get(id),publicKey=k.publicKey.slice();if(wrongPublic)publicKey[0]^=1;return join(t(1,new Uint8Array([a.alg])),t(2,new Uint8Array([3,a.touch])),t(4,t(k.algorithm.startsWith('ML-DSA')?0x87:k.algorithm.startsWith('ML-KEM')?0x88:0x86,publicKey)));};
 const stub={...p,inspectEmptyPivCandidate:inspect,withPivSession:async(serial,fn)=>{assert.equal(serial,'12345678');return fn({}, {serial,version:'6.0.0'});},transmitChained:async(c,a)=>{
  if(a[1]===0xcb)return {sw:0x6a82};assert.equal(a[1],0xf7);
  if(a[3]===0x9b)return {sw:0x9000,data:t(1,new Uint8Array([10]))};
  if(a[3]===occupied)return {sw:0x9000,data:new Uint8Array()};
  return slots.has(a[3])?{sw:0x9000,data:meta(a[3])}:{sw:0x6a88};
 },transmitCommandChained:async(c,ins,p1,p2,data)=>{
  if(ins===0x87){const inner=p.parseBerTlv(p.parseBerTlv(data).get(0x7c));if(!inner.get(0x80).length)return {sw:0x9000,data:t(0x7c,t(0x80,crypt(plain)))};
   assert.deepEqual([...inner.get(0x80)],[...plain]);const response=crypt(inner.get(0x81));if(wrongManagement)response[0]^=1;return {sw:0x9000,data:t(0x7c,t(0x82,response))};}
  assert.equal(ins,0xfe);const fields=p.parseBerTlv(data),k=material.find(k=>parseInt(k.slot,16)===p2);assert.deepEqual([...fields.get(k.algorithm.startsWith('ML-DSA')?9:k.algorithm.startsWith('ML-KEM')?10:k.algorithm==='Ed25519'?7:8)],[...k.seed]);
  assert.equal(fields.get(0xaa)[0],3);imports.push(p2);slots.set(p2,{alg:p1,touch:fields.get(0xab)[0]});return {sw:0x9000,data:new Uint8Array()};
 }};
 globalThis.SequoiaSecureChannel={isRequired:()=>true};globalThis.SequoiaSmartCardPiv=stub;
 const importer=createPivImporter({promptManagement:async()=>{prompt++;return key.toString('hex');}});
 return {importer,material,imports,get prompt(){return prompt;},async plan(){return planPivBackup({profile:'level3',...await importer.inspect()});}};
}
test('import authenticates AES management key, writes six exact seeds, matches public keys and policies',async()=>{
 const h=harness(),plan=await h.plan(),done=[];await h.importer.importAll(plan,h.material,{guard:async()=>{},completed:async slot=>done.push(slot)});
 assert.equal(h.prompt,1);assert.equal(h.imports.length,6);assert.equal(h.importer.getSlots().length,6);assert.equal(done.length,6);
});
test('unrelated occupied slot rejects before management prompt or any write',async()=>{
 const h=harness({occupied:0x9a});await assert.rejects(h.importer.importAll(await h.plan(),h.material,{guard:async()=>{},completed:async()=>{}}),/empty/);assert.equal(h.prompt,0);assert.equal(h.imports.length,0);
});
test('bad management response refuses all imports; wrong public readback stops after first import',async()=>{
 for(const options of [{wrongManagement:true},{wrongPublic:true}]){const h=harness(options);await assert.rejects(h.importer.importAll(await h.plan(),h.material,{guard:async()=>{},completed:async()=>{}}));assert.equal(h.imports.length,options.wrongManagement?0:1);assert.throws(()=>h.importer.getSlots());}
});
// A user can lock the vault while the PIN dialog is open. Returning a valid
// PIN must not resume the private operation after that authority was revoked.
test('vault lock during PIN entry prevents submission to card',async()=>{
 const {operateImportedKey}=await import('../app/piv-import.js');let unlocked=true,submitted=false;
 globalThis.SequoiaSecureChannel={isRequired:()=>true};
 globalThis.hardwareTransport={promptPin:async()=>{unlocked=false;return '123456';}};
 globalThis.SequoiaSmartCardPiv={decapsulateComponentsViaSmartCard:async(r,b,prompt)=>{await prompt({});submitted=true;}};
 await assert.rejects(operateImportedKey('decapsulate',{}, {},{guard:async()=>{if(!unlocked)throw Error('Vault locked');}}),/Vault locked/);
 assert.equal(submitted,false);
});
