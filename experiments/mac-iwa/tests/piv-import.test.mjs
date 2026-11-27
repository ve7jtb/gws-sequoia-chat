import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';import {createCipheriv,createDecipheriv} from 'node:crypto';
import {createPivImporter,FACTORY_MANAGEMENT_KEY} from '../app/piv-import.js';import {planPivBackup,planLevel3Provisioning,USER_PIV_SLOTS} from '../app/piv-backup-plan.js';
// Node cannot fetch file: URLs. Initialize the same packaged verifier the
// browser loads, so the management tests exercise the Chromium fallback path.
import initVerifier,{provisioning_aes192_block} from '../app/wasm/sequoia_iwa_verify.js';
await initVerifier({module_or_path:fs.readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});

test('packaged WASM matches the AES-192 single-block reference in both directions',()=>{
 const key=Buffer.from('000102030405060708090a0b0c0d0e0f1011121314151617','hex');
 const clear=Buffer.from('00112233445566778899aabbccddeeff','hex');
 const cipher=Buffer.from('dda97ca4864cdfe06eaf70a0ec0d7191','hex');
 assert.deepEqual(Buffer.from(provisioning_aes192_block(key,clear,false)),cipher);
 assert.deepEqual(Buffer.from(provisioning_aes192_block(key,cipher,true)),clear);
 assert.throws(()=>provisioning_aes192_block(key.subarray(1),clear,false),/Invalid PIV AES-192 challenge/);
});
function harness({occupied,wrongManagement=false,wrongPublic=false,extended=false,ssh=false,factoryFlag,selectFactory=false,occupiedObject=false,badObject=false}={}){
 const context={Uint8Array,TextEncoder,TextDecoder,atob,btoa,crypto};context.globalThis=context;vm.createContext(context);vm.runInContext(fs.readFileSync(new URL('../app/smartcard-piv.js',import.meta.url),'utf8'),context);
 const p=context.SequoiaSmartCardPiv,t=p.encodeBerTlv,join=(...a)=>new Uint8Array(a.flatMap(x=>[...x]));
 const imports=[],plain=Buffer.alloc(16,9),slots=new Map();
 const key=selectFactory?Buffer.from([1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8]):Buffer.alloc(24,5);
 let prompt=0,offeredFactory,sessions=0;const objects=new Map(),writes=[];
 if(occupiedObject)objects.set(0x5f5000,Uint8Array.of(1));
 const crypt=(v,decrypt=false)=>{const c=(decrypt?createDecipheriv:createCipheriv)('aes-192-ecb',key,null);c.setAutoPadding(false);return new Uint8Array(Buffer.concat([c.update(v),c.final()]));};
 const material=['86','87','9c','84','9d','85'].map((slot,i)=>{const algorithm=['ML-DSA-65','Ed25519','ML-DSA-65','Ed25519','ML-KEM-768','X25519'][i];return {slot,algorithm,seed:new Uint8Array(algorithm==='ML-KEM-768'?64:32).fill(i+1),publicKey:new Uint8Array(algorithm==='ML-DSA-65'?1952:algorithm==='ML-KEM-768'?1184:32).fill(i+10)};});
 if(extended)material.push(...[
  ['83','P-384',48,97],['82','P-384',48,97],['8a','ML-DSA-65',32,1952],['8b','P-384',48,97],
 ].map(([slot,algorithm,seedSize,publicSize],i)=>({
  slot,algorithm,seed:new Uint8Array(seedSize).fill(i+20),
  publicKey:new Uint8Array(publicSize).fill(algorithm==='P-384'?4:i+25),
 })));
 if(ssh)material.push({slot:'8c',algorithm:'ML-DSA-44',seed:new Uint8Array(32).fill(61),publicKey:new Uint8Array(1312).fill(62)},{slot:'8d',algorithm:'Ed25519',seed:new Uint8Array(32).fill(63),publicKey:new Uint8Array(32).fill(64)});
 const inspect=async()=>({serial:'12345678',version:'6.0.0',slots:USER_PIV_SLOTS.map(slot=>({slot,keyPresent:false,certificatePresent:false}))});
 const meta=id=>{const k=material.find(k=>parseInt(k.slot,16)===id),a=slots.get(id),publicKey=k.publicKey.slice();if(wrongPublic)publicKey[0]^=1;return join(t(1,new Uint8Array([a.alg])),t(2,new Uint8Array([3,a.touch])),t(3,new Uint8Array([a.origin])),t(4,t(k.algorithm.startsWith('ML-DSA')?0x87:k.algorithm.startsWith('ML-KEM')?0x88:0x86,publicKey)));};
 const stub={...p,inspectEmptyPivCandidate:inspect,readPivDataObject:async(_conn,tag)=>objects.get(tag)??null,
  readProvisioningInventory:async()=>{const inventory=await inspect();
   if(occupied)inventory.slots.find(row=>row.slot===occupied.toString(16)).keyPresent=true;
   return inventory;
  },withPivSession:async(serial,fn)=>{assert.equal(serial,'12345678');sessions++;return fn({}, {serial,version:'6.0.0'});},transmitChained:async(c,a)=>{
  if(a[1]===0xcb){
   const tag=(a[7]<<16)|(a[8]<<8)|a[9];
   const value=objects.get(tag);
   return value?{sw:0x9000,data:t(0x53,value)}:{sw:0x6a82};
  }
  assert.equal(a[1],0xf7);
  if(a[3]===0x9b)return {sw:0x9000,data:join(t(1,new Uint8Array([10])),
   ...(factoryFlag===undefined?[]:[t(5,Uint8Array.of(factoryFlag))]))};
  if(a[3]===occupied)return {sw:0x9000,data:new Uint8Array()};
  return slots.has(a[3])?{sw:0x9000,data:meta(a[3])}:{sw:0x6a88};
 },transmitCommandChained:async(c,ins,p1,p2,data)=>{
  if(ins===0x87){const inner=p.parseBerTlv(p.parseBerTlv(data).get(0x7c));if(!inner.get(0x80).length)return {sw:0x9000,data:t(0x7c,t(0x80,crypt(plain)))};
   assert.deepEqual([...inner.get(0x80)],[...plain]);const response=crypt(inner.get(0x81));if(wrongManagement)response[0]^=1;return {sw:0x9000,data:t(0x7c,t(0x82,response))};}
  if(ins===0x47){
   assert.equal(p1,0);
   const fields=p.parseBerTlv(p.parseBerTlv(data).get(0xac));
   const k=material.find(k=>parseInt(k.slot,16)===p2);
   assert.equal(fields.get(0xaa)[0],3);
   imports.push(p2);
   slots.set(p2,{alg:fields.get(0x80)[0],touch:fields.get(0xab)[0],origin:1});
   return {sw:0x9000,data:t(0x7f49,t(k.algorithm.startsWith('ML-DSA')?0x87:k.algorithm.startsWith('ML-KEM')?0x88:0x86,k.publicKey))};
  }
  if(ins===0xdb){
   assert.equal(p1,0x3f);assert.equal(p2,0xff);
   assert.equal(imports.length,material.length);
   const fields=p.parseBerTlv(data),selector=fields.get(0x5c);
   const tag=(selector[0]<<16)|(selector[1]<<8)|selector[2];
   writes.push(tag);const value=fields.get(0x53).slice();
   if(badObject)value[0]^=1;
   objects.set(tag,value);
   return {sw:0x9000,data:new Uint8Array()};
  }
  assert.equal(ins,0xfe);const fields=p.parseBerTlv(data),k=material.find(k=>parseInt(k.slot,16)===p2);assert.deepEqual([...fields.get(k.algorithm.startsWith('ML-DSA')?9:k.algorithm.startsWith('ML-KEM')?10:k.algorithm==='Ed25519'?7:k.algorithm==='P-384'?6:8)],[...k.seed]);
  assert.equal(fields.get(0xaa)[0],3);imports.push(p2);slots.set(p2,{alg:p1,touch:fields.get(0xab)[0],origin:2});return {sw:0x9000,data:new Uint8Array()};
 }};
 globalThis.SequoiaSecureChannel={isRequired:()=>true};globalThis.SequoiaSmartCardPiv=stub;
 const importer=createPivImporter({promptManagement:async(length,{allowFactory})=>{
  assert.equal(length,24);prompt++;offeredFactory=allowFactory;
  return selectFactory?FACTORY_MANAGEMENT_KEY:key.toString('hex');
 }});
 return {importer,material,imports,writes,get sessions(){return sessions;},get offeredFactory(){return offeredFactory;},get prompt(){return prompt;},async plan(){return planPivBackup({profile:'level3',...await importer.inspect()});}};
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

for(const mode of ['backup','on-card']){
 test(mode+' operates on ten reviewed slots and checks the origin and both P-384 roles',async()=>{
  const h=harness({extended:true}),done=[];
  const plan=planLevel3Provisioning({profile:'level3',mode,includeSmime:true,
   includeExperimentalNist:true,...await h.importer.inspect()});
  const options={guard:async()=>{},completed:async slot=>done.push(slot)};
  if(mode==='backup')await h.importer.importAll(plan,h.material,options);
  else await h.importer.generateAll(plan,options);
  const rows=await h.importer.readPublicKeys(plan);
  assert.equal(rows.length,10);
  assert.deepEqual(done,plan.keys.map(key=>key.slot));
  assert(rows.every(key=>key.origin===(mode==='backup'?'imported':'generated')));
  assert.deepEqual(rows.filter(key=>key.component==='P-384').map(key=>key.slot),['83','82','8b']);
 });
}

// Even a caller returning the factory choice directly cannot bypass the
// authenticated default flag or reach the first import with a custom key set.
test('factory option uses the same AES challenge only when the card reports the default',async()=>{
 const options={guard:async()=>{},completed:async()=>{}};
 for(const factoryFlag of [0,undefined,1]){
  const h=harness({factoryFlag,selectFactory:true}),plan=await h.plan();
  const run=h.importer.importAll(plan,h.material,options);
  if(factoryFlag===1)await run;
  else await assert.rejects(run,/does not report a supported factory-default/);
  assert.equal(h.offeredFactory,factoryFlag===1);
  assert.equal(h.imports.length,factoryFlag===1?6:0);
 }
});

// Exercise both APDU paths with the new pair and assert all readback policies.
for(const mode of ['backup','on-card'])test('SSH pair '+mode+' preserves distinct slots and UP policy',async()=>{
 const h=harness({extended:true,ssh:true});
 const plan=planLevel3Provisioning({profile:'level3',mode,includeSmime:true,includeExperimentalNist:true,includeSsh:true,...await h.importer.inspect()});
 const options={guard:async()=>{},completed:async()=>{}};
 if(mode==='backup')await h.importer.importAll(plan,h.material,options);
 else await h.importer.generateAll(plan,options);
 const rows=await h.importer.readPublicKeys(plan);
 assert.equal(rows.length,12);
 assert.equal(rows.find(k=>k.slot==='8c').touch,'always');
 assert.equal(rows.find(k=>k.slot==='8d').touch,'never');
 assert(rows.every(k=>k.pin==='always'));
 assert.equal(plan.certificates.smime.pure.signing[0],'9c');
});

test('backup commits the manifest last in the same authenticated key-import session',async()=>{
 for(const flags of [{},{occupiedObject:true},{badObject:true}]){
  const h=harness(flags),plan=await h.plan(),attempted=[],readBack=[];
  const bundle=new Uint8Array(4097);bundle.set(new TextEncoder().encode('PQMZIP01'));
  const run=h.importer.importAll(plan,h.material,{bundle,guard:async()=>{},completed:async()=>{},
   bundleAttempting:async tag=>attempted.push(tag),bundleCompleted:async tag=>readBack.push(tag)});
  if(flags.occupiedObject){
   await assert.rejects(run,/already exists/);
   assert.deepEqual(h.imports,[]);assert.deepEqual(h.writes,[]);assert.equal(h.prompt,0);
  }else if(flags.badObject){
   await assert.rejects(run,/readback did not match/);
   assert.deepEqual(attempted,[0x5f5001]);assert.deepEqual(readBack,[]);
   assert.throws(()=>h.importer.getSlots());
  }else{
   assert.equal((await run).length,6);
   assert.deepEqual(h.writes,[0x5f5001,0x5f5002,0x5f5003,0x5f5000]);
   assert.deepEqual(attempted,h.writes);assert.deepEqual(readBack,h.writes);
   assert.equal(h.prompt,1);
  }
  assert.equal(h.sessions,1);
 }
});
