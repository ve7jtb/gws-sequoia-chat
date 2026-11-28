import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import * as wasm from '../app/wasm/sequoia_iwa_verify.js';
import {Vault,b64,random} from '../app/vault/core.js';
import {operateLocalFile} from '../app/local-files/crypto.js';
import {createLocalFileStore} from '../app/local-files/store.js';

await wasm.default({module_or_path:await readFile(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const operate=(op,input)=>operateLocalFile(wasm,op,input);

test('hybrid file envelopes authenticate both KEM components, metadata and contents',async()=>{
 const vaultId=crypto.randomUUID(),keyId=crypto.randomUUID(),id=crypto.randomUUID();
 const binding={vaultId,keyId};
 const pair=await operate('generate',binding);
 const payload=Uint8Array.of(0,1,2,255,128);
 const sealed=await operate('seal',{...binding,id,publicKey:pair.publicKey,name:'fixture.bin',plain:payload.slice()});
 const reveal=row=>operate('open',{...binding,...pair,row});
 const {name,plain}=await reveal(sealed);
 assert.equal(name,'fixture.bin');
 assert.deepEqual(plain,payload);
 for(const [field,offset] of [['capsule',0],['capsule',1568],['nameBox',0],['fileBox',0]]){
  const tampered=structuredClone(sealed);
  tampered[field][offset]^=1;
  await assert.rejects(reveal(tampered));
 }
 await assert.rejects(reveal({...sealed,id:crypto.randomUUID()}));
 await assert.rejects(operate('open',{...binding,...pair,vaultId:crypto.randomUUID(),row:sealed}));
 const other=await operate('generate',binding);
 await assert.rejects(operate('open',{...binding,...pair,seed:other.seed,row:sealed}));
 const empty=await operate('seal',{...binding,id,publicKey:pair.publicKey,name:'empty',plain:new Uint8Array()});
 assert.equal((await reveal(empty)).plain.length,0);
});

test('file key survives vault restore, with ciphertext scoped to the original vault',async()=>{
 let vault=new Vault();
 const secret=random(32);
 const wrapper={id:crypto.randomUUID(),type:'prf',name:'Fixture PRF',binding:{credentialId:b64(random(32))}};
 await vault.create(wrapper,secret);
 const records=new Map();
 const storage={
  async list(vaultId){return [...records.values()].filter(row=>row.vaultId===vaultId);},
  async read(vaultId,id){return records.get(vaultId+id);},
  async add(row){records.set(row.vaultId+row.id,row);},
  async remove(vaultId,id){records.delete(vaultId+id);},
 };
 const snapshot=()=>({unlocked:vault.unlocked,vaultId:vault.record?.id,revision:vault.record?.revision,items:vault.data?.items||[]});
 const access={
  snapshot,
  async assertCurrent(expected){
   const state=snapshot();
   if(!state.unlocked||state.vaultId!==expected.vaultId||state.revision!==expected.revision)throw Error('Vault changed.');
  },
  async replaceItems(items,state){
   await access.assertCurrent(state);
   vault.data.items=items;
   await vault.save();
  },
 };
 let releaseOpen;
 const service=()=>createLocalFileStore(access,{storage,async operate(op,input){
  if(op==='open'&&releaseOpen)await releaseOpen.promise;
  return operate(op,input);
 }});
 const store=service(),file=new File(['synthetic local content'],'fixture-secret-name.txt');
 assert.deepEqual(await store.list(),[]);
 await store.add(file);
 await store.add(new File([],'empty.bin'));
 assert.equal(vault.data.items.length,1);
 const backup=structuredClone(vault.record);
 assert(!JSON.stringify(backup).includes(vault.data.items[0].seed));
 const known=await store.list();
 const {id}=known.find(row=>row.name===file.name);
 const before=await storage.read(backup.id,id);
 assert(before.fileBox instanceof Blob);
 assert(!JSON.stringify(before).includes(file.name));
 assert(!new TextDecoder().decode(await before.fileBox.arrayBuffer()).includes('synthetic local content'));
 releaseOpen=Promise.withResolvers();
 const pending=store.open(id);
 await new Promise(resolve=>setImmediate(resolve));
 vault.lock();
 releaseOpen.resolve();
 await assert.rejects(pending,/Vault changed/);
 releaseOpen=null;
 await assert.rejects(store.list(),/Unlock/);
 vault=new Vault();
 await vault.create(wrapper,secret);
 assert.deepEqual(await service().list(),[]);
 await vault.unlock(backup,wrapper.id,secret);
 const restored=service();
 assert.deepEqual(await restored.list(),known);
 assert.equal(new TextDecoder().decode((await restored.open(id)).plain),'synthetic local content');
 await restored.remove(id);
 assert.equal((await restored.list()).length,1);
 vault.lock();
});
