import test from 'node:test';
import assert from 'node:assert/strict';
import {createPrivateKey,createPublicKey,verify} from 'node:crypto';
import {createImportedSshStore} from '../app/ssh/imported-keys.js';
import {Vault,b64,random} from '../app/vault/core.js';

test('standalone imported Ed25519 key signs after encrypted vault restore',async()=>{
 const engine=new Vault(),secret=random(32),wrapper={id:crypto.randomUUID(),type:'prf',name:'Synthetic PRF',binding:{credentialId:b64(random(32))}};
 await engine.create(wrapper,secret);
 const seed=Buffer.alloc(32,7),pkcs8=Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]);
 const publicKey=createPublicKey(createPrivateKey({key:pkcs8,format:'der',type:'pkcs8'}));
 const publicBytes=publicKey.export({format:'der',type:'spki'}).subarray(-32);
 let session=engine,epoch=1;
 const snapshot=()=>({unlocked:session.unlocked,vaultId:session.record?.id,epoch,revision:session.record?.revision,items:session.data?.items||[]});
 const freshStore=()=>createImportedSshStore({
  snapshot,assertCurrent:async expected=>assert.equal(snapshot().revision,expected.revision),
  replaceItems:async items=>{session.data.items=items;await session.save();},
 },{openFile:async()=>({seed:new Uint8Array(seed),publicKey:new Uint8Array(publicBytes)})});
 const store=freshStore(),row=await store.importKey('Standalone SSH',Uint8Array.of(1),new Uint8Array());
 assert(row.publicKey.startsWith('ssh-ed25519 '));
 assert(!Object.hasOwn(row,'seed'));
 assert(!JSON.stringify(engine.record).includes(b64(seed)));
 const disk=structuredClone(engine.record);
 engine.lock();
 await assert.rejects(store.get(row.id),/Unlock/);
 session=new Vault();epoch++;await session.unlock(disk,wrapper.id,secret);
 const restored=freshStore(),current=await restored.get(row.id);
 const message=new Uint8Array(64).fill(2),signature=await restored.signSsh(current,message);
 assert(verify(null,message,publicKey,signature));
 await assert.rejects(restored.signSsh(row,message),/changed/);
 session.lock();
});
