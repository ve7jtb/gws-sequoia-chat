import test from 'node:test';
import assert from 'node:assert/strict';
import {createSshAddressBook} from '../app/ssh/address-book.js';
import {Vault,b64,random} from '../app/vault/core.js';

test('saved SSH hosts survive encrypted vault restore without storing passwords',async()=>{
 let vault=new Vault();
 const secret=random(32);
 const wrapper={id:crypto.randomUUID(),type:'prf',name:'Fixture PRF',binding:{credentialId:b64(random(32))}};
 await vault.create(wrapper,secret);
 const unrelated={id:crypto.randomUUID(),kind:'SSH host trust',name:'Existing trust'};
 vault.data.items=[unrelated];
 await vault.save();
 const snapshot=()=>({unlocked:vault.unlocked,revision:vault.record?.revision,items:vault.data?.items||[]});
 const book=createSshAddressBook({
  snapshot,
  assertCurrent:async state=>assert.equal(state.revision,snapshot().revision),
  replaceItems:async(items,state,{change})=>{
   assert.equal(state.revision,snapshot().revision);
   assert.equal(change,'ssh-address-book');
   vault.data.items=items;
   await vault.save();
  },
 });
 const host={host:'fixture.internal',port:'2222',username:'fixture-operator',identityId:'fixture-identity',serial:'12345678'};
 const id=await book.save({...host,password:'fixture-password'});
 assert.deepEqual(await book.list(),[{...host,id,name:host.host,port:2222}]);
 assert(!JSON.stringify(vault.data.items).includes('fixture-password'));
 const disk=structuredClone(vault.record);
 for(const value of [host.host,host.username,host.identityId,host.serial])assert(!JSON.stringify(disk).includes(value));
 vault.lock();
 await assert.rejects(book.list(),/Unlock/);
 vault=new Vault();
 await vault.unlock(disk,wrapper.id,secret);
 await book.save({...host,id,name:' Lab ',port:22});
 assert.deepEqual(await book.list(),[{...host,id,name:'Lab',port:22}]);
 await assert.rejects(book.save({...host,username:'invalid name'}),/username/);
 await assert.rejects(book.save({...host,identityId:''}),/identity/);
 await book.remove(id);
 assert.deepEqual(await book.list(),[]);
 assert.deepEqual(vault.data.items,[unrelated]);
 vault.lock();
});
