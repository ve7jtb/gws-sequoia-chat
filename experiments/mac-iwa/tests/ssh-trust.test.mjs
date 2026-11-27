import test from 'node:test';import assert from 'node:assert/strict';
import {parseKnownHosts,createSshTrustStore} from '../app/ssh/trust.js';
import {Vault,random,b64} from '../app/vault/core.js';
const blob=Buffer.concat([Buffer.from([0,0,0,11]),Buffer.from('ssh-ed25519'),Buffer.from([0,0,0,32]),Buffer.alloc(32,7)]).toString('base64');
const text='example.invalid ssh-ed25519 '+blob;
test('known_hosts preserves hashed names, negations, ports, CA and revocations',()=>{const hash='|1|'+Buffer.alloc(20,1).toString('base64')+'|'+Buffer.alloc(20,2).toString('base64');const rows=parseKnownHosts('# comment\n'+text+' comment\n@revoked [example.invalid]:2222 ssh-ed25519 '+blob+'\n@cert-authority *.example.invalid,!bad.example.invalid ssh-ed25519 '+blob+'\n'+hash+' ssh-ed25519 '+blob);assert.equal(rows.length,4);assert.equal(rows[1].marker,'@revoked');assert.equal(rows[2].marker,'@cert-authority');assert.equal(rows[3].hosts,hash);});
test('malformed file fails as a whole instead of silently dropping trust restrictions',()=>{for(const value of ['@unknown '+text,'host ssh-rsa '+blob,'host ssh-ed25519 INVALID','|2|a|b ssh-ed25519 '+blob,text+'\nbadline'])assert.throws(()=>parseKnownHosts(value),/line/);});
test('reviewed host trust persists encrypted, restores, and rejects modified or stale reviews',async()=>{
 const v=new Vault(),secret=random(32),wrapper={id:crypto.randomUUID(),type:'prf',name:'Test',binding:{credentialId:b64(random(32))}};await v.create(wrapper,secret);
 const state=()=>({unlocked:v.unlocked,vaultId:v.record?.id,epoch:1,revision:v.record?.revision,items:v.data?.items});
 const access={snapshot:state,assertCurrent:async s=>assert.equal(s.revision,v.record.revision),replaceItems:async items=>{v.data.items=items;await v.save();}};
 const store=createSshTrustStore(access),review=await store.review(text);await assert.rejects(store.import({...review,entries:[]}));await store.import(review);
 assert.equal((await store.list()).length,1);assert(!JSON.stringify(v.record).includes('example.invalid'));await assert.rejects(store.import(review));
 const second=new Vault();await second.unlock(v.record,wrapper.id,secret);assert.deepEqual(second.data.items,v.data.items);second.lock();
 const next=await store.review(text);v.lock();await assert.rejects(store.import(next),/Unlock/);store.cancel();
});
