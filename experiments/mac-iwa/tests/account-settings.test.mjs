// Public settings use real serialization/revision checks and controlled memory
// storage. Synthetic addresses only; no Google account, token or hardware I/O.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {ACCOUNT_SETTINGS_KEY,accountEmail,createAccountSettings,legacyAccount} from '../app/account-settings.js';
import {createSession} from '../app/google-session.js';
import {createTransport} from '../app/google-transport.js';

export function memoryStorage(){const values=new Map();return {values,getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)};}
const settings=storage=>createAccountSettings({storage,newRevision:()=>webcrypto.randomUUID()});
test('only a normalized bare public mailbox can be configured',()=>{
 assert.equal(accountEmail(' Sender@Example.Invalid '),'sender@example.invalid');
 for(const bad of ['',null,{},'Sender <sender@example.invalid>','a@b\r\nBcc: x@y','a..b@example.invalid','a@-example.invalid','a@example..invalid','a'.repeat(65)+'@example.invalid'])assert.throws(()=>accountEmail(bad));
});
test('reviewed settings persist only mailbox/schema/revision and survive a new controller',()=>{
 const storage=memoryStorage(),store=settings(storage);assert.equal(store.read(),null);
 assert.throws(()=>store.save('sender@example.invalid',null,false),/confirm/);
 const email=legacyAccount({account:'Sender@Example.Invalid',serial:'12345678',identity:{certificate:'public'},token:'never copied'});
 const saved=store.save(email,null,true);
 assert.deepEqual(Object.keys(saved).sort(),['email','revision','version']);
 assert.equal(settings(storage).read().email,'sender@example.invalid');
 assert.doesNotMatch(storage.getItem(ACCOUNT_SETTINGS_KEY),/token|serial|identity|certificate/);
});
test('account revision invalidates stale reviews, including change-away/change-back',()=>{
 const storage=memoryStorage(),first=settings(storage),second=settings(storage);
 const original=first.save('sender@example.invalid',null,true);
 const other=second.save('other@example.invalid',original,true);
 second.save(original.email,other,true);
 assert.throws(()=>first.assert(original),/changed/);
 assert.throws(()=>first.save('third@example.invalid',original,true),/changed/);
 assert.equal(first.read().email,original.email);
});
test('corrupt or extended account records fail closed and explicit clearing preserves other stores',()=>{
 const storage=memoryStorage(),store=settings(storage);
 storage.setItem('existing-vault-marker','unchanged');
 for(const raw of ['{',JSON.stringify({version:1,revision:webcrypto.randomUUID(),email:'a@example.invalid',token:'forbidden'})]){
  storage.setItem(ACCOUNT_SETTINGS_KEY,raw);assert.throws(()=>store.read(),/invalid/);
  assert.throws(()=>store.clear(false),/Confirm/);store.clear(true);assert.equal(store.read(),null);
 }
 assert.equal(storage.getItem('existing-vault-marker'),'unchanged');
});
test('missing or invalid configured email never opens OAuth or requests a profile',async()=>{
 let connects=0,requests=0;
 const session=createSession({unlocked:()=>true,connect:()=>{connects++;throw Error('Unexpected OAuth');},fetcher:()=>{requests++;throw Error('Unexpected fetch');}});
 for(const value of ['',undefined,'Alice <a@example.invalid>']){
  await assert.rejects(session.login(value));await assert.rejects(session.profile(value));
 }
 assert.equal(connects,0);assert.equal(requests,0);
});
test('a changed account after profile or review consumption cannot upload Gmail ciphertext',async()=>{
 for(const changeAt of ['profile','review']){
  const store=settings(memoryStorage()),snapshot=store.save('sender@example.invalid',null,true);let consumed=0,uploads=0;
  const revise=()=>store.save('other@example.invalid',snapshot,true);
  const transport=createTransport({profile:async()=>{if(changeAt==='profile')revise();},request:async()=>{uploads++;}});
  const context={account:snapshot.email,assertAccount:()=>store.assert(snapshot),composeReviews:{take:async()=>{consumed++;if(changeAt==='review')revise();return {raw:btoa('synthetic ciphertext')};}}};
  await assert.rejects(transport.call('chat-mail-send',{review:'synthetic',confirmed:true},()=>assert.fail('No native fallback'),context),/changed/);
  assert.equal(uploads,0);assert.equal(consumed,changeAt==='profile'?0:1);
 }
});
test('changing account between Chat stages stops subsequent uploads and messages without retry',async()=>{
 const store=settings(memoryStorage()),snapshot=store.save('sender@example.invalid',null,true);let uploads=0,messages=0;
 const transport=createTransport({profile:async()=>{},media:async()=>{uploads++;store.save('other@example.invalid',snapshot,true);return {attachmentDataRef:{attachmentUploadToken:'synthetic'}};},request:async()=>{messages++;}});
 const context={account:snapshot.email,assertAccount:()=>store.assert(snapshot),composeReviews:{take:async()=>({space:'spaces/test',cipher:btoa('cipher'),certificate:btoa('public')})}};
 await assert.rejects(transport.call('chat-send',{review:'synthetic',confirmed:true},()=>assert.fail('No native fallback'),context),/public-certificate upload failed/);
 assert.equal(uploads,1);assert.equal(messages,0);
});
