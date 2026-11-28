import test from 'node:test';
import assert from 'node:assert/strict';
import {Vault,b64} from '../app/vault/core.js';
import {classicalWrap} from '../app/vault/piv.js';
import {backupUnlockChoices,unlockBackup} from '../app/vault/backup-unlock.js';

test('backup picker preserves every wrapper and selects the saved default',()=>{
 const wrappers=['prf','ecdh','mlkem768-x25519','mlkem1024-p384-v1'].map((kind,id)=>({
  id:String(id),type:id===0?'prf':'piv',binding:{kind},
 }));
 const record={wrappers,default:'2'};
 assert.deepEqual(backupUnlockChoices(record,'other'),{methods:wrappers,selected:'2'});
 assert.deepEqual(backupUnlockChoices(record,'0'),{methods:wrappers,selected:'0'});
});

test('either enrolled PRF or legacy PIV credential opens the same encrypted vault',async()=>{
 const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-384'},true,['deriveBits']);
 const pub=b64(await crypto.subtle.exportKey('spki',pair.publicKey));
 const piv=await classicalWrap({serial:'12',slot:'82',public:pub,fingerprint:'fixture',algorithm:'ECDH-P384'});
 const prfSecret=crypto.getRandomValues(new Uint8Array(32)),credentialId=new Uint8Array([1,2,3]);
 const prf={id:crypto.randomUUID(),name:'Existing passkey',type:'prf',binding:{serial:'14',rpId:'fixture.test',credentialId:b64(credentialId),salt:b64(new Uint8Array(32))}};
 const hardware={id:crypto.randomUUID(),name:'Existing PIV key',type:'piv',binding:piv.binding};
 const source=new Vault();await source.create(prf,prfSecret);await source.add(hardware,piv.secret);
 const signal=new AbortController().signal;
 const request=async(op,{serial,slot,peer})=>{
  assert.equal(op,'chat-vault-ecdh');assert.equal(serial,'12');assert.equal(slot,'82');
  const remote=await crypto.subtle.importKey('spki',Buffer.from(peer,'base64'),{name:'ECDH',namedCurve:'P-384'},false,[]);
  return {fingerprint:'fixture',secret:b64(await crypto.subtle.deriveBits({name:'ECDH',public:remote},pair.privateKey,384))};
 };
 const restored=new Vault();
 await unlockBackup(source.record,hardware.id,restored,{signal,request});
 assert.equal(restored.unlocked,true);restored.lock();
 const evaluate=async input=>{
  assert.equal(input.serial,'14');assert.equal(input.rpId,'fixture.test');
  assert.deepEqual(input.credentialId,credentialId);
  return {secret:prfSecret.slice(),credentialId};
 };
 await unlockBackup(source.record,prf.id,restored,{signal,mode:'smartcard',evaluate});
 assert.equal(restored.unlocked,true);
 await assert.rejects(unlockBackup(source.record,'unknown',new Vault(),{signal}),/Select an enrolled/);
});

test('hybrid recovery binds the selected card and vault wrapper to the WASM operation',async()=>{
 const method={id:crypto.randomUUID(),name:'Level 3 backup',type:'piv',binding:{
  serial:'12',kind:'openpgp',cipher:'envelope',recipientKey:'key',
 }};
 const secret=crypto.getRandomValues(new Uint8Array(32)),source=new Vault();
 await source.create(method,secret);
 const restored=new Vault(),signal=new AbortController().signal;
 const request=async(op,data)=>{
  assert.equal(op,'chat-decryption-material');
  assert.deepEqual(data,{service:'Vault',serial:'12',recipientKey:'key'});
 };
 const decrypt=async options=>{
  assert.equal(options.purpose,'vault');assert.equal(options.cipher,'envelope');
  assert.deepEqual(options.vault,{vaultId:source.record.id,wrapperId:method.id});
  await options.native('chat-decryption-material',{service:'Vault'});
  return {secret:b64(secret)};
 };
 await unlockBackup(source.record,method.id,restored,{signal,request,decrypt});
 assert.equal(restored.unlocked,true);
});
