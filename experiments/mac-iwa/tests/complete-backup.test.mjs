import test from 'node:test';import assert from 'node:assert/strict';
import {Vault} from '../app/vault/core.js';
import {capture,seal,unseal,restore,digest,recoveryVault,DATABASES,PENDING} from '../app/complete-backup.js';
import {createBackupDrive,DRIVE_SCOPE} from '../app/backup-drive.js';
import {localFileDatabase} from '../app/local-files/storage.js';
const origin='isolated-app://test-package';
function storage(){const db=new Map(),ls=new Map();return {db,settings:{get length(){return ls.size;},key:i=>[...ls.keys()][i],getItem:k=>ls.get(k)??null,setItem:(k,v)=>ls.set(k,v),removeItem:k=>ls.delete(k)},names:async()=>[...db.keys()],read:async n=>structuredClone(db.get(n)??null),put:async(n,s,v)=>{if(db.has(n)&&JSON.stringify(db.get(n))!==JSON.stringify(v))throw Error('conflict');if(v!==null)db.set(n,structuredClone(v));}};}
async function fixture(){const vault=new Vault(),secret=crypto.getRandomValues(new Uint8Array(32)),id=crypto.randomUUID();await vault.create({id,name:'Existing PRF',type:'prf',binding:{credentialId:'public-id'}},secret);const source=storage();source.db.set(DATABASES[0][0],structuredClone(vault.record));source.db.set(DATABASES[1][0],{format:'sequoia-iwa-identities',version:1,revision:1,records:[{certificate:'synthetic identity'}]});source.db.set(DATABASES[2][0],{format:'sequoia-iwa-certificates',version:1,revision:1,bindings:[{email:'test@example.org',fingerprint:'test'}]});source.settings.setItem('account','test@example.org');return {vault,secret,id,source,snapshot:await capture(source,origin)};}
test('authenticator backup restores every record in a separate instance',async()=>{const f=await fixture(),box=await seal(f.snapshot,f.vault),second=new Vault();await second.unlock(recoveryVault(box,origin),f.id,f.secret);const restored=await unseal(box,second,origin),destination=storage();await restore(destination,restored,origin);assert.equal(await digest(await capture(destination,origin)),await digest(f.snapshot));assert.equal(destination.settings.getItem(PENDING),null);assert.equal(box.version,2);assert.ok(!JSON.stringify(box).includes('test@example.org'));});
test('new nonces and wrong authenticator are rejected',async()=>{const f=await fixture(),a=await seal(f.snapshot,f.vault),b=await seal(f.snapshot,f.vault);assert.notEqual(a.iv,b.iv);await assert.rejects(new Vault().unlock(a.recoveryVault,f.id,new Uint8Array(32)));});
test('tampering and foreign origins fail before restore',async()=>{const f=await fixture(),b=await seal(f.snapshot,f.vault);await assert.rejects(unseal({...b,cipher:'AAAA'},f.vault,origin));await assert.rejects(unseal(b,f.vault,'isolated-app://other'));await assert.rejects(unseal({...b,extra:true},f.vault,origin));});
test('locked vault cannot export',async()=>{const f=await fixture();f.vault.lock();await assert.rejects(seal(f.snapshot,f.vault));});
test('conflicting destinations are never overwritten',async()=>{const f=await fixture(),d=storage();d.settings.setItem('account','different');await assert.rejects(restore(d,f.snapshot,origin));assert.equal(d.db.size,0);assert.equal(d.settings.getItem(PENDING),null);});
test('interrupted restore resumes idempotently and retains marker',async()=>{const f=await fixture(),d=storage(),put=d.put;let count=0;d.put=async(...args)=>{if(++count===2)throw Error('disk full');return put(...args);};await assert.rejects(restore(d,f.snapshot,origin));assert.ok(d.settings.getItem(PENDING));d.put=put;await restore(d,f.snapshot,origin);assert.equal(await digest(await capture(d,origin)),await digest(f.snapshot));assert.equal(d.settings.getItem(PENDING),null);});
test('Drive backup captures the vault key with Local files present and leaves file records in place',async()=>{
 const {vault,secret,id,source}=await fixture();
 const fileKey={kind:'Local file encryption key',id:crypto.randomUUID(),name:'Local files',seed:'synthetic-file-key'};
 vault.data.items.push(fileKey);
 await vault.save();
 source.db.set(DATABASES[0][0],structuredClone(vault.record));
 const encryptedFile={ciphertext:'device-local-encrypted-fixture'};
 source.db.set(localFileDatabase,encryptedFile);
 const snapshot=await capture(source,origin);
 assert.equal(snapshot.databases.length,3);
 assert(!snapshot.databases.some(r=>r.name===localFileDatabase));
 const box=await seal(snapshot,vault);
 let uploaded;
 const drive=createBackupDrive({fetcher:async(url,options)=>{
  if(options.method==='POST'){
   uploaded=options.body;
   return Response.json({id:'fixture'});
  }
  return Response.json(box);
 }});
 drive.connect({token:'fixture',scope:DRIVE_SCOPE,expiresIn:3600});
 const {id:driveId}=await drive.upload(box);
 assert(uploaded.includes(box.cipher));
 assert(!uploaded.includes(fileKey.seed));
 assert(!uploaded.includes(encryptedFile.ciphertext));
 const downloaded=await drive.download(driveId),restoredVault=new Vault();
 await restoredVault.unlock(recoveryVault(downloaded,origin),id,secret);
 const target=storage();
 const existingLocalFile={ciphertext:'existing-encrypted-fixture'};
 target.db.set(localFileDatabase,existingLocalFile);
 await restore(target,await unseal(downloaded,restoredVault,origin),origin);
 assert.deepEqual(restoredVault.data.items,[fileKey]);
 assert.deepEqual(source.db.get(localFileDatabase),encryptedFile);
 assert.deepEqual(target.db.get(localFileDatabase),existingLocalFile);
});
test('unknown databases abort complete capture',async()=>{const d=storage();d.db.set('unknown',{});await assert.rejects(capture(d,origin));});
test('Drive upload contains encrypted envelope and requests only bounded API paths',async()=>{const f=await fixture(),box=await seal(f.snapshot,f.vault),calls=[];const drive=createBackupDrive({fetcher:async(u,o)=>{calls.push([u,o]);return new Response(JSON.stringify({id:'safe',name:'backup'}));}});drive.connect({token:'test-token',scope:DRIVE_SCOPE,expiresIn:3600});await drive.upload(box);assert.ok(calls[0][0].startsWith('https://www.googleapis.com/upload/drive/v3/files?'));assert.ok(!calls[0][1].body.includes('test@example.org'));assert.equal(calls[0][1].redirect,'error');await assert.rejects(drive.download('../bad'));drive.disconnect();await assert.rejects(drive.list());});
test('Drive rejects wrong scopes, plaintext and expired sessions',async()=>{let time=0;const d=createBackupDrive({clock:()=>time,fetcher:()=>{throw Error('must not fetch');}});assert.throws(()=>d.connect({token:'x',scope:'email',expiresIn:1}));d.connect({token:'x',scope:DRIVE_SCOPE,expiresIn:1});await assert.rejects(d.upload({plaintext:'secret'}));time=2000;await assert.rejects(d.list());});
// These are host connection decisions, not account or certificate trust data.
// Importing a backup must not undo required SCP or opt another host into beta.
test('restore preserves local SCP, beta pin and transport without altering backup',async()=>{
 const f=await fixture(),d=storage(),hash=await digest(f.snapshot);
 d.settings.setItem('sequoia_secure_yubikey_connection','required');d.settings.setItem('sequoia_secure_yubikey_beta_pin','enabled');d.settings.setItem('sequoia_hardware_transport','smartcard');
 await restore(d,f.snapshot,origin);
 assert.equal(d.settings.getItem('sequoia_secure_yubikey_connection'),'required');assert.equal(d.settings.getItem('sequoia_secure_yubikey_beta_pin'),'enabled');assert.equal(d.settings.getItem('sequoia_hardware_transport'),'smartcard');assert.equal(await digest(f.snapshot),hash);
 assert.deepEqual((await capture(d,origin)).databases,f.snapshot.databases);assert.equal(d.settings.getItem(PENDING),null);
});
test('backup cannot introduce beta trust or replace local SCP policy',async()=>{
 const f=await fixture();f.snapshot.settings.push(['sequoia_secure_yubikey_connection','off'],['sequoia_secure_yubikey_beta_pin','enabled']);
 const d=storage();d.settings.setItem('sequoia_secure_yubikey_connection','required');await restore(d,f.snapshot,origin);
 assert.equal(d.settings.getItem('sequoia_secure_yubikey_connection'),'required');assert.equal(d.settings.getItem('sequoia_secure_yubikey_beta_pin'),null);
});
test('preserving connection settings does not permit conflicting certificate trust',async()=>{
 const f=await fixture(),d=storage();d.settings.setItem('sequoia_secure_yubikey_beta_pin','enabled');d.db.set(DATABASES[2][0],{format:'sequoia-iwa-certificates',version:1,bindings:[]});
 await assert.rejects(restore(d,f.snapshot,origin),/database differs/);assert.equal(d.db.size,1);assert.equal(d.settings.getItem(PENDING),null);
});
test('interrupted restore with local SCP policy resumes and verifies',async()=>{
 const f=await fixture(),d=storage(),put=d.put;d.settings.setItem('sequoia_secure_yubikey_connection','required');let n=0;d.put=async(...a)=>{if(++n===2)throw Error('interrupted');return put(...a);};
 await assert.rejects(restore(d,f.snapshot,origin));d.put=put;await restore(d,f.snapshot,origin);assert.equal(d.settings.getItem(PENDING),null);assert.equal(d.settings.getItem('sequoia_secure_yubikey_connection'),'required');
});
