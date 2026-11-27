// Real WASM generates disposable keys; all card readbacks below are simulated.
// No card transport, PIN or management key is reachable from this test.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
const variant=process.env.IWA_WASM_VARIANT||'wasm';
assert(['wasm','wasm-wide'].includes(variant));
const {default:init,software_generate,software_backup_material,inspect_identity}=await import('../app/'+variant+'/sequoia_iwa_verify.js');
import {Vault,b64,random} from '../app/vault/core.js';
import {createSoftwareIdentityStore} from '../app/software/store.js';
import {level3Layout} from '../app/piv-backup-plan.js';
import {validateSshKeys,sshPublicLine} from '../app/vault/ssh-keys.js';
globalThis.self=globalThis;
await init({module_or_path:fs.readFileSync(new URL('../app/'+variant+'/sequoia_iwa_verify_bg.wasm',import.meta.url))});
test('PRF-mixed WASM keys persist across two card imports and encrypted vault restore',async()=>{
 const vault=new Vault(),secret=random(32),wrapper={id:crypto.randomUUID(),type:'prf',name:'Synthetic PRF',binding:{credentialId:b64(random(32))}};
 await vault.create(wrapper,secret);
 let revision=vault.record.revision;
 const snapshot=()=>({unlocked:vault.unlocked,vaultId:vault.record.id,epoch:1,revision,items:vault.data.items});
 let generation=0;
 const store=createSoftwareIdentityStore({access:{snapshot,assertCurrent:async s=>assert.equal(s.revision,revision),replaceItems:async items=>{vault.data.items=items;await vault.save();revision=vault.record.revision;}},
  inspectPublic:async certificate=>JSON.parse(inspect_identity(JSON.stringify({certificate}))),
  entropyCollector:async()=>random(32),cryptoCall:async(op,input)=>{
   if(op==='generate'){generation++;return JSON.parse(software_generate(JSON.stringify(input)));}
   assert.equal(op,'backup-material');return JSON.parse(software_backup_material(JSON.stringify(input)));
  }});
 const email='ssh@example.invalid';
 let selected=await store.create({name:'Disposable SSH',profile:'level3',includeSmime:true,includeNist:true,includeSsh:true,entropy:true},email);
 const savedKeys=structuredClone(validateSshKeys(vault.data.items[0].sshKeys));
 assert.notEqual(savedKeys.pq.seed,savedKeys.ed.seed);
 // Independently derive Ed25519 from the seed and prove the public key signs.
 const privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(savedKeys.ed.seed,'base64')]),format:'der',type:'pkcs8'});
 assert.equal(createPublicKey(privateKey).export({format:'der',type:'spki'}).subarray(-32).toString('base64'),savedKeys.ed.publicKey);
 assert(verify(null,Buffer.from('synthetic SSH check'),createPublicKey(privateKey),sign(null,Buffer.from('synthetic SSH check'),privateKey)));
 let first;
 for(const serial of ['12345678','87654321']){
  const plan=level3Layout({profile:'level3',serial,includeSmime:true,includeExperimentalNist:true,includeSsh:true});
  const prepared=await store.prepareCombinedBackup(selected,plan,()=>assert.fail('Must reuse NIST keys'),{existingOnly:true});
  const material=prepared.material.map(k=>({...k,seed:b64(k.seed),publicKey:b64(k.publicKey)}));
  if(first)assert.deepEqual(material,first);else first=structuredClone(material);
  const readback=await Promise.all(prepared.material.map(async k=>({slot:k.slot,publicKey:k.publicKey,publicKeySha256:Buffer.from(await crypto.subtle.digest('SHA-256',k.publicKey)).toString('hex')})));
  await store.saveProvisioned({review:{identity:prepared.identity,email,name:selected.name},plan,readback,certificates:{rfc9980:Buffer.from(selected.certificate,'base64')},guard:async()=>{}});
  for(const k of prepared.material)k.seed.fill(0);
  selected=await store.get(selected.id,email);
 }
 assert.equal(generation,1);
 assert.equal(vault.data.items[0].hardware.serial,'12345678');
 assert.deepEqual(vault.data.items[0].hardwareCopies.map(k=>k.serial),['12345678','87654321']);
 const disk=structuredClone(vault.record),second=new Vault();
 assert(!JSON.stringify(disk).includes(savedKeys.pq.seed));
 await second.unlock(disk,wrapper.id,secret);
 assert.deepEqual(second.data.items,vault.data.items);
 assert.deepEqual(second.data.items[0].sshKeys,savedKeys);
 // Independently validate the ML-DSA seed/public correspondence with OpenSSL,
 // rather than accepting the generator's own public bytes as the oracle.
 const pqPrivate=createPrivateKey({key:Buffer.concat([Buffer.from('3034020100300b060960864801650304031104228020','hex'),Buffer.from(savedKeys.pq.seed,'base64')]),format:'der',type:'pkcs8'});
 assert.equal(createPublicKey(pqPrivate).export({format:'der',type:'spki'}).subarray(-1312).toString('base64'),savedKeys.pq.publicKey);
 assert(verify(null,Buffer.from('synthetic PQ check'),createPublicKey(pqPrivate),sign(null,Buffer.from('synthetic PQ check'),pqPrivate)));
 const line=sshPublicLine(Buffer.from(savedKeys.pq.publicKey,'base64'),Buffer.from(savedKeys.ed.publicKey,'base64'));
 assert.equal(line,second.data.items[0].provisioned.ssh.publicKey);
 const blob=Buffer.from(line.split(' ')[1],'base64'),offset=4+blob.readUInt32BE(0);
 assert.equal(blob.readUInt32BE(offset),1344);
 assert.equal(blob.subarray(offset+4,offset+4+1312).toString('base64'),savedKeys.pq.publicKey);
 second.lock();vault.lock();
});
test('WASM refuses SSH generation without the PRF contribution',()=>{
 assert.throws(()=>software_generate(JSON.stringify({name:'No entropy',email:'ssh@example.invalid',profile:'level3',password:'disposable test password',includeSsh:true})),/generation rejected/);
});
