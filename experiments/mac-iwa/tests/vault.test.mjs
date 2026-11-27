import test from 'node:test';import assert from 'node:assert/strict';
import {Vault,random,b64,bytes,validate} from '../app/vault/core.js';
import {classicalWrap,reduce} from '../app/vault/piv.js';
const wrapper=type=>({id:crypto.randomUUID(),type,name:type+' test',binding:type==='prf'?{salt:b64(random(32)),credentialId:b64(random(32))}:{kind:'hybrid',recipientKey:'A'.repeat(64),cipher:'test-envelope'}});
test('same vault unlocks with independent PIV and PRF wraps across restart',async()=>{const v=new Vault(),p=wrapper('piv'),f=wrapper('prf'),a=random(32),b=random(32);await v.create(p,a);v.data.items.push({name:'p12',password:'test-only secret',file:'secret bytes'});await v.save();await v.add(f,b);const saved=JSON.parse(JSON.stringify(v.record));assert.equal(saved.default,p.id);assert(!JSON.stringify(saved).includes('test-only secret'));v.lock();assert.equal(v.data,null);for(const [w,key] of [[p,a],[f,b]]){const reopened=new Vault();await reopened.unlock(saved,w.id,key);assert.equal(reopened.data.items[0].password,'test-only secret');reopened.lock();}});
test('wrong key, swapped vault/wrapper, ciphertext and metadata tampering fail closed',async()=>{const v=new Vault(),w=wrapper('prf'),key=random(32);await v.create(w,key);const saved=structuredClone(v.record);await assert.rejects(new Vault().unlock(saved,w.id,random(32)));for(const change of [r=>r.id=crypto.randomUUID(),r=>r.revision++,r=>r.wrappers[0].binding.credentialId='other',r=>r.body.cipher=b64(random(64)),r=>r.wrappers[0].box.cipher=b64(random(64))]){const r=structuredClone(saved);change(r);const reopened=new Vault();await assert.rejects(reopened.unlock(r,w.id,key));assert(!reopened.unlocked);}});
test('PIV becomes default; method rename/removal requires unlock; last method retained',async()=>{const v=new Vault(),f=wrapper('prf'),p=wrapper('piv'),key=random(32);await v.create(f,key);await assert.rejects(v.remove(f.id));await v.add(p,random(32));assert.equal(v.record.default,p.id);await v.rename(p.id,'My older key');assert.equal(v.record.wrappers[1].name,'My older key');await v.remove(p.id);assert.equal(v.record.default,f.id);const saved=structuredClone(v.record);v.lock();await assert.rejects(v.add(p,key));await v.unlock(saved,f.id,key);assert(v.unlocked);});
for(const curve of ['P-256','P-384'])test('classical '+curve+' PIV wrapping matches private ECDH and unlocks vault',async()=>{const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:curve},true,['deriveBits']);const publicKey=b64(await crypto.subtle.exportKey('spki',pair.publicKey));const r=await classicalWrap({algorithm:curve==='P-256'?'ECDH-P256':'ECDH-P384',public:publicKey,fingerprint:'test',serial:'test',slot:'82'});const peer=await crypto.subtle.importKey('spki',bytes(r.binding.peer),{name:'ECDH',namedCurve:curve},false,[]);const secret=await reduce(new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:peer},pair.privateKey,curve==='P-256'?256:384)));assert.deepEqual(secret,r.secret);const v=new Vault(),w={...wrapper('piv'),binding:r.binding};await v.create(w,r.secret);const saved=structuredClone(v.record);v.lock();await v.unlock(saved,w.id,secret);assert(v.unlocked);});
test('unsupported/empty vault and duplicate wrappers rejected',async()=>{assert.throws(()=>validate({}));const v=new Vault(),w=wrapper('prf'),key=random(32);await v.create(w,key);await assert.rejects(v.add({...w,id:crypto.randomUUID()},key));});


test('post-provisioning PIV enrollment preserves the default and both methods unlock',async()=>{
 const vault=new Vault(),original=wrapper('prf'),provisioned=wrapper('piv');
 const originalKey=random(32),newKey=random(32);
 await vault.create(original,originalKey);
 await vault.add(provisioned,newKey,{makeDefault:false});
 const saved=structuredClone(vault.record);
 assert.equal(saved.default,original.id);
 vault.lock();
 for(const [method,key] of [[original,originalKey],[provisioned,newKey]]){
  await vault.unlock(saved,method.id,key);
  assert(vault.unlocked);
  vault.lock();
 }
});
