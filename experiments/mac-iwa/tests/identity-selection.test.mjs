// Selection tests use only public synthetic certificates and a deterministic
// inspector. Native grants and private operations are never invoked here.
import test from 'node:test';import assert from 'node:assert/strict';
import {createIdentitySelection,nativeIdentity} from '../app/identities/selection.js';
const fp='A'.repeat(64),certHash='b'.repeat(64),bundleHash='c'.repeat(64),sign='D'.repeat(64),recipient='E'.repeat(64);
const account='me@example.invalid',certificate=btoa('public-only');
function setup(){
 const data={revision:1,identities:[{id:'yubikey:123',serial:'123',bundleSignatureVerified:true,liveKeysMatched:true,bundleHash,slots:[{slot:'9c',role:'signing'}],certificates:[{version:6,fingerprint:fp,certificateHash:certHash,certificate}]}]};
 const info={supported:true,fingerprint:fp,certificateHash:certHash,certificate,emails:[account],algorithms:['ML-DSA-65+Ed25519','ML-KEM-768+X25519'],signingFingerprint:sign,recipientKey:recipient};
 let matching=async({cipher,candidates})=>({cipherHash:[...new Uint8Array(await crypto.subtle.digest('SHA-256',Uint8Array.from(atob(cipher),c=>c.charCodeAt(0))))].map(b=>b.toString(16).padStart(2,'0')).join(''),recipientKey:recipient,matches:candidates.map(c=>({id:c.id,fingerprint:fp,certificateHash:certHash,recipientKey:recipient}))});
 const model=createIdentitySelection({store:{list:async()=>structuredClone(data)},inspect:async()=>structuredClone(info),match:r=>matching(r)});
 return {model,data,info,setMatch:f=>matching=f};
}
test('only reviewed mapped current v6 identities for the account can be selected',async()=>{
 const {model,data,info}=setup();let choices=(await model.list(account)).choices;assert.equal(choices.length,1);
 assert.deepEqual(nativeIdentity(choices[0]),{serial:'123',bundleHash,fingerprint:fp,certificateHash:certHash,email:account});
 assert.equal((await model.list('other@example.invalid')).choices.length,0);
 data.identities[0].liveKeysMatched=false;assert.equal((await model.list(account)).choices.length,0);
 data.identities[0].liveKeysMatched=true;data.identities[0].serial=null;assert.equal((await model.list(account)).choices.length,0);
 data.identities[0].serial='123';info.supported=false;assert.equal((await model.list(account)).choices.length,0);
});
test('revision, packet hash, mapping and certified email changes invalidate snapshots',async()=>{
 for(const mutate of [s=>s.data.revision++,s=>s.data.identities[0].slots[0].slot='84',s=>s.info.emails=[],s=>s.info.certificateHash='f'.repeat(64)]){
  const s=setup(),snapshot=(await s.model.list(account)).choices[0];mutate(s);await assert.rejects(s.model.assert(snapshot));
 }
});
test('native material must match every selected public identity field and subkey',async()=>{
 const {model}=setup(),s=(await model.list(account)).choices[0];
 const material={identity:nativeIdentity(s),senderCertificate:certificate,senderEmail:account,signingFingerprint:sign};
 assert.equal(await model.validateMaterial(material,s,'signing'),material);
 for(const field of ['serial','bundleHash','fingerprint','certificateHash','email']){
  const bad=structuredClone(material);bad.identity[field]='changed';await assert.rejects(model.validateMaterial(bad,s,'signing'),/selection changed/);
 }
 await assert.rejects(model.validateMaterial({...material,signingFingerprint:recipient},s,'signing'),/operation key/);
 await assert.rejects(model.validateMaterial({...material,recipientCertificate:certificate,recipientKey:sign},s,'decryption'),/operation key/);
});
test('recipient match returns all matching devices for explicit selection and never guesses',async()=>{
 const {model,data}=setup();data.identities.push({...structuredClone(data.identities[0]),id:'yubikey:456',serial:'456'});
 const matched=await model.match(btoa('ciphertext'),account);assert.equal(matched.choices.length,2);
 assert.deepEqual(matched.choices.map(c=>c.serial),['123','456']);
});
test('missing, duplicated and rebound recipient matches cannot reach hardware',async()=>{
 const s=setup(),cipher=btoa('ciphertext'),original=await s.model.match(cipher,account);
 s.setMatch(async()=>({...original,matches:[]}));await assert.rejects(s.model.match(cipher,account),/No saved/);
 s.setMatch(async()=>({cipherHash:'0'.repeat(64),matches:[]}));await assert.rejects(s.model.match(cipher,account),/bound/);
 const match={id:original.choices[0].id,fingerprint:fp,certificateHash:certHash,recipientKey:recipient};
 s.setMatch(async()=>({...original,matches:[match,match]}));await assert.rejects(s.model.match(cipher,account),/Invalid recipient/);
 s.setMatch(async()=>({...original,matches:[{...match,certificateHash:'0'.repeat(64)}]}));await assert.rejects(s.model.match(cipher,account),/Invalid recipient/);
});

test('manifest-backed v4/v5 and classical Level5 v6 preserve exact view, algorithms and custody',async()=>{
 for(const [version,profile,pqSigning,pqEncryption] of [[4,'level5-v4-hybrid-p384',false,true],[5,'level3-v5-hybrid',false,true],[6,'level5-v6-classical',false,false]]){
  const {model,data,info}=setup(),cert=data.identities[0].certificates[0];
  cert.version=info.version=version;cert.fingerprint=info.fingerprint='A'.repeat(version===4?40:64);
  Object.assign(info,{profile,pqSigning,pqEncryption,signingAlgorithm:version===5?'Ed25519':'ECDSA P-384',encryptionAlgorithm:pqEncryption?'ML-KEM-768 + X25519':'ECDH P-384'});
  cert.components=[{role:'signing-classical',algorithm:info.signingAlgorithm,storage:'piv',slot:'88',publicKey:btoa('public')}];
  const selected=(await model.list(account)).choices[0];
  assert.equal(selected.version,version);assert.equal(selected.profile,profile);assert.equal(selected.pqSigning,pqSigning);assert.equal(selected.pqEncryption,pqEncryption);
  assert.equal(selected.custody,'hardware');assert.deepEqual(selected.components,cert.components);
  const material={identity:nativeIdentity(selected),senderCertificate:certificate,senderEmail:account,signingFingerprint:sign,hardwareProfile:profile};
  await model.validateMaterial(material,selected,'signing');
  await assert.rejects(model.validateMaterial({...material,hardwareProfile:'level3'},selected,'signing'),/hardware profile/);
 }
});
test('companion selections stay hardware-bound and cannot silently become software providers',async()=>{
 const {model,data,info}=setup();Object.assign(info,{profile:'level5',pqSigning:true,pqEncryption:true});
 data.identities[0].id+=':companion';data.identities[0].companion={encoded:btoa('encrypted only'),serial:123,publicKeys:{'82':btoa('public')},certificate};
 const selected=(await model.list(account)).choices[0];assert.equal(selected.custody,'hardware-companion');assert.equal(selected.provider,undefined);
 assert.deepEqual(nativeIdentity(selected),{serial:'123',bundleHash,fingerprint:fp,certificateHash:certHash,email:account,certificate});
 data.identities[0].companion.encoded=btoa('different ciphertext');await assert.rejects(model.assert(selected),/changed/);
});
test('v4 certificate widths and version changes cannot be accepted as v6 identity metadata',async()=>{
 const {model,data,info}=setup();info.version=4;info.fingerprint='A'.repeat(40);
 await assert.rejects(model.list(account),/version changed/);
 data.identities[0].certificates[0].version=4;info.fingerprint='A'.repeat(64);
 await assert.rejects(model.list(account),/version changed/);
});
