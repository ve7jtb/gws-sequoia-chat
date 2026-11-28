import test from 'node:test';import assert from 'node:assert/strict';
import {vaultPolicy,prepareVaultMaterial} from '../app/vault/hardware.js';
test('policy is firmware based, not tied to a test serial',()=>{assert.equal(vaultPolicy('5.8.0'),'classical');assert.equal(vaultPolicy('6.0.0'),'hybrid');assert.throws(()=>vaultPolicy(null));assert.throws(()=>vaultPolicy('4.0.0'));});
function setup(version='6.0.0'){
 const calls=[],bundle={serial:'123',bundleHash:'a'.repeat(64),slots:[{slot:'9d'}],certificates:[{certificate:'CERT'}]};
 return {calls,bundle,serial:'123',piv:{readVaultMaterialViaSmartCard:async o=>{calls.push(o);if(o.level5Only)return null;return {version,serial:'123',classical:{algorithm:'ECDH-P384'}};},readPublicSnapshotViaSmartCard:async()=>{calls.push('bundle');return {};}},inspectBundle:async()=>bundle,parseCardBundle:async()=>bundle,inspectIdentity:async()=>({supported:true,version:6,profile:'level3',recipientKey:'R',certificate:'CERT'}),store:{previewBundle:async()=>{calls.push('preview');return {};},save:async()=>calls.push('save')}};
}
test('YK6 restores verified bundle and selects hybrid, no classical probe',async()=>{const f=setup(),m=await prepareVaultMaterial(f);assert.equal(m.classicalAllowed,false);assert.equal(m.identity.serial,'123');assert.deepEqual(f.calls.slice(2),['bundle','preview','save']);});
test('YK6 missing or unsupported bundle fails without classical fallback',async()=>{const f=setup();f.inspectIdentity=async()=>({supported:false});await assert.rejects(prepareVaultMaterial(f),/no classical fallback/);assert.equal(f.calls.includes('save'),false);});
test('YK5 uses existing P384 only, never public PQ bundle assumptions',async()=>{const f=setup('5.8.0');const m=await prepareVaultMaterial(f);assert.equal(m.classicalAllowed,true);assert.equal(f.calls.includes('bundle'),false);});
test('native Level 5 vault uses the detected PIV keys without an OpenPGP certificate',async()=>{
 const f=setup(),read=f.piv.readVaultMaterialViaSmartCard;
 f.piv.readVaultMaterialViaSmartCard=async o=>o.level5Only?{kemPublic:'kem',ecPublic:'ec'}:read(o);
 const m=await prepareVaultMaterial(f);
 assert.deepEqual(m,{serial:'123',level5:{kemPublic:'kem',ecPublic:'ec'},classicalAllowed:false});
 assert.equal(f.calls.includes('bundle'),false);
});

test('Level 3 unlock authenticates the exact enrolled recipient and selects only its two live slots',async()=>{
 const {prepareLevel3VaultUnlock}=await import('../app/vault/hardware.js');
 const recipientKey='F'.repeat(64),stages=[];
 const preview={serial:'123',bundleSignatureVerified:true,bundleHash:'a'.repeat(64),
  slots:['9c','85','9d','86'].map(slot=>({slot,publicKeySha256:slot.repeat(32)})),
  certificates:[{kind:'openpgp',profile:'level3',certificate:'primary'},
   {kind:'openpgp',profile:'level3-v4-hybrid',certificate:'compatibility'}]};
 const f={serial:'123',recipientKey,progress:event=>stages.push(event.stage),
  piv:{readLevel3VaultBundle:async serial=>{assert.equal(serial,'123');return {bundle:'packed'};}},
  inspectBundle:async bundle=>{assert.equal(bundle,'packed');return preview;},
  inspectIdentity:async cert=>{assert.equal(cert,'primary');return {certificate:cert,supported:true,version:6,profile:'level3',recipientKey};}};
 const identity=await prepareLevel3VaultUnlock(f);
 assert.deepEqual(identity.slots.map(key=>key.slot),['9d','85']);
 assert.deepEqual(stages,['verify','prepare']);
 await assert.rejects(prepareLevel3VaultUnlock({...f,recipientKey:'A'.repeat(64)}),/recipient changed/);
 preview.slots=preview.slots.filter(key=>key.slot!=='85');
 await assert.rejects(prepareLevel3VaultUnlock(f),/slot mapping/);
 preview.serial='456';
 await assert.rejects(prepareLevel3VaultUnlock(f),/signed vault bundle/);
 preview.serial='123';preview.bundleSignatureVerified=false;
 await assert.rejects(prepareLevel3VaultUnlock(f),/signed vault bundle/);
});
