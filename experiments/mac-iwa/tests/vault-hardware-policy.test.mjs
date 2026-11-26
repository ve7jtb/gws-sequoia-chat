import test from 'node:test';import assert from 'node:assert/strict';
import {vaultPolicy,prepareVaultMaterial} from '../app/vault/hardware.js';
test('policy is firmware based, not tied to a test serial',()=>{assert.equal(vaultPolicy('5.8.0'),'classical');assert.equal(vaultPolicy('6.0.0'),'hybrid');assert.throws(()=>vaultPolicy(null));assert.throws(()=>vaultPolicy('4.0.0'));});
function setup(version='6.0.0'){
 const calls=[],bundle={serial:'123',bundleHash:'a'.repeat(64),slots:[{slot:'9d'}],certificates:[{certificate:'CERT'}]};
 return {calls,bundle,serial:'123',piv:{readVaultMaterialViaSmartCard:async o=>{calls.push(o);return {version,serial:'123',classical:{algorithm:'ECDH-P384'}};},readPublicSnapshotViaSmartCard:async()=>{calls.push('bundle');return {};}},inspectBundle:async()=>bundle,parseCardBundle:async()=>bundle,inspectIdentity:async()=>({supported:true,version:6,profile:'level3',recipientKey:'R',certificate:'CERT'}),store:{previewBundle:async()=>{calls.push('preview');return {};},save:async()=>calls.push('save')}};
}
test('YK6 restores verified bundle and selects hybrid, no classical probe',async()=>{const f=setup(),m=await prepareVaultMaterial(f);assert.equal(m.classicalAllowed,false);assert.equal(m.identity.serial,'123');assert.deepEqual(f.calls.slice(1),['bundle','preview','save']);});
test('YK6 missing or unsupported bundle fails without classical fallback',async()=>{const f=setup();f.inspectIdentity=async()=>({supported:false});await assert.rejects(prepareVaultMaterial(f),/no classical fallback/);assert.equal(f.calls.includes('save'),false);});
test('YK5 uses existing P384 only, never public PQ bundle assumptions',async()=>{const f=setup('5.8.0');const m=await prepareVaultMaterial(f);assert.equal(m.classicalAllowed,true);assert.equal(f.calls.includes('bundle'),false);});
