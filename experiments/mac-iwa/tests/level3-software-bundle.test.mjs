import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {deflateSync,inflateSync} from 'node:zlib';
import {createPivImporter} from '../app/piv-import.js';
import {level3Layout,USER_PIV_SLOTS} from '../app/piv-backup-plan.js';
import {encodeLevel3ProvisioningBundle} from '../app/provisioning/public-bundle.js';
import {provisionLevel3} from '../app/provisioning/level3-transaction.js';
import {createLevel3SoftwareSigner} from '../app/provisioning/software-signer.js';
import {createCertificateVerifier} from '../app/provisioning/certificate-verifier.js';
import {Vault,b64,random} from '../app/vault/core.js';
import {createSoftwareIdentityStore} from '../app/software/store.js';
import init,{software_generate,software_backup_material,inspect_bundle,inspect_identity} from '../app/wasm/sequoia_iwa_verify.js';

const raw=value=>Uint8Array.from(atob(value),c=>c.charCodeAt(0));

test('software keys produce independently verified RFC 9980, S/MIME and experimental NIST certificates before card import',async()=>{
 await init({module_or_path:fs.readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});
 const context={Uint8Array,TextEncoder,TextDecoder,atob,btoa,crypto};context.globalThis=context;
 vm.createContext(context);
 vm.runInContext(fs.readFileSync(new URL('../app/smartcard-piv.js',import.meta.url),'utf8'),context);
 const piv=context.SequoiaSmartCardPiv;
 globalThis.SequoiaSmartCardPiv=piv;
 globalThis.SequoiaSecureChannel={isRequired:()=>true};
 const card=createPivImporter({promptManagement:()=>assert.fail('Test must never authenticate a physical card')});
 const email='software-certs@example.invalid',serial='12345678';
 const inspect=certificate=>JSON.parse(inspect_identity(JSON.stringify({certificate})));
 const inspectBundle=bundle=>JSON.parse(inspect_bundle(JSON.stringify({bundle})));
 const localVault=new Vault(),secret=random(32);
 const wrapper={id:crypto.randomUUID(),type:'prf',name:'Synthetic PRF',binding:{credentialId:b64(random(32))}};
 await localVault.create(wrapper,secret);
 const store=createSoftwareIdentityStore({
  access:{
   snapshot:()=>({unlocked:localVault.unlocked,vaultId:localVault.record.id,epoch:1,
    revision:localVault.record.revision,items:localVault.data.items}),
   assertCurrent:async state=>assert.equal(state.revision,localVault.record.revision),
   replaceItems:async items=>{localVault.data.items=items;await localVault.save();},
  },
  inspectPublic:inspect,entropyCollector:async()=>random(32),
  cryptoCall:async(op,input)=>{
   if(op==='generate')return JSON.parse(software_generate(JSON.stringify(input)));
   assert.equal(op,'backup-material');
   return JSON.parse(software_backup_material(JSON.stringify(input)));
  },
 });
 const identity=await store.create({name:'Test',profile:'level3',includeSmime:true,includeNist:true,entropy:true},email);
 const plan=level3Layout({profile:'level3',serial,mode:'backup',includeSmime:true,includeExperimentalNist:true});
 const {material}=await store.prepareCombinedBackup(identity,plan,undefined,{existingOnly:true});
 const verify=await createCertificateVerifier(piv);
 let stage,baseBundle,committed=false;
 card.inspect=async()=>({serial,slots:USER_PIV_SLOTS.map(slot=>({slot,keyPresent:false,certificatePresent:false})),supportedAlgorithms:material.map(row=>row.algorithm)});
 card.importAll=async(plan,keys,options)=>{
  assert.deepEqual(options.bundle,stage.bundle);
  assert.deepEqual(stage.certificates.rfc9980,raw(identity.certificate));
  assert.equal(localVault.data.items[0].stagedProvisioning.bundle,b64(stage.bundle));
  assert.equal(localVault.data.items[0].hardware,undefined);
  assert(!JSON.stringify(localVault.record).includes(b64(stage.bundle)));
  for(const slot of plan.keys.map(key=>key.slot)){await options.attempting(slot);await options.completed(slot);}
  await options.bundleAttempting(0x5f5000);await options.bundleCompleted(0x5f5000);
  return card.plannedPublicKeys(plan,keys);
 };
 await provisionLevel3({review:{plan,email,identity,name:'Test'},
  confirmed:true,card,verify,inspectRfc9980:inspect,inspectBundle,createSoftwareSigner:createLevel3SoftwareSigner,
  guard:()=>{},withTouch:()=>assert.fail('Software certificate issuance must not request PIV PIN or touch'),
  journal:{save:async()=>{}},vault:{prepareBackup:async()=>material,
   stageCertificates:async input=>{
    await store.stageProvisioningCertificates(input);
    stage=input;
    const signer=await createLevel3SoftwareSigner(material);
    const {experimentalNist:_experimental,...base}=input.certificates;
    baseBundle=await encodeLevel3ProvisioningBundle(plan,base,signer.signBundle);
   },
   saveCertificates:async input=>{
    assert.equal(stage.certificates,input.certificates);
    await store.saveProvisioned(input);
    committed=true;
   }}});
 assert.equal(localVault.data.items[0].stagedProvisioning,undefined);
 assert.equal(localVault.data.items[0].hardware.serial,serial);
 assert.equal(localVault.data.items[0].hardware.slots.length,10);
 assert.equal(localVault.data.items[0].provisioned.experimentalNist,b64(stage.certificates.experimentalNist.certificate));
 localVault.lock();secret.fill(0);
 assert(committed);
 assert(material.every(row=>!row.seed.some(Boolean)));
 const bundleInfo=inspectBundle(Buffer.from(stage.bundle).toString('base64'));
 assert.equal(bundleInfo.bundleSignatureVerified,true);
 assert.equal(bundleInfo.slots.length,8);
 assert(bundleInfo.warnings.some(message=>message.includes('signed optional material')));
 const baseInfo=inspectBundle(Buffer.from(baseBundle).toString('base64'));
 assert.equal(baseInfo.bundleSignatureVerified,true);
 assert.deepEqual(baseInfo.slots,bundleInfo.slots);
 const envelope=inflateSync(stage.bundle.subarray(12));
 const nistAt=envelope.indexOf(stage.certificates.experimentalNist.certificate);
 assert(nistAt>0);
 // Recompress successfully after modifying the optional certificate. The
 // signed envelope, rather than zlib integrity, must detect the change.
 envelope[nistAt+25]^=1;
 const altered=Buffer.concat([stage.bundle.subarray(0,12),deflateSync(envelope)]);
 assert.throws(()=>inspectBundle(altered.toString('base64')));
});
