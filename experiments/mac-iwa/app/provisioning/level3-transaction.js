import {level3Layout,planLevel3Provisioning} from '../piv-backup-plan.js';
import {issueProvisionedLevel3} from './level3-issuance.js';
import {issueRfc9980V6} from './nist-v6-certificates.js';
import {createLevel3CardSigner} from './card-signer.js';
import {encodeLevel3ProvisioningBundle,PROVISIONING_BUNDLE_BANK} from './public-bundle.js';
import {b64} from '../vault/core.js';

// Journal before each mutation. A lost response leaves the slot marked
// attempted, so the next run cannot treat the same card as unprovisioned.
export async function provisionLevel3({review,card,piv,vault,verify,inspectRfc9980,promptPin,createSoftwareSigner,inspectBundle,
 confirmed=false,guard,signal,journal,resume,withTouch=(_serial,_guard,perform)=>perform(promptPin)}){
 if(!confirmed||!review||typeof guard!=='function'||typeof journal?.save!=='function'||
    typeof verify?.rfc9980!=='function'||typeof inspectRfc9980!=='function')
  throw Error('A reviewed Level 3 transaction and certificate verification are required.');
 const mode=review.plan.operation==='generate-on-card'?'on-card':'backup';
 const check=async()=>{
  if(signal?.aborted)throw Error('Provisioning cancelled.');
  await guard();
  if(signal?.aborted)throw Error('Provisioning cancelled.');
 };
 const options={profile:'level3',mode,serial:review.plan.serial,expectedSerial:review.plan.serial,
  includeSsh:!!review.plan.ssh,includeSmime:!!review.plan.certificates.smime,includeExperimentalNist:!!review.plan.certificates.experimentalNist};
 const plan=resume?level3Layout(options):planLevel3Provisioning({...options,...await card.inspect(review.plan.serial)});
 if(JSON.stringify(plan)!==JSON.stringify(review.plan))throw Error('The reviewed plan changed.');
 if((plan.certificates.smime&&typeof verify.smime!=='function')||
    (plan.certificates.experimentalNist&&typeof verify.experimentalNist!=='function'))
  throw Error('Selected certificate verification is unavailable.');
 const slots=plan.keys.map(key=>key.slot);
 if(resume&&(mode!=='backup'||resume.version!==1||resume.serial!==plan.serial||
    resume.operation!==plan.operation||resume.state!=='issuing'||resume.attempted!==null||
    !Array.isArray(resume.completed)||JSON.stringify(resume.completed)!==JSON.stringify(slots)||
    (resume.identityId&&resume.identityId!==review.identity?.identityId)||!review.identity))
  throw Error('Certificate recovery requires a complete matching import journal.');
 const record=resume?structuredClone(resume):{version:1,serial:plan.serial,operation:plan.operation,completed:[],state:'prepared',attempted:null,includeSsh:!!plan.ssh};
 let material;
 try{
  await check();
  const writeOptions={signal,guard:check,
   attempting:async slot=>{record.state='writing';record.attempted=slot;await journal.save(record);},
   completed:async slot=>{record.completed.push(slot);record.attempted=null;await journal.save(record);},
  };
  const originalRfc9980=async({email})=>{
   // Preserve the independently verified software certificate and fingerprint.
   const original=await inspectRfc9980(review.identity.certificate);
   if(!original.supported||original.profile!=='level3'||!original.emails.includes(email))
    throw Error('Software source certificate failed independent verification.');
   return Uint8Array.from(atob(review.identity.certificate),byte=>byte.charCodeAt(0));
  };
  const issue=(readPublicKeys,sign,rfc9980)=>issueProvisionedLevel3({
   plan,email:review.email,aliases:review.aliases,guard:check,verify,
   provider:{serial:plan.serial,operation:plan.operation,readPublicKeys,sign},
   rfc9980,
  });

  if(mode==='backup'&&!resume){
   if(typeof createSoftwareSigner!=='function'||typeof inspectBundle!=='function'||
      typeof vault.stageCertificates!=='function'||typeof card.plannedPublicKeys!=='function')
    throw Error('Software certificate and bundle verification are required before import.');
   material=await vault.prepareBackup(review,plan);
   await check();
   const rows=await card.plannedPublicKeys(plan,material);
   const signer=await createSoftwareSigner(material);
   const certificates=await issue(async()=>rows,signer.sign,originalRfc9980);
   await check();
   const bundle=await encodeLevel3ProvisioningBundle(plan,certificates,signer.signBundle);
   const verified=await inspectBundle(b64(bundle),{signal});
   const boundSlots=new Map(verified.slots?.map(row=>[row.slot,row.publicKeySha256]));
   const baseSlots=new Set([...Object.values(plan.certificates.rfc9980).flat(),
    ...Object.values(plan.certificates.smime.hybrid).flat()]);
   if(!verified.bundleSignatureVerified||verified.serial!==plan.serial||
      boundSlots.size!==baseSlots.size||rows.some(row=>baseSlots.has(row.slot)&&boundSlots.get(row.slot)!==row.publicKeySha256))
    throw Error('Signed certificate bundle does not match the reviewed software keys.');
   await check();
   await vault.stageCertificates({review,plan,readback:rows,certificates,bundle,guard:check});
   await check();
   record.identityId=review.identity.identityId;
   await journal.save(record);
   const readback=await card.importAll(plan,material,{...writeOptions,bundle,
    bundleAttempting:async tag=>{record.state='writing-bundle';record.attemptedBundleObject=tag;await journal.save(record);},
    bundleCompleted:async tag=>{record.lastVerifiedBundleObject=tag;record.attemptedBundleObject=null;await journal.save(record);},
   });
   if(record.completed.join()!==slots.join()||!readback||record.lastVerifiedBundleObject!==PROVISIONING_BUNDLE_BANK)
    throw Error('Incomplete card or certificate bundle readback.');
   record.state='bundle-verified';await journal.save(record);
   await vault.saveCertificates({review,plan,readback,certificates,bundle,guard:check});
   record.state='saved';await journal.save(record);
   return {serial:plan.serial,defaultOpenPgp:certificates.defaultOpenPgp};
  }

  let readback,readCurrent;
  if(resume){
   // Older journals did not include an identity ID. Match every staged
   // public key before requesting a PIN or performing any signatures.
   const expected=await vault.recoveryPublicKeys(review,plan);
   readCurrent=()=>card.verifyImportedKeys(plan,expected);
  }else{
   if(review.identity?.identityId)record.identityId=review.identity.identityId;
   await journal.save(record);
   await card.generateAll(plan,writeOptions);
   if(record.completed.join()!==slots.join())throw Error('Incomplete card write acknowledgements.');
   readCurrent=()=>card.readPublicKeys(plan);
  }
  await check();
  readback=await readCurrent();
  await check();
  const sign=request=>withTouch(plan.serial,check,(prompt,beforeSign,onStall)=>
   createLevel3CardSigner({piv,plan,readback,promptPin:prompt,guard:check,beforeSign,onStall})(request));
  if(review.identity?.identityId)record.identityId=review.identity.identityId;
  record.state='issuing';await journal.save(record);
  const certificates=await issue(readCurrent,sign,mode==='backup'?originalRfc9980:async({email,publicKeys,sign})=>{
   const keys=Object.fromEntries(Object.entries(publicKeys).map(([role,[pq,ec]])=>[role,{pq,ec}]));
   const {certificate}=await issueRfc9980V6({email,keys,sign,verify:verify.rfc9980});
   const independent=await inspectRfc9980(b64(certificate));
   if(!independent.supported||independent.profile!=='level3'||!independent.emails.includes(email))
    throw Error('The new RFC 9980 certificate failed independent validation.');
   return certificate;
  });
  await check();
  // Persistence is a single encrypted vault commit. Key retention is the
  // default. Removal is a separate feature gated by independent recovery.
  await vault.saveCertificates({review,plan,readback,certificates,guard:check});
  record.state='saved';await journal.save(record);
  return {serial:plan.serial,defaultOpenPgp:certificates.defaultOpenPgp};
 }finally{
  for(const component of material||[])component.seed?.fill(0);
 }
}
