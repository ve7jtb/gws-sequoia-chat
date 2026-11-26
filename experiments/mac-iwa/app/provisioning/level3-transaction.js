import {planLevel3Provisioning} from '../piv-backup-plan.js';
import {issueProvisionedLevel3} from './level3-issuance.js';
import {issueRfc9980V6} from './nist-v6-certificates.js';
import {createLevel3CardSigner} from './card-signer.js';
import {b64} from '../vault/core.js';

// Journal before each mutation. A lost response leaves the slot marked
// attempted, so the next run cannot treat the same card as unprovisioned.
export async function provisionLevel3({review,card,piv,vault,verify,inspectRfc9980,promptPin,
 confirmed=false,guard,signal,journal}){
 if(!confirmed||!review||typeof guard!=='function'||typeof journal?.save!=='function'||
    typeof verify?.rfc9980!=='function'||typeof inspectRfc9980!=='function')
  throw Error('A reviewed Level 3 transaction and certificate verification are required.');
 const mode=review.plan.operation==='generate-on-card'?'on-card':'backup';
 const check=async()=>{
  if(signal?.aborted)throw Error('Provisioning cancelled.');
  await guard();
  if(signal?.aborted)throw Error('Provisioning cancelled.');
 };
 const plan=planLevel3Provisioning({profile:'level3',mode,...await card.inspect(review.plan.serial),
  expectedSerial:review.plan.serial,includeSmime:!!review.plan.certificates.smime,
  includeExperimentalNist:!!review.plan.certificates.experimentalNist});
 if(JSON.stringify(plan)!==JSON.stringify(review.plan))throw Error('The reviewed plan changed.');
 if((plan.certificates.smime&&typeof verify.smime!=='function')||
    (plan.certificates.experimentalNist&&typeof verify.experimentalNist!=='function'))
  throw Error('Selected certificate verification is unavailable.');
 const record={version:1,serial:plan.serial,operation:plan.operation,completed:[],state:'prepared',attempted:null};
 let material;
 try{
  await check();
  // On the backup path, prepareBackup must commit all independent secret
  // components to the encrypted vault before returning import material.
  if(mode==='backup')material=await vault.prepareBackup(review,plan);
  await check();
  await journal.save(record);
  const options={signal,guard:check,
   attempting:async slot=>{record.state='writing';record.attempted=slot;await journal.save(record);},
   completed:async slot=>{record.completed.push(slot);record.attempted=null;await journal.save(record);},
  };
  if(mode==='backup')await card.importAll(plan,material,options);
  else await card.generateAll(plan,options);
  if(record.completed.join()!==plan.keys.map(key=>key.slot).join())
   throw Error('Incomplete card write acknowledgements.');
  await check();
  const readback=await card.readPublicKeys(plan);
  const sign=createLevel3CardSigner({piv,plan,readback,promptPin,guard:check});
  record.state='issuing';await journal.save(record);
  const certificates=await issueProvisionedLevel3({
   plan,email:review.email,aliases:review.aliases,guard:check,verify,
   provider:{serial:plan.serial,operation:plan.operation,readPublicKeys:()=>card.readPublicKeys(plan),sign},
   rfc9980:async({email,publicKeys,sign})=>{
    if(mode==='backup'){
     // The imported RFC 9980 identity already has a verified self-signature.
     // Retain the certificate bytes and fingerprint of the software source.
     const original=await inspectRfc9980(review.identity.certificate);
     if(!original.supported||original.profile!=='level3'||!original.emails.includes(email))
      throw Error('Software source certificate failed independent verification.');
     return Uint8Array.from(atob(review.identity.certificate),byte=>byte.charCodeAt(0));
    }
    const keys=Object.fromEntries(Object.entries(publicKeys).map(([role,[pq,ec]])=>[role,{pq,ec}]));
    const {certificate}=await issueRfc9980V6({email,keys,sign,verify:verify.rfc9980});
    const independent=await inspectRfc9980(b64(certificate));
    if(!independent.supported||independent.profile!=='level3'||!independent.emails.includes(email))
     throw Error('The new RFC 9980 certificate failed independent validation.');
    return certificate;
   },
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
