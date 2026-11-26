// Transaction coordinator for copying an existing identity to an empty card.
// The adapter owns serial-checked SCP transactions, import APDUs and independent
// signature/KEM verification. The vault owns CAS persistence and key disposal.
// This layer neither invents keys nor accepts a UI-supplied success receipt.
import {planPivBackup} from './piv-backup-plan.js';
const identical=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
export function createProvisioning({card,vault,journal}){
 let active=false,review=null,verified=null;
 const fail=message=>{throw Error(message);};
 async function discover(identity){
  if(active)fail('Finish the current provisioning operation first.');
  verified=null;review=null;
  await vault.assert(identity);
  const snapshot=await card.inspect();
  const plan=planPivBackup({profile:identity.profile,...snapshot});
  await vault.assert(identity);
  // The identity binding and serial are retained privately; subsequent writes
  // may not substitute a different device or a similarly named identity.
  review={id:crypto.randomUUID(),identity:structuredClone(identity),plan,expires:Date.now()+300000};
  return {id:review.id,plan:structuredClone(plan),fingerprint:identity.fingerprint};
 }
 async function provision(id,{confirmed=false,signal}={}){
  if(active||!confirmed||!review||review.id!==id||Date.now()>review.expires)fail('Review the detected YubiKey and confirm the current import plan.');
  const selected=review;review=null;active=true;verified=null;
  const guard=async()=>{if(signal?.aborted)fail('Provisioning cancelled.');await vault.assert(selected.identity);};
  let material;
  try{
   await guard();
   const live=await card.inspect(selected.plan.serial);
   const plan=planPivBackup({profile:selected.identity.profile,...live,expectedSerial:selected.plan.serial});
   if(!identical(plan,selected.plan))fail('Card capabilities or import plan changed.');
   // Commit the public journal before the first irreversible card write. No
   // plaintext key, management key or PIN may be stored in this record.
   const record={version:1,id,serial:plan.serial,fingerprint:selected.identity.fingerprint,certificateHash:selected.identity.certificateHash,plan,completed:[],state:'prepared'};
   await journal.save(record);await guard();
   material=await vault.material(selected.identity,plan,{signal});await guard();
   if(!Array.isArray(material)||material.length!==plan.keys.length)fail('Incomplete source key material.');
   // importAll must re-check emptiness *inside* its exclusive card transaction.
   // This callback journals each acknowledged slot. Any failure stops; there is
   // no retry, rollback, slot deletion or software-key deletion on error.
   await card.importAll(plan,material,{signal,guard,completed:async slot=>{
    if(!plan.keys.some(k=>k.slot===slot)||record.completed.includes(slot))fail('Invalid import acknowledgement.');
    record.completed.push(slot);record.state='partial';await journal.save(record);
   }});
   if(record.completed.length!==plan.keys.length)fail('Not all imports were acknowledged.');
   await guard();
   const proof=await card.verify(plan,selected.identity,{signal});await guard();
   if(proof?.publicKeysMatch!==true||proof?.signingVerified!==true||proof?.decryptionVerified!==true)fail('Hardware verification did not pass; software keys retained.');
   // Persist a usable, independently validated hardware identity and its public
   // certificates BEFORE offering removal. A bare card import is insufficient.
   const hardware=await vault.saveHardware(selected.identity,plan,proof);
   await vault.assertHardware(hardware);
   record.state='verified';await journal.save(record);
   verified={id,identity:hardware.identity||selected.identity,hardware,serial:plan.serial};
   return {id,serial:plan.serial,verified:true,canRemoveSoftwareKeys:true};
  }finally{
   // Clear mutable buffers on every path, including partial imports. Browser
   // runtimes may retain copies; software custody is never hardware isolation.
   for(const key of material||[]){key.seed?.fill?.(0);key.privateKey?.fill?.(0);}material=null;active=false;
  }
 }
 async function removeSoftwareKeys(id,{confirmed=false}={}){
  if(active||!confirmed||!verified||verified.id!==id)fail('Successful hardware verification and separate removal confirmation are required.');
  active=true;const done=verified;verified=null;
  try{
   await vault.assert(done.identity);await vault.assertHardware(done.hardware);
   // Atomic vault mutation must retain public certificates and slot mappings.
   // Earlier exported encrypted backups cannot be revoked by this operation.
   await vault.removePrivate(done.identity,done.hardware);
   return {removed:true,serial:done.serial};
  }finally{active=false;}
 }
 return {discover,provision,removeSoftwareKeys};
}
