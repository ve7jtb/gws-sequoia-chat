import {digest,seal,unseal,PENDING} from '../complete-backup.js';

// Same-document capability for backup. The UI can seal a snapshot or hand
// over a verified Vault instance. It has no getter for the live key.
export let backupVaultSession;
export function registerBackupVaultSession(session){
 if(backupVaultSession)throw Error('The vault backup session is already registered.');
 backupVaultSession=Object.freeze(session);
}

export function createBackupVaultAccess({current,load,settings,origin,activate,touch}){
 const check=(started,expected)=>{
  const now=current();
  if(now.epoch!==started.epoch||now.engine!==started.engine||now.revision!==started.revision||!expected.unlocked)
   throw Error('The vault changed during backup. Try again.');
  return now;
 };
 return {
  unlocked:()=>current().engine.unlocked&&current().revision>0,
  async create(snapshot){
   const started=current(),{engine,revision}=started;
   if(started.active)throw Error('Finish the current vault operation first.');
   if(!engine.unlocked||!revision)throw Error('Unlock the current source vault first.');
   const box=await seal(snapshot,engine);
   const verified=await unseal(box,engine,origin);
   if(await digest(snapshot)!==await digest(verified))throw Error('Encrypted backup verification failed.');
   check(started,engine);
   touch();
   return box;
  },
  async adopt(candidate,{restored=false}={}){
   const started=current();
   if(started.active||!candidate.unlocked)throw Error('The verified vault is no longer available.');
   const expected=await digest(candidate.record),saved=await load();
   if(!saved||await digest(saved)!==expected||settings.getItem(PENDING))
    throw Error('The saved vault changed. Unlock the current vault.');
   if(started.engine.unlocked&&await digest(started.engine.record)!==expected)
    throw Error('The current vault is different.');
   if(check(started,candidate).active)throw Error('Finish the current vault operation first.');
   activate(candidate,saved,restored);
  },
 };
}
