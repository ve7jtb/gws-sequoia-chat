import {bytes,b64} from './core.js';
import {openPivWrapper} from './open-piv.js';

export function backupUnlockChoices(record,previous){
 const methods=record?.wrappers||[];
 return {methods,selected:methods.some(w=>w.id===previous)?previous:record?.default};
}

// Restore uses only the selected wrapper. There is no credential creation,
// automatic retry, or fallback to a different credential or transport.
export async function unlockBackup(record,id,vault,{request,evaluate,promptPin,decrypt,mode,legacyRp,expectedSerial,signal,progress}){
 const method=record?.wrappers.find(w=>w.id===id);
 if(!method)throw Error('Select an enrolled unlock method.');
 const {binding}=method;
 const guard=()=>signal.throwIfAborted();
 let secret,serial=binding.serial;
 try{
  guard();
  if(method.type==='piv'){
   secret=await openPivWrapper(record,method,{request,decrypt,guard});
  }else if(mode==='smartcard'){
   serial ||= expectedSerial;
   if(!serial){
    const {devices}=await request('chat-identity-devices');
    if(devices.length!==1)throw Error('Connect only the YubiKey for the selected FIDO credential.');
    serial=devices[0].serial;
   }
   guard();
   const result=await evaluate({serial,rpId:binding.rpId||legacyRp,
    credentialId:binding.credentialId?bytes(binding.credentialId):undefined,salt:bytes(binding.salt)},
    promptPin,{signal,progress});
   secret=result.secret;
   if(binding.credentialId&&b64(result.credentialId)!==binding.credentialId)throw Error('Unexpected FIDO credential.');
  }else{
   if(binding.rpId&&binding.rpId!==legacyRp)throw Error('Select Web Smart Card to use this FIDO credential’s original RP ID.');
   const result=await request('vault-prf',{name:method.name,salt:binding.salt,credentialId:binding.credentialId||''});
   try{secret=bytes(result.secret);}finally{delete result.secret;}
   if(binding.credentialId&&result.credentialId!==binding.credentialId)throw Error('Unexpected FIDO credential.');
  }
  guard();
  await vault.unlock(record,method.id,secret);
  guard();
  return {serial,mode};
 }catch(error){
  vault.lock();
  throw error;
 }finally{secret?.fill(0);}
}
