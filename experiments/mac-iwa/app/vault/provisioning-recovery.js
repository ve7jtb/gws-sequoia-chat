import {sameLevel3SmimeKeys} from './level3-smime-keys.js';
import {Vault,validate} from './core.js';

// Open the file in a separate engine. The current vault remains unlocked,
// and a successful assertion alone does not prove that this file has the keys.
export async function verifyProvisioningRecovery({file,methodId,targetSerial,sourceRecord,item,assertPrf}){
 if(!file||file.size>4_000_000)throw Error('Choose a vault-only encrypted backup file.');
 const backup=validate(JSON.parse(await file.text()));
 if(backup.id!==sourceRecord.id)throw Error('The backup belongs to a different vault.');
 const method=backup.wrappers.find(w=>w.id===methodId&&w.type==='prf');
 if(!method?.binding.credentialId||!method.binding.rpId||!/^[1-9][0-9]{5,9}$/.test(method.binding.serial)||
    String(method.binding.serial)===String(targetSerial))
  throw Error('Choose a FIDO PRF recovery credential on a separate YubiKey.');
 const recovery=new Vault();
 let secret;
 try{
  secret=await assertPrf(method);
  await recovery.unlock(backup,method.id,secret);
  const restored=recovery.data.items.find(candidate=>candidate.id===item.id);
  if(!item.encryptedSecret||!item.password||restored?.encryptedSecret!==item.encryptedSecret||
     restored?.password!==item.password||restored?.public?.certificateHash!==item.public.certificateHash||
     !sameLevel3SmimeKeys(item.smimeKeys,restored?.smimeKeys)||
     JSON.stringify(item.nistKeys)!==JSON.stringify(restored?.nistKeys)||
     JSON.stringify(item.sshKeys)!==JSON.stringify(restored?.sshKeys)||
     JSON.stringify(item.hardwareCopies)!==JSON.stringify(restored?.hardwareCopies))
   throw Error('The backup does not contain the current private identity. Export a fresh encrypted vault backup.');
 }finally{
  secret?.fill(0);
  recovery.lock();
 }
}
