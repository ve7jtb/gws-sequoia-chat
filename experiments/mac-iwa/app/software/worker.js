// Dedicated one-shot software-key worker. It has no native bridge, account,
// network transport, persistent storage or trusted-contact API. Imported secret
// packets are unlocked only within WASM for this operation; the owner terminates
// this worker on every exit and on vault lock/navigation.
import init,{software_inspect,software_sign,software_decapsulate,software_generate,software_export,software_backup_material,software_import_p12,software_p12_verify_mac} from '../wasm/sequoia_iwa_verify.js';
import {decodePqMailP12} from './p12.js';
let used=false;
self.onmessage=async({data})=>{
 if(used)return;used=true;let input=data?.input;const id=data?.id;
 try{
  if(!data||Object.keys(data).sort().join(',')!=='id,input,op'||typeof id!=='string'||!/^[a-f0-9-]{36}$/.test(id)||!['inspect','sign','decapsulate','generate','export','backup-material','import-p12'].includes(data.op)||JSON.stringify(input).length>(data.op==='import-p12'?1500000:400000))throw Error();
  await init();const functions={inspect:software_inspect,sign:software_sign,decapsulate:software_decapsulate,generate:software_generate,export:software_export,'backup-material':software_backup_material};
  let result;
  if(data.op==='import-p12'){
   if(!input||Object.keys(input).sort().join(',')!=='newPassword,p12,password')throw Error();
   const decoded=await decodePqMailP12(input,{verifyMac:value=>JSON.parse(software_p12_verify_mac(JSON.stringify(value)))});
   try{result=JSON.parse(software_import_p12(JSON.stringify({...decoded,password:input.newPassword})));}
   finally{for(const key of decoded.keys)key.pkcs8='';decoded.keys.length=0;}
  }else result=JSON.parse(functions[data.op](JSON.stringify(input)));
  // Lifecycle exports may return password-encrypted secret packets; operations
  // return only public metadata/signatures or ephemeral KEM shares. Decrypted
  // keys return only for the explicit backup-material import operation; those
  // transient seed buffers go to the reviewed SCP card importer, never downloads
  // or native messaging. The importer clears them on success and failure.
  self.postMessage({id,ok:true,result});
 }catch(_){self.postMessage({id,ok:false});}
 finally{if(input){input.password='';input.encryptedSecret='';input.newPassword='';input.p12='';}input=null;self.close();}
};
