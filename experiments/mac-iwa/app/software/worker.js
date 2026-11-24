// Dedicated one-shot software-key worker. It has no native bridge, account,
// network transport, persistent storage or trusted-contact API. Imported secret
// packets are unlocked only within WASM for this operation; the owner terminates
// this worker on every exit and on vault lock/navigation.
import init,{software_inspect,software_sign,software_decapsulate} from '../wasm/sequoia_iwa_verify.js';
let used=false;
self.onmessage=async({data})=>{
 if(used)return;used=true;let input=data?.input;const id=data?.id;
 try{
  if(!data||Object.keys(data).sort().join(',')!=='id,input,op'||typeof id!=='string'||!/^[a-f0-9-]{36}$/.test(id)||!['inspect','sign','decapsulate'].includes(data.op)||JSON.stringify(input).length>400000)throw Error();
  await init();const functions={inspect:software_inspect,sign:software_sign,decapsulate:software_decapsulate};
  const result=JSON.parse(functions[data.op](JSON.stringify(input)));
  // The exports return public metadata/signatures or ephemeral KEM shares only,
  // never decrypted OpenPGP secret packets or a password.
  self.postMessage({id,ok:true,result});
 }catch(_){self.postMessage({id,ok:false});}
 finally{if(input){input.password='';input.encryptedSecret='';}input=null;self.close();}
};
