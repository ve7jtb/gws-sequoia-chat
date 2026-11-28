import {bytes} from './core.js';
import {classicalOpen} from './piv.js';
import {openLevel5} from './level5.js';

// Use the same serial, key binding and authenticated vault purpose for an
// ordinary unlock and for opening a wrapper carried in an encrypted backup.
export async function openPivWrapper(record,w,{request,vaultRequest=request,decrypt,guard}){
 if(w.binding.kind==='mlkem1024-p384-v1')return openLevel5(w.binding,vaultRequest);
 if(w.binding.kind==='ecdh')return classicalOpen(w.binding,vaultRequest);
 const result=await decrypt({cipher:w.binding.cipher,recipientKey:w.binding.recipientKey,
  native:(op,data,options)=>request(op,op==='chat-decryption-material'
   ?{...data,serial:w.binding.serial,recipientKey:w.binding.recipientKey}:data,options),
  service:'Vault',purpose:'vault',vault:{vaultId:record?.id||w.vaultId,wrapperId:w.id},gate:guard});
 try{return bytes(result.secret);}finally{delete result.secret;}
}
