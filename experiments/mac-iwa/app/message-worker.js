// Baseline only: no wide-arithmetic module and no native verification fallback.
import init,{verify_detached,encrypt_signed,decrypt_with_session_key} from './wasm/sequoia_iwa_verify.js';
import {readMessage,composeMime} from './message-mime.js';
self.onmessage=async({data})=>{try{
 if(JSON.stringify(data).length>800000)throw Error('Oversized worker request');
 if(data.compose){self.postMessage({ok:true,result:composeMime(data.compose)});return;}
 await init();
 if(data.encrypt){self.postMessage({ok:true,result:JSON.parse(encrypt_signed(JSON.stringify(data.encrypt)))});return;}
 // A session key exists only for this worker operation. Never post it back,
 // persist it, or fall back to native message decryption on authentication failure.
 if(data.packet?.sessionKey){
  const input=data.packet;
  try {const clear=JSON.parse(decrypt_with_session_key(JSON.stringify(input)));data.packet={...clear,expectedEmail:input.expectedEmail,expectedFingerprint:input.expectedFingerprint,recipient:input.recipient};}
  finally {delete input.sessionKey;}
 }
 const result=await readMessage(data.packet,data.material,request=>JSON.parse(verify_detached(JSON.stringify(request))));
 self.postMessage({ok:true,result});
}catch(_){self.postMessage({ok:false,error:'Browser decryption/MIME/verification rejected this message. No native fallback was used.'});}};
