// Baseline only: no wide-arithmetic module and no native verification fallback.
import init,{verify_detached} from './wasm/sequoia_iwa_verify.js';
import {readMessage,composeMime} from './message-mime.js';
self.onmessage=async({data})=>{try{
 if(JSON.stringify(data).length>800000)throw Error('Oversized worker request');
 if(data.compose){self.postMessage({ok:true,result:composeMime(data.compose)});return;}
 await init();
 const result=await readMessage(data.packet,data.material,request=>JSON.parse(verify_detached(JSON.stringify(request))));
 self.postMessage({ok:true,result});
}catch(_){self.postMessage({ok:false,error:'Browser MIME/verification rejected this message. No native fallback was used.'});}};
