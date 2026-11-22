// Public detached verification only. This worker has no native bridge, OAuth
// token or private key, and fetches only the WASM asset in the signed IWA.
import init,{verify_detached} from './wasm/sequoia_iwa_verify.js';
const compact=rows=>rows.map(s=>Object.fromEntries(['status','fingerprint','signingFingerprint','algorithm','candidateOnly'].filter(k=>s[k]!==undefined).map(k=>[k,s[k]])));
self.onmessage=async({data})=>{
 try{
  if(data?.version!==1||!Array.isArray(data.cases)||!data.cases.length||data.cases.length>16||JSON.stringify(data).length>2000000)throw Error('Invalid test vectors');
  await init();const rows=[];
  for(const test of data.cases){
   const start=performance.now();
   const actual=JSON.parse(verify_detached(JSON.stringify(test.request)));
   const passed=JSON.stringify(compact(actual.signatures))===JSON.stringify(compact(test.expected));
   rows.push({name:String(test.name).slice(0,100),passed,signatures:compact(actual.signatures),milliseconds:Math.round((performance.now()-start)*10)/10});
  }
  self.postMessage({ok:true,passed:rows.every(r=>r.passed),rows});
 }catch(_){self.postMessage({ok:false,error:'WASM verification rejected the input; no native fallback was used.'});}
};
