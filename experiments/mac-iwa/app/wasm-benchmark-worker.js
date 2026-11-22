// Verification-only A/B benchmark. Both modules have the same source and lockfile;
// the wide build differs only in Rust's +wide-arithmetic target feature.
import initBase,{verify_detached as base} from './wasm/sequoia_iwa_verify.js';
import initWide,{verify_detached as wide} from './wasm-wide/sequoia_iwa_verify.js';
const compact=rows=>rows.map(s=>Object.fromEntries(['status','fingerprint','signingFingerprint','algorithm','candidateOnly'].filter(k=>s[k]!==undefined).map(k=>[k,s[k]])));
const summary=a=>{const s=[...a].sort((x,y)=>x-y);return {median:s[Math.floor(s.length/2)],p10:s[Math.floor(s.length*.1)],p90:s[Math.floor(s.length*.9)]};};
self.onmessage=async({data})=>{
 try{
  if(data?.version!==1||!Array.isArray(data.cases)||!data.cases.length||data.cases.length>16||JSON.stringify(data).length>2000000)throw Error('Invalid vectors');
  const [bb,wb]=await Promise.all(['./wasm/sequoia_iwa_verify_bg.wasm','./wasm-wide/sequoia_iwa_verify_bg.wasm'].map(async url=>{const r=await fetch(url);if(!r.ok)throw Error('Missing module');return r.arrayBuffer();}));
  if(!WebAssembly.validate(wb)){self.postMessage({ok:false,error:'This browser rejects the wide-arithmetic module. No baseline substitution or benchmark was performed.'});return;}
  await initBase({module_or_path:bb});await initWide({module_or_path:wb});
  const rounds=21,batch=5,warmup=5,rows=[];
  for(const test of data.cases){
   const request=JSON.stringify(test.request),expected=JSON.stringify(compact(test.expected));
   const check=result=>{if(JSON.stringify(compact(JSON.parse(result).signatures))!==expected)throw Error('Verification mismatch');};
   // Warm both independently. Alternate order each round to reduce systematic
   // JIT, frequency and scheduling bias. Never time loading or user interaction.
   for(let i=0;i<warmup;i++){check(base(request));check(wide(request));}
   const times={baseline:[],wide:[]};
   for(let round=0;round<rounds;round++){
    for(const name of (round%2?['wide','baseline']:['baseline','wide'])){
     const fn=name==='wide'?wide:base;let elapsed=0;
     for(let j=0;j<batch;j++){const start=performance.now();const result=fn(request);elapsed+=performance.now()-start;check(result);}
     times[name].push(elapsed/batch);
    }
   }
   const b=summary(times.baseline),w=summary(times.wide);
   rows.push({name:String(test.name).slice(0,100),passed:true,baseline:b,wide:w,ratio:b.median/w.median,samples:times});
  }
  self.postMessage({ok:true,passed:true,rounds,batch,warmup,baselineBytes:bb.byteLength,wideBytes:wb.byteLength,rows,userAgent:navigator.userAgent});
 }catch(_){self.postMessage({ok:false,error:'Benchmark stopped: load, input or verification check failed. No native fallback was used.'});}
};
