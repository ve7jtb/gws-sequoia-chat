// The external origin/frame check in background.js runs before this broker.
// Only an extension-owned popup receives the one-time request. No PRF output,
// PIN, credential private key or vault content is stored by the extension.
let prfPending=null;
function startPrf(port,r){
 if(prfPending||!r||Object.keys(r).sort().join(',')!=='credentialId,name,op,salt'||r.op!=='vault-prf'||typeof r.name!=='string'||!r.name.trim()||r.name.length>80||typeof r.credentialId!=='string'||r.credentialId.length>2048||typeof r.salt!=='string'||!/^[A-Za-z0-9+/]{43}=$/.test(r.salt)){port.postMessage({type:'error',message:'Invalid or concurrent passkey request.'});return;}
 const p={id:crypto.randomUUID(),request:{name:r.name,salt:r.salt,credentialId:r.credentialId},port};prfPending=p;
 const finish=(reply)=>{if(prfPending!==p)return;prfPending=null;clearTimeout(p.timer);clearInterval(p.heartbeat);if(reply)try{port.postMessage(reply);}catch(_){}if(p.window)chrome.windows.remove(p.window).catch(()=>{});};p.finish=finish;
 // MV3 may suspend an idle worker even with an open external port. Keep this
 // bounded user ceremony alive with progress messages; stop on every exit.
 const pulse=()=>{try{port.postMessage({type:'progress',message:'Waiting for FIDO PRF authentication in the browser passkey window…'});}catch(_){finish();}};
 p.heartbeat=setInterval(()=>{chrome.runtime.getPlatformInfo().then(()=>{if(prfPending===p)pulse();}).catch(()=>finish({type:'error',message:'Passkey bridge stopped. No vault was changed.'}));},15000);pulse();
 p.timer=setTimeout(()=>finish({type:'error',message:'Passkey operation expired. No vault was changed.'}),240000);
 port.onDisconnect.addListener(()=>finish());
 chrome.windows.create({url:chrome.runtime.getURL('prf.html')+'#'+p.id,type:'popup',width:520,height:420}).then(w=>{if(prfPending===p)p.window=w.id;else chrome.windows.remove(w.id);}).catch(()=>finish({type:'error',message:'Could not open the passkey chooser.'}));
}
chrome.windows.onRemoved.addListener(id=>{if(prfPending?.window===id)prfPending.finish({type:'error',message:'Passkey operation cancelled. No vault was changed.'});});
chrome.runtime.onMessage.addListener((m,s,reply)=>{
 const p=prfPending;if(!p||s.id!==chrome.runtime.id||s.url!==chrome.runtime.getURL('prf.html')+'#'+p.id||m.id!==p.id)return;
 if(m.op==='vault-prf-request'){reply(p.request);return;}
 if(m.op==='vault-prf-alive'){reply({active:true});return;}
 if(m.op==='vault-prf-result'){
  const r=m.result;if(!r||typeof r.credentialId!=='string'||r.credentialId.length>2048||!r.credentialId||typeof r.secret!=='string'||!/^[A-Za-z0-9+/]{43}=$/.test(r.secret))return;
  reply({ok:true});p.finish({type:'result',data:r});
 }
});
