// An extension origin can use WebAuthn without pretending to be an HTTPS RP.
// Omit RP ID: Chromium uses the stable, signed extension ID as the RP scope.
const id=location.hash.slice(1),status=document.getElementById('status');
const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const b64=a=>{let s='';for(const b of new Uint8Array(a))s+=String.fromCharCode(b);return btoa(s);};
const random=n=>crypto.getRandomValues(new Uint8Array(n));
let request,working=false;
const ceremony=new AbortController();
// Incoming extension messages keep MV3 alive while the browser owns the modal
// authenticator UI. Stop a stale ceremony rather than creating an orphan key.
const heartbeat=setInterval(()=>chrome.runtime.sendMessage({op:'vault-prf-alive',id}).then(r=>{if(!r?.active){ceremony.abort();say('Passkey operation expired. Return to the IWA.');}}).catch(()=>{ceremony.abort();say('Passkey bridge closed. Return to the IWA.');}),10000);
window.addEventListener('pagehide',()=>{clearInterval(heartbeat);ceremony.abort();});
function say(s){status.textContent=s;}
async function get(credentialId){return navigator.credentials.get({signal:ceremony.signal,publicKey:{challenge:random(32),timeout:90000,userVerification:'required',allowCredentials:credentialId?[{type:'public-key',id:bytes(credentialId)}]:[],extensions:{prf:{eval:{first:bytes(request.salt)}}}}});}
function result(credential){
 const prf=credential?.getClientExtensionResults()?.prf?.results?.first;
 if(!prf||prf.byteLength!==32)throw Error('This credential/provider did not return PRF output. No vault was changed.');
 if(request.credentialId&&b64(credential.rawId)!==request.credentialId)throw Error('Unexpected credential.');
 return {credentialId:b64(credential.rawId),secret:b64(prf)};
}
async function run(create){
 if(working)return;working=true;document.getElementById('existing').disabled=true;document.getElementById('create').disabled=true;
 try{
  let credential;
  if(create){
   // A fresh random user handle prevents another instance's discoverable
   // credential from being overwritten. Never auto-create after cancellation.
   credential=await navigator.credentials.create({signal:ceremony.signal,publicKey:{challenge:random(32),rp:{name:'Sequoia IWA vault'},user:{id:random(32),name:request.name,displayName:request.name},pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],authenticatorSelection:{residentKey:'required',userVerification:'required'},attestation:'none',timeout:90000,extensions:{prf:{eval:{first:bytes(request.salt)}}}}});
   // Some authenticators only enable PRF on creation. If so, evaluate it with
   // one assertion for this newly created credential; no silent fallback.
   if(!credential.getClientExtensionResults()?.prf?.results?.first)credential=await get(b64(credential.rawId));
  }else credential=await get(request.credentialId);
  const value=result(credential);
  await chrome.runtime.sendMessage({op:'vault-prf-result',id,result:value});window.close();
 }catch(e){say(e.name==='NotAllowedError'?'Passkey selection cancelled or timed out. No vault was changed.':e.message);if(!request.credentialId)document.getElementById('create').hidden=false;}
 finally{working=false;document.getElementById('existing').disabled=false;document.getElementById('create').disabled=false;}
}
document.getElementById('existing').onclick=()=>run(false);
document.getElementById('create').onclick=()=>run(true);
document.getElementById('cancel').onclick=()=>window.close();
chrome.runtime.sendMessage({op:'vault-prf-request',id}).then(r=>{if(!r)throw Error('Expired passkey operation.');request=r;say('Use your passkey for '+r.name+'. Start by checking for an existing credential.');}).catch(e=>{say(e.message);document.getElementById('existing').disabled=true;});
