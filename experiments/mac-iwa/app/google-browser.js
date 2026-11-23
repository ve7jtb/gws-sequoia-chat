// Experimental browser-only Gmail transport. Access token is closure memory
// only; never rendered, logged, exported, sent to helper, or persisted.
export const AUTH_ORIGIN='https://ve7jtb.github.io';
export function validReply(e,source,nonce,deadline,now=Date.now()){
 return e.origin===AUTH_ORIGIN&&e.source===source&&!!e.data&&e.data.nonce===nonce&&now<deadline;
}
export function validToken(d){return typeof d.token==='string'&&d.token.length>=20&&d.token.length<8192&&Number.isFinite(d.expiresIn)&&d.expiresIn>0&&d.expiresIn<=86400&&typeof d.scope==='string'&&d.scope.split(' ').includes('https://www.googleapis.com/auth/gmail.readonly');}
if(typeof document!=='undefined'){
 const $=id=>document.getElementById(id);let frame=null,nonce=null,deadline=0,token=null,expires=0,timer=null,request=null,epoch=0,oauthPort=null;
 const say=t=>$('google-browser-status').textContent=t;
 function clear(){epoch++;oauthPort?.disconnect();oauthPort=null;token=null;expires=0;nonce=null;deadline=0;clearTimeout(timer);request?.abort();request=null;frame?.remove();frame=null;$('google-browser-profile').disabled=true;}
 function gate(){if(!window.vaultIsUnlocked?.())throw Error('Unlock the credential vault in the Vault tab first.');}
 $('google-browser-start').onclick=()=>{
  try{gate();clear();
   const clientId=$('google-browser-client').value.trim();
   if(clientId&&!/^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(clientId))throw Error('Enter a public Web client ID, never a secret.');
   if(!('credentialless' in HTMLIFrameElement.prototype))throw Error('Credentialless iframe not available; no fallback.');
   nonce=Array.from(crypto.getRandomValues(new Uint8Array(32)),n=>n.toString(16).padStart(2,'0')).join('');deadline=Date.now()+600000;
   frame=document.createElement('iframe');frame.credentialless=true;frame.referrerPolicy='no-referrer';frame.title='Google authorization companion';
   frame.setAttribute('sandbox','allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox');
   frame.src=AUTH_ORIGIN+'/pq-mail/iwa-google-auth/';
   frame.onload=()=>frame?.contentWindow.postMessage({type:'iwa-google-init',nonce,clientId},AUTH_ORIGIN);
   $('google-browser-frame').append(frame);say('Waiting for static authorization page handshake…');
   timer=setTimeout(()=>{clear();say('Authorization expired. Start again.');},600000);
  }catch(e){say(e.message);}
 };
 function acceptToken(d){
  if(!validToken(d)){clear();say('Invalid token response rejected.');return;}
  const value=d.token,lifetime=d.expiresIn;clear();token=value;expires=Date.now()+lifetime*1000;
  timer=setTimeout(()=>{clear();say('Google session expired. Reconnect Google.');},Math.max(0,lifetime*1000-30000));
  $('google-browser-profile').disabled=false;say('Google access token received in IWA memory. Ready for read-only Gmail check.');
 }
 $('google-extension-start').onclick=()=>{
  if(!window.vaultIsUnlocked?.()){clear();say('Unlock the credential vault in the Vault tab first.');return;}
  try{gate();clear();const current=epoch;
   const p=chrome.runtime.connect(EXTENSION_ID,{name:'google-oauth-test'});oauthPort=p;
   say('Complete Google authorization in the browser window. Gmail read only; no refresh token.');
   p.onMessage.addListener(d=>{if(current!==epoch)return;try{gate();}catch(_){clear();return;}
    if(d?.type==='google-token')acceptToken(d);
    else if(d?.type==='error'){clear();say('Google extension authorization stopped. No token saved.');}
   });
   p.onDisconnect.addListener(()=>{const ignored=chrome.runtime.lastError;if(current===epoch){clear();say('Google extension disconnected. No token saved.');}});
   p.postMessage({op:'google-oauth-test'});
   timer=setTimeout(()=>{clear();say('Google authorization expired. Start again.');},600000);
  }catch(_){clear();say('Could not start Google extension authorization. Check the updated extension.');}
 };
 window.addEventListener('message',e=>{
  if(!frame||!validReply(e,frame.contentWindow,nonce,deadline))return;
  try{gate();}catch(_){clear();say('Vault locked; authorization discarded.');return;}
  if(e.data.type==='iwa-google-ready')say('PASS: HTTPS iframe ↔ IWA postMessage handshake. No Google token yet.');
  if(e.data.type==='iwa-google-error'){clear();say('Google authorization stopped. No token saved.');}
  if(e.data.type==='iwa-google-token'){
   acceptToken(e.data);
  }
 });
 $('google-browser-clear').onclick=()=>{clear();say('Google access token and authorization frame cleared.');};
 $('google-browser-profile').onclick=async()=>{
  try{gate();if(!token||Date.now()>=expires)throw Error('Reconnect Google first.');
   const current=epoch;request=new AbortController();
   const r=await fetch('https://gmail.googleapis.com/gmail/v1/users/me/profile',{headers:{Authorization:'Bearer '+token},credentials:'omit',cache:'no-store',redirect:'error',signal:request.signal});
   if(current!==epoch)return;
   if(!r.ok){if(r.status===401)clear();throw Error('Gmail profile request returned HTTP '+r.status);}
   const data=await r.json();if(current!==epoch)return;gate();
   // Show account identity only. Do not retrieve messages or render response data wholesale.
   say('PASS: direct authenticated Gmail profile read for '+String(data.emailAddress||'authorized account')+'. No native helper or gws call.');
  }catch(e){say(e.name==='AbortError'?'Request cancelled; session cleared.':e.message);}
 };
 window.addEventListener('iwa-vault-locked',()=>{clear();say('Vault locked; Google access token cleared.');});
 window.addEventListener('pagehide',clear);
}
