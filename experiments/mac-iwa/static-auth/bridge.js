// Static OAuth broker: no backend, token storage, mailbox requests or analytics.
// The exact signed IWA origin is the only allowed caller. Never use '*'.
const IWA='isolated-app://xk6yfmgz7ckh2kpx2clfmy3yeibdnlw526gs3amhkuaedvmt4ijaaaic';
const SCOPE='https://www.googleapis.com/auth/gmail.readonly';
let active=null,client=null,used=false;
const status=t=>document.getElementById('status').textContent=t;
function reply(type,extra={}){if(active)parent.postMessage({type,nonce:active.nonce,...extra},IWA);}
window.addEventListener('message',e=>{
 if(e.origin!==IWA||e.source!==parent||!e.data||e.data.type!=='iwa-google-init'||active)return;
 const {nonce,clientId}=e.data;
 if(typeof nonce!=='string'||!/^[a-f0-9]{64}$/.test(nonce))return;
 if(clientId && !/^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(clientId))return;
 active={nonce,deadline:Date.now()+600000};reply('iwa-google-ready');
 status('Secure message channel established. This test requests Gmail read-only access.');
 if(!clientId){status('Message channel passed. Configure a Web OAuth client to enable sign-in.');return;}
 const script=document.createElement('script');script.src='https://accounts.google.com/gsi/client';script.referrerPolicy='no-referrer';
 script.onerror=()=>{status('Google authorization library could not load.');reply('iwa-google-error');};
 script.onload=()=>{
  client=google.accounts.oauth2.initTokenClient({client_id:clientId,scope:SCOPE,include_granted_scopes:false,
   callback:r=>{
    if(used||!active||Date.now()>active.deadline)return;
    used=true;document.getElementById('login').disabled=true;
    if(r.error||!r.access_token){reply('iwa-google-error');status('Google authorization did not complete.');return;}
    reply('iwa-google-token',{token:r.access_token,expiresIn:Number(r.expires_in),scope:r.scope});
    r.access_token='';client=null;status('Authorization returned to the IWA. This page stores no token.');
   },error_callback:()=>{reply('iwa-google-error');status('Google popup closed or could not open.');}});
  document.getElementById('login').disabled=false;
 };
 document.head.append(script);
});
document.getElementById('login').onclick=()=>{
 if(!client||used||!active||Date.now()>active.deadline){status('Operation expired. Start again in the IWA.');return;}
 client.requestAccessToken({prompt:'select_account'});
};
setTimeout(()=>{if(!active)status('No authorized IWA connection. Open this page from Sequoia Chat Lab.');},10000);
