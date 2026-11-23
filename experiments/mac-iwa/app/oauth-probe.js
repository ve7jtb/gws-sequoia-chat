// Feasibility probe only: no native bridge, Google credentials, mail content,
// token persistence, or automatic OAuth login. Fixed endpoints prevent using
// this page as an arbitrary authenticated network proxy.
export const probes=[
 ['Google discovery','https://accounts.google.com/.well-known/openid-configuration','GET'],
 ['OAuth token endpoint','https://oauth2.googleapis.com/token','POST'],
 ['Gmail profile','https://gmail.googleapis.com/gmail/v1/users/me/profile','GET'],
 ['Chat spaces','https://chat.googleapis.com/v1/spaces?pageSize=1','GET'],
];
export async function probe(fetcher,url,method){
 const begin=performance.now();
 try{
  const response=await fetcher(url,{method,mode:'cors',credentials:'omit',cache:'no-store',redirect:'error',
   signal:AbortSignal.timeout(15000),...(method==='POST'?{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'grant_type=iwa_probe_invalid'}:{})});
  // HTTP 400/401 proves this response is readable; it does NOT prove OAuth,
  // authorized requests, uploads, token refresh or account access works.
  return {status:response.status,responseReadable:true,ms:Math.round(performance.now()-begin)};
 }catch(_){return {responseReadable:false,reason:'Fetch blocked or failed (CORS, CSP, network, redirect or timeout); inspect browser console',ms:Math.round(performance.now()-begin)};}
}
export function authorizationURL(clientId,origin,state,challenge){
 if(!/^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(clientId))throw Error('Enter a Google public client ID, not a client secret.');
 if(!/^isolated-app:\/\/[a-z2-7]+$/.test(origin))throw Error('Run this check from the installed IWA.');
 const u=new URL('https://accounts.google.com/o/oauth2/v2/auth');
 u.search=new URLSearchParams({client_id:clientId,redirect_uri:origin+'/oauth-callback.html',response_type:'code',
  scope:'openid',state,code_challenge:challenge,code_challenge_method:'S256'}).toString();return u.href;
}
const enc=a=>btoa(String.fromCharCode(...a)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
if(typeof document!=='undefined'){
 const $=id=>document.getElementById(id);let report=null;
 $('probe-origin').textContent=location.origin;
 $('probe-run').onclick=async()=>{
  $('probe-run').disabled=true;report={version:1,origin:location.origin,authenticated:false,tests:[]};
  try{for(const [name,url,method] of probes){
   $('probe-results').textContent='Checking '+name+'…';report.tests.push({name,...await probe(fetch,url,method)});
  }$('probe-results').textContent=JSON.stringify(report,null,2);$('probe-export').disabled=false;}
  finally{$('probe-run').disabled=false;}
 };
 $('probe-export').onclick=()=>{if(!report)return;const u=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=u;a.download='iwa-oauth-cors-probe.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);};
 $('probe-authorize').onclick=async()=>{
  try{
   // This tests whether Google accepts the IWA redirect at all. No offline
   // access is requested. The callback never exchanges or saves returned codes.
   const state=enc(crypto.getRandomValues(new Uint8Array(32)));
   const verifier=enc(crypto.getRandomValues(new Uint8Array(32)));
   const challenge=enc(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))));
   const url=authorizationURL($('probe-client').value.trim(),location.origin,state,challenge);
   sessionStorage.setItem('iwa-oauth-probe-state',state);
   // Do not preserve a verifier: this milestone deliberately cannot exchange
   // authorization codes. Real OAuth needs a validated callback + PKCE lifecycle.
   const a=$('probe-link');a.href=url;a.hidden=false;
   $('probe-auth-result').textContent='Open the Google redirect check below. If Google rejects the redirect, record its error. No Gmail/Chat scopes, refresh token or code exchange are requested.';
  }catch(e){$('probe-auth-result').textContent=e.message;}
 };
}
