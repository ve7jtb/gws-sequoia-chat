// Browser-owned OAuth redirect interception. No native host, client secret,
// refresh token, storage API, or arbitrary URLs/scopes from the caller.
const GOOGLE_CLIENT='543645939161-955igu4ma7c0hqnmhvnhik24vhjdtj41.apps.googleusercontent.com';
const GOOGLE_SCOPE='https://www.googleapis.com/auth/gmail.readonly';
const GOOGLE_SCOPES=[GOOGLE_SCOPE,'gmail.send','chat.spaces.readonly','chat.messages.readonly','chat.messages.create'].map(s=>s.startsWith('https:')?s:'https://www.googleapis.com/auth/'+s);
function parseGoogleReply(raw,redirect,state,required=[GOOGLE_SCOPE]){
 const u=new URL(raw),expected=new URL(redirect);
 if(u.origin!==expected.origin||u.pathname!==expected.pathname||u.search)throw Error('callback');
 const p=new URLSearchParams(u.hash.slice(1));
 for(const key of ['state','access_token','expires_in','token_type','scope'])if(p.getAll(key).length!==1)throw Error('response');
 if(p.get('state')!==state||p.has('error')||p.get('token_type').toLowerCase()!=='bearer')throw Error('response');
 const token=p.get('access_token'),expiresIn=Number(p.get('expires_in')),scope=p.get('scope');
 if(!token||token.length<20||token.length>8192||!Number.isFinite(expiresIn)||expiresIn<=0||expiresIn>86400||!required.every(s=>scope.split(' ').includes(s)))throw Error('token');
 return {token,expiresIn,scope};
}
let googlePending=false;
async function startGoogleOAuth(port,full=false){
 if(googlePending){port.postMessage({type:'error',message:'Google authorization already in progress.'});return;}
 googlePending=true;let alive=true;
 const stop=()=>{alive=false;};port.onDisconnect.addListener(stop);
 // The browser window may survive disconnection; its eventual result must not
 // reach an IWA that locked, navigated, or started a replacement operation.
 const timer=setTimeout(stop,600000);
 try{
  const state=Array.from(crypto.getRandomValues(new Uint8Array(32)),v=>v.toString(16).padStart(2,'0')).join('');
  const redirect=chrome.identity.getRedirectURL('google');
  const u=new URL('https://accounts.google.com/o/oauth2/v2/auth');
  u.search=new URLSearchParams({client_id:GOOGLE_CLIENT,redirect_uri:redirect,response_type:'token',scope:(full?GOOGLE_SCOPES:[GOOGLE_SCOPE]).join(' '),state,prompt:'select_account',include_granted_scopes:'false'}).toString();
  let raw=await chrome.identity.launchWebAuthFlow({url:u.href,interactive:true});
  if(!alive)return;
  const result=parseGoogleReply(raw,redirect,state,full?GOOGLE_SCOPES:[GOOGLE_SCOPE]);raw=null;
  port.postMessage({type:'google-token',...result});result.token=null;
 }catch(_){if(alive)port.postMessage({type:'error',message:'Google browser authorization failed or was cancelled. No token saved.'});}
 finally{clearTimeout(timer);port.onDisconnect.removeListener(stop);googlePending=false;}
}
