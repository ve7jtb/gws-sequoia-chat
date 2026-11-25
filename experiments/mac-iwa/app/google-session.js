// Access tokens live only in this closure. No refresh token, storage, native
// callback, arbitrary URL or retry path is available to the transport layer.
import {accountEmail} from './account-settings.js';
import {getOAuthMode,getLoopbackClientId,getLoopbackClientSecret,runLoopbackPkceOAuth} from './google-loopback-oauth.js';
export const SCOPES=['gmail.readonly','gmail.send','chat.spaces.readonly','chat.messages.readonly','chat.messages.create'].map(s=>'https://www.googleapis.com/auth/'+s);
export function createSession({fetcher=fetch,unlocked=()=>window.vaultIsUnlocked?.(),connect=()=>chrome.runtime.connect(EXTENSION_ID,{name:'google-services'}),mediaConnect=()=>chrome.runtime.connect(EXTENSION_ID,{name:'google-chat-media'}),clock=()=>Date.now(),mediaTimeoutMs=45000}={}){
 let token=null,expires=0,epoch=0,port=null,timer=null,account='',pending=false;
 const controllers=new Set(),mediaOperations=new Set();
 function clear(){epoch++;token=null;expires=0;account='';clearTimeout(timer);port?.disconnect();port=null;for(const c of controllers)c.abort();controllers.clear();for(const operation of [...mediaOperations])operation.cancel();}
 // Chat attachment responses do not expose the CORS headers required by the
 // IWA. Only those two typed operations use an extension port; ordinary Chat
 // REST and all Gmail requests remain browser requests below. The broker has
 // a fixed HTTPS origin/path policy and never forwards a caller-selected URL.
 // A fresh port carries one request and closes on completion, lock or timeout.
 const mediaLimit=262144;
 function mediaBytes(value){
  if(typeof value!=='string'||value.length>Math.ceil(mediaLimit/3)*4)throw Error('Invalid Chat attachment encoding or size.');
  let raw;try{raw=atob(value);}catch(_){throw Error('Invalid Chat attachment encoding or size.');}
  if(!raw.length||raw.length>mediaLimit||btoa(raw)!==value)throw Error('Invalid Chat attachment encoding or size.');
  return Uint8Array.from(raw,c=>c.charCodeAt(0));
 }
 function mediaRequest(input){
  if(!input||typeof input!=='object'||Array.isArray(input))throw Error('Unsupported Chat attachment operation.');
  const upload=input.op==='google-chat-upload',download=input.op==='google-chat-download';
  const fields=upload?['op','space','filename','data']:['op','resource'];
  if((!upload&&!download)||Object.keys(input).length!==fields.length||Object.keys(input).some(k=>!fields.includes(k)))throw Error('Unsupported Chat attachment operation.');
  if(upload){
   if(typeof input.space!=='string'||input.space.length>256||!/^spaces\/[A-Za-z0-9_-]+$/.test(input.space)||!['message.pgp','pq-mail-sender-key.pgp'].includes(input.filename))throw Error('Invalid Chat attachment destination.');
   mediaBytes(input.data);return {op:input.op,space:input.space,filename:input.filename,data:input.data};
  }
  if(typeof input.resource!=='string'||!input.resource||input.resource.length>4096||! /^[A-Za-z0-9_./=-]+$/.test(input.resource)||input.resource.split('/').some(s=>s==='.'||s==='..'))throw Error('Unsafe Chat media reference');
  return {op:input.op,resource:input.resource};
 }
 function mediaResult(op,result){
  if(!result||typeof result!=='object'||Array.isArray(result))throw Error('Invalid Chat attachment response.');
  if(op==='google-chat-download'){
   if(Object.keys(result).length!==1||!Object.hasOwn(result,'data'))throw Error('Invalid Chat attachment response.');
   return mediaBytes(result.data);
  }
  const ref=result.attachmentDataRef;
  if(Object.keys(result).length!==1||!ref||typeof ref!=='object'||Array.isArray(ref)||!Object.keys(ref).length||Object.keys(ref).some(k=>!['attachmentUploadToken','resourceName'].includes(k)||typeof ref[k]!=='string'||!ref[k].length||ref[k].length>65536))throw Error('Invalid Chat attachment response.');
  return {attachmentDataRef:{...ref}};
 }
 async function media(input){
  gate();if(mediaOperations.size)throw Error('A Google Chat attachment operation is already running.');const request=mediaRequest(input),current=epoch;
  return new Promise((resolve,reject)=>{
   let p=null,done=false,wait=null;
   const operation={cancel:()=>finish(Error('Google session cleared; Chat attachment response discarded.'))};
   // A clear() rejects immediately even if the browser never reports port
   // disconnection. Late replies cannot revive a cleared/locked session.
   function finish(error,value){
    if(done)return;done=true;clearTimeout(wait);mediaOperations.delete(operation);
    if(p){p.onMessage.removeListener?.(receive);p.onDisconnect.removeListener?.(disconnected);try{p.disconnect();}catch(_){}}
    error?reject(error):resolve(value);
   }
   function disconnected(){void globalThis.chrome?.runtime?.lastError;finish(Error('Google Chat attachment connection closed. No automatic retry.'));}
   function receive(reply){
    if(done)return;
    if(current!==epoch)return finish(Error('Google session cleared; Chat attachment response discarded.'));
    try{
     gate();
     if(reply?.type==='error'){
      // The extension already sanitizes errors. Keep the independent IWA
      // boundary strict as well: never echo arbitrary returned text or tokens.
      const status=typeof reply.message==='string'&&reply.message.match(/^Google API HTTP ([0-9]{3})\./);
      if(status){const error=Error('Google API HTTP '+status[1]+'. No automatic retry.');if(status[1]==='401'){finish(error);clear();return;}throw error;}
      throw Error('Google Chat attachment request did not complete. No automatic retry.');
     }
     if(reply?.type!=='google-chat-media')throw Error('Invalid Chat attachment response.');
     finish(null,mediaResult(request.op,reply.result));
    }catch(error){finish(error);}
   }
   mediaOperations.add(operation);
   wait=setTimeout(()=>{const error=Error('Google Chat attachment request timed out. No automatic retry.');error.name='AbortError';finish(error);},mediaTimeoutMs);
   try{
    p=mediaConnect();p.onMessage.addListener(receive);p.onDisconnect.addListener(disconnected);
    // The bearer token is copied only to this authenticated, short-lived
    // extension port. No native helper, local storage or refresh token path is
    // involved; the extension drops its request state when the port closes.
    p.postMessage({...request,token});
   }catch(_){finish(Error('Google Chat attachment broker unavailable. No automatic retry.'));}
  });
 }
 function gate(){if(!unlocked())throw Error('Unlock the credential vault first.');if(!token||clock()>=expires)throw Error('Sign in to Google again; access expires and clears on vault lock.');}
 async function request(origin,path,{method='GET',body,contentType='application/json',binary=false,limit=1048576}={}){
  gate();if(!['https://gmail.googleapis.com','https://chat.googleapis.com'].includes(origin)||!path.startsWith('/')||path.startsWith('//')||path.includes('..')||path.includes('#'))throw Error('Disallowed Google endpoint');
  const current=epoch,c=new AbortController();controllers.add(c);const timeout=setTimeout(()=>c.abort(),45000);
  try{
   const r=await fetcher(origin+path,{method,body,headers:{Authorization:'Bearer '+token,...(body?{'Content-Type':contentType}:{})},credentials:'omit',cache:'no-store',redirect:'error',signal:c.signal});
   if(current!==epoch)throw Error('Google session cleared.');
   if(!r.ok){if(r.status===401)clear();throw Error('Google API HTTP '+r.status+'. No automatic retry; a failed send may have reached Google.');}
   // Bound streamed response bytes, including responses lacking Content-Length.
   const reader=r.body.getReader(),chunks=[];let size=0;
   try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>limit)throw Error('Google response exceeds preview limit.');chunks.push(value);}}
   finally{await reader.cancel();}
   if(current!==epoch)throw Error('Google session cleared.');gate();
   const bytes=new Uint8Array(size);let offset=0;for(const part of chunks){bytes.set(part,offset);offset+=part.length;}
   return binary?bytes:JSON.parse(new TextDecoder().decode(bytes));
  }finally{clearTimeout(timeout);controllers.delete(c);}
 }
 async function profile(expected){const configured=accountEmail(expected),r=await request('https://gmail.googleapis.com','/gmail/v1/users/me/profile');if(typeof r.emailAddress!=='string'||r.emailAddress.toLowerCase()!==configured){clear();throw Error('Google account does not match the account configured in this IWA.');}account=r.emailAddress;return {account};}
 async function login(expected){
  // Missing/corrupt local configuration must fail before opening OAuth. The
  // Google response proves account ownership; entering an email alone does not.
  expected=accountEmail(expected);
  if(!unlocked())throw Error('Unlock the credential vault first.');if(pending)throw Error('Google sign-in already running.');clear();pending=true;
  const current=epoch;
  try{
   if(getOAuthMode()==='loopback-pkce'){
    const clientId=getLoopbackClientId()||globalThis.document?.getElementById?.('google-loopback-client')?.value?.trim()||'';
    const secretField=globalThis.document?.getElementById?.('google-loopback-secret');
    const clientSecret=getLoopbackClientSecret(clientId,secretField?.value||'');if(secretField)secretField.value='';
    const c=new AbortController();controllers.add(c);
    try{
     const d=await runLoopbackPkceOAuth({clientId,clientSecret,scopes:SCOPES,fetcher,signal:c.signal});
     if(current!==epoch||!unlocked())throw Error('Vault locked; authorization discarded.');
     token=d.token;expires=clock()+(d.expiresIn-30)*1000;timer=setTimeout(clear,(d.expiresIn-30)*1000);
    }finally{controllers.delete(c);}
    return await profile(expected);
   }
   await new Promise((resolve,reject)=>{
    let done=false;
    let p;
    try{p=connect();}catch(_){return reject(Error('Companion extension is unavailable. Switch Google OAuth mode to "Direct Sockets loopback PKCE" in the Google browser test tab (and enter your Desktop OAuth client ID).'));}
    if(!p)return reject(Error('Companion extension is unavailable. Switch Google OAuth mode to "Direct Sockets loopback PKCE" in the Google browser test tab.'));
    port=p;
    const finish=e=>{if(done)return;done=true;clearTimeout(wait);e?reject(e):resolve();};
    const wait=setTimeout(()=>finish(Error('Google sign-in expired.')),600000);
    p.onDisconnect.addListener(()=>{void globalThis.chrome?.runtime?.lastError;finish(Error('Google sign-in closed.'));});
    p.onMessage.addListener(d=>{
     if(done)return;
     if(current!==epoch||!unlocked())return finish(Error('Vault locked; authorization discarded.'));
     if(d?.type!=='google-token')return finish(Error('Google authorization stopped.'));
     if(typeof d.token!=='string'||d.token.length<20||d.token.length>8192||!Number.isFinite(d.expiresIn)||d.expiresIn<=30||d.expiresIn>86400||typeof d.scope!=='string'||!SCOPES.every(s=>d.scope.split(' ').includes(s)))return finish(Error('Required Gmail/Chat permissions were not granted.'));
     token=d.token;expires=clock()+(d.expiresIn-30)*1000;timer=setTimeout(clear,(d.expiresIn-30)*1000);finish();
    });p.postMessage({op:'google-oauth-services'});
   });port?.disconnect();port=null;return await profile(expected);
  }catch(e){clear();throw e;}finally{pending=false;}
 }
 return {clear,login,profile,request,media,gate};
}
