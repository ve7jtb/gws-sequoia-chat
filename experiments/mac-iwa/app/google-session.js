// Access tokens live only in this closure. No refresh token, storage, native
// callback, arbitrary URL or retry path is available to the transport layer.
export const SCOPES=['gmail.readonly','gmail.send','chat.spaces.readonly','chat.messages.readonly','chat.messages.create'].map(s=>'https://www.googleapis.com/auth/'+s);
export function createSession({fetcher=fetch,unlocked=()=>window.vaultIsUnlocked?.(),connect=()=>chrome.runtime.connect(EXTENSION_ID,{name:'google-services'}),clock=()=>Date.now()}={}){
 let token=null,expires=0,epoch=0,port=null,timer=null,account='',pending=false;
 const controllers=new Set();
 function clear(){epoch++;token=null;expires=0;account='';clearTimeout(timer);port?.disconnect();port=null;for(const c of controllers)c.abort();controllers.clear();}
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
 async function profile(expected){const r=await request('https://gmail.googleapis.com','/gmail/v1/users/me/profile');if(typeof r.emailAddress!=='string'||r.emailAddress.toLowerCase()!==expected.toLowerCase()){clear();throw Error('Google account does not match the selected signing identity.');}account=r.emailAddress;return {account};}
 async function login(expected){
  if(!unlocked())throw Error('Unlock the credential vault first.');if(pending)throw Error('Google sign-in already running.');clear();pending=true;
  const current=epoch;
  try{await new Promise((resolve,reject)=>{
   let done=false;const p=connect();port=p;
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
 return {clear,login,profile,request,gate};
}
