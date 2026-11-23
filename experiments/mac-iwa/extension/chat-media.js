// Narrow, ephemeral HTTPS attachment broker for the authenticated IWA origin.
// background.js checks the exact external origin, root URL and top-level frame
// before calling this function. The IWA retains account checks, send reviews,
// certificates, trust and all OpenPGP processing. This broker neither creates
// Chat messages nor calls Native Messaging, a storage API, or an OAuth endpoint.
const CHAT_MEDIA_ORIGIN='https://chat.googleapis.com';
const CHAT_MEDIA_LIMIT=262144,CHAT_MEDIA_JSON_LIMIT=131072;
const chatMediaPorts=new WeakMap();
let chatMediaOwner=null;

class ChatMediaError extends Error {}
function mediaRequire(ok,message){if(!ok)throw new ChatMediaError(message);}
function mediaToken(value){
 // RFC 6750 bearer characters exclude whitespace/control characters, so even
 // an invalid caller cannot inject an additional HTTP header or request line.
 mediaRequire(typeof value==='string'&&value.length>=20&&value.length<=8192&&/^[A-Za-z0-9._~+/-]+=*$/.test(value),'Invalid Google Chat attachment request.');
 return value;
}
function mediaResource(value){
 // Accept only the opaque Google media path alphabet used by Chat; encode
 // each segment before appending it to our fixed origin. URLs, queries,
 // fragments, dot segments and empty identifiers cannot choose another host.
 mediaRequire(typeof value==='string'&&value.length>0&&value.length<=4096&&/^[A-Za-z0-9_./=-]+$/.test(value)&&value.split('/').every(s=>s!=='.'&&s!=='..'),'Invalid Google Chat media reference.');
 return value;
}
function mediaBase64(value){
 // Bound the encoded representation before decoding and require a canonical
 // re-encoding. This rejects whitespace, URL-safe variants, misplaced padding
 // and nonzero unused pad bits while preserving every binary ciphertext byte.
 mediaRequire(typeof value==='string'&&value.length>0&&value.length<=4*Math.ceil(CHAT_MEDIA_LIMIT/3)&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value),'Invalid Google Chat attachment data.');
 let raw;try{raw=atob(value);}catch(_){throw new ChatMediaError('Invalid Google Chat attachment data.');}
 mediaRequire(raw.length>0&&raw.length<=CHAT_MEDIA_LIMIT&&btoa(raw)===value,'Invalid Google Chat attachment data.');
 return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
function mediaEncode(bytes){
 // Avoid spreading a 256 KiB buffer into a function call; some browsers impose
 // much smaller argument-count limits. The result is always standard base64.
 let raw='';for(let offset=0;offset<bytes.length;offset+=8192)raw+=String.fromCharCode(...bytes.subarray(offset,offset+8192));
 return btoa(raw);
}
function mediaRequest(request){
 mediaRequire(request&&typeof request==='object'&&!Array.isArray(request),'Invalid Google Chat attachment request.');
 const upload=request.op==='google-chat-upload',download=request.op==='google-chat-download';
 mediaRequire(upload||download,'Unsupported Google Chat attachment operation.');
 const keys=Object.keys(request).sort().join(',');
 mediaRequire(keys===(upload?'data,filename,op,space,token':'op,resource,token'),'Invalid Google Chat attachment request fields.');
 const token=mediaToken(request.token);
 if(download){
  const resource=mediaResource(request.resource);
  return {token,path:'/v1/media/'+resource.split('/').map(encodeURIComponent).join('/')+'?alt=media',method:'GET',limit:CHAT_MEDIA_LIMIT};
 }
 mediaRequire(typeof request.space==='string'&&request.space.length<=256&&/^spaces\/[A-Za-z0-9_-]+$/.test(request.space),'Invalid Google Chat conversation.');
 mediaRequire(['message.pgp','pq-mail-sender-key.pgp'].includes(request.filename),'Unsupported Google Chat attachment filename.');
 const bytes=mediaBase64(request.data),boundary='sequoia-'+crypto.randomUUID();
 // Filename and destination come only from the allowlists above. Binary bytes
 // remain opaque: the extension cannot substitute another MIME interpretation
 // or upload local files, and no plaintext key or password is requested here.
 const body=new Blob(['--'+boundary+'\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n'+JSON.stringify({filename:request.filename})+'\r\n--'+boundary+'\r\nContent-Type: application/octet-stream\r\n\r\n',bytes,'\r\n--'+boundary+'--\r\n']);
 return {token,path:'/upload/v1/'+request.space+'/attachments:upload?uploadType=multipart',method:'POST',body,contentType:'multipart/related; boundary='+boundary,limit:CHAT_MEDIA_JSON_LIMIT};
}
async function mediaRead(response,limit,active){
 // Content-Length may be absent or untrustworthy. Count actual streamed bytes
 // before retaining each chunk, including JSON error/success representations.
 mediaRequire(response.body&&typeof response.body.getReader==='function','Google Chat returned an unreadable attachment response.');
 const reader=response.body.getReader(),chunks=[];let size=0;
 try{
  for(;;){
   if(!active())return null;
   const {done,value}=await reader.read();
   if(!active())return null;if(done)break;
   size+=value.byteLength;mediaRequire(size<=limit,'Google Chat attachment response exceeds the size limit.');chunks.push(value);
  }
 }finally{try{await reader.cancel();}catch(_){}reader.releaseLock();}
 const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
 return bytes;
}
function mediaUploadResult(bytes){
 let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch(_){throw new ChatMediaError('Google Chat returned an invalid upload response.');}
 const ref=value?.attachmentDataRef;
 mediaRequire(ref&&typeof ref==='object'&&!Array.isArray(ref),'Google Chat returned no attachment reference.');
 const result={};
 // Return only the two documented public attachment reference fields. Never
 // forward arbitrary server JSON, a download URI, headers, or diagnostic body.
 for(const key of ['attachmentUploadToken','resourceName'])if(Object.prototype.hasOwnProperty.call(ref,key)){
  mediaRequire(typeof ref[key]==='string'&&ref[key].length>0&&ref[key].length<=65536,'Google Chat returned an invalid attachment reference.');
  if(key==='resourceName')mediaResource(ref[key]);
  result[key]=ref[key];
 }
 mediaRequire(Object.keys(result).length>0,'Google Chat returned no attachment reference.');
 return {attachmentDataRef:result};
}
async function startChatMedia(port,request){
 // Each external port owns at most one attempt, including validation failures.
 // A second request on that port cancels its active fetch; opening another port
 // cannot circumvent the global single-request memory/concurrency bound.
 const previous=chatMediaPorts.get(port);
 if(previous){if(!previous.done)previous.finish({type:'error',message:'Duplicate Google Chat attachment request. No automatic retry.'},true);return;}
 const state={done:false,controller:new AbortController(),timer:null};chatMediaPorts.set(port,state);
 function cleanup(){
  clearTimeout(state.timer);port.onDisconnect.removeListener(disconnect);
  // Delayed callbacks from an old aborted request must never release a newer
  // port's ownership. Identity comparison, rather than a boolean, prevents it.
  if(chatMediaOwner===state)chatMediaOwner=null;
 }
 function finish(reply,abort=false){
  if(state.done)return;state.done=true;if(abort)state.controller.abort();cleanup();
  if(reply)try{port.postMessage(reply);}catch(_){}
 }
 function disconnect(){finish(null,true);}
 state.finish=finish;port.onDisconnect.addListener(disconnect);
 if(chatMediaOwner){finish({type:'error',message:'Another Google Chat attachment request is in progress. No automatic retry.'});return;}
 chatMediaOwner=state;
 let prepared=null;
 try{
  prepared=mediaRequest(request);request=null;
  state.timer=setTimeout(()=>finish({type:'error',message:'Google Chat attachment request timed out. No automatic retry.'},true),45000);
  const response=await fetch(CHAT_MEDIA_ORIGIN+prepared.path,{method:prepared.method,body:prepared.body,
   headers:{Authorization:'Bearer '+prepared.token,...(prepared.body?{'Content-Type':prepared.contentType}:{})},
   credentials:'omit',cache:'no-store',redirect:'error',signal:state.controller.signal});
  if(state.done)return;
  // An unreadable/aborted POST may already have reached Google. Preserve that
  // uncertainty: no retries or native fallbacks are hidden inside this broker.
  if(!response.ok){
   try{await response.body?.cancel();}catch(_){}
   throw new ChatMediaError('Google API HTTP '+response.status+'. No automatic retry; an attachment POST may have reached Google.');
  }
  const bytes=await mediaRead(response,prepared.limit,()=>!state.done);if(state.done||!bytes)return;
  const result=prepared.method==='POST'?mediaUploadResult(bytes):{data:mediaEncode(bytes)};
  finish({type:'google-chat-media',result});
 }catch(error){
  // Only messages created in this module are exposed. fetch/decoder/parser
  // exceptions may contain URLs or implementation details; discard them.
  finish({type:'error',message:error instanceof ChatMediaError?error.message:
   'Google Chat attachment request failed (browser policy or network). No automatic retry.'});
 }finally{
  if(prepared){prepared.token=null;prepared.body=null;}request=null;cleanup();
 }
}
