import {createSession} from './google-session.js';
import {b64,bytes64,envelope,LIMIT} from './message-mime.js';
const GMAIL='https://gmail.googleapis.com',CHAT='https://chat.googleapis.com';
const routes=new Set(['chat-mail-connect','chat-mail-list','chat-mail-read','chat-mail-open','chat-mail-prepare','chat-prepare','chat-mail-send','chat-spaces','chat-messages','chat-open','chat-send']);
const query=o=>new URLSearchParams(Object.entries(o).filter(([,v])=>v!=='')).toString();
function resource(value,kind){const re=kind==='space'?/^spaces\/[A-Za-z0-9_-]+$/:/^spaces\/[A-Za-z0-9_-]+\/messages\/[A-Za-z0-9_.~-]+$/;if(typeof value!=='string'||!re.test(value))throw Error('Invalid Chat resource');return value;}
function mailId(value){if(typeof value!=='string'||! /^[a-fA-F0-9]{1,64}$/.test(value))throw Error('Invalid Gmail message');return value;}
export function mediaPath(value){if(typeof value!=='string'||value.length>4096||! /^[A-Za-z0-9_./=-]+$/.test(value)||value.split('/').some(s=>s==='.'||s==='..'))throw Error('Unsafe Chat media reference');return '/v1/media/'+value.split('/').map(encodeURIComponent).join('/')+'?alt=media';}
export function createTransport(session){
 let running=false;
 async function raw(message){const r=await session.request(GMAIL,'/gmail/v1/users/me/messages/'+mailId(message)+'?format=raw');if(typeof r.raw!=='string'||r.raw.length>400000)throw Error('Message exceeds preview limit');const bytes=bytes64(r.raw.replace(/-/g,'+').replace(/_/g,'/'));if(bytes.length>LIMIT)throw Error('Message exceeds preview limit');return {raw:b64(bytes)};}
 async function download(message,wanted){const matches=(message.attachment||[]).filter(a=>a.contentName===wanted);if(matches.length!==1)throw Error('Expected one '+wanted);return session.request(CHAT,mediaPath(matches[0].attachmentDataRef?.resourceName),{binary:true,limit:LIMIT});}
 async function upload(space,filename,data){
  const bytes=bytes64(data);if(!bytes.length||bytes.length>LIMIT)throw Error('Attachment limit');
  const boundary='sequoia-'+crypto.randomUUID();
  const body=new Blob(['--'+boundary+'\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n'+JSON.stringify({filename})+'\r\n--'+boundary+'\r\nContent-Type: application/octet-stream\r\n\r\n',bytes,'\r\n--'+boundary+'--\r\n']);
  const result=await session.request(CHAT,'/upload/v1/'+resource(space,'space')+'/attachments:upload?uploadType=multipart',{method:'POST',body,contentType:'multipart/related; boundary='+boundary});
  const ref=result.attachmentDataRef;if(!ref||!['attachmentUploadToken','resourceName'].some(k=>typeof ref[k]==='string'&&ref[k].length>0&&ref[k].length<=65536))throw Error('Missing uploaded attachment reference');
  return {attachmentDataRef:Object.fromEntries(['attachmentUploadToken','resourceName'].filter(k=>typeof ref[k]==='string').map(k=>[k,ref[k]]))};
 }
 async function perform(op,d,native,context){
  // Preparation is entirely local: the fixed native identity binds the sender,
  // IWA trust binds the recipient, and the vault gates the private operation.
  // Requiring OAuth here would prevent explicit offline encrypted-file export.
  if(op==='chat-mail-prepare'||op==='chat-prepare'){
   const service=op==='chat-mail-prepare'?'Gmail':'Chat';
   const space=service==='Gmail'?'Gmail':resource(d.space,'space');
   // Trust is resolved from current IWA storage, never from a UI label or a
   // legacy native contact. The native helper selects only its configured key.
   const contact=await context.certificateStore.trustedContact(d.contact);
   const own=await native('chat-signing-material',{});
   return context.composeReviews.prepare(own,contact,{account:context.account,subject:d.subject,service,space});
  }
  // Every network operation still checks the authenticated Google account
  // before reading data or consuming a send review. Offline preparation does
  // not authorize an upload, restore a token, or bypass this send-time check.
  await session.profile(context.account);
  if(op==='chat-mail-connect')return {account:context.account};
  if(op==='chat-mail-list'){
   if(d.query.length>1024||d.page.length>4096)throw Error('Search/page limit');
   const r=await session.request(GMAIL,'/gmail/v1/users/me/messages?'+query({maxResults:10,labelIds:'INBOX',q:d.query,pageToken:d.page})),messages=[];
   for(const m of r.messages||[]){
    // Metadata gives an accurate list even for messages above the preview cap.
    const meta=await session.request(GMAIL,'/gmail/v1/users/me/messages/'+mailId(m.id)+'?format=full');
    const headers=meta.payload?.headers||[],header=n=>headers.find(h=>h.name.toLowerCase()===n)?.value||'';
    let encrypted=false;
    const ct=meta.payload?.mimeType;
    if(['multipart/encrypted','multipart/mixed'].includes(ct)&&meta.sizeEstimate<=LIMIT){
     try{const packet=await raw(m.id);encrypted=envelope(bytes64(packet.raw)).kind==='encrypted';}
     catch(e){if(e.message.startsWith('Google')||e.message.startsWith('Sign in'))throw e;}
    }
    messages.push({name:m.id,text:(header('from')+' — '+header('subject')).slice(0,2000),time:header('date').slice(0,200),encrypted});
   }return {messages,next:r.nextPageToken||''};
  }
  if(op==='chat-mail-read'||op==='chat-mail-open')return raw(d.message);
  if(op==='chat-spaces'){const r=await session.request(CHAT,'/v1/spaces?'+query({pageSize:50,pageToken:d.page}));return {spaces:(r.spaces||[]).map(s=>({name:resource(s.name,'space'),title:s.displayName||s.name})),next:r.nextPageToken||''};}
  if(op==='chat-messages'){const r=await session.request(CHAT,'/v1/'+resource(d.space,'space')+'/messages?'+query({pageSize:20,pageToken:d.page,orderBy:'createTime desc'}));return {messages:(r.messages||[]).map(m=>({name:resource(m.name,'message'),text:(m.text||'').slice(0,2000),time:m.createTime||'',encrypted:(m.attachment||[]).some(a=>a.contentName==='message.pgp')})),next:r.nextPageToken||''};}
  if(op==='chat-open'){
   const name=resource(d.message,'message'),m=await session.request(CHAT,'/v1/'+name);let certMessage=m;
   if(!(m.attachment||[]).some(a=>a.contentName==='pq-mail-sender-key.pgp')){
    const links=[...(m.text||'').matchAll(/(?:^|\s)Certificate message:\s*(\S+)/g)];if(links.length!==1)throw Error('Missing certificate link');
    const linked=resource(links[0][1],'message');if(linked===name||linked.split('/messages/')[0]!==name.split('/messages/')[0])throw Error('Certificate link leaves conversation');
    certMessage=await session.request(CHAT,'/v1/'+linked);if(!m.sender?.name||certMessage.sender?.name!==m.sender.name)throw Error('Certificate message sender differs');
   }
   // Attached certificates establish mathematical identity only. Match the
   // full fingerprint against the selected, currently valid local trust entry.
   const contact=await context.certificateStore.trustedContact(d.contact);
   const certificate=await download(certMessage,'pq-mail-sender-key.pgp');
   const info=await context.certificateStore.preview(b64(certificate));
   if(contact.fingerprint!==info.fingerprint)throw Error('Attached certificate does not match the trusted sender');
   const cipher=b64(await download(m,'message.pgp'));
   await context.certificateStore.assertContact(contact);
   return {encrypted:true,cipher};
  }
  if(op==='chat-mail-send'||op==='chat-send'){
   if(d.confirmed!==true)throw Error('Explicit send confirmation required');
   const outgoing=await context.composeReviews.take(d.review,op==='chat-mail-send'?'Gmail':'Chat',d.confirmed,context.account);
   if(op==='chat-mail-send'){const r=await session.request(GMAIL,'/gmail/v1/users/me/messages/send',{method:'POST',body:JSON.stringify({raw:outgoing.raw.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')})});return {sent:r.id};}
   const space=resource(outgoing.space,'space');
   const bundle=await upload(space,'message.pgp',outgoing.cipher),certificate=await upload(space,'pq-mail-sender-key.pgp',outgoing.certificate);
   const send=body=>session.request(CHAT,'/v1/'+space+'/messages?requestId='+crypto.randomUUID(),{method:'POST',body:JSON.stringify(body)});
   const first=await send({text:'PQ Mail public OpenPGP certificate. Verify its fingerprint independently.',attachment:[certificate]});
   const certName=resource(first.name,'message');if(!certName.startsWith(space+'/messages/'))throw Error('Unexpected certificate destination');
   try{const r=await send({text:'PQ Mail signed OpenPGP bundle.\nCertificate message: '+certName,attachment:[bundle]});return {sent:r.name};}
   catch(e){throw Error('Certificate message was sent ('+certName+'); encrypted bundle delivery is uncertain. Inspect the conversation before another send. '+e.message);}
  }
  throw Error('Unsupported browser transport operation');
 }
 return {handles:op=>routes.has(op),login:expected=>session.login(expected),clear:()=>session.clear(),async call(...args){if(running)throw Error('A Google operation is already running.');running=true;try{return await perform(...args);}finally{running=false;}}};
}
if(typeof window!=='undefined'){
 const transport=createTransport(createSession());window.googleTransport=transport;
 window.addEventListener('iwa-vault-locked',()=>transport.clear());window.addEventListener('pagehide',()=>transport.clear());
}
