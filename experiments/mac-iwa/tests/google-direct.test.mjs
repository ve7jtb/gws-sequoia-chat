// These broker tests explicitly exercise extension authorization, independent
// of the production default (loopback); no browser storage is involved.
globalThis.localStorage={getItem:key=>key==='sequoia_google_oauth_mode'?'extension':null};
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createSession,SCOPES} from '../app/google-session.js';
import {createTransport,mediaPath} from '../app/google-transport.js';
function port(){const message=[],disconnect=[];return {onMessage:{addListener:f=>message.push(f)},onDisconnect:{addListener:f=>disconnect.push(f)},disconnect(){for(const f of disconnect)f();},postMessage(){queueMicrotask(()=>message.forEach(f=>f({type:'google-token',token:'synthetic-token-not-a-credential',expiresIn:3600,scope:SCOPES.join(' ')})));}};}
test('memory session validates account, constrains endpoints, and clears on lock',async()=>{
 let unlocked=true;const calls=[];const s=createSession({connect:port,unlocked:()=>unlocked,fetcher:async(url,opts)=>{calls.push({url,opts});return new Response(JSON.stringify({emailAddress:'test@example.org'}));}});
 try{await s.login('test@example.org');assert.equal(calls.length,1);assert.equal(calls[0].opts.redirect,'error');assert.equal(calls[0].opts.credentials,'omit');await assert.rejects(s.request('https://evil.test','/steal'));s.clear();await assert.rejects(s.profile('test@example.org'));assert.equal(calls.length,1);unlocked=false;await assert.rejects(s.login('test@example.org'));}finally{s.clear();}
});
test('wrong account, oversized response and HTTP errors fail closed without retry',async()=>{
 let mode='wrong',calls=0;const s=createSession({connect:port,unlocked:()=>true,fetcher:async()=>{calls++;return mode==='error'?new Response('{}',{status:503}):new Response(JSON.stringify({emailAddress:mode==='wrong'?'other@example.org':'test@example.org'}));}});
 try{await assert.rejects(s.login('test@example.org'),/does not match/);mode='ok';await s.login('test@example.org');await assert.rejects(s.request('https://gmail.googleapis.com','/gmail/v1/users/me/profile',{limit:1}),/limit/);mode='error';const before=calls;await assert.rejects(s.profile('test@example.org'),/503/);assert.equal(calls,before+1);}finally{s.clear();}
});
test('late response cannot restore session after vault lock',async()=>{
 let release;const s=createSession({connect:port,unlocked:()=>true,fetcher:()=>new Promise(r=>release=r)});const pending=s.login('test@example.org');await new Promise(r=>setImmediate(r));s.clear();release(new Response('{"emailAddress":"test@example.org"}'));await assert.rejects(pending,/cleared/);assert.throws(s.gate);
});
test('Gmail sends exact browser-reviewed bytes and never invokes native transport',async()=>{
 const calls=[],native=[];const t=createTransport({profile:async()=>{},request:async(...args)=>{calls.push(args);return {id:'abc'};}});
 const result=await t.call('chat-mail-send',{review:'ticket',confirmed:true},async(op)=>{native.push(op);assert.fail('No native send export');},{account:'test@example.org',composeReviews:{take:async()=>({raw:btoa('synthetic\r\nbytes')})}});
 assert.equal(result.sent,'abc');assert.deepEqual(native,[]);assert.equal(atob(JSON.parse(calls[0][2].body).raw),'synthetic\r\nbytes');assert.match(calls[0][1],/messages\/send$/);
});
test('Chat uploads exact binary bytes through typed broker and preserves linked certificate order',async()=>{
 const calls=[];const t=createTransport({profile:async()=>{},media:async input=>{calls.push({media:input});return {attachmentDataRef:{attachmentUploadToken:'test-upload'}};},request:async(o,p,opts)=>{calls.push({o,p,opts});assert.ok(!p.includes('attachments:upload'));return {name:'spaces/test/messages/'+calls.length};}});
 await t.call('chat-send',{review:'ticket',confirmed:true},()=>assert.fail('No native send export'),{account:'test@example.org',composeReviews:{take:async()=>({space:'spaces/test',cipher:btoa('\x00\xffcipher'),certificate:btoa('public')})}});
 assert.equal(calls.length,4);assert.deepEqual(calls[0].media,{op:'google-chat-upload',space:'spaces/test',filename:'message.pgp',data:btoa('\x00\xffcipher')});assert.equal(calls[1].media.filename,'pq-mail-sender-key.pgp');assert.match(JSON.parse(calls[3].opts.body).text,/Certificate message: spaces\/test\/messages\/3/);
});
// CORS can hide a successful server-side POST. Inject the same browser failure
// at each stage and require both precise progress and a consumed send review.
// These tests exercise uncertainty handling; they do not simulate browser CORS.
for(const [failureStage,label,outcome] of [
 [1,'encrypted-bundle upload','no Chat message creation was attempted'],
 [2,'public-certificate upload','no Chat message creation was attempted'],
 [3,'public-certificate message creation','Certificate delivery is uncertain; encrypted-bundle message creation was not attempted'],
 [4,'encrypted-bundle message creation','Certificate message was sent (spaces/test/messages/3); encrypted-bundle delivery is uncertain']
])test('Chat '+label+' failure identifies stage and never resends',async()=>{
 let requests=0,consumed=false;
 const network=async()=>{
  requests++;if(requests===failureStage)throw new TypeError('Failed to fetch');
  return requests<=2?{attachmentDataRef:{attachmentUploadToken:'test-upload'}}:{name:'spaces/test/messages/'+requests};
 };
 const transport=createTransport({profile:async()=>{},request:network,media:network});
 const context={account:'test@example.org',composeReviews:{take:async()=>{
  if(consumed)throw Error('Review already consumed');consumed=true;
  return {space:'spaces/test',cipher:btoa('encrypted'),certificate:btoa('public')};
 }}};
 const send=()=>transport.call('chat-send',{review:'ticket',confirmed:true},()=>assert.fail('No native transport fallback'),context);
 await assert.rejects(send(),error=>{
  assert.ok(error.message.startsWith('Chat '+label+' failed.'));
  assert.ok(error.message.includes(outcome));assert.match(error.message,/No automatic retry/);
  assert.match(error.message,/including CORS/);return true;
 });
 assert.equal(requests,failureStage);
 await assert.rejects(send(),/Review already consumed/);assert.equal(requests,failureStage);
});
test('Chat stage diagnostics keep HTTP status but omit untrusted error contents',async()=>{
 const transport=createTransport({profile:async()=>{},request:()=>assert.fail('Upload fails before normal REST'),media:async()=>{
  throw Error('Google API HTTP 403. Synthetic headers and bearer token must not reach UI');
 }});
 const context={account:'test@example.org',composeReviews:{take:async()=>({space:'spaces/test',cipher:btoa('encrypted'),certificate:btoa('public')})}};
 await assert.rejects(transport.call('chat-send',{review:'ticket',confirmed:true},()=>assert.fail('No native fallback'),context),error=>{
  assert.match(error.message,/encrypted-bundle upload failed/);assert.match(error.message,/Google API HTTP 403\.$/);
  assert.doesNotMatch(error.message,/Synthetic|headers|bearer token/);return true;
 });
});
test('Chat malformed create response remains an uncertain send instead of false success',async()=>{
 let requests=0;
 const network=async()=>{
  requests++;return requests<=2?{attachmentDataRef:{attachmentUploadToken:'test-upload'}}:
   {name:requests===3?'spaces/test/messages/certificate':'spaces/other/messages/unexpected'};
 };
 const transport=createTransport({profile:async()=>{},request:network,media:network});
 const context={account:'test@example.org',composeReviews:{take:async()=>({space:'spaces/test',cipher:btoa('encrypted'),certificate:btoa('public')})}};
 await assert.rejects(transport.call('chat-send',{review:'ticket',confirmed:true},()=>assert.fail('No native fallback'),context),error=>{
  assert.match(error.message,/encrypted-bundle message creation failed/);
  assert.match(error.message,/Certificate message was sent \(spaces\/test\/messages\/certificate\)/);
  assert.match(error.message,/delivery is uncertain/);return true;
 });
 assert.equal(requests,4);
});
test('Chat media path rejects injected origins and traversal',()=>{for(const bad of ['https://evil.test/x','../x','a/../b','a?token=x','a#x'])assert.throws(()=>mediaPath(bad));assert.equal(mediaPath('spaces/a/media/b='),'/v1/media/spaces/a/media/b%3D?alt=media');});
test('Chat rejects certificate links outside conversation before download',async()=>{
 const t=createTransport({profile:async()=>{},request:async()=>({text:'Certificate message: spaces/other/messages/a'})});await assert.rejects(t.call('chat-open',{message:'spaces/test/messages/b',contact:'a'},()=>assert.fail('no native call'),{account:'test@example.org',contacts:[]}),/leaves conversation/);
});
// The transport must carry only the selected public authority tuple to native
// discovery. Recipient trust, MIME and Google access remain in the IWA.
function selectedIdentity(account='test@example.org'){return {id:'selected-id',revision:2,
 serial:'12345678',bundleHash:'b'.repeat(64),fingerprint:'C'.repeat(64),
 certificateHash:'d'.repeat(64),email:account};}
function binding(identity){const {serial,bundleHash,fingerprint,certificateHash,email}=identity;
 return {serial,bundleHash,fingerprint,certificateHash,email};}
function identitySelection(identity,calls=[]){return {
 get:async(id,account)=>{assert.equal(id,identity.id);assert.equal(account,identity.email);calls.push({op:'local-identity'});return identity;},
 nativeBinding:binding,
 validateMaterial:async(own,selected,kind)=>{assert.equal(kind,'signing');assert.equal(selected,identity);
  assert.deepEqual(own.identity,binding(identity));calls.push({op:'material-validated'});}
};}
test('signing preparation resolves trust and selected identity before public-only native discovery',async()=>{
 const calls=[];let accounts=0;
 const transport=createTransport({profile:async()=>{accounts++;},request:()=>assert.fail('No Google message upload during preparation')});
 const contact={id:'trusted-id',email:'recipient@example.invalid',fingerprint:'A'.repeat(64)},identity=selectedIdentity();
 const context={account:identity.email,identitySelection:identitySelection(identity,calls),
  certificateStore:{trustedContact:async id=>{assert.equal(id,contact.id);calls.push({op:'local-trust'});return contact;}},
  composeReviews:{prepare:async(own,peer,metadata)=>({own,peer,metadata})}};
 for(const service of ['Gmail','Chat']){
  const input={contact:'trusted-id',identity:identity.id,subject:'Synthetic signing test',...(service==='Chat'?{space:'spaces/test'}:{})};
  const output=await transport.call(service==='Gmail'?'chat-mail-prepare':'chat-prepare',input,async(op,data)=>{
   calls.push({op,data});return {review:'prepared',identity:binding(identity)};
  },context);
  assert.equal(output.peer,contact);assert.equal(output.metadata.service,service);assert.equal(output.metadata.identity,identity);
  assert.deepEqual(calls.slice(-4).map(c=>c.op),['local-trust','local-identity','chat-selected-signing-material','material-validated']);
  assert.deepEqual(calls.at(-2).data,{identity:binding(identity)});
 }
 assert.equal(accounts,0);
 context.certificateStore.trustedContact=async()=>{throw Error('Trust removed');};
 await assert.rejects(transport.call('chat-mail-prepare',{contact:'trusted-id',identity:identity.id,subject:'Test'},()=>assert.fail('Untrusted recipient must not reach native'),context),/Trust removed/);
});
test('missing selection or mismatched native identity cannot create a signing review',async()=>{
 const identity=selectedIdentity(),transport=createTransport({profile:()=>assert.fail('No OAuth preparation')}),calls=[];
 const context={account:identity.email,identitySelection:identitySelection(identity),
  certificateStore:{trustedContact:async()=>({email:'peer@example.invalid'})},
  composeReviews:{prepare:()=>assert.fail('Invalid selected identity cannot reach review')}};
 await assert.rejects(transport.call('chat-mail-prepare',{contact:'trusted',subject:'Missing identity'},
  ()=>assert.fail('Missing identity cannot reach native'),context));
 await assert.rejects(transport.call('chat-mail-prepare',{contact:'trusted',identity:identity.id,subject:'Wrong serial'},
  async(op,data)=>{calls.push(op);return {identity:{...data.identity,serial:'87654321'}};},context));
 assert.deepEqual(calls,['chat-selected-signing-material']);
});
test('transport carries only literal compatibility confirmation into the revision-bound Compose review',async()=>{
 const identity=selectedIdentity(),transport=createTransport({profile:()=>assert.fail('No Google login for offline preparation')});
 const context={account:identity.email,identitySelection:identitySelection(identity),certificateStore:{trustedContact:async()=>({email:'recipient@example.invalid',pqEncryption:false})},composeReviews:{prepare:async(_own,_peer,options)=>options}};
 for(const value of [undefined,false,'true',true]){
  const result=await transport.call('chat-mail-prepare',{identity:identity.id,contact:'trusted',subject:'Compatibility',compatibilityConfirmed:value},async(_op,data)=>({identity:data.identity}),context);
  assert.equal(result.compatibilityConfirmed,value===true);
 }
});
test('certificate save/trust routes are no longer Google or native transport operations',()=>{
 const t=createTransport({});for(const op of ['chat-mail-cert-save','chat-mail-cert-trust'])assert.equal(t.handles(op),false);
});
test('send consumes browser review once and cannot retry an uncertain network send',async()=>{
 let taken=0,requests=0;const t=createTransport({profile:async()=>{},request:async()=>{requests++;throw Error('Network uncertain');}});
 const context={account:'test@example.org',composeReviews:{take:async(id,service,confirmed,account)=>{assert.deepEqual([id,service,confirmed,account],['ticket','Gmail',true,context.account]);if(taken++)throw Error('Consumed');return {raw:btoa('encrypted')};}}};
 await assert.rejects(t.call('chat-mail-send',{review:'ticket',confirmed:true},()=>assert.fail('No native request'),context),/Network uncertain/);
 await assert.rejects(t.call('chat-mail-send',{review:'ticket',confirmed:true},()=>assert.fail('No native request'),context),/Consumed/);
 assert.equal(requests,1);
});
test('Chat public certificate matching uses WASM-backed browser store and rechecks selected trust',async()=>{
 const fp='A'.repeat(64),calls=[];const contact={id:'trusted',email:'peer@example.invalid',fingerprint:fp};
 const t=createTransport({profile:async()=>{},request:async(o,p)=>{
  if(p.endsWith('/messages/test'))return {sender:{name:'users/peer'},attachment:[{contentName:'pq-mail-sender-key.pgp',attachmentDataRef:{resourceName:'public'}},{contentName:'message.pgp',attachmentDataRef:{resourceName:'encrypted'}}]};
  assert.fail('No direct browser media download');
 },media:async input=>{assert.equal(input.op,'google-chat-download');return new TextEncoder().encode(input.resource==='public'?'public certificate':'ciphertext');}});
 const context={account:'test@example.org',certificateStore:{trustedContact:async()=>contact,preview:async certificate=>{calls.push(atob(certificate));return {fingerprint:fp};},assertContact:async c=>{assert.equal(c,contact);calls.push('checked');}}};
 const result=await t.call('chat-open',{message:'spaces/test/messages/test',contact:'trusted'},()=>assert.fail('No native certificate operation'),context);
 assert.equal(atob(result.cipher),'ciphertext');assert.deepEqual(calls,['public certificate','checked']);
 context.certificateStore.preview=async()=>({fingerprint:'B'.repeat(64)});
 await assert.rejects(t.call('chat-open',{message:'spaces/test/messages/test',contact:'trusted'},()=>assert.fail('No native request'),context),/does not match/);
});

// Offline preparation must work with an absent Google session, while a Send
// remains account-authenticated before it consumes a review or uploads bytes.
test('offline preparation needs no OAuth but send still rejects an absent account session',async()=>{
 let uploads=0,consumed=0,signing=0;
 const transport=createTransport({profile:async()=>{throw Error('Sign in required');},request:async()=>{uploads++;}});
 const identity=selectedIdentity('sender@example.invalid');
 const context={account:identity.email,identitySelection:identitySelection(identity),certificateStore:{trustedContact:async()=>({email:'recipient@example.invalid'})},composeReviews:{prepare:async()=>({review:'ready'}),take:async()=>{consumed++;}}};
 const result=await transport.call('chat-mail-prepare',{contact:'saved',identity:identity.id,subject:'Offline test'},async op=>{assert.equal(op,'chat-selected-signing-material');signing++;return {identity:binding(identity)};},context);
 assert.equal(result.review,'ready');assert.equal(signing,1);
 await assert.rejects(transport.call('chat-mail-send',{review:'ready',confirmed:true},()=>assert.fail('No private operation during send'),context),/Sign in required/);
 assert.equal(consumed,0);assert.equal(uploads,0);
});

// Controlled extension ports exercise the real session lifecycle. The fake
// token is synthetic; neither these tests nor their fixtures contact Google.
function mediaFixture(options={}){
 const ports=[],calls=[];let isUnlocked=true,now=0;
 const session=createSession({connect:port,unlocked:()=>isUnlocked,clock:()=>now,mediaTimeoutMs:options.timeout??45000,
  fetcher:async(url,opts)=>{calls.push({url,opts});return new Response('{"emailAddress":"test@example.org"}');},
  mediaConnect:()=>{
   const listeners=new Set(),closed=new Set(),requests=[];
   const p={requests,disconnected:false,
    onMessage:{addListener:f=>listeners.add(f),removeListener:f=>listeners.delete(f)},
    onDisconnect:{addListener:f=>closed.add(f),removeListener:f=>closed.delete(f)},
    postMessage:request=>requests.push(structuredClone(request)),
    disconnect(){p.disconnected=true;for(const f of [...closed])f();},
    reply(value){for(const f of [...listeners])f(value);},
    pendingCallbacks(){return [...listeners];}};
   ports.push(p);return p;
  }});
 return {session,ports,calls,lock:()=>{isUnlocked=false;},expire:()=>{now=3600000;}};
}
const uploadInput=()=>({op:'google-chat-upload',space:'spaces/test',filename:'message.pgp',data:btoa('\x00\xffcipher')});
const uploadReply=()=>({type:'google-chat-media',result:{attachmentDataRef:{attachmentUploadToken:'synthetic-upload-reference'}}});
test('media session relays only typed binary attachment operations and closes each port',async()=>{
 const f=mediaFixture(),s=f.session;
 try{
  await s.login('test@example.org');
  const pending=s.media(uploadInput()),p=f.ports[0];
  assert.deepEqual(p.requests,[{...uploadInput(),token:'synthetic-token-not-a-credential'}]);
  p.reply(uploadReply());assert.deepEqual(await pending,uploadReply().result);assert.equal(p.disconnected,true);
  const download=s.media({op:'google-chat-download',resource:'spaces/test/media/abc='}),p2=f.ports[1];
  p2.reply({type:'google-chat-media',result:{data:btoa('\x00\xffattachment')}});
  assert.deepEqual(await download,Uint8Array.from(Buffer.from('\x00\xffattachment','latin1')));
  assert.equal(p2.disconnected,true);assert.equal(f.calls.length,1,'Only account profile uses ordinary fetch');
 }finally{s.clear();}
});
test('media operation inputs reject arbitrary paths, tokens and oversized data before connecting',async()=>{
 const f=mediaFixture(),s=f.session;
 try{
  await assert.rejects(s.media(uploadInput()),/Sign in/);await s.login('test@example.org');
  for(const bad of [{...uploadInput(),token:'caller-token'},{...uploadInput(),url:'https://evil.test'},
   {...uploadInput(),filename:'secret.p12'},{...uploadInput(),space:'spaces/a/messages/b'},
   {...uploadInput(),space:'spaces/'+ 'a'.repeat(256)},
   {...uploadInput(),data:'not base64!'},{...uploadInput(),data:'YQ'},
   {...uploadInput(),data:btoa('a'.repeat(262145))},{op:'google-chat-download',resource:'https://evil.test'},
   {op:'google-chat-download',resource:'a/../b'},{op:'google-chat-download',resource:''},
   {op:'native-sign',resource:'a'}])await assert.rejects(s.media(bad));
  assert.equal(f.ports.length,0);
 }finally{s.clear();}
});
test('vault lock cancels media immediately and late broker success cannot restore access',async()=>{
 const f=mediaFixture(),s=f.session;await s.login('test@example.org');
 const pending=s.media(uploadInput()),p=f.ports[0],late=p.pendingCallbacks();
 const rejected=assert.rejects(pending,/session cleared/);s.clear();await rejected;
 assert.equal(p.disconnected,true);for(const callback of late)callback(uploadReply());
 assert.throws(s.gate,/Sign in/);assert.equal(p.requests.length,1);
});
test('media response is discarded if vault locks or token expires before completion',async()=>{
 for(const change of ['lock','expire']){
  const f=mediaFixture(),s=f.session;
  try{await s.login('test@example.org');const pending=s.media(uploadInput());f[change]();f.ports[0].reply(uploadReply());await assert.rejects(pending,/Unlock|Sign in/);assert.equal(f.ports[0].disconnected,true);}
  finally{s.clear();}
 }
});
test('concurrent media operation is refused and old port cannot settle a replacement',async()=>{
 const f=mediaFixture(),s=f.session;
 try{
  await s.login('test@example.org');const first=s.media(uploadInput()),p=f.ports[0],late=p.pendingCallbacks();
  await assert.rejects(s.media(uploadInput()),/already running/);assert.equal(f.ports.length,1);
  p.reply(uploadReply());await first;
  const second=s.media({op:'google-chat-download',resource:'new'}),p2=f.ports[1];
  for(const callback of late)callback({type:'error',message:'old failure'});
  assert.equal(p2.disconnected,false);p2.reply({type:'google-chat-media',result:{data:btoa('new ciphertext')}});
  assert.equal(new TextDecoder().decode(await second),'new ciphertext');
 }finally{s.clear();}
});
test('media broker timeout/disconnect close the port without request retry',async()=>{
 for(const mode of ['timeout','disconnect']){
  const f=mediaFixture({timeout:5}),s=f.session;
  try{
   await s.login('test@example.org');const pending=s.media(uploadInput()),p=f.ports[0];
   if(mode==='disconnect')p.disconnect();
   await assert.rejects(pending,/timed out|connection closed/);
   assert.equal(f.ports.length,1);assert.equal(p.requests.length,1);assert.equal(p.disconnected,true);
  }finally{s.clear();}
 }
});
test('media replies are bounded, validated and never expose arbitrary broker errors',async()=>{
 const f=mediaFixture(),s=f.session;
 try{
  await s.login('test@example.org');
  for(const reply of [
   {type:'google-chat-media',result:{attachmentDataRef:{attachmentUploadToken:''}}},
   {type:'google-chat-media',result:{attachmentDataRef:{attachmentUploadToken:'x',url:'https://evil.test'}}},
   {type:'google-chat-media',result:{attachmentDataRef:{resourceName:'a'.repeat(65537)}}},
   {type:'error',message:'SENSITIVE_TOKEN_OR_BODY'},
   {type:'google-token',token:'SENSITIVE_TOKEN_OR_BODY'}]){
   const pending=s.media(uploadInput());f.ports.at(-1).reply(reply);
   await assert.rejects(pending,error=>{assert.doesNotMatch(error.message,/SENSITIVE_TOKEN_OR_BODY|evil.test/);return true;});
  }
  for(const data of ['YQ','!',btoa('a'.repeat(262145))]){
   const pending=s.media({op:'google-chat-download',resource:'safe'});f.ports.at(-1).reply({type:'google-chat-media',result:{data}});await assert.rejects(pending,/encoding or size/);
  }
  const pending=s.media(uploadInput());f.ports.at(-1).reply({type:'error',message:'Google API HTTP 401. SENSITIVE_TOKEN_OR_BODY'});
  await assert.rejects(pending,error=>{assert.match(error.message,/HTTP 401/);assert.doesNotMatch(error.message,/SENSITIVE/);return true;});assert.throws(s.gate,/Sign in/);
 }finally{s.clear();}
});

test('Drive preparation selects a Drive-only review without requesting mail scopes or making network calls',async()=>{
 const identity=selectedIdentity(),transport=createTransport({profile:()=>assert.fail('No Gmail/Chat access'),request:()=>assert.fail('No network during preparation')});
 const context={account:identity.email,identitySelection:identitySelection(identity),certificateStore:{trustedContact:async()=>({email:'recipient@example.invalid'})},composeReviews:{prepare:async(_own,_peer,options)=>options}};
 const result=await transport.call('chat-drive-prepare',{identity:identity.id,contact:'trusted',subject:'Encrypted file'},async(_op,data)=>({identity:data.identity}),context);
 assert.equal(result.service,'Drive');assert.equal(result.space,'Drive');assert.equal(result.account,identity.email);
});
