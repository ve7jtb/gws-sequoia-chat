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
test('Chat uploads exact binary bytes and preserves linked certificate order',async()=>{
 const calls=[];const t=createTransport({profile:async()=>{},request:async(o,p,opts)=>{calls.push({o,p,opts});if(p.includes('attachments:upload'))return {attachmentDataRef:{attachmentUploadToken:'test-upload'}};return {name:'spaces/test/messages/'+calls.length};}});
 await t.call('chat-send',{review:'ticket',confirmed:true},()=>assert.fail('No native send export'),{account:'test@example.org',composeReviews:{take:async()=>({space:'spaces/test',cipher:btoa('\x00\xffcipher'),certificate:btoa('public')})}});
 assert.equal(calls.length,4);const upload=new Uint8Array(await calls[0].opts.body.arrayBuffer());assert.ok(Buffer.from(upload).includes(Buffer.from([0,255,99,105,112,104,101,114])));assert.match(JSON.parse(calls[3].opts.body).text,/Certificate message: spaces\/test\/messages\/3/);
});
test('Chat media path rejects injected origins and traversal',()=>{for(const bad of ['https://evil.test/x','../x','a/../b','a?token=x','a#x'])assert.throws(()=>mediaPath(bad));assert.equal(mediaPath('spaces/a/media/b='),'/v1/media/spaces/a/media/b%3D?alt=media');});
test('Chat rejects certificate links outside conversation before download',async()=>{
 const t=createTransport({profile:async()=>{},request:async()=>({text:'Certificate message: spaces/other/messages/a'})});await assert.rejects(t.call('chat-open',{message:'spaces/test/messages/b',contact:'a'},()=>assert.fail('no native call'),{account:'test@example.org',contacts:[]}),/leaves conversation/);
});
test('signing preparation resolves browser trust before native key discovery and carries no recipient to native',async()=>{
 const calls=[];let accounts=0;
 const transport=createTransport({profile:async()=>{accounts++;},request:()=>assert.fail('No Google message upload during preparation')});
 const contact={id:'trusted-id',email:'recipient@example.invalid',fingerprint:'A'.repeat(64)};
 const context={account:'test@example.org',certificateStore:{trustedContact:async id=>{assert.equal(id,contact.id);calls.push({op:'local-trust'});return contact;}},composeReviews:{prepare:async(own,peer,metadata)=>({own,peer,metadata})}};
 for(const service of ['Gmail','Chat']){
  const input={contact:'trusted-id',subject:'Synthetic signing test',...(service==='Chat'?{space:'spaces/test'}:{})};
  const output=await transport.call(service==='Gmail'?'chat-mail-prepare':'chat-prepare',input,async(op,data)=>{
   calls.push({op,data});return {review:'prepared'};
  },context);
  assert.equal(output.peer,contact);assert.equal(output.metadata.service,service);
  assert.equal(calls.at(-2).op,'local-trust');assert.equal(calls.at(-1).op,'chat-signing-material');
  assert.deepEqual(calls.at(-1).data,{});
 }
 assert.equal(accounts,0);
 context.certificateStore.trustedContact=async()=>{throw Error('Trust removed');};
 await assert.rejects(transport.call('chat-mail-prepare',{contact:'trusted-id',subject:'Test'},()=>assert.fail('Untrusted recipient must not reach native'),context),/Trust removed/);
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
  return new TextEncoder().encode(p.includes('public')?'public certificate':'ciphertext');
 }});
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
 const context={account:'sender@example.invalid',certificateStore:{trustedContact:async()=>({email:'recipient@example.invalid'})},composeReviews:{prepare:async()=>({review:'ready'}),take:async()=>{consumed++;}}};
 const result=await transport.call('chat-mail-prepare',{contact:'saved',subject:'Offline test'},async op=>{assert.equal(op,'chat-signing-material');signing++;return {};},context);
 assert.equal(result.review,'ready');assert.equal(signing,1);
 await assert.rejects(transport.call('chat-mail-send',{review:'ready',confirmed:true},()=>assert.fail('No private operation during send'),context),/Sign in required/);
 assert.equal(consumed,0);assert.equal(uploads,0);
});
