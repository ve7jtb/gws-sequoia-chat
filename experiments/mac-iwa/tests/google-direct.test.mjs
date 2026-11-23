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
test('Gmail sends exact exported bytes once and never invokes native transport',async()=>{
 const calls=[],native=[];const t=createTransport({profile:async()=>{},request:async(...args)=>{calls.push(args);return {id:'abc'};}});
 const result=await t.call('chat-mail-send',{review:'ticket',confirmed:true},async(op,d)=>{native.push(op);return {raw:btoa('synthetic\r\nbytes')};},{account:'test@example.org'});
 assert.equal(result.sent,'abc');assert.deepEqual(native,['chat-browser-export']);assert.equal(atob(JSON.parse(calls[0][2].body).raw),'synthetic\r\nbytes');assert.match(calls[0][1],/messages\/send$/);
});
test('Chat uploads exact binary bytes and preserves linked certificate order',async()=>{
 const calls=[];const t=createTransport({profile:async()=>{},request:async(o,p,opts)=>{calls.push({o,p,opts});if(p.includes('attachments:upload'))return {attachmentDataRef:{attachmentUploadToken:'test-upload'}};return {name:'spaces/test/messages/'+calls.length};}});
 await t.call('chat-send',{review:'ticket',confirmed:true},async()=>({space:'spaces/test',cipher:btoa('\x00\xffcipher'),certificate:btoa('public')}),{account:'test@example.org'});
 assert.equal(calls.length,4);const upload=new Uint8Array(await calls[0].opts.body.arrayBuffer());assert.ok(Buffer.from(upload).includes(Buffer.from([0,255,99,105,112,104,101,114])));assert.match(JSON.parse(calls[3].opts.body).text,/Certificate message: spaces\/test\/messages\/3/);
});
test('Chat media path rejects injected origins and traversal',()=>{for(const bad of ['https://evil.test/x','../x','a/../b','a?token=x','a#x'])assert.throws(()=>mediaPath(bad));assert.equal(mediaPath('spaces/a/media/b='),'/v1/media/spaces/a/media/b%3D?alt=media');});
test('Chat rejects certificate links outside conversation before download',async()=>{
 const t=createTransport({profile:async()=>{},request:async()=>({text:'Certificate message: spaces/other/messages/a'})});await assert.rejects(t.call('chat-open',{message:'spaces/test/messages/b',contact:'a'},()=>assert.fail('no native call'),{account:'test@example.org',contacts:[]}),/leaves conversation/);
});
test('signing preparation stays offline after browser account check and carries no message body',async()=>{
 const calls=[];let accounts=0;
 const transport=createTransport({profile:async()=>{accounts++;},request:()=>assert.fail('No Google message upload during preparation')});
 for(const service of ['Gmail','Chat']){
  const input={contact:'trusted-id',subject:'Synthetic signing test',...(service==='Chat'?{space:'spaces/test'}:{})};
  const output=await transport.call(service==='Gmail'?'chat-mail-prepare':'chat-prepare',input,async(op,data)=>{
   calls.push({op,data});return {review:'prepared'};
  },{account:'test@example.org'});
  assert.deepEqual(output,{review:'prepared'});
  assert.equal(calls.at(-1).op,'chat-browser-prepare');
  assert.deepEqual(Object.keys(calls.at(-1).data).sort(),['contact','service','space','subject']);
  assert.equal(calls.at(-1).data.service,service);
 }
 assert.equal(accounts,2);
});
