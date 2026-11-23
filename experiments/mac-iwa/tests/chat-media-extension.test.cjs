const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync(require('node:path').join(__dirname,'../extension/chat-media.js'),'utf8');
const token='synthetic-access-token-not-a-credential';
const upload=()=>({op:'google-chat-upload',token,space:'spaces/TEST',filename:'message.pgp',data:Buffer.from([0,255,128,13,10]).toString('base64')});
const download=()=>({op:'google-chat-download',token,resource:'spaces/TEST/media/id='});
function port(){
 const messages=[],listeners=new Set();
 return {messages,listeners,postMessage:value=>messages.push(structuredClone(value)),
  onDisconnect:{addListener:f=>listeners.add(f),removeListener:f=>listeners.delete(f)},
  disconnect(){for(const listener of [...listeners])listener();}};
}
function setup(fetcher,timers={setTimeout,clearTimeout}){
 // No chrome/native/storage objects exist in this realm. Tests use only mock
 // fetch responses, including streamed binary data; no Google request occurs.
 const calls=[],context=vm.createContext({AbortController,Blob,TextDecoder,Uint8Array,WeakMap,
  atob,btoa,crypto:require('node:crypto').webcrypto,...timers,
  fetch:async(...args)=>{calls.push(args);return fetcher(...args);}});
 vm.runInContext(source,context);return {context,calls};
}
function uploaded(){return new Response(JSON.stringify({attachmentDataRef:{attachmentUploadToken:'opaque-test-upload',resourceName:'spaces/TEST/media/id='},unrelated:'must not return'}));}

test('upload uses fixed endpoint and exact binary multipart with ephemeral bearer',async()=>{
 const s=setup(async()=>uploaded()),p=port();await s.context.startChatMedia(p,upload());
 assert.equal(s.calls.length,1);const [url,options]=s.calls[0];
 assert.equal(url,'https://chat.googleapis.com/upload/v1/spaces/TEST/attachments:upload?uploadType=multipart');
 assert.equal(options.method,'POST');assert.equal(options.credentials,'omit');assert.equal(options.cache,'no-store');assert.equal(options.redirect,'error');
 assert.equal(options.headers.Authorization,'Bearer '+token);assert.match(options.headers['Content-Type'],/^multipart\/related; boundary=sequoia-/);
 const body=Buffer.from(await options.body.arrayBuffer());assert.ok(body.includes(Buffer.from([0,255,128,13,10])));
 assert.ok(body.includes(Buffer.from('"filename":"message.pgp"')));
 assert.deepEqual(p.messages,[{type:'google-chat-media',result:{attachmentDataRef:{attachmentUploadToken:'opaque-test-upload',resourceName:'spaces/TEST/media/id='}}}]);
 assert.equal(p.listeners.size,0);
});
test('download returns canonical binary base64 without native or storage calls',async()=>{
 const data=Uint8Array.from([0,255,128,13,10]),s=setup(async()=>new Response(data)),p=port();
 await s.context.startChatMedia(p,download());
 assert.equal(s.calls[0][0],'https://chat.googleapis.com/v1/media/spaces/TEST/media/id%3D?alt=media');
 assert.equal(s.calls[0][1].method,'GET');assert.equal(s.calls[0][1].body,undefined);
 assert.equal(s.calls[0][1].headers['Content-Type'],undefined);
 assert.deepEqual(p.messages,[{type:'google-chat-media',result:{data:Buffer.from(data).toString('base64')}}]);
});
test('unknown operations and fields cannot create an arbitrary HTTPS proxy',async()=>{
 const s=setup(async()=>assert.fail('Invalid requests must not fetch'));
 for(const request of [null,[],{}, {...upload(),op:'chat-send'}, {...upload(),url:'https://evil.test'},
                       {...upload(),headers:{}},{...download(),method:'POST'},{...download(),data:'YQ=='},
                       {...upload(),filename:'secret.p12'},{...upload(),space:'https://evil.test'},
                       {...upload(),space:'spaces/../other'},{...upload(),space:'spaces/'+ 'a'.repeat(257)}]){
  const p=port();await s.context.startChatMedia(p,request);assert.equal(p.messages[0].type,'error');
 }
 assert.equal(s.calls.length,0);
});
test('bearer header input refuses controls, whitespace, empty and oversized values',async()=>{
 const s=setup(async()=>assert.fail('Invalid bearer must not fetch'));
 for(const bad of ['', 'short',token+'\r\nX-Other: value',token+' ', 'a'.repeat(8193),{}]){
  const p=port();await s.context.startChatMedia(p,{...upload(),token:bad});assert.equal(p.messages[0].type,'error');
 }
 assert.equal(s.calls.length,0);
});
test('upload rejects noncanonical base64 and decoded or encoded size overflow',async()=>{
 const s=setup(async()=>assert.fail('Invalid bytes must not fetch'));
 for(const data of ['', 'AA', 'AA==\n','AB==','AA__','a===','A'.repeat(349532),Buffer.alloc(262145).toString('base64')]){
  const p=port();await s.context.startChatMedia(p,{...upload(),data});assert.equal(p.messages[0].type,'error');
 }
 assert.equal(s.calls.length,0);
});
test('exact input limit and both fixed public filenames are accepted',async()=>{
 const s=setup(async()=>uploaded());
 for(const filename of ['message.pgp','pq-mail-sender-key.pgp']){
  const p=port();await s.context.startChatMedia(p,{...upload(),filename,data:Buffer.alloc(262144).toString('base64')});
  assert.equal(p.messages[0].type,'google-chat-media');
 }
 assert.equal(s.calls.length,2);
});
test('download resource cannot inject host, query, fragment or traversal',async()=>{
 const s=setup(async()=>assert.fail('Invalid media reference must not fetch'));
 for(const resource of ['', 'https://evil.test/a','a?token=x','a#frag','a/../b','./a','a/./b','a'.repeat(4097)]){
  const p=port();await s.context.startChatMedia(p,{...download(),resource});assert.equal(p.messages[0].type,'error');
 }
 assert.equal(s.calls.length,0);
});
test('streamed response limits apply without Content-Length and cancel the reader',async()=>{
 for(const [request,limit] of [[upload(),131072],[download(),262144]]){
  let cancelled=false;
  const stream=new ReadableStream({start(controller){controller.enqueue(new Uint8Array(limit));controller.enqueue(new Uint8Array(1));},cancel(){cancelled=true;}});
  const s=setup(async()=>new Response(stream)),p=port();await s.context.startChatMedia(p,request);
  assert.equal(p.messages[0].type,'error');assert.match(p.messages[0].message,/size limit/);assert.equal(cancelled,true);
 }
});
test('upload JSON must contain a validated bounded attachment reference',async()=>{
 for(const value of [null,{}, {attachmentDataRef:{}},{attachmentDataRef:[]},
  {attachmentDataRef:{attachmentUploadToken:''}},{attachmentDataRef:{attachmentUploadToken:'a'.repeat(65537)}},
  {attachmentDataRef:{resourceName:'https://evil.test'}},{attachmentDataRef:{attachmentUploadToken:'ok',resourceName:7}}]){
  const s=setup(async()=>new Response(JSON.stringify(value))),p=port();await s.context.startChatMedia(p,upload());
  assert.equal(p.messages[0].type,'error');assert.doesNotMatch(p.messages[0].message,/evil.test/);
 }
});
test('non-JSON success and fetch errors return sanitized fixed diagnostics',async()=>{
 for(const fetcher of [async()=>new Response('server diagnostic with private text'),async()=>{throw new TypeError('URL Bearer PRIVATE');}]){
  const s=setup(fetcher),p=port();await s.context.startChatMedia(p,upload());
  assert.equal(p.messages[0].type,'error');assert.doesNotMatch(p.messages[0].message,/private text|Bearer|PRIVATE|URL/);
 }
});
test('HTTP failures disclose only the status and never retry',async()=>{
 const s=setup(async()=>new Response('private error body',{status:403})),p=port();
 await s.context.startChatMedia(p,upload());await s.context.startChatMedia(p,upload());
 assert.equal(s.calls.length,1);assert.equal(p.messages.length,1);
 assert.match(p.messages[0].message,/^Google API HTTP 403\./);assert.doesNotMatch(p.messages[0].message,/private error/);
});
test('disconnect aborts and discards a late success',async()=>{
 let resolve;const s=setup(()=>new Promise(r=>resolve=r)),p=port();
 const pending=s.context.startChatMedia(p,upload());p.disconnect();
 assert.equal(s.calls[0][1].signal.aborted,true);resolve(uploaded());await pending;
 assert.equal(p.messages.length,0);assert.equal(p.listeners.size,0);
});
test('duplicate request aborts its first attempt and cannot return a late result',async()=>{
 let resolve;const s=setup(()=>new Promise(r=>resolve=r)),p=port();
 const pending=s.context.startChatMedia(p,upload());await s.context.startChatMedia(p,download());
 assert.equal(s.calls.length,1);assert.equal(s.calls[0][1].signal.aborted,true);
 assert.equal(p.messages.length,1);assert.match(p.messages[0].message,/Duplicate/);
 resolve(uploaded());await pending;assert.equal(p.messages.length,1);
});
test('global owner excludes concurrent ports and stale cleanup cannot release a new owner',async()=>{
 const pending=[],s=setup(()=>new Promise(resolve=>pending.push(resolve))),first=port(),blocked=port(),next=port(),third=port();
 const a=s.context.startChatMedia(first,upload());await s.context.startChatMedia(blocked,download());
 assert.match(blocked.messages[0].message,/in progress/);assert.equal(s.calls.length,1);
 first.disconnect();const b=s.context.startChatMedia(next,upload());assert.equal(s.calls.length,2);
 pending[0](uploaded());await a;
 await s.context.startChatMedia(third,download());assert.match(third.messages[0].message,/in progress/);assert.equal(s.calls.length,2);
 pending[1](uploaded());await b;
 const final=port(),c=s.context.startChatMedia(final,download());assert.equal(s.calls.length,3);
 pending[2](new Response('bytes'));await c;assert.equal(final.messages[0].type,'google-chat-media');
});
test('45-second timeout aborts, reports once and releases global ownership',async()=>{
 let timer,delay,resolve;
 const s=setup(()=>new Promise(r=>resolve=r),{setTimeout:(f,ms)=>{timer=f;delay=ms;return 1;},clearTimeout:()=>{}}),p=port();
 const pending=s.context.startChatMedia(p,upload());assert.equal(delay,45000);timer();
 assert.equal(s.calls[0][1].signal.aborted,true);assert.match(p.messages[0].message,/timed out/);
 resolve(uploaded());await pending;assert.equal(p.messages.length,1);assert.equal(p.listeners.size,0);
 const next=port(),again=s.context.startChatMedia(next,download());resolve(new Response('ok'));await again;
 assert.equal(next.messages[0].type,'google-chat-media');
});
