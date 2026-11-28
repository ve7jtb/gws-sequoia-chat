import test from 'node:test';import assert from 'node:assert/strict';import {connectSsh} from '../app/ssh/client.js';
class FakeWorker{static instance;constructor(){FakeWorker.instance=this;this.sent=[];}postMessage(x){this.sent.push(x)}terminate(){this.stopped=true}async emit(data){await this.onmessage({data})}}
const b=new Uint8Array([1,2,3]),entry={hosts:'host',type:'ssh-ed25519',key:btoa(String.fromCharCode(...b)),marker:''};
test('client refuses signer before trust; vault lock destroys session',async()=>{
 let signatures=0;const status=[];const controller=new AbortController();
 const opts={host:'host',port:22,username:'user',publicKey:b,entries:[entry],sign:async()=>{signatures++;return b},guard(){},signal:controller.signal,onOutput(){},onStatus:x=>status.push(x),WorkerClass:FakeWorker};
 connectSsh(opts);await FakeWorker.instance.emit({type:'sign',id:1,data:b});assert.equal(signatures,0);assert(FakeWorker.instance.stopped);
 const session=connectSsh(opts),worker=FakeWorker.instance;await worker.emit({type:'host',id:1,algorithm:'ssh-ed25519',data:b});await worker.emit({type:'sign',id:2,data:b});assert.equal(signatures,1);controller.abort();assert(worker.stopped);session.close();
});
test('client rejects changed host before signing',async()=>{
 let signed=false;connectSsh({host:'host',port:22,username:'user',publicKey:b,entries:[entry],acceptUnknownHost:()=>assert.fail('Must not offer to trust a changed key'),sign:async()=>{signed=true},guard(){},onOutput(){},onStatus(){},WorkerClass:FakeWorker});
 await FakeWorker.instance.emit({type:'host',id:1,algorithm:'ssh-ed25519',data:new Uint8Array([4])});assert(FakeWorker.instance.stopped);assert(!signed);
});

test('first-use review must save the same host key before any authentication',async()=>{
 let entries=[],signatures=0,reviewed=0,save=false;
 const attempt=()=>connectSsh({host:'host',port:22,username:'user',publicKey:b,getEntries:()=>entries,
  acceptUnknownHost:async(candidate,check)=>{
   check();reviewed++;
   assert.deepEqual(candidate,{host:'host',port:22,type:entry.type,key:entry.key});
   assert.equal(signatures,0);
   if(save)entries=[entry];
  },
  sign:async()=>{signatures++;return b;},guard(){},onOutput(){},onStatus(){},WorkerClass:FakeWorker});
 const host={type:'host',id:1,algorithm:entry.type,data:b};
 attempt();await FakeWorker.instance.emit(host);assert(FakeWorker.instance.stopped);assert.equal(reviewed,1);
 save=true;
 const session=attempt();await FakeWorker.instance.emit(host);
 await FakeWorker.instance.emit({type:'sign',id:2,data:b});
 assert.equal(signatures,1);assert.equal(reviewed,2);session.close();
 const reconnect=attempt();await FakeWorker.instance.emit(host);
 assert.equal(reviewed,2);reconnect.close();
});

test('password is requested once after host verification and is cleared after handoff',async()=>{
 let prompts=0,secret;
 class PasswordWorker extends FakeWorker{
  postMessage(message){super.postMessage(structuredClone(message));}
 }
 const options={host:'host',port:22,username:'user',publicKey:b,entries:[entry],
  authorizeKey:true,requestPassword:async target=>{
   prompts++;assert.deepEqual(target,{host:'host',port:22,username:'user',algorithms:['ssh-ed25519']});
   secret=new TextEncoder().encode('disposable password');return secret;
  },
  sign:()=>assert.fail('Key authorization must not access private keys'),
  guard(){},onOutput(){},onStatus(){},WorkerClass:PasswordWorker};
 connectSsh(options);
 await FakeWorker.instance.emit({type:'password',id:1});
 assert.equal(prompts,0);assert(FakeWorker.instance.stopped);
 connectSsh(options);
 const worker=FakeWorker.instance;
 await worker.emit({type:'host',id:1,algorithm:entry.type,data:b});
 await worker.emit({type:'password',id:2,algorithms:['ssh-ed25519']});
 assert.equal(prompts,1);assert(secret.every(byte=>byte===0));
 assert.equal(new TextDecoder().decode(worker.sent.at(-1).result),'disposable password');
 await worker.emit({type:'password',id:3});
 assert.equal(prompts,1);assert(worker.stopped);
});

test('SSH connection and signing use a fixed TrustedScriptURL and module worker',async()=>{
 const oldPolicy=globalThis.trustedTypes,oldWorker=globalThis.Worker;
 let createScriptURL;
 const created=[];
 globalThis.trustedTypes={createPolicy(name,rules){
  assert.equal(name,'sequoia-ssh-worker');
  createScriptURL=rules.createScriptURL;
  return {createScriptURL:url=>({trustedUrl:createScriptURL(url)})};
 }};
 globalThis.Worker=class{
  constructor(url,options){
   assert.deepEqual(url,{trustedUrl:'/ssh/worker.js'});
   assert.deepEqual(options,{type:'module'});
   created.push(this);
  }
  postMessage(data){
   if(data.type==='software-sign')queueMicrotask(()=>this.onmessage({data:{type:'signature',signature:b}}));
  }
  terminate(){}
 };
 try{
  const {connectSsh,signSoftwareSsh}=await import('../app/ssh/client.js?trusted-types-test');
  assert.throws(()=>createScriptURL('/other-worker.js'),/Unexpected SSH worker URL/);
  connectSsh({host:'host',port:22,username:'user',publicKey:b,guard(){}}).close();
  assert.deepEqual(await signSoftwareSsh({publicKey:b}),b);
  assert.equal(created.length,2);
 }finally{
  if(oldPolicy===undefined)delete globalThis.trustedTypes;else globalThis.trustedTypes=oldPolicy;
  if(oldWorker===undefined)delete globalThis.Worker;else globalThis.Worker=oldWorker;
 }
});
