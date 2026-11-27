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
 let signed=false;connectSsh({host:'host',port:22,username:'user',publicKey:b,entries:[entry],sign:async()=>{signed=true},guard(){},onOutput(){},onStatus(){},WorkerClass:FakeWorker});
 await FakeWorker.instance.emit({type:'host',id:1,algorithm:'ssh-ed25519',data:new Uint8Array([4])});assert(FakeWorker.instance.stopped);assert(!signed);
});
