import test from 'node:test';
import assert from 'node:assert/strict';
import {createFileTransfer} from '../app/ssh/file-transfer.js';

test('the SFTP bridge copies bytes only between the vault and the bound session',async()=>{
 const payload=Uint8Array.of(0,128,255);
 const replies=[],operations=[],saved=[];
 const putPlain=payload.slice(),remotePlain=payload.slice();
 const files={
  list:async()=>[{id:'stored',name:'fixture.bin',size:3}],
  async add(file){saved.push({name:file.name,bytes:await file.bytes()});},
  async open(id){assert.equal(id,'stored');return {name:'fixture.bin',plain:putPlain};},
 };
 const ssh={async transfer(op,{directory,name,bytes}){
  assert.equal(directory,'/home/fixture');
  assert.equal(name,'fixture.bin');
  operations.push(op);
  if(op==='get')return remotePlain;
  assert.deepEqual(bytes,payload);
 }};
 const transfer=createFileTransfer({session:()=>ssh,store:()=>files,guard(){},reply:(id,result)=>replies.push([id,result])});
 await transfer.request({id:1,op:'local'});
 await transfer.request({id:2,op:'put',directory:'/home/fixture',fileId:'stored'});
 await transfer.request({id:3,op:'get',directory:'/home/fixture',name:'fixture.bin'});
 assert.deepEqual(operations,['put','get']);
 assert.deepEqual(saved,[{name:'fixture.bin',bytes:payload}]);
 assert.deepEqual(replies,[[1,{result:[{id:'stored',name:'fixture.bin',size:3}]}],[2,{result:undefined}],[3,{result:undefined}]]);
 assert.deepEqual(putPlain,new Uint8Array(3));
 assert.deepEqual(remotePlain,new Uint8Array(3));
});

test('closing a terminal prevents a late download from reaching encrypted storage',async()=>{
 const started=Promise.withResolvers(),late=Promise.withResolvers();
 const result=Uint8Array.of(11);
 const transfer=createFileTransfer({
  session:()=>({transfer(_op,_fields,signal){started.resolve(signal);return late.promise;}}),
  store:()=>({add(){assert.fail('A closed session cannot save a file');}}),
  guard(){},
  reply(){assert.fail('A closed popup cannot receive a reply');},
 });
 const downloading=transfer.request({id:1,op:'get',directory:'/',name:'test.bin'});
 const signal=await started.promise;
 transfer.cancel();assert(signal.aborted);
 late.resolve(result);
 await downloading;
 assert.deepEqual(result,Uint8Array.of(0));
});
