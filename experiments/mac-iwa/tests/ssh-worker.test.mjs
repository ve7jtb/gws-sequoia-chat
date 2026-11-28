import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {Worker} from 'node:worker_threads';

function startWorker(t){
 // Run the shipped worker and Go engine with a synthetic socket that closes
 // before the banner. A real startup failure exercises Go's net.Conn.Close.
 const worker=new Worker(`
  const {parentPort,workerData}=require('node:worker_threads');
  const {readFile}=require('node:fs/promises');
  globalThis.fetch=async path=>new Response(await readFile(new URL(path,workerData)),{headers:{'Content-Type':'application/wasm'}});
  globalThis.TCPSocket=class{
   closed=Promise.resolve();
   opened=Promise.resolve({
    readable:new ReadableStream({start(controller){controller.close();}}),
    writable:new WritableStream(),
   });
   async close(){}
  };
  globalThis.postMessage=message=>parentPort.postMessage(message);
  globalThis.close=()=>parentPort.close();
  import(workerData).then(()=>parentPort.on('message',data=>globalThis.onmessage({data})));
 `,{eval:true,workerData:new URL('../app/ssh/worker.js',import.meta.url).href});
 t.after(()=>worker.terminate());
 return worker;
}

test('SSH worker reports the Go handshake error after transport cleanup',{timeout:5000},async t=>{
 const worker=startWorker(t);
 const key=Buffer.concat([Buffer.from([0,0,0,11]),Buffer.from('ssh-ed25519'),Buffer.from([0,0,0,32]),Buffer.alloc(32,7)]);
 worker.postMessage({type:'connect',host:'example.invalid',port:22,username:'test',publicKey:key});
 const [event]=await once(worker,'message');
 assert.equal(event.type,'error');
 assert.match(event.message,/handshake failed.*EOF/);
});

test('SSH software signing failure is reported before the worker exits',{timeout:5000},async t=>{
 const worker=startWorker(t);
 worker.postMessage({type:'software-sign',ml:new Uint8Array(31),ed:new Uint8Array(32),publicKey:new Uint8Array(),message:new Uint8Array()});
 const [event]=await once(worker,'message');
 assert.deepEqual(event,{type:'error',message:'SSH software signature failed.'});
});
