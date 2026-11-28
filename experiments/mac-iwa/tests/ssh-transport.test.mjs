import test from 'node:test';import assert from 'node:assert/strict';
import {probe,endpoint} from '../app/ssh/transport.js';
// Synthetic sockets exercise the same stream boundary without opening a network
// connection, submitting a credential, or accessing a physical authenticator.
function socket(chunks,{pending=false}={}){
 const calls={opened:0,closed:0,sent:[]};
 class Socket{
  constructor(){
   calls.opened++;this.closed=Promise.resolve();
   this.opened=Promise.resolve({
    readable:new ReadableStream({start(c){for(const s of chunks)c.enqueue(new TextEncoder().encode(s));if(!pending)c.close();}}),
    writable:new WritableStream({write(b){calls.sent.push(new TextDecoder().decode(b));}})
   });
  }
  close(){calls.closed++;return Promise.resolve();}
 }
 return {Socket,calls};
}
test('identification handles fragmented lines and closes without authentication',async()=>{const f=socket(['notice\r\nSSH-','2.0-Test_1\r','\n']);const result=await probe({host:'localhost',port:22,guard:()=>{},Socket:f.Socket});assert.equal(result.identification,'SSH-2.0-Test_1');assert.equal(result.authenticated,false);assert.deepEqual(f.calls.sent,['SSH-2.0-SequoiaIWA_probe\r\n']);assert(f.calls.closed>0);});
test('locked vault and invalid endpoints open no socket',async()=>{const f=socket([]);await assert.rejects(probe({host:'localhost',port:22,Socket:f.Socket,guard:()=>{throw Error('locked');}}),/locked/);assert.equal(f.calls.opened,0);for(const host of ['','a/b','user@host','host\n'])assert.throws(()=>endpoint(host,22));for(const port of [0,65536,1.2])assert.throws(()=>endpoint('localhost',port));});
test('lock cancellation closes a pending connection and rejects late data',async()=>{const f=socket([],{pending:true}),abort=new AbortController();const pending=probe({host:'localhost',port:22,Socket:f.Socket,guard:()=>{},signal:abort.signal});await new Promise(r=>setImmediate(r));abort.abort();await assert.rejects(pending,/cancelled/);assert(f.calls.closed>0);});
test('unsupported protocol, excessive line and control characters fail closed',async()=>{for(const text of ['SSH-1.5-old\r\n','x'.repeat(254),'SSH-2.0-evil\x1b\n']){const f=socket([text]);await assert.rejects(probe({host:'localhost',port:22,Socket:f.Socket,guard:()=>{}}));assert(f.calls.closed>0);}});
test('TCP connection timeout is reported even when socket close is pending',async()=>{
 let closing=false;
 class Socket{
  opened=new Promise(()=>{});
  close(){closing=true;return new Promise(()=>{});}
 }
 await assert.rejects(probe({host:'localhost',port:22,Socket,guard:()=>{},timeoutMs:5}),/Timed out waiting for a TCP connection/);
 assert(closing);
});
test('server identification timeout closes the stalled stream',async()=>{
 const f=socket([],{pending:true});
 await assert.rejects(probe({host:'localhost',port:22,Socket:f.Socket,guard:()=>{},timeoutMs:5}),/Timed out waiting for the server’s SSH identification/);
 assert(f.calls.closed>0);
});
