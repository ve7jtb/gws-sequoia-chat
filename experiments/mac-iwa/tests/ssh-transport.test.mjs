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
    readable:new ReadableStream({start(c){for(const s of chunks)c.enqueue(typeof s==='string'?new TextEncoder().encode(s):s);if(!pending)c.close();}}),
    writable:new WritableStream({write(b){calls.sent.push(b);}})
   });
  }
  close(){calls.closed++;return Promise.resolve();}
 }
 return {Socket,calls};
}
function serverProposal(keyExchanges,sendCipher,receiveCipher=sendCipher){
 const lists=[keyExchanges,'ssh-ed25519',sendCipher,receiveCipher,'hmac-sha2-256','hmac-sha2-256','none','none','',''];
 const fields=lists.map(text=>{
  const value=Buffer.from(text),field=Buffer.alloc(4+value.length);field.writeUInt32BE(value.length);value.copy(field,4);return field;
 });
 const payload=Buffer.concat([Buffer.from([20]),Buffer.alloc(16),...fields,Buffer.alloc(5)]);
 const padding=Array.from({length:8},(_,i)=>i+4).find(n=>(payload.length+5+n)%8===0);
 const header=Buffer.alloc(5);header.writeUInt32BE(payload.length+padding+1);header[4]=padding;
 return Buffer.concat([header,payload,Buffer.alloc(padding)]);
}
test('fragmented and coalesced identification and proposals report preferred hybrid transport',async()=>{
 const packet=serverProposal('curve25519-sha256,mlkem768x25519-sha256','aes256-ctr','chacha20-poly1305@openssh.com');
 const f=socket(['notice\r\nSSH-',Buffer.concat([Buffer.from('2.0-Test_1\r\n'),packet.subarray(0,2)]),packet.subarray(2,15),packet.subarray(15)]);
 const result=await probe({host:'localhost',port:22,guard:()=>{},Socket:f.Socket});
 assert.deepEqual(result,{identification:'SSH-2.0-Test_1',authenticated:false,keyExchange:'mlkem768x25519-sha256',clientToServer:'aes256-ctr',serverToClient:'chacha20-poly1305@openssh.com',postQuantum:true});
 assert.equal(new TextDecoder().decode(f.calls.sent[0]),'SSH-2.0-SequoiaIWA_probe\r\n');
 assert.equal(f.calls.sent[1][5],20);assert.equal(f.calls.sent.length,2);assert(f.calls.closed>0);
});
test('an unsupported hybrid offer falls back to classical or reports no compatible transport',async()=>{
 const offer=keyExchanges=>socket(['SSH-2.0-Test\r\n',serverProposal(keyExchanges,'aes256-ctr')]);
 const f=offer('sntrup761x25519-sha512@openssh.com,curve25519-sha256');
 const result=await probe({host:'localhost',port:22,guard:()=>{},Socket:f.Socket});
 assert.equal(result.keyExchange,'curve25519-sha256');assert.equal(result.postQuantum,false);
 await assert.rejects(probe({host:'localhost',port:22,guard:()=>{},Socket:offer('unsupported').Socket}),/No compatible SSH transport/);
 const malformed=socket(['SSH-2.0-Test\r\n',Uint8Array.of(127,0,0,0)]);
 await assert.rejects(probe({host:'localhost',port:22,guard:()=>{},Socket:malformed.Socket}),/packet length/);
});
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
