import test from 'node:test';import assert from 'node:assert/strict';
import {matchesHost,verifyHost} from '../app/ssh/host-verifier.js';
test('SSH hostname matching preserves negation and nondefault ports',async()=>{
 assert.equal(await matchesHost('*.example,!bad.example','ok.example'),true);
 assert.equal(await matchesHost('*.example,!bad.example','bad.example'),false);
 assert.equal(await matchesHost('[host]:2222','host',2222),true);
 assert.equal(await matchesHost('host','host',2222),false);
});
test('SSH hashed known_hosts matches only the salted host',async()=>{
 const salt=crypto.getRandomValues(new Uint8Array(20)),key=await crypto.subtle.importKey('raw',salt,{name:'HMAC',hash:'SHA-1'},false,['sign']);
 const mac=new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode('[host]:2222')));
 const b64=x=>btoa(String.fromCharCode(...x)),entry='|1|'+b64(salt)+'|'+b64(mac);
 assert.equal(await matchesHost(entry,'host',2222),true);assert.equal(await matchesHost(entry,'other',2222),false);
});
test('SSH trust rejects unknown, changed, revoked, certificates and lock races',async()=>{
 const entry={hosts:'host',type:'ssh-ed25519',key:'test',marker:''};
 const args={host:'host',type:entry.type,key:entry.key,entries:[entry]};
 assert.equal(await verifyHost(args),true);
 await assert.rejects(verifyHost({...args,host:'other'}),/Unknown/);
 await assert.rejects(verifyHost({...args,key:'different'}),/changed/);
 await assert.rejects(verifyHost({...args,entries:[entry,{...entry,marker:'@revoked',hosts:'elsewhere'}]}),/revoked/);
 await assert.rejects(verifyHost({...args,type:'ssh-ed25519-cert-v01@openssh.com'}),/not supported/);
 await assert.rejects(verifyHost({...args,entries:[{...entry,key:'ca',marker:'@cert-authority'}]}),/not trusted/);
 let calls=0;await assert.rejects(verifyHost({...args,guard(){if(++calls>1)throw Error('locked');}}),/locked/);
});
