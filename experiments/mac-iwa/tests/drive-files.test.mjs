import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createDriveFiles,DRIVE_SCOPE,encryptedPacket} from '../app/drive-files.js';
import {createComposeReviews} from '../app/compose-review.js';
const cipher=Buffer.from([0xc1,2,6,0,0xd2,2,2,0]).toString('base64');
// Packet bytes are synthetic here: crypto validity belongs to the real-WASM
// and independent Sequoia test, not this HTTP policy test.
const session={token:'disposable-token',expiresIn:60,scope:DRIVE_SCOPE};
function fixture(){
 let time=0,locked=false,raw,requests=[];
 const drive=createDriveFiles({clock:()=>time,gate:()=>{if(locked)throw Error('Locked');},fetcher:async(url,options)=>{
  requests.push({url,options});assert.equal(options.redirect,'error');assert.equal(options.headers.Authorization,'Bearer disposable-token');
  assert(url.startsWith('https://www.googleapis.com/'));
  if(options.method==='POST'){
   const data=new Uint8Array(await options.body.arrayBuffer()),text=new TextDecoder().decode(data);
   assert(!text.includes('private.txt'));assert(!text.includes('secret subject'));
   assert(text.includes('sequoiaOpenPgp'));assert(text.includes('application/pgp-encrypted'));
   raw=encryptedPacket(cipher);assert(Buffer.from(data).includes(Buffer.from(raw)));
   return Response.json({id:'file_123',name:'encrypted-test.pgp'});
  }
  if(url.endsWith('alt=media'))return new Response(raw);
  if(url.includes('/file_123?'))return Response.json({id:'file_123',appProperties:{sequoiaOpenPgp:'1'},size:raw.length});
  return Response.json({files:[{id:'file_123',name:'encrypted-test.pgp'}]});
 }});drive.connect(session);return {drive,requests,expire:()=>time=61000,lock:()=>{locked=true;drive.clear();}};
}
test('Drive uploads only ciphertext and downloads identical packet bytes',async()=>{
 const f=fixture();await f.drive.upload(cipher);assert.equal(await f.drive.download('file_123'),cipher);
 assert.equal((await f.drive.list()).files.length,1);assert.match(decodeURIComponent(f.requests.at(-1).url),/sequoiaOpenPgp/);
 await assert.rejects(f.drive.download('../outside'));await assert.rejects(f.drive.upload(btoa('plaintext private.txt')));
 f.expire();await assert.rejects(f.drive.list(),/Connect/);
});
test('requires drive.file; lock and redirect/session changes fail closed',async()=>{
 const f=fixture();assert.throws(()=>f.drive.connect({...session,scope:'https://www.googleapis.com/auth/drive'}));
 f.drive.connect(session);f.lock();await assert.rejects(f.drive.upload(cipher),/Locked/);
 let finish;const drive=createDriveFiles({fetcher:()=>new Promise(resolve=>finish=resolve)});drive.connect(session);
 const pending=drive.list();drive.clear();finish(Response.json({files:[]}));await assert.rejects(pending,/session changed/);
});
test('metadata mismatch, oversized streaming response and HTTP error are rejected without retry',async()=>{
 for(const response of [()=>Response.json({id:'file_123',size:8,appProperties:{}}),()=>new Response(new Uint8Array(262145)),()=>new Response('',{status:403})]){
  let calls=0;const drive=createDriveFiles({fetcher:async()=>{calls++;return response();}});drive.connect(session);
  await assert.rejects(drive.download('file_123'));assert.equal(calls,1);
 }
});
test('Drive review is one-use, bound to current trust, and cannot send Gmail',async()=>{
 let trusted=true;const account='a@example.invalid',contact={email:'b@example.invalid',fingerprint:'B'.repeat(64),certificate:btoa('public')};
 const reviews=createComposeReviews({certificateStore:{assertContact:async()=>{if(!trusted)throw Error('Trust removed');}}});
 const material={review:'a'.repeat(48),senderCertificate:btoa('public'),senderEmail:account,signingFingerprint:'A'.repeat(64)};
 const prepare=async()=>{await reviews.prepare(material,contact,{account,subject:'private subject',service:'Drive',space:'Drive'});await reviews.complete(material.review,cipher);};
 await prepare();assert.deepEqual(await reviews.exportPgp(material.review,account,true),{cipher});await assert.rejects(reviews.exportPgp(material.review,account,true));
 await prepare();trusted=false;await assert.rejects(reviews.exportPgp(material.review,account,true),/Trust removed/);
 trusted=true;await prepare();await assert.rejects(reviews.take(material.review,'Gmail',true,account),/destination changed/);
});
