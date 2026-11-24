// Only synthetic fixtures are accepted by this optional integration test. Its
// Node crypto MAC oracle is independent of the production WASM implementation.
import test from 'node:test';import assert from 'node:assert/strict';
import {createHash,createHmac,timingSafeEqual} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {decodePqMailP12} from '../app/software/p12.js';
function verifyMac({data,salt,iterations,mac,password,hash}){
 const S=Buffer.from(salt,'base64'),P=Buffer.alloc((password.length+1)*2);for(let i=0;i<password.length;i++)P.writeUInt16BE(password.charCodeAt(i),i*2);
 const repeat=input=>Buffer.from(Array.from({length:64*Math.ceil(input.length/64)},(_,i)=>input[i%input.length]));
 const D=Buffer.alloc(64,3),I=Buffer.concat([repeat(S),repeat(P)]);let A=createHash(hash.replace('-','').toLowerCase()).update(D).update(I).digest();
 for(let i=1;i<iterations;i++)A=createHash(hash.replace('-','').toLowerCase()).update(A).digest();
 const actual=createHmac(hash.replace('-','').toLowerCase(),A).update(Buffer.from(data,'base64')).digest(),expected=Buffer.from(mac,'base64');A.fill(0);P.fill(0);I.fill(0);
 if(expected.length!==(hash==='SHA-1'?20:32)||!timingSafeEqual(actual,expected))throw Error('MAC failed');return {verified:true};
}
test('PKCS12 import rejects malformed, indefinite primitive and trailing data before authentication',async()=>{
 for(const raw of [[],[0x30,0x80,0,0],[4,0x80,0,0],[0x30,3,2,1,3,0],[0x30,0x84,0x7f,0xff,0xff,0xff]]){
  let called=false;await assert.rejects(decodePqMailP12({p12:Buffer.from(raw).toString('base64'),password:'synthetic'},{verifyMac:()=>{called=true;return {verified:true};}}));assert.equal(called,false);
 }
});
test('PKCS12 authenticated PQ Mail Level5 import preserves all ten PKCS8 keys and both public keyrings',
 {skip:!process.env.IWA_P12_FIXTURE},async()=>{
 const p12=(await readFile(process.env.IWA_P12_FIXTURE)).toString('base64'),password='synthetic-iwa-p12-test-password';
 const decoded=await decodePqMailP12({p12,password},{verifyMac});assert.equal(decoded.keys.length,10);
 assert.deepEqual(decoded.keys.map(k=>k.alias),['cert-ml','cert-ed','sign-ml','sign-ed','kem-ml','kem-x','v4-sign','v4-ml','v4-x','v4-ec'].map(x=>'pgp5-'+x));
 for(const key of decoded.keys){assert.equal(Buffer.from(key.pkcs8,'base64')[0],48);assert.equal(Buffer.from(key.certificate,'base64')[0],48);}
 assert(Buffer.from(decoded.modern,'base64').length>10000);assert(Buffer.from(decoded.compatibility,'base64').length>1000);
 await assert.rejects(decodePqMailP12({p12,password:'wrong password'},{verifyMac}),/MAC/);
 // An authenticated failure must stop before any encrypted key bag is opened.
 let seen=false;await assert.rejects(decodePqMailP12({p12,password},{verifyMac:()=>{seen=true;return {verified:false};}}));assert(seen);
 const tampered=Buffer.from(p12,'base64');tampered[tampered.length-40]^=1;
 await assert.rejects(decodePqMailP12({p12:tampered.toString('base64'),password},{verifyMac}));
});
