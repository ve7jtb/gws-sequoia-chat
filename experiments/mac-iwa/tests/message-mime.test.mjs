import test from 'node:test';import os from 'node:os';import path from 'node:path';import assert from 'node:assert/strict';import fs from 'node:fs';
import {readMessage,envelope,b64,bytes64,composeMime} from '../app/message-mime.js';
import init,{verify_detached} from '../app/wasm/sequoia_iwa_verify.js';
await init({module_or_path:fs.readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const verify=r=>JSON.parse(verify_detached(JSON.stringify(r)));
const fixtures=process.env.IWA_PUBLIC_TEST_FIXTURES||path.join(os.tmpdir(),'iwa-public-fixtures');
const empty={certificates:[],bindings:[],saved:[]};
for(const version of ['v4','v6'])test(`${version} exact signed MIME, attached certificate and tamper`,async()=>{
 const v=JSON.parse(fs.readFileSync(path.join(fixtures,`${version}.json`)));
 const payload=Buffer.from(v.payload,'base64').toString('binary');
 const raw=Buffer.from('From: sender@example.invalid\r\nSubject: synthetic\r\nContent-Type: multipart/signed; protocol="application/pgp-signature"; boundary="outer"\r\n\r\n--outer\r\n'+payload+'\r\n--outer\r\nContent-Type: application/pgp-signature\r\nContent-Transfer-Encoding: base64\r\n\r\n'+v.signature+'\r\n--outer--\r\n','binary');
 assert.equal(b64(envelope(raw).payload),v.payload);
 const result=await readMessage({raw:b64(raw)},empty,verify);assert.equal(result.signatureStatus,'valid');assert.equal(result.certificateTrust,'untrusted');
 const fp=result.signatures[0].fingerprint,material={certificates:[],bindings:[{email:'sender@example.invalid',fingerprint:fp}],saved:[fp]};
 const bad=Buffer.from(raw.toString('binary').replace('Signed test body.','Altered test body.'),'binary');
 const altered=await readMessage({raw:b64(bad)},material,verify);assert.equal(altered.signatureStatus,'invalid');assert.equal(altered.certificateTrust,'trusted');assert.ok(altered.warning);assert.deepEqual(altered.certificateActions,[]);
});
test('ordinary multipart text HTML exact attachment bytes',async()=>{
 const raw=fs.readFileSync(new URL('multipart-fixture.mime',import.meta.url));const result=await readMessage({raw:b64(raw)},empty,verify);
 assert.equal(result.signatureStatus,'not-signed');assert.ok(result.html);assert.ok(result.text);assert.ok(result.attachments.length);
});
test('reject malformed envelope, oversized input and duplicate headers',async()=>{
 assert.throws(()=>envelope(Buffer.from('Content-Type: multipart/signed; protocol="application/pgp-signature"; boundary=x\r\n\r\n--x\r\ntext\r\n--x--\r\n')));
 assert.throws(()=>envelope(new Uint8Array(262145)));
 assert.throws(()=>envelope(Buffer.from('From: a@b\r\nFrom: c@d\r\n\r\nx')));
});
// Account-specific fixtures remain outside source control. They exercise the
// identical browser parser/verifier without modifying the original or trust.
if(process.env.IWA_PROTON_ORIGINAL)test('Proton original valid; body alteration invalid with saved trust retained',async()=>{
 const original=fs.readFileSync(process.env.IWA_PROTON_ORIGINAL),tampered=fs.readFileSync(process.env.IWA_PROTON_TAMPERED);
 const good=await readMessage({raw:b64(original)},empty,verify);assert.equal(good.signatureStatus,'valid');
 const fp=good.signatures[0].fingerprint,material={certificates:[],saved:[fp],bindings:[{email:good.sender.toLowerCase(),fingerprint:fp}]};
 const bad=await readMessage({raw:b64(tampered)},material,verify);assert.equal(bad.signatureStatus,'invalid');assert.equal(bad.certificateTrust,'trusted');
});

test('browser composition round trip preserves Unicode, HTML and every attachment byte',async()=>{
 const data=Uint8Array.from({length:308},(_,i)=>i%256);
 const raw=composeMime({sender:'alice@example.invalid',recipient:'bob@example.invalid',subject:'MIME ✓',body:'Plain ü',html:'<p>HTML <strong>ü</strong></p>',attachments:[{name:'test ü.bin',data:b64(data)}]});
 const result=await readMessage({raw},empty,verify);assert.equal(result.subject,'MIME ✓');assert.match(result.text,/Plain ü/);assert.match(result.html,/<strong>ü/);assert.equal(result.attachments[0].name,'test ü.bin');assert.deepEqual(bytes64(result.attachments[0].data),data);
});
test('native AEAD decryption to browser hybrid verification, wrong sender and tamper',async()=>{
 const {packet,material}=JSON.parse(fs.readFileSync(path.join(fixtures,'browser-open.json')));
 const result=await readMessage(packet,material,verify);assert.equal(result.signatureStatus,'valid');assert.equal(result.certificateTrust,'trusted');assert.equal(result.encrypted,true);assert.equal(result.attachments[0].data,'AP90ZXN0IGZpbGUNCg==');
 await assert.rejects(readMessage({...packet,expectedEmail:'wrong@example.invalid'},material,verify));
 await assert.rejects(readMessage({...packet,raw:b64(Buffer.from(Buffer.from(packet.raw,'base64').toString().replace('Hello bold','Tampered bold')))},material,verify));
});

test('Gmail exact rewritten encrypted envelope permits text/plain ciphertext only',()=>{
 const raw='Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\n-----BEGIN PGP MESSAGE-----\r\n\r\nYQ==\r\n-----END PGP MESSAGE-----\r\n--x\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--x--\r\n';
 assert.equal(envelope(Buffer.from(raw)).kind,'encrypted');assert.throws(()=>envelope(Buffer.from(raw.replace('Version: 1','Version: 2'))));
});

// Synthetic provider-rewrite fixtures never contain a live message or key.
// Only MIME framing is repaired here; the native/WASM path still authenticates
// the decrypted ciphertext and verifies the selected sender and recipient.
function rewrittenBinary(encoded,type='application/octet-stream',encoding='base64'){
 return 'Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--x\r\nContent-Type: '+type+'\r\nContent-Transfer-Encoding: '+encoding+'\r\n\r\n'+encoded+'\r\n--x--\r\n';
}
test('Gmail rewritten base64 binary envelope preserves leading and trailing ciphertext bytes',()=>{
 const cipher=Buffer.from([32,9,13,10,193,0,255,98,105,110,97,114,121,0,13,10,9,32]);
 const encoded=cipher.toString('base64'),raw=rewrittenBinary(' \t'+encoded.slice(0,12)+'\r\n'+encoded.slice(12)+'\r\n');
 const result=envelope(Buffer.from(raw));assert.equal(result.kind,'encrypted');assert.deepEqual(Buffer.from(result.cipher),cipher);
 // The provider also converted the control leaf to base64; that affects no
 // cryptographic bytes and must still decode to exactly the Version 1 record.
 const encodedControl=raw.replace('Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1',
  'Content-Type: application/pgp-encrypted\r\nContent-Transfer-Encoding: base64\r\n\r\nVmVyc2lvbjogMQ0K');
 assert.deepEqual(Buffer.from(envelope(Buffer.from(encodedControl)).cipher),cipher);
});
test('Gmail binary rewrite rejects noncanonical base64 and ambiguous MIME',()=>{
 for(const encoded of ['', 'wQ', 'wQ===', 'wR==', 'wQ==!', 'wQ==\v', 'wQ==\u00a0'])assert.throws(()=>envelope(Buffer.from(rewrittenBinary(encoded))));
 const raw=rewrittenBinary('wQ==');
 for(const invalid of [rewrittenBinary('wQ==','text/plain'),rewrittenBinary('ciphertext','application/octet-stream','8bit'),
  raw.replace('application/octet-stream','multipart/mixed; boundary=y'),
  raw.replace('--x--','--x\r\nContent-Type: text/plain\r\n\r\nUntrusted extra\r\n--x--'),
  raw.replace('Version: 1','Version: 2'),
  raw.replace('Content-Transfer-Encoding: base64','Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: 7bit'),
  raw.replace('Content-Type: application/octet-stream','Content-Type: application/octet-stream\r\nContent-Type: text/plain'),
  raw.replace('Content-Type: multipart/mixed; boundary=x','Content-Type: multipart/mixed; boundary=x\r\nContent-Type: text/plain')])assert.throws(()=>envelope(Buffer.from(invalid)));
});

// A valid signature on a newer attached certificate must not inherit the older
// saved certificate's email binding when that mailbox is no longer certified.
test('valid signature without a current sender mailbox stays untrusted',async()=>{
 const fp='A'.repeat(64),material={certificates:[],saved:[fp],bindings:[{email:'sender@example.invalid',fingerprint:fp}]};
 const verify=async()=>({signatures:[{status:'valid',fingerprint:fp,algorithm:'test',certificate:'YQ==',emails:['other@example.invalid']}]});
 const mime=b64(Buffer.from('From: sender@example.invalid\r\nContent-Type: multipart/signed; protocol="application/pgp-signature"; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nBody\r\n--x\r\nContent-Type: application/pgp-signature\r\n\r\na\r\n--x--\r\n'));
 const signed=await readMessage({raw:mime},material,verify);
 assert.equal(signed.signatureStatus,'valid');assert.equal(signed.certificateTrust,'untrusted');assert.equal(signed.certificateActions[0].canTrust,false);
 const raw=b64(Buffer.from('From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nContent-Type: text/plain\r\n\r\nBody'));
 await assert.rejects(readMessage({raw,encrypted:true,signature:'YQ==',expectedFingerprint:fp,expectedEmail:'sender@example.invalid',recipient:'recipient@example.invalid'},material,verify),/trust checks/);
});
