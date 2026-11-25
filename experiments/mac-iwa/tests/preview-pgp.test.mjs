import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {p256} from '../app/vendor/curves/nist.js';
import {prepareCertificate,prepareMessage,signedMessage} from '../app/preview-pgp.js';
import init,{inspect_public,verify_detached} from '../app/wasm/sequoia_iwa_verify.js';
const b64=x=>Buffer.from(x).toString('base64');
// Ten disposable software signers exercise the exact packet path without any
// authenticator. ARKG derivation has its separate independent reference vector.
test('Sequoia validates ten P-256 self-certified identities and their message signatures',async()=>{
 await init({module_or_path:readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});
 const time=Math.floor(Date.now()/1000)-1,seen=new Set();
 for(let i=1;i<=10;i++){
  const secret=new Uint8Array(32);secret[31]=i;const pub=p256.getPublicKey(secret,false);
  const cert=prepareCertificate(pub,i,time),signature=p256.sign(cert.self.digest,secret,{prehash:false,format:'der'});
  const certificate=b64(cert.finish(signature)),info=JSON.parse(inspect_public(JSON.stringify({certificate})));
  assert.ok(info.emails.includes(cert.email));assert.ok(!seen.has(info.fingerprint));seen.add(info.fingerprint);
  const payload=new TextEncoder().encode('Synthetic test '+i),prepared=prepareMessage(payload,cert.fingerprint,time);
  const messageSignature=prepared.finish(p256.sign(prepared.digest,secret,{prehash:false,format:'der'}));
  const request={certificates:[certificate],payload:b64(payload),signature:b64(messageSignature)};
  const result=JSON.parse(verify_detached(JSON.stringify(request)));
  assert.equal(result.signatures[0].status,'valid');assert.equal(result.signatures[0].fingerprint,info.fingerprint);
  assert.ok(signedMessage(payload,messageSignature,time,cert.fingerprint).length>payload.length);
  try{assert.ok(!JSON.parse(verify_detached(JSON.stringify({...request,payload:b64(new Uint8Array([...payload,0]))}))).signatures.some(s=>s.status==='valid'));}catch(e){if(e instanceof assert.AssertionError)throw e;}
  if(process.env.PREVIEW_TEST_SQ){
   const dir=mkdtempSync(join(tmpdir(),'preview-pgp-'));
   try{writeFileSync(join(dir,'cert.pgp'),Buffer.from(certificate,'base64'));writeFileSync(join(dir,'message.pgp'),signedMessage(payload,messageSignature,time,cert.fingerprint));
    const clear=execFileSync(process.env.PREVIEW_TEST_SQ,['--home',join(dir,'sq-home'),'verify','--message','--signer-file',join(dir,'cert.pgp'),join(dir,'message.pgp')],{stdio:['ignore','pipe','pipe']});
    assert.deepEqual(new Uint8Array(clear),payload);
   }finally{rmSync(dir,{recursive:true,force:true});}
  }
  secret.fill(0);
 }
 assert.equal(seen.size,10);
});
