import test from 'node:test';
import assert from 'node:assert/strict';
import {createCipheriv,createHash} from 'node:crypto';
import {encode,decode,exchange,command,session,rawCbc,prfSalt,evaluate,checkRp} from '../app/ctap2-smartcard.js';
globalThis.IWA_BUNDLE_ID='aj2ncwirtvyf4zn2hxc2c2gqps6cmcap77dpanzkgh2tlfj7inkqaaic';
const m=(...p)=>new Map(p),u=(...b)=>new Uint8Array(b);
const ok=b=>u(...b,0x90,0);
test('CBOR round trips CTAP/COSE keys without prototype conversion',()=>{
 const value=m([1,[2,-25,true]],['__proto__',u(1,2)],[-2,'hello']);
 assert.deepEqual(decode(encode(value)),value);
 assert.deepEqual([...encode(m([-2,0],[1,0],[-1,0]))],[0xa3,1,0,0x20,0,0x21,0]);
});
test('CBOR rejects duplicate, indefinite, truncated and trailing values',()=>{
 for(const b of [u(0xa2,1,1,1,2),u(0x9f,0xff),u(0x58,5,1),u(1,1)])assert.throws(()=>decode(b));
});
test('PRF uses the exact WebAuthn domain-separated salt',async()=>{
 const salt=u(1,2,3);assert.equal(Buffer.from(await prfSalt(salt)).toString('hex'),createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF\0'),salt])).digest('hex'));
});
test('CTAP no-padding CBC matches independent native crypto for varying blocks',async()=>{
 const key=Buffer.alloc(32,7),iv=Buffer.alloc(16,3);
 for(const n of [16,32,64]){const plain=Buffer.alloc(n,5),cipher=createCipheriv('aes-256-cbc',key,iv);cipher.setAutoPadding(false);const expected=Buffer.concat([cipher.update(plain),cipher.final()]);const actual=await rawCbc(key,iv,plain);assert.deepEqual(Buffer.from(actual),expected);assert.deepEqual(Buffer.from(await rawCbc(key,iv,actual,true)),plain);}
});
test('short APDU chaining and GET RESPONSE preserve response bytes',async()=>{
 const sent=[];const replies=[ok([]),u(0,1,0x61,2),ok([2,3])];
 const result=await exchange({transmit:async a=>{sent.push(a);return replies.shift();}},0x80,0x10,0x80,new Uint8Array(300));
 assert.deepEqual([...result],[0,1,2,3]);assert.equal(sent[0][0],0x90);assert.deepEqual([...sent[2]],[0,0xc0,0,0,2]);
});
test('CTAP keepalive polls without resubmitting assertion',async()=>{
 const sent=[],progress=[];const replies=[u(2,0x91,0),ok([0,0xa0])];
 await command({transmit:async a=>{sent.push(a);return replies.shift();}},2,m([1,'test']),{progress:s=>progress.push(s)});
 assert.deepEqual([...sent[1]],[0x80,0x11,0,0,0]);assert.match(progress[0],/Touch/);
});
test('PIN error is returned once with no automatic retry',async()=>{
 let calls=0;await assert.rejects(command({transmit:async()=>{calls++;return ok([0x31]);}},6,m([1,2],[2,9])),/Incorrect FIDO PIN/);assert.equal(calls,1);
});
test('write and credential-management CTAP commands are forbidden',async()=>{
 const conn={transmit:()=>{throw Error('must not transmit');}};
 for(const cmd of [1,7,10,12])await assert.rejects(command(conn,cmd),/Forbidden/);
 for(const sub of [3,4,5,6])await assert.rejects(command(conn,6,m([2,sub])),/Forbidden/);
});
test('cancelled request transmits nothing and unknown RP cannot prompt',async()=>{
 const c=new AbortController();c.abort();let calls=0;
 await assert.rejects(command({transmit:()=>{calls++;}},4,undefined,{signal:c.signal}),/cancelled/);assert.equal(calls,0);
 assert.throws(()=>checkRp('accounts.google.com'),/Unsupported/);
 await assert.rejects(evaluate({rpId:'evil.example',salt:new Uint8Array(32)},()=>{throw Error('must not prompt');}),/Unsupported/);
});
test('serial is passed to the existing transaction selector before selecting FIDO',async()=>{
 let selected;const result=await session('123',async()=>42,{piv:{withPivSession:async(serial,fn)=>{selected=serial;return fn({transmit:async a=>a[1]===0xa4?ok(Buffer.from('U2F_V2')):ok(u(0,...encode(m([1,['FIDO_2_1']]))))},{serial});}}});assert.equal(selected,'123');assert.equal(result,42);
});

test('existing PRF assertion interoperates with independent PIN protocol 2 peer',async()=>{
 const {createECDH,hkdfSync,createHmac,createDecipheriv}=await import('node:crypto');
 const ec=createECDH('prime256v1');ec.generateKeys();const pub=ec.getPublicKey(),pin='test-only-pin';
 const rp='ve7jtb.github.io',credential=u(9,8,7),salt=new Uint8Array(32).fill(4),token=Buffer.alloc(32,6),prf=Buffer.alloc(32,8),seen=[];
 let keys;
 const hmac=(key,b)=>createHmac('sha256',key).update(b).digest();
 const crypt=(bytes,decrypt=false)=>{const iv=decrypt?bytes.slice(0,16):Buffer.alloc(16,2),data=decrypt?bytes.slice(16):bytes;const c=decrypt?createDecipheriv('aes-256-cbc',keys.aes,iv):createCipheriv('aes-256-cbc',keys.aes,iv);c.setAutoPadding(false);const r=Buffer.concat([c.update(data),c.final()]);return decrypt?r:Buffer.concat([iv,r]);};
 let chunks=[];
 const conn={transmit:async a=>{
  if(a[1]===0xa4)return ok(Buffer.from('U2F_V2'));
  chunks.push(a.slice(5,5+a[4]));if(a[0]&0x10)return ok([]);
  const data=Buffer.concat(chunks);chunks=[];const cmd=data[0],q=data.length>1?decode(data.slice(1)):null;seen.push([cmd,q?.get(2)]);
  let result;
  if(cmd===4)result=m([1,['FIDO_2_1']],[2,['hmac-secret']],[4,m(['clientPin',true],['pinUvAuthToken',true])],[6,[2]]);
  else if(cmd===6&&q.get(2)===1)result=m([3,8]);
  else if(cmd===6&&q.get(2)===2)result=m([1,m([1,2],[3,-25],[-1,1],[-2,new Uint8Array(pub.slice(1,33))],[-3,new Uint8Array(pub.slice(33))])]);
  else if(cmd===6&&q.get(2)===9){
   const key=q.get(3),z=ec.computeSecret(Buffer.concat([u(4),key.get(-2),key.get(-3)]));
   keys={aes:Buffer.from(hkdfSync('sha256',z,Buffer.alloc(32),Buffer.from('CTAP2 AES key'),32)),hmac:Buffer.from(hkdfSync('sha256',z,Buffer.alloc(32),Buffer.from('CTAP2 HMAC key'),32))};
   assert.equal(q.get(9),2);assert.equal(q.get(10),rp);assert.deepEqual(crypt(q.get(6),true),createHash('sha256').update(pin).digest().slice(0,16));result=m([2,new Uint8Array(crypt(token))]);
  }else if(cmd===2){
   assert.equal(q.get(1),rp);assert.deepEqual(Buffer.from(q.get(6)),hmac(token,q.get(2)));assert.deepEqual(q.get(3)[0].get('id'),credential);
   const ext=q.get(4).get('hmac-secret');assert.equal(ext.get(4),2);assert.deepEqual(Buffer.from(ext.get(3)),hmac(keys.hmac,ext.get(2)));assert.deepEqual(crypt(ext.get(2),true),createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF\0'),salt])).digest());
   const auth=Buffer.concat([createHash('sha256').update(rp).digest(),u(0x85,0,0,0,1),encode(m(['hmac-secret',new Uint8Array(crypt(prf))]))]);
   result=m([1,m(['type','public-key'],['id',credential])],[2,new Uint8Array(auth)],[3,u(1,2,3)]);
  }else throw Error('Unexpected CTAP command');
  return ok(u(0,...encode(result)));
 }};
 const result=await evaluate({serial:'123',rpId:rp,credentialId:credential,salt},async()=>pin,{piv:{withPivSession:async(s,fn)=>fn(conn,{serial:s})}});
 assert.deepEqual(Buffer.from(result.secret),prf);assert.deepEqual(result.credentialId,credential);
 assert.deepEqual(seen.map(([cmd])=>cmd),[4,6,6,6,2]);
});

// Neither the extension ID nor an arbitrary caller-controlled host may become
// the default scope for new direct-CTAP vault enrollments.
test('direct FIDO defaults to the signed package ID and preserves explicit legacy RP scopes',async()=>{
 const {packageRp,extensionRp}=await import('../app/ctap2-smartcard.js');
 assert.equal(packageRp(),'isolated-app://'+globalThis.IWA_BUNDLE_ID);
 assert.equal(checkRp(globalThis.IWA_BUNDLE_ID),globalThis.IWA_BUNDLE_ID);
 assert.equal(checkRp(packageRp()),packageRp());
 assert.equal(checkRp(extensionRp()),extensionRp());
 assert.equal(checkRp('ve7jtb.github.io'),'ve7jtb.github.io');
 assert.throws(()=>checkRp(packageRp()+'/'),/Unsupported/);
 assert.throws(()=>checkRp(packageRp()+'/path'),/Unsupported/);
});

test('discoverable creation evaluates PRF at makeCredential with scoped permission',async()=>{
 const {createECDH,hkdfSync,createHmac,createDecipheriv}=await import('node:crypto');
 const ec=createECDH('prime256v1');ec.generateKeys();const pub=ec.getPublicKey(),pin='test-only-pin';
 const rp='isolated-app://'+globalThis.IWA_BUNDLE_ID,credential=u(9,8,7),salt=new Uint8Array(32).fill(4),token=Buffer.alloc(32,6),prf=Buffer.alloc(32,8),seen=[];
 let keys;
 const hmac=(key,b)=>createHmac('sha256',key).update(b).digest();
 const crypt=(bytes,decrypt=false)=>{const iv=decrypt?bytes.slice(0,16):Buffer.alloc(16,2),data=decrypt?bytes.slice(16):bytes;const c=decrypt?createDecipheriv('aes-256-cbc',keys.aes,iv):createCipheriv('aes-256-cbc',keys.aes,iv);c.setAutoPadding(false);const r=Buffer.concat([c.update(data),c.final()]);return decrypt?r:Buffer.concat([iv,r]);};
 let chunks=[];
 const conn={transmit:async a=>{
  if(a[1]===0xa4)return ok(Buffer.from('U2F_V2'));
  chunks.push(a.slice(5,5+a[4]));if(a[0]&0x10)return ok([]);
  const data=Buffer.concat(chunks);chunks=[];const cmd=data[0],q=data.length>1?decode(data.slice(1)):null;seen.push([cmd,q?.get(2)]);
  let result;
  if(cmd===4)result=m([1,['FIDO_2_1']],[2,['hmac-secret','hmac-secret-mc']],[4,m(['rk',true],['clientPin',true],['pinUvAuthToken',true])],[6,[2]]);
  else if(cmd===6&&q.get(2)===1)result=m([3,8]);
  else if(cmd===6&&q.get(2)===2)result=m([1,m([1,2],[3,-25],[-1,1],[-2,new Uint8Array(pub.slice(1,33))],[-3,new Uint8Array(pub.slice(33))])]);
  else if(cmd===6&&q.get(2)===9){
   const key=q.get(3),z=ec.computeSecret(Buffer.concat([u(4),key.get(-2),key.get(-3)]));
   keys={aes:Buffer.from(hkdfSync('sha256',z,Buffer.alloc(32),Buffer.from('CTAP2 AES key'),32)),hmac:Buffer.from(hkdfSync('sha256',z,Buffer.alloc(32),Buffer.from('CTAP2 HMAC key'),32))};
   assert.equal(q.get(9),1);assert.equal(q.get(10),rp);assert.deepEqual(crypt(q.get(6),true),createHash('sha256').update(pin).digest().slice(0,16));result=m([2,new Uint8Array(crypt(token))]);
  }else if(cmd===1){
   assert.equal(q.get(2).get('id'),rp);assert.equal(q.get(7).get('rk'),true);
   assert.equal(q.get(3).get('id').length,32);assert.equal(q.get(3).get('name'),'Test vault');
   assert.deepEqual(Buffer.from(q.get(8)),hmac(token,q.get(1)));
   const ext=q.get(6).get('hmac-secret-mc');assert.equal(q.get(6).get('hmac-secret'),true);
   assert.deepEqual(Buffer.from(ext.get(3)),hmac(keys.hmac,ext.get(2)));
   assert.deepEqual(crypt(ext.get(2),true),createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF\0'),salt])).digest());
   const cose=m([1,2],[3,-7],[-1,1],[-2,new Uint8Array(pub.slice(1,33))],[-3,new Uint8Array(pub.slice(33))]);
   const auth=Buffer.concat([createHash('sha256').update(rp).digest(),u(0xc5,0,0,0,1),Buffer.alloc(16),u(0,credential.length),credential,encode(cose),encode(m(['hmac-secret',true],['hmac-secret-mc',new Uint8Array(crypt(prf))]))]);
   result=m([1,'packed'],[2,new Uint8Array(auth)],[3,m()]);
  }else throw Error('Unexpected CTAP command');
  return ok(u(0,...encode(result)));
 }};
 const {createCredential}=await import('../app/ctap2-smartcard.js');let journaled;
 const result=await createCredential({serial:'123',rpId:rp,userId:crypto.getRandomValues(new Uint8Array(32)),name:'Test vault',salt},async()=>pin,{created:id=>{journaled=id;},piv:{withPivSession:async(s,fn)=>fn(conn,{serial:s})}});
 assert.deepEqual(Buffer.from(result.secret),prf);assert.deepEqual(result.credentialId,credential);assert.deepEqual(journaled,credential);
 assert.deepEqual(seen.map(([cmd])=>cmd),[4,6,6,6,1]);
});

test('bare package RP is retained for assertions but forbidden for new creation',async()=>{
 const {createCredential}=await import('../app/ctap2-smartcard.js');
 assert.throws(()=>createCredential({rpId:globalThis.IWA_BUNDLE_ID},()=>{throw Error('must not prompt');}),/Creation requires/);
});

test('previewSign setup uses separate non-discoverable UV-protected credential',async()=>{
 const {createECDH,hkdfSync,createHmac,createDecipheriv}=await import('node:crypto');
 const ec=createECDH('prime256v1');ec.generateKeys();const pub=ec.getPublicKey(),pin='test-only-pin';
 const rp='isolated-app://'+globalThis.IWA_BUNDLE_ID,credential=u(9,8,7),salt=new Uint8Array(32).fill(4),token=Buffer.alloc(32,6),prf=Buffer.alloc(32,8),seen=[];
 let keys;
 const hmac=(key,b)=>createHmac('sha256',key).update(b).digest();
 const crypt=(bytes,decrypt=false)=>{const iv=decrypt?bytes.slice(0,16):Buffer.alloc(16,2),data=decrypt?bytes.slice(16):bytes;const c=decrypt?createDecipheriv('aes-256-cbc',keys.aes,iv):createCipheriv('aes-256-cbc',keys.aes,iv);c.setAutoPadding(false);const r=Buffer.concat([c.update(data),c.final()]);return decrypt?r:Buffer.concat([iv,r]);};
 let chunks=[];
 const conn={transmit:async a=>{
  if(a[1]===0xa4)return ok(Buffer.from('U2F_V2'));
  chunks.push(a.slice(5,5+a[4]));if(a[0]&0x10)return ok([]);
  const data=Buffer.concat(chunks);chunks=[];const cmd=data[0],q=data.length>1?decode(data.slice(1)):null;seen.push([cmd,q?.get(2)]);
  let result;
  if(cmd===4)result=m([1,['FIDO_2_1']],[2,['hmac-secret','hmac-secret-mc','previewSign']],[4,m(['rk',true],['clientPin',true],['pinUvAuthToken',true])],[6,[2]]);
  else if(cmd===6&&q.get(2)===1)result=m([3,8]);
  else if(cmd===6&&q.get(2)===2)result=m([1,m([1,2],[3,-25],[-1,1],[-2,new Uint8Array(pub.slice(1,33))],[-3,new Uint8Array(pub.slice(33))])]);
  else if(cmd===6&&q.get(2)===9){
   const key=q.get(3),z=ec.computeSecret(Buffer.concat([u(4),key.get(-2),key.get(-3)]));
   keys={aes:Buffer.from(hkdfSync('sha256',z,Buffer.alloc(32),Buffer.from('CTAP2 AES key'),32)),hmac:Buffer.from(hkdfSync('sha256',z,Buffer.alloc(32),Buffer.from('CTAP2 HMAC key'),32))};
   assert.equal(q.get(9),1);assert.equal(q.get(10),rp);assert.deepEqual(crypt(q.get(6),true),createHash('sha256').update(pin).digest().slice(0,16));result=m([2,new Uint8Array(crypt(token))]);
  }else if(cmd===1){
   assert.equal(q.get(2).get('id'),rp);assert.equal(q.get(7).get('rk'),false);
   assert.equal(q.get(3).get('id').length,32);assert.equal(q.get(3).get('name'),'Test vault');
   assert.deepEqual(Buffer.from(q.get(8)),hmac(token,q.get(1)));
   assert.deepEqual(q.get(6).get('previewSign'),m([3,[-65539]],[4,5]));
   const cose=m([1,2],[3,-7],[-1,1],[-2,new Uint8Array(pub.slice(1,33))],[-3,new Uint8Array(pub.slice(33))]);
   const auth=Buffer.concat([createHash('sha256').update(rp).digest(),u(0xc5,0,0,0,1),Buffer.alloc(16),u(0,credential.length),credential,encode(cose),encode(m(['previewSign',m([3,-65539])]))]);
   result=m([1,'packed'],[2,new Uint8Array(auth)],[3,m()],[6,m(['previewSign',m([7,encode(m([1,'packed'],[2,new Uint8Array(auth)],[3,m()]))])])]);
  }else throw Error('Unexpected CTAP command');
  return ok(u(0,...encode(result)));
 }};
 const {createPreviewSign}=await import('../app/ctap2-smartcard.js');let journaled;
 const result=await createPreviewSign({serial:'123',rpId:rp,userId:crypto.getRandomValues(new Uint8Array(32)),name:'Test vault',salt},async()=>pin,{created:id=>{journaled=id;},piv:{withPivSession:async(s,fn)=>fn(conn,{serial:s})}});
 assert.deepEqual(result.keyHandle,credential);assert.deepEqual(result.credentialId,credential);assert.deepEqual(journaled,credential);
 assert.deepEqual(seen.map(([cmd])=>cmd),[4,6,6,6,1]);
});

