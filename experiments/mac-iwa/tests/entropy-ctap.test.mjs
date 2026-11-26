// An independent Node crypto authenticator peer checks real protocol-2 bytes,
// not a mocked collectEntropy result. All secrets below are disposable fixtures.
import test from 'node:test';import assert from 'node:assert/strict';
import {createECDH,hkdfSync,createHmac,createHash,createCipheriv,createDecipheriv} from 'node:crypto';
import {collectEntropy,encode,decode} from '../app/ctap2-smartcard.js';
globalThis.IWA_BUNDLE_ID='aj2ncwirtvyf4zn2hxc2c2gqps6cmcap77dpanzkgh2tlfj7inkqaaic';
const m=(...a)=>new Map(a),u=(...a)=>new Uint8Array(a),ok=b=>u(...b,0x90,0);
function peer({always=false,failAt=0,missing=false,cancelAt=0}={}){
 const ec=createECDH('prime256v1');ec.generateKeys();const pub=ec.getPublicKey(),token=Buffer.alloc(32,17),pin='test-pin';
 const rp='isolated-app://'+IWA_BUNDLE_ID,controller=new AbortController();let chunks=[],keys,makes=0,prompts=0,pins=0,salts=[],handles=[];
 const hmac=(key,b)=>createHmac('sha256',key).update(b).digest();
 function agree(cose){const z=ec.computeSecret(Buffer.concat([u(4),cose.get(-2),cose.get(-3)]));keys={aes:Buffer.from(hkdfSync('sha256',z,Buffer.alloc(32),'CTAP2 AES key',32)),hmac:Buffer.from(hkdfSync('sha256',z,Buffer.alloc(32),'CTAP2 HMAC key',32))};}
 function crypt(bytes,decrypt=false){const iv=decrypt?bytes.slice(0,16):Buffer.alloc(16,2),data=decrypt?bytes.slice(16):bytes,c=(decrypt?createDecipheriv:createCipheriv)('aes-256-cbc',keys.aes,iv);c.setAutoPadding(false);const out=Buffer.concat([c.update(data),c.final()]);return decrypt?out:Buffer.concat([iv,out]);}
 const conn={transmit:async a=>{
  if(a[1]===0xa4)return ok(Buffer.from('U2F_V2'));
  chunks.push(a.slice(5,5+a[4]));if(a[0]&16)return ok([]);const raw=Buffer.concat(chunks);chunks=[];const cmd=raw[0],q=raw.length>1?decode(raw.slice(1)):null;let r;
  if(cmd===4)r=m([1,['FIDO_2_3']],[2,missing?['hmac-secret']:['hmac-secret','hmac-secret-mc']],[4,m(['alwaysUv',always],['makeCredUvNotRqd',true],['clientPin',true],['pinUvAuthToken',true])],[6,[2]]);
  else if(cmd===6&&q.get(2)===1)r=m([3,8]);
  else if(cmd===6&&q.get(2)===2)r=m([1,m([1,2],[3,-25],[-1,1],[-2,new Uint8Array(pub.slice(1,33))],[-3,new Uint8Array(pub.slice(33))])]);
  else if(cmd===6&&q.get(2)===9){pins++;agree(q.get(3));assert.equal(q.get(9),1);assert.equal(q.get(10),rp);assert.deepEqual(crypt(q.get(6),true),createHash('sha256').update(pin).digest().slice(0,16));r=m([2,new Uint8Array(crypt(token))]);}
  else if(cmd===1){
   makes++;if(makes===failAt)return ok(u(0x31));
   assert.equal(q.get(7).get('rk'),false);assert.equal(q.get(2).get('id'),rp);assert.equal(q.has(8),always);
   if(always)assert.deepEqual(Buffer.from(q.get(8)),hmac(token,q.get(1)));
   const ext=q.get(6).get('hmac-secret-mc');agree(ext.get(1));assert.equal(ext.get(4),2);assert.deepEqual(Buffer.from(ext.get(3)),hmac(keys.hmac,ext.get(2)));
   salts.push(crypt(ext.get(2),true).toString('hex'));handles.push(Buffer.from(q.get(3).get('id')).toString('hex'));
   const cose=m([1,2],[3,-7],[-1,1],[-2,new Uint8Array(pub.slice(1,33))],[-3,new Uint8Array(pub.slice(33))]);
   const auth=Buffer.concat([createHash('sha256').update(rp).digest(),u(always?0xc5:0xc1,0,0,0,1),Buffer.alloc(16),u(0,2,7,makes),encode(cose),encode(m(['hmac-secret',true],['hmac-secret-mc',new Uint8Array(crypt(Buffer.alloc(32,makes)))]))]);
   r=m([1,'packed'],[2,new Uint8Array(auth)],[3,m()]);if(makes===cancelAt)controller.abort();
  }else throw Error('Unexpected command');return ok(u(0,...encode(r)));
 }};
 return {run:()=>collectEntropy('12345678',async()=>{prompts++;return pin;},{signal:controller.signal,piv:{withPivSession:async(serial,fn)=>{assert.equal(serial,'12345678');return fn(conn,{serial});}}}),stats:()=>({makes,prompts,pins,salts,handles})};
}
test('one PIN-free nonresident creation returns one 32-byte contribution',async()=>{const h=peer(),out=await h.run(),s=h.stats();assert.equal(out.length,32);assert(out.every(x=>x===1));assert.equal(s.makes,1);assert.equal(s.prompts,0);assert.equal(s.pins,0);assert.equal(s.salts.length,1);assert.equal(s.handles.length,1);});
test('alwaysUV prompts once for one scoped token and one creation',async()=>{const h=peer({always:true});await h.run();assert.equal(h.stats().prompts,1);assert.equal(h.stats().pins,1);assert.equal(h.stats().makes,1);});
test('missing extension, PIN error and cancellation never retry or return entropy',async()=>{for(const options of [{missing:true},{always:true,failAt:1},{cancelAt:1}]){const h=peer(options);await assert.rejects(h.run());assert.equal(h.stats().makes,options.missing?0:1);}});
