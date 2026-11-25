// Emulate only card APDUs. No native host, device, real PIN or key material.
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {webcrypto,createHash}=require('node:crypto');
function harness({rejectPin=false,wrongKey=false}={}){
 const events=[],sent=[],alg={0x9c:0xe3,0x84:0xe0,0x9d:0xe6,0x85:0xe1};let connections=0;
 const ctx={Uint8Array,Array,Map,Set,Error,TextEncoder,TextDecoder,crypto:webcrypto,atob,btoa};ctx.globalThis=ctx;
 vm.createContext(ctx);vm.runInContext(fs.readFileSync(__dirname+'/../app/smartcard-piv.js','utf8'),ctx);
 const p=ctx.SequoiaSmartCardPiv,tlv=p.encodeBerTlv;
 const metadata=slot=>new Uint8Array([...tlv(1,new Uint8Array([alg[slot]])),...tlv(4,tlv(0x86,new Uint8Array(32).fill(slot)))]);
 const slots=Object.keys(alg).map(x=>({slot:Number(x).toString(16),publicKeySha256:createHash('sha256').update(p.pivMetadataToSpki(p.parseSlotMetadata(metadata(x)))).digest('hex')}));
 if(wrongKey)slots[0].publicKeySha256='0'.repeat(64);
 const ok=data=>new Uint8Array([...(data||[]),0x90,0]);let parts=[];
 const conn={status:async()=>({state:'specific',answerToReset:new Uint8Array()}),startTransaction:async fn=>fn(),disconnect:async()=>events.push('disconnect'),transmit:async raw=>{
  const a=new Uint8Array(raw);sent.push([...a]);
  if(a[1]===0xa4)return ok();if(a[1]===0xfd)return ok([6,0,0]);if(a[1]===0xf8)return ok([0,0,0,123]);
  if(a[1]===0xf7)return ok(metadata(a[3]));
  if(a[1]===0x20){events.push('pin');return rejectPin?new Uint8Array([0x63,0xc2]):ok();}
  assert.equal(a[1],0x87);parts.push(...a.slice(5,5+a[4]));if(a[0]===0x10)return ok();
  const inner=p.parseBerTlv(p.parseBerTlv(new Uint8Array(parts)).get(0x7c));parts=[];
  events.push({slot:a[3],tags:[...inner.keys()]});
  const value=new Uint8Array(a[3]===0x9c?3309:a[3]===0x84?64:32).fill(1);
  return ok(tlv(0x7c,tlv(0x82,value)));
 }};
 ctx.navigator={smartCard:{establishContext:async()=>({listReaders:async()=>['YubiKey A','YubiKey B'],connect:async()=>{connections++;return {connection:conn,activeProtocol:'t1'};}})}};
 const identity={serial:'123',slots};return {p,identity,events,sent,connections:()=>connections};
}
test('direct signing uses external-mu tag and a fresh PIN verification per component',async()=>{
 const h=harness();await h.p.signDigestViaSmartCard({digest:Buffer.alloc(64,2).toString('base64'),mu:Buffer.alloc(64,3).toString('base64')},h.identity,async()=> '123456');
 assert.equal(h.events.filter(x=>x==='pin').length,2);
 assert.ok(h.events.some(x=>x.slot===0x9c&&x.tags.includes(0x88)));
 assert.ok(!h.sent.some(a=>[0x47,0xfe,0xff,0xdb].includes(a[1])));
});
test('direct ML-KEM uses KEM tag; X25519 uses exponentiation tag',async()=>{
 const h=harness();await h.p.decapsulateComponentsViaSmartCard({mlkemCiphertext:Buffer.alloc(1088,2).toString('base64'),x25519Ephemeral:Buffer.alloc(32,3).toString('base64')},h.identity,async()=> '123456');
 assert.equal(h.events.filter(x=>x==='pin').length,2);
 assert.ok(h.events.some(x=>x.slot===0x9d&&x.tags.includes(0x86)));
 assert.ok(h.events.some(x=>x.slot===0x85&&x.tags.includes(0x85)));
});
test('wrong live key is rejected before PIN submission',async()=>{
 const h=harness({wrongKey:true});await assert.rejects(h.p.signDigestViaSmartCard({digest:Buffer.alloc(64).toString('base64'),mu:Buffer.alloc(64).toString('base64')},h.identity,async()=> '123456'),/Live public key differs/);
 assert.equal(h.events.filter(x=>x==='pin').length,0);assert.equal(h.connections(),1);
});
test('PIN rejection is preserved and never retried on another reader',async()=>{
 const h=harness({rejectPin:true});await assert.rejects(h.p.signDigestViaSmartCard({digest:Buffer.alloc(64).toString('base64'),mu:Buffer.alloc(64).toString('base64')},h.identity,async()=> '123456'),/Incorrect PIV PIN/);
 assert.equal(h.events.filter(x=>x==='pin').length,1);assert.equal(h.connections(),1);
});
