// Emulate only card APDUs. No native host, device, real PIN or key material.
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {webcrypto,createHash}=require('node:crypto');
function harness({rejectPin=false,wrongKey=false,shares=null,secureFailure=false,firstSerial=123}={}){
 const events=[],sent=[],alg={0x9c:0xe3,0x84:0xe0,0x9d:0xe6,0x85:0xe1};let connections=0;
 const ctx={Uint8Array,Array,Map,Set,Error,TextEncoder,TextDecoder,crypto:webcrypto,atob,btoa};ctx.globalThis=ctx;
 if(secureFailure)ctx.SequoiaSecureChannel={isRequired:()=>true,acquire:async()=>{throw Error("Untrusted SCP chain");}};
 vm.createContext(ctx);vm.runInContext(fs.readFileSync(__dirname+'/../app/smartcard-piv.js','utf8'),ctx);
 const p=ctx.SequoiaSmartCardPiv,tlv=p.encodeBerTlv;
 const metadata=slot=>new Uint8Array([...tlv(1,new Uint8Array([alg[slot]])),...tlv(4,tlv(0x86,new Uint8Array(32).fill(slot)))]);
 const slots=Object.keys(alg).map(x=>({slot:Number(x).toString(16),publicKeySha256:createHash('sha256').update(p.pivMetadataToSpki(p.parseSlotMetadata(metadata(x)))).digest('hex')}));
 if(wrongKey)slots[0].publicKeySha256='0'.repeat(64);
 const ok=data=>new Uint8Array([...(data||[]),0x90,0]);let parts=[];
 const conn={status:async()=>({state:'specific',answerToReset:new Uint8Array()}),startTransaction:async fn=>fn(),disconnect:async()=>events.push('disconnect'),transmit:async raw=>{
  const a=new Uint8Array(raw);sent.push([...a]);
  if(a[1]===0xa4)return ok();if(a[1]===0xfd)return ok([6,0,0]);if(a[1]===0xf8)return ok([0,0,0,connections===1?firstSerial:123]);
  if(a[1]===0xf7)return ok(metadata(a[3]));
  if(a[1]===0x20){events.push('pin');return rejectPin?new Uint8Array([0x63,0xc2]):ok();}
  assert.equal(a[1],0x87);parts.push(...a.slice(5,5+a[4]));if(a[0]===0x10)return ok();
  const inner=p.parseBerTlv(p.parseBerTlv(new Uint8Array(parts)).get(0x7c));parts=[];
  events.push({slot:a[3],tags:[...inner.keys()]});
  // Synthetic fixture shares emulate only card primitives; the real WASM
  // still parses the recipient packet and authenticates the encrypted message.
  const value=shares && (a[3]===0x9d || a[3]===0x85)
    ? new Uint8Array(Buffer.from(shares[a[3]===0x9d ? "mlkemSecret" : "x25519Secret"],"base64"))
    : new Uint8Array(a[3]===0x9c?3309:a[3]===0x84?64:32).fill(1);
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

// Exercise the boundary that APDU-only tests missed: the exact production
// adapter response must satisfy the real WASM schema and recover authenticated
// plaintext. All private material comes from a disposable software fixture.
test('Web Smart Card response decrypts and verifies with shipped WASM',
 {skip:process.env.IWA_SPLIT_DECAP_FIXTURE ? false : 'Requires generated Sequoia software fixture'},async()=>{
 const path=process.env.IWA_SPLIT_DECAP_FIXTURE;
 assert.ok(path,'Set IWA_SPLIT_DECAP_FIXTURE to a synthetic Sequoia fixture');
 const f=JSON.parse(fs.readFileSync(path,'utf8'));
 const wasm=await import('../app/wasm/sequoia_iwa_verify.js');
 await wasm.default({module_or_path:fs.readFileSync(__dirname+'/../app/wasm/sequoia_iwa_verify_bg.wasm')});
 const request=JSON.parse(wasm.prepare_decryption(JSON.stringify(f.request)));
 const h=harness({shares:f.reply});
 const response=await h.p.decapsulateComponentsViaSmartCard(request,h.identity,async()=> '123456');
 assert.deepEqual(Object.keys(response).sort(),['requestId','cipherHash','recipientKey','mlkemCiphertext','x25519Ephemeral','mlkemSecret','x25519Secret'].sort());
 const opened=JSON.parse(wasm.finalize_decryption(JSON.stringify(response)));
 assert.equal(opened.raw,f.payload);
 const verified=JSON.parse(wasm.verify_detached(JSON.stringify({payload:opened.raw,signature:opened.signature,certificates:[f.certificate]})));
 assert.equal(verified.signatures[0].status,'valid');
 assert.ok(!h.sent.some(a=>[0x47,0xfe,0xff,0xdb].includes(a[1])),'No provisioning or policy APDUs');
});

test('required SCP failure stops before PIN, private APDUs or another reader',async()=>{
 const h=harness({secureFailure:true});let prompts=0;
 await assert.rejects(h.p.signDigestViaSmartCard({digest:Buffer.alloc(64).toString('base64'),mu:Buffer.alloc(64).toString('base64')},h.identity,async()=>{prompts++;return '123456';}),/Untrusted SCP chain/);
 assert.equal(prompts,0);assert.equal(h.sent.length,0);assert.equal(h.connections(),1);assert.ok(h.events.includes('disconnect'));
});

const vaultCipher={mlkemCiphertext:Buffer.alloc(1088,2).toString('base64'),x25519Ephemeral:Buffer.alloc(32,3).toString('base64')};
const vaultBinding=h=>({...h.identity,slots:['9d','85'].map(slot=>h.identity.slots.find(key=>key.slot===slot))});

test('Level 3 vault checks just one authenticated metadata read per decryption slot before prompting',async()=>{
 const h=harness({firstSerial:42}),progress=[];
 let prompts=0;
 await h.p.decapsulateComponentsViaSmartCard(vaultCipher,vaultBinding(h),async()=>{
  prompts++;
  assert.deepEqual(h.sent.filter(a=>a[1]===0xf7).map(a=>a[3]),[0x9d,0x85]);
  assert(!h.sent.some(a=>a[1]===0x20||a[1]===0x87));
  return '123456';
 },{vaultUnlock:true,vaultProgress:event=>progress.push([event.stage,event.serial,event.slot])});
 assert.equal(prompts,1);
 assert.deepEqual(progress,[
  ['found','42',undefined],['found','123',undefined],['slot',undefined,'9d'],['slot-verified',undefined,'9d'],
  ['slot',undefined,'85'],['slot-verified',undefined,'85'],
 ]);
});

test('either mismatched vault component stops before the PIN prompt or any private APDU',async()=>{
 for(const slot of ['9d','85']){
  const h=harness(),identity=vaultBinding(h);
  identity.slots=identity.slots.map(key=>key.slot===slot?{...key,publicKeySha256:'0'.repeat(64)}:key);
  await assert.rejects(h.p.decapsulateComponentsViaSmartCard(vaultCipher,identity,
   ()=>assert.fail('must not prompt'),{vaultUnlock:true}),/Live vault key differs/);
  assert(!h.sent.some(a=>a[1]===0x20||a[1]===0x87));
 }
});

test('required SCP failure blocks the optimized vault path before PIN or metadata',async()=>{
 const h=harness({secureFailure:true});
 await assert.rejects(h.p.decapsulateComponentsViaSmartCard(vaultCipher,vaultBinding(h),
  ()=>assert.fail('must not prompt'),{vaultUnlock:true}),/Untrusted SCP chain/);
 assert.deepEqual(h.sent,[]);
});

test('missing target reports only discovered public serials and makes no slot or PIN requests',async()=>{
 const h=harness({firstSerial:42}),identity={...vaultBinding(h),serial:'999'};
 await assert.rejects(h.p.decapsulateComponentsViaSmartCard(vaultCipher,identity,
  ()=>assert.fail('must not prompt'),{vaultUnlock:true}),error=>{
   assert.equal(error.code,'YUBIKEY_NOT_FOUND');
   assert.equal(error.expectedSerial,'999');
   assert.deepEqual([...error.attachedSerials],['42','123']);
   return true;
  });
 assert(!h.sent.some(a=>[0xf7,0x20,0x87].includes(a[1])));
});
