// Public-only fake reader: fail if discovery reaches an unused slot after
// finding P-384. This reproduces the beta SCP failure without weakening MACs.
const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),{webcrypto}=require('node:crypto');
function fixture(fail=false){
 const reads=[],ctx={Uint8Array,Array,Map,Error,TextEncoder,crypto:webcrypto,btoa:s=>Buffer.from(s,'binary').toString('base64'),module:{exports:{}}};ctx.globalThis=ctx;
 vm.createContext(ctx);vm.runInContext(fs.readFileSync(__dirname+'/../app/smartcard-piv.js','utf8'),ctx);const p=ctx.SequoiaSmartCardPiv;
 const conn={status:async()=>({answerToReset:new Uint8Array()}),startTransaction:async f=>f(),disconnect:async()=>{},transmit:async a=>{
 const ok=d=>new Uint8Array([...d,0x90,0]);
 if(a[1]===0xa4)return ok([]);if(a[1]===0xfd)return ok([6,0,0]);if(a[1]===0xf8)return ok([0,0,0,1]);
 assert.equal(a[1],0xf7);reads.push(a[3]);
 if(fail)throw Error('Missing SCP response MAC (SW=6a88)');
 if(a[3]===0x9d)return ok([1,1,0xe6]);
 assert.equal(a[3],0x82,'must not read unused slots after finding wrapping key');
 const point=new Uint8Array(97);point[0]=4;
 return ok([1,1,0x14,...p.encodeBerTlv(4,p.encodeBerTlv(0x86,point))]);
 }};
 ctx.navigator={smartCard:{establishContext:async()=>({listReaders:async()=>['YubiKey'],connect:async()=>({connection:conn})})}};
 return {p,reads,ctx};
}
test('PIV wrapping probe stops at first authenticated EC key',async()=>{const {p,reads}=fixture();const r=await p.readVaultMaterialViaSmartCard({serial:'1'});assert.equal(r.classical.slot,'82');assert.deepEqual(reads,[0x9d,0x82]);});
test('explicit wrapping slot avoids scanning unrelated slots',async()=>{const {p,reads}=fixture();await p.readVaultMaterialViaSmartCard({serial:'1',slot:'82'});assert.deepEqual(reads,[0x82]);});
test('missing response MAC still fails closed',async()=>{const {p}=fixture(true);await assert.rejects(p.readVaultMaterialViaSmartCard({serial:'1'}),/Missing SCP response MAC/);});

test('beta management qualifier supplies actual version and binds serial',()=>{
 const {p}=fixture();const body=new Uint8Array([2,4,0,0,0,1,5,3,0,0,1,0x19,11,1,3,6,0,0,2,1,1,3,1,0]);
 const data=new Uint8Array([body.length,...body]);assert.equal(p.parseVaultDeviceInfo(data,'1').version,'6.0.0');
 assert.throws(()=>p.parseVaultDeviceInfo(data,'2'),/serial mismatch/);
});

test('management pagination obtains beta version from the second page',async()=>{
 const {p}=fixture(),seen=[];
 const pages=[[2,4,0,0,0,1,5,3,0,0,1,0x10,1,1],[0x19,11,1,3,6,0,0,2,1,1,3,1,0]];
 const result=await p.readVaultDeviceInfo(async page=>{seen.push(page);return new Uint8Array([pages[page].length,...pages[page]]);},'1');
 assert.equal(result.version,'6.0.0');assert.deepEqual(seen,[0,1]);
});
test('management pagination rejects an unbounded continuation',async()=>{
 const {p}=fixture();await assert.rejects(p.readVaultDeviceInfo(async()=>new Uint8Array([3,0x10,1,1]),'1'),/Too many/);
});

test('Beta0 inventory authenticates aggregate counts and verifies F9 on the same card', async()=>{
 const {p,ctx}=fixture();
 // Model the output of the SCP adapter. Bare errors still reject at the
 // transport boundary. Neither empty-slot probing nor writes are expected.
 const storage=[1,30,0,0,154,1,162,1,0,1,0,30,2,0,1,0,0,3,0,4,0,32,4,0,0,0,0,5,0,0,0,0];
 const management=[2,4,0,0,0,1,0x19,14,1,3,6,0,0,2,1,1,3,4,0,0,0,0];
 const commands=[];
 function card({inventory=storage,serial=1,missingMac=false,hasCertificate=true}={}){
  return {authenticatedDevice:{},async transmit(a){
   commands.push(a[1]);
   const ok=d=>new Uint8Array([...d,0x90,0]);
   switch(a[1]){
    case 0xa4:return ok([]);
    case 0x1d:return ok([management.length,...management]);
    case 0x30:if(missingMac)throw Error('Missing SCP response MAC');return ok(inventory);
    case 0xf8:return ok([0,0,0,serial]);
    case 0xf7:assert.equal(a[3],0xf9);return ok([1,1,0xe4,4,1,1]);
    case 0xcb:return ok(hasCertificate?[0x53,1,1]:[]);
    default:assert.fail('Unexpected provisioning APDU');
   }
  }};
 }
 const info={serial:'1',version:'0.0.1'};
 // Enable the same fail-closed policy used by the real browser adapter.
 Object.assign(ctx,{SequoiaSecureChannel:{isRequired:()=>true}});
 const proof=await p.readProvisioningInventory(card(),info);
 assert.equal(proof.slots.length,24);
 assert(proof.slots.every(s=>s.keyPresent===false&&s.certificatePresent===false));
 assert.deepEqual(commands,[0xa4,0x1d,0x30,0xa4,0xf8,0xf7,0xcb]);
 for(const index of [9,14]){
  const occupied=storage.slice();occupied[index]=2;
  await assert.rejects(p.readProvisioningInventory(card({inventory:occupied}),info),/not empty/);
 }
 const duplicate=storage.slice();duplicate[12]=1;
 await assert.rejects(p.readProvisioningInventory(card({inventory:duplicate}),info),/Unrecognized/);
 await assert.rejects(p.readProvisioningInventory(card({missingMac:true}),info),/Missing SCP response MAC/);
 await assert.rejects(p.readProvisioningInventory(card({serial:2}),info),/YubiKey changed/);
 await assert.rejects(p.readProvisioningInventory(card({hasCertificate:false}),info),/factory PIV attestation entries/);
 await assert.rejects(p.readProvisioningInventory({},info),/authenticated SCP11b/);
});
