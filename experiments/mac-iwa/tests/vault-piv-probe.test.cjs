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
 return {p,reads};
}
test('PIV wrapping probe stops at first authenticated EC key',async()=>{const {p,reads}=fixture();const r=await p.readVaultMaterialViaSmartCard({serial:'1'});assert.equal(r.classical.slot,'82');assert.deepEqual(reads,[0x9d,0x82]);});
test('explicit wrapping slot avoids scanning unrelated slots',async()=>{const {p,reads}=fixture();await p.readVaultMaterialViaSmartCard({serial:'1',slot:'82'});assert.deepEqual(reads,[0x82]);});
test('missing response MAC still fails closed',async()=>{const {p}=fixture(true);await assert.rejects(p.readVaultMaterialViaSmartCard({serial:'1'}),/Missing SCP response MAC/);});
