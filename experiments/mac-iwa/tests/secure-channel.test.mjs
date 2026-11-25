// Software-only SCP interoperability checks. Certificates and private keys are
// generated in a temporary directory, never read from or written to a YubiKey.
import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createCipheriv,createDecipheriv,createHash,createPrivateKey,createPublicKey,diffieHellman,generateKeyPairSync} from 'node:crypto';
import {cmac,SecureMessaging,openSecureConnection,tlv} from '../app/secure-channel/scp11.js';
import {hex,join,elements,validateChain,parseCertificate,unbase64} from '../app/secure-channel/certificates.js';
const h=s=>new Uint8Array(Buffer.from(s,'hex')),zero=new Uint8Array(16),status=h('9000');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'iwa-scp-test-'));
after(()=>fs.rmSync(dir,{recursive:true,force:true}));
const openssl=process.env.OPENSSL||'openssl';
const run=args=>execFileSync(openssl,args,{cwd:dir,stdio:'pipe'});
run(['req','-x509','-newkey','rsa:2048','-nodes','-keyout','root.key','-out','root.pem','-days','2','-subj','/CN=SCP test root','-addext','basicConstraints=critical,CA:TRUE,pathlen:0','-addext','keyUsage=critical,keyCertSign']);
run(['req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout','leaf.key','-out','leaf.csr','-subj','/CN=SCP test card']);
fs.writeFileSync(path.join(dir,'extensions'),'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyAgreement\n');
run(['x509','-req','-in','leaf.csr','-CA','root.pem','-CAkey','root.key','-CAcreateserial','-out','leaf.pem','-days','1','-extfile','extensions']);
const der=name=>new Uint8Array(run(['x509','-in',name+'.pem','-outform','DER']));
const root=der('root'),leaf=der('leaf'),trust={root,rootSha256:createHash('sha256').update(root).digest('hex')};
function aes(key,iv,data,dec=false){const c=(dec?createDecipheriv:createCipheriv)('aes-128-cbc',key,iv);c.setAutoPadding(false);return new Uint8Array(Buffer.concat([c.update(data),c.final()]));}
const ecb=(key,b)=>{const c=createCipheriv('aes-128-ecb',key,null);c.setAutoPadding(false);return new Uint8Array(Buffer.concat([c.update(b),c.final()]));};
// Independent OpenSSL CMAC is used by the simulated card rather than calling
// the production module's MAC, so shared mistakes do not self-validate.
function cardMac(key,data){return new Uint8Array(execFileSync(openssl,['mac','-macopt','cipher:AES-128-CBC','-macopt','hexkey:'+hex(key),'-binary','CMAC'],{input:data}));}
function reply(enc,rmac,chain,counter,plain,sw=status){const iv=new Uint8Array(16);iv[0]=128;new DataView(iv.buffer).setUint32(12,counter);const p=new Uint8Array(Math.ceil((plain.length+1)/16)*16);p.set(plain);p[plain.length]=128;const ct=aes(enc,ecb(enc,iv),p);return join(ct,cardMac(rmac,join(chain,ct,sw)).slice(0,8),sw);}
test('AES-CMAC matches NIST empty and full-block vectors',async()=>{const k=h('2b7e151628aed2a6abf7158809cf4f3c');assert.equal(hex(await cmac(k,new Uint8Array())), 'bb1d6929e95937287fa37d129b756746');assert.equal(hex(await cmac(k,h('6bc1bee22e409f96e93d7e117393172a'))),'070a16b46b4d4144f79bdd9dd04a287c');});
test('pinned chain accepts a signed device and rejects wrong root, expiry, tampering and CA leaf',async()=>{const result=await validateChain([leaf],trust);assert.equal(result.publicKey.length,65);await assert.rejects(validateChain([leaf],{...trust,rootSha256:'00'}),/pin/i);await assert.rejects(validateChain([leaf],trust,Date.now()+5*86400000),/Expired/);const bad=leaf.slice();bad[bad.length-1]^=1;await assert.rejects(validateChain([bad],trust),/not trusted/);await assert.rejects(validateChain([root],trust),/leaf/);});
test('bundled Yubico root and all intermediate certificates parse offline',()=>{const t=JSON.parse(fs.readFileSync(new URL('../app/secure-channel/yubico-trust.json',import.meta.url)));assert.equal(createHash('sha256').update(unbase64(t.root)).digest('hex'),t.rootSha256);assert.ok(parseCertificate(unbase64(t.root)).ca);for(const c of t.intermediates)assert.ok(parseCertificate(unbase64(c)).ca);});
test('encrypted command and authenticated response match independent OpenSSL primitives',async()=>{
 const enc=h('00112233445566778899aabbccddeeff'),mac=h('102132435465768798a9bacbdcedfe0f'),rmac=h('2031425364758697a8b9cadbecfd0e1f');let calls=0;
 const conn={async transmit(a){calls++;assert.equal(a[0],4);const payload=a.slice(5,5+a[4]),chain=cardMac(mac,join(zero,a.slice(0,5),payload.slice(0,-8)));assert.equal(hex(payload.slice(-8)),hex(chain.slice(0,8)));const iv=zero.slice();iv[15]=1;assert.equal(hex(aes(enc,ecb(enc,iv),payload.slice(0,-8),true)).slice(0,16),'313233343536ffff');return reply(enc,rmac,chain,1,h('010203'));}};
 const s=new SecureMessaging(conn,enc,mac,rmac,zero.slice());assert.equal(hex(await s.send(0,0x20,0,0x80,h('313233343536ffff'))),'0102039000');assert.equal(calls,1);s.close();await assert.rejects(s.send(0,1,0,0,h('')),/closed/);
});
test('MAC corruption permanently closes session without retry',async()=>{let n=0;const s=new SecureMessaging({async transmit(){n++;return h('00000000000000009000');}},zero.slice(),zero.slice(),zero.slice(),zero.slice());await assert.rejects(s.send(0,1,0,0,h('')),/MAC/);await assert.rejects(s.send(0,1,0,0,h('')),/closed/);assert.equal(n,1);});

function fakeCard({badReceipt=false}={}){
 const staticKey=createPrivateKey(fs.readFileSync(path.join(dir,'leaf.key')));let state,handshakes=0,fragments=[],lastHeader;
 return {get handshakes(){return handshakes;},async transmit(apdu){
  const a=new Uint8Array(apdu),data=a.length>5?a.slice(5,5+a[4]):new Uint8Array();
  if(a[0]&16){fragments.push(data);lastHeader=[a[0]&~16,a[1],a[2],a[3]];return status;}
  const whole=join(...fragments,data);fragments=[];
  if(a[1]===0xa4)return join(new TextEncoder().encode('U2F_V2'),status);
  if(a[1]===0xca&&a[3]===0xe0)return join(tlv(0xc0,h('13018810')),status);
  if(a[1]===0xca&&a[2]===0xbf)return join(leaf,status);
  if(a[1]===0x88){
   handshakes++;const fields=elements(whole),hostPoint=fields[1].value;
   const host=createPublicKey({key:Buffer.from(join(h('3059301306072a8648ce3d020106082a8648ce3d030107034200'),hostPoint)),format:'der',type:'spki'});
   const ep=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),point=new Uint8Array(ep.publicKey.export({format:'der',type:'spki'})).slice(-65);
   const z=Buffer.concat([diffieHellman({privateKey:ep.privateKey,publicKey:host}),diffieHellman({privateKey:staticKey,publicKey:host})]);let derived=Buffer.alloc(0);for(let n=1;derived.length<80;n++)derived=Buffer.concat([derived,createHash('sha256').update(Buffer.concat([z,Buffer.from([0,0,0,n,0x3c,0x88,16])])).digest()]);
   const receipt=cardMac(derived.subarray(0,16),join(whole,tlv(0x5f49,point)));state={enc:derived.subarray(16,32),mac:derived.subarray(32,48),rmac:derived.subarray(48,64),chain:receipt.slice(),counter:1};if(badReceipt)receipt[0]^=1;return join(tlv(0x5f49,point),tlv(0x86,receipt),status);
  }
  assert.ok(a[0]&4,'application commands must be protected');const header=whole.length>255?new Uint8Array([a[0],a[1],a[2],a[3],0,whole.length>>8,whole.length&255]):new Uint8Array([a[0],a[1],a[2],a[3],whole.length]);
  state.chain=cardMac(state.mac,join(state.chain,header,whole.slice(0,-8)));assert.equal(hex(whole.slice(-8)),hex(state.chain.slice(0,8)));return reply(state.enc,state.rmac,state.chain,state.counter++,h('01020304'));
 }};
}
test('full SCP11b handshake authenticates, encrypts long commands and rekeys after PIV/FIDO SELECT',async()=>{const card=fakeCard(),c=await openSecureConnection(card,{trust});await c.transmit(h('00a4040001aa'));assert.equal(hex(await c.transmit(h('00f80000'))),'010203049000');const long=new Uint8Array(255).fill(9);await c.transmit(join(h('10870000ff'),long));assert.equal(hex(await c.transmit(h('00870000010100'))),'010203049000');await c.transmit(h('00a4040001bb'));await c.transmit(h('80108000010400'));assert.equal(card.handshakes,2);c.close();await assert.rejects(c.transmit(h('00f80000')),/Closed/);});
test('invalid handshake receipt stops before any application or PIN APDU',async()=>{const c=await openSecureConnection(fakeCard({badReceipt:true}),{trust});await assert.rejects(c.transmit(h('00a4040001aa')),/receipt/);await assert.rejects(c.transmit(h('0020008006313233343536')),/Closed/);});
