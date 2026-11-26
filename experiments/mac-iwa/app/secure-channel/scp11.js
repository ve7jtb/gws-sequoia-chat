// Transport-independent GlobalPlatform SCP11b, implemented against Yubico's
// yubikit/core/smartcard/scp.py and GP Amendment F. Exposes no provisioning,
// credential creation, key import, PIN change or Security Domain write API.
import {bytes,join,same,elements,validateChain} from './certificates.js';
const SD=new Uint8Array([0xa0,0,0,1,0x51,0,0,0]);
const empty=new Uint8Array();
export function tlv(tag,value){return join(new Uint8Array(tag>255?[tag>>8,tag&255]:[tag]),length(value.length),value);}
function length(n){return new Uint8Array(n<128?[n]:n<256?[0x81,n]:[0x82,n>>8,n&255]);}
function split(b){b=bytes(b);if(b.length<2)throw Error('Truncated SCP response');return {data:b.slice(0,-2),sw:(b.at(-2)<<8)|b.at(-1)};}
function command(cla,ins,p1,p2,data,extended=false,le=false){
 const header=new Uint8Array([cla,ins,p1,p2]);if(!data.length)return join(header,le?new Uint8Array([0]):empty);
 return join(header,extended?new Uint8Array([0,data.length>>8,data.length&255]):new Uint8Array([data.length]),data,le?new Uint8Array(extended?2:1):empty);
}
// GET RESPONSE and physical command chaining happen *below* SCP: authenticate
// the assembled ciphertext, not each transport fragment. Limits apply before
// concatenation, including certificate discovery on an unauthenticated card.
// Record only public command headers and the transport stage. A status
// received without a valid MAC remains untrusted diagnostic information.
function scpStatusError(message,sw,ins,p1,p2,stage){
 // Web Smart Card can recreate a callback exception using only its message.
 // Put the safe header in the message before it crosses that boundary.
 const hex=value=>value.toString(16).padStart(2,'0').toUpperCase();
 return Object.assign(Error(`${message} [INS=${hex(ins)} P1=${hex(p1)} P2=${hex(p2)}, ${stage}, SW=${hex(sw)}]`),
  {scpCommand:{sw,ins,p1,p2,stage}});
}
async function raw(conn,cla,ins,p1,p2,data=empty){
 let r,off=0;while(data.length-off>255){r=split(await conn.transmit(command(cla|16,ins,p1,p2,data.slice(off,off+255))));if(r.sw!==0x9000||r.data.length)throw scpStatusError('SCP command chaining rejected',r.sw,ins,p1,p2,'command fragment');off+=255;}
 r=split(await conn.transmit(command(cla,ins,p1,p2,data.slice(off),false,true)));let chunks=[],total=0;
 for(let n=0;n<512;n++){chunks.push(r.data);total+=r.data.length;if(total>65536)throw Error('SCP response too large');if((r.sw>>8)!==0x61)return {data:join(...chunks),sw:r.sw,stage:n?'GET RESPONSE':'final command'};r=split(await conn.transmit(new Uint8Array([0,0xc0,0,0,r.sw&255])));}
 throw Error('SCP response chaining limit');
}
async function ok(conn,...args){const r=await raw(conn,...args);if(r.sw!==0x9000)throw Error('Secure channel setup failed: SW='+r.sw.toString(16));return r.data;}
// WebCrypto adds PKCS#7 padding. Keep only the aligned plaintext's blocks for
// encryption. For decryption append a generated padding block before using its
// checked unpadding, as in the existing CTAP PIN/UV protocol implementation.
async function cbc(key,iv,data,decrypt=false){
 const k=await crypto.subtle.importKey('raw',key,'AES-CBC',false,['encrypt','decrypt']);
 if(!decrypt)return bytes(await crypto.subtle.encrypt({name:'AES-CBC',iv},k,data)).slice(0,data.length);
 if(!data.length||data.length%16)throw Error('Invalid SCP ciphertext length');
 const pad=bytes(await crypto.subtle.encrypt({name:'AES-CBC',iv:data.slice(-16)},k,new Uint8Array(16).fill(16))).slice(0,16);
 return bytes(await crypto.subtle.decrypt({name:'AES-CBC',iv},k,join(data,pad)));
}
const block=(key,data)=>cbc(key,new Uint8Array(16),data);
function double(b){const out=new Uint8Array(16);let carry=0;for(let i=15;i>=0;i--){out[i]=(b[i]<<1)|carry;carry=b[i]>>7;}if(carry)out[15]^=0x87;return out;}
export async function cmac(key,data){
 const k1=double(await block(key,new Uint8Array(16))),k2=double(k1),n=Math.max(1,Math.ceil(data.length/16)),m=new Uint8Array(n*16);m.set(data);
 const complete=data.length>0&&data.length%16===0;if(!complete)m[data.length]=128;const sub=complete?k1:k2;for(let i=0;i<16;i++)m[m.length-16+i]^=sub[i];return (await cbc(key,new Uint8Array(16),m)).slice(-16);
}
export async function x963(z,info,size){let out=empty;for(let i=1;out.length<size;i++){out=join(out,bytes(await crypto.subtle.digest('SHA-256',join(z,new Uint8Array([i>>>24,i>>>16&255,i>>>8&255,i&255]),info))));}return out.slice(0,size);}
async function handshake(conn,ref,publicKey){
 const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const pub=bytes(await crypto.subtle.exportKey('raw',pair.publicKey));
 const request=join(tlv(0xa6,join(tlv(0x90,new Uint8Array([0x11,0])),tlv(0x95,new Uint8Array([0x3c])),tlv(0x80,new Uint8Array([0x88])),tlv(0x81,new Uint8Array([16])))),tlv(0x5f49,pub));
 const r=elements(await ok(conn,0x80,0x88,ref[1],ref[0],request));if(r.length!==2||r[0].tag!==0x5f49||r[0].value.length!==65||r[1].tag!==0x86||r[1].value.length!==16)throw Error('Invalid SCP11 handshake');
 const agree=async p=>{const k=await crypto.subtle.importKey('raw',p,{name:'ECDH',namedCurve:'P-256'},false,[]);return bytes(await crypto.subtle.deriveBits({name:'ECDH',public:k},pair.privateKey,256));};
 const ephemeral=await agree(r[0].value),stat=await agree(publicKey);let derived;
 try{derived=await x963(join(ephemeral,stat),new Uint8Array([0x3c,0x88,16]),80);const receipt=await cmac(derived.slice(0,16),join(request,r[0].raw));if(!same(receipt,r[1].value))throw Error('SCP11 device authentication receipt mismatch');return new SecureMessaging(conn,derived.slice(16,32),derived.slice(32,48),derived.slice(48,64),receipt);}
 finally{ephemeral.fill(0);stat.fill(0);derived?.fill(0);}
}
export class SecureMessaging{
 constructor(conn,enc,mac,rmac,chain){this.conn=conn;this.enc=enc;this.mac=mac;this.rmac=rmac;this.chain=chain;this.counter=1;this.closed=false;}
 close(){this.closed=true;for(const k of [this.enc,this.mac,this.rmac,this.chain])k.fill(0);}
 async send(cla,ins,p1,p2,data){
  if(this.closed||this.counter>0xffffffff)throw Error('Secure channel is closed');
  try{
   const counter=this.counter++,ivData=new Uint8Array(16);new DataView(ivData.buffer).setUint32(12,counter);
   const padded=new Uint8Array(Math.ceil((data.length+1)/16)*16);padded.set(data);padded[data.length]=128;
   const cipher=await cbc(this.enc,await block(this.enc,ivData),padded);padded.fill(0);
   const framed=command(cla|4,ins,p1,p2,join(cipher,new Uint8Array(8)),cipher.length+8>255);
   this.chain=await cmac(this.mac,join(this.chain,framed.slice(0,-8)));
   const r=await raw(this.conn,cla|4,ins,p1,p2,join(cipher,this.chain.slice(0,8)));
   // An unauthenticated status is never passed to an application as a valid
   // PIN rejection/success. Tear down on any corruption; no plaintext retry.
   if(r.data.length<8)throw scpStatusError('Missing SCP response MAC (SW='+r.sw.toString(16)+')',r.sw,ins,p1,p2,r.stage);
   const ciphertext=r.data.slice(0,-8),tag=await cmac(this.rmac,join(this.chain,ciphertext,new Uint8Array([r.sw>>8,r.sw&255])));
   if(!same(tag.slice(0,8),r.data.slice(-8)))throw Error('SCP response MAC mismatch');
   let plain=empty;if(ciphertext.length){ivData[0]=128;const paddedResponse=await cbc(this.enc,await block(this.enc,ivData),ciphertext,true);let end=paddedResponse.length-1;while(end>=0&&paddedResponse[end]===0)end--;if(end<0||paddedResponse[end]!==128)throw Error('Invalid SCP response padding');plain=paddedResponse.slice(0,end);paddedResponse.fill(0);}
   return join(plain,new Uint8Array([r.sw>>8,r.sw&255]));
  }catch(e){this.close();throw e;}
 }
}
// Parse only the short APDUs used by our PIV/CTAP clients. Logical command
// chaining is buffered until its final fragment, then encrypted once. The
// underlying raw transport may fragment that protected command independently.
function parse(apdu){const a=bytes(apdu);if(a.length<4)throw Error('Invalid APDU');let data=empty;if(a.length>5){if(!a[4]||![5+a[4],6+a[4]].includes(a.length))throw Error('Unsupported APDU encoding');data=a.slice(5,5+a[4]);}return {cla:a[0],ins:a[1],p1:a[2],p2:a[3],data};}
export async function openSecureConnection(conn,{trust,onStatus=()=>{}}){
 let secure=null,pending=null,busy=false,closed=false;
 onStatus('Authenticating YubiKey Secure Domain certificate…');
 await ok(conn,0,0xa4,4,0,SD);
 const refs=elements(await ok(conn,0,0xca,0,0xe0)).filter(t=>t.tag===0xc0&&t.value[0]===0x13).map(t=>t.value.slice(0,2));
 if(refs.length!==1)throw Error('Expected one SCP11b device key');const ref=refs[0];
 const certs=elements(await ok(conn,0,0xca,0xbf,0x21,tlv(0xa6,tlv(0x83,ref)))).map(t=>t.raw);
 const verified=await validateChain(certs,trust);
 onStatus('Yubico certificate chain verified; waiting for applet session.');
 return {
  authenticatedDevice:Object.freeze({certificateSha256:verified.certificateSha256,rootSha256:verified.rootSha256}),
  close(){closed=true;secure?.close();pending?.data.fill(0);pending=null;},
  async transmit(apdu){
   if(closed||busy)throw Error('Closed or concurrent secure channel');busy=true;
   try{
    const a=parse(apdu);
    if(a.ins===0xa4){
     if(pending||a.cla!==0||a.p1!==4||a.p2!==0)throw Error('Invalid secure applet selection');
     secure?.close();secure=null;const selected=await ok(conn,0,0xa4,4,0,a.data);
     secure=await handshake(conn,ref,verified.publicKey);onStatus('Secure YubiKey connection authenticated — SCP11b encryption active.');return join(selected,new Uint8Array([0x90,0]));
    }
    if(!secure)throw Error('Select an applet before secure operations');
    const header=[a.cla&~16,a.ins,a.p1,a.p2];if(pending){if(!header.every((x,i)=>x===pending.header[i]))throw Error('Interrupted command chain');a.data=join(pending.data,a.data);pending.data.fill(0);pending=null;}
    if(a.data.length>32768)throw Error('Secure command too large');if(a.cla&16){pending={header,data:a.data};return new Uint8Array([0x90,0]);}
    try{return await secure.send(...header,a.data);}finally{a.data.fill(0);}
   }catch(e){closed=true;secure?.close();pending?.data.fill(0);pending=null;onStatus('Secure connection failed: '+e.message);throw e;}finally{busy=false;}
  }
 };
}
