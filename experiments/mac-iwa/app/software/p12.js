// Narrow PKCS#12 import for PQ Mail's software OpenPGP keyset. This parser runs
// only inside the disposable software worker. It authenticates the complete
// AuthenticatedSafe before interpreting/decrypting bags, never creates keys or
// certificates, and returns the existing certified OpenPGP packets unchanged.
// It is not a general-purpose X.509 importer or a source of recipient trust.
const LIMIT=1048576,MAX_NODES=8192,MAX_DEPTH=24;
const OID={data:'1.2.840.113549.1.7.1',encrypted:'1.2.840.113549.1.7.6',
 sha1:'1.3.14.3.2.26',sha256:'2.16.840.1.101.3.4.2.1',pbes2:'1.2.840.113549.1.5.13',pbkdf2:'1.2.840.113549.1.5.12',
 hmac256:'1.2.840.113549.2.9',hmac384:'1.2.840.113549.2.10',hmac512:'1.2.840.113549.2.11',
 aes128:'2.16.840.1.101.3.4.1.2',aes256:'2.16.840.1.101.3.4.1.42',
 keyBag:'1.2.840.113549.1.12.10.1.2',certBag:'1.2.840.113549.1.12.10.1.3',
 x509:'1.2.840.113549.1.9.22.1',friendly:'1.2.840.113549.1.9.20',keyId:'1.2.840.113549.1.9.21',
 metadata:'2.25.302661978184745645819285730512635507321'};
const fail=()=>{throw Error('Unsupported or unauthenticated PQ Mail PKCS#12 identity.');};
const require=(value)=>{if(!value)fail();};
const b64=bytes=>{let s='';for(const byte of bytes)s+=String.fromCharCode(byte);return btoa(s);};
function unbase64(value){require(typeof value==='string'&&value.length>0&&value.length<=Math.ceil(LIMIT/3)*4);let bytes;try{bytes=Uint8Array.from(atob(value),c=>c.charCodeAt(0));}catch(_){fail();}require(bytes.length<=LIMIT&&b64(bytes)===value);return bytes;}

/** Accept bounded BER containers because Bouncy Castle emits constructed,
 * indefinite-length OCTET STRINGs. Children must consume their parent exactly;
 * a primitive indefinite value, trailing data, huge length or depth is rejected.
 * No ASN.1 input can select a URL, algorithm implementation or native operation.
 */
function parse(bytes){
 require(bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=LIMIT);let nodes=0;
 function element(start,end,depth){
  require(++nodes<=MAX_NODES&&depth<=MAX_DEPTH&&start+2<=end);let at=start;
  const tag=bytes[at++];require((tag&31)!==31&&tag!==0);let length=bytes[at++],indefinite=length===128;
  if(length>128){const n=length&127;require(n>0&&n<=3&&at+n<=end&&bytes[at]!==0);length=0;for(let i=0;i<n;i++)length=length*256+bytes[at++];require(length>=128);}
  const body=at;let stop=indefinite?end:body+length;require(stop<=end&&(!indefinite||!!(tag&32)));
  const children=[];
  if(tag&32){
   while(at<stop){if(indefinite&&at+1<stop&&bytes[at]===0&&bytes[at+1]===0){stop=at;at+=2;break;}const child=element(at,stop,depth+1);children.push(child);at=child.end;}
   require(indefinite?at===stop+2:at===stop);
  }else at=stop;
  return {tag,children,bytes:bytes.subarray(body,stop),raw:bytes.subarray(start,at),end:at};
 }
 const value=element(0,bytes.length,0);require(value.end===bytes.length);return value;
}
function sequence(node,count){require(node?.tag===48&&(count===undefined||node.children.length===count));return node.children;}
function oid(node){require(node?.tag===6&&node.bytes.length>0&&node.bytes.length<=64);const values=[];let value=0n,open=false;for(const b of node.bytes){require(!(open===false&&b===128));value=value*128n+BigInt(b&127);open=!!(b&128);if(!open){values.push(value);value=0n;}}require(!open&&values.length>0);const first=values.shift();const a=first<40n?0n:first<80n?1n:2n;return [a,first-a*40n,...values].join('.');}
function integer(node,max=1000000){require(node?.tag===2&&node.bytes.length>0&&node.bytes.length<=4&&!(node.bytes[0]&128));let n=0;for(const byte of node.bytes)n=n*256+byte;require(n<=max);return n;}
function octets(node,implicit=false){
 require(node&&(node.tag===4||node.tag===36||(implicit&&(node.tag===128||node.tag===160))));
 if(!(node.tag&32))return node.bytes.slice();const parts=node.children.map(x=>octets(x)),size=parts.reduce((n,p)=>n+p.length,0);require(size<=LIMIT);const out=new Uint8Array(size);let at=0;for(const p of parts){out.set(p,at);at+=p.length;}return out;
}
function explicit(node){require(node?.tag===160&&node.children.length===1);return node.children[0];}
function algorithm(node){const c=sequence(node);require(c.length===1||c.length===2);return {oid:oid(c[0]),params:c[1]};}
function bmp(node){require(node?.tag===30&&node.bytes.length>0&&node.bytes.length<=256&&node.bytes.length%2===0);let value='';for(let i=0;i<node.bytes.length;i+=2){const x=node.bytes[i]*256+node.bytes[i+1];require(x>=32&&x!==127&&!(x>=0xd800&&x<=0xdfff));value+=String.fromCharCode(x);}return value;}
function attributes(node){
 if(!node)return {};require(node.tag===49&&node.children.length<=16);const out={};
 for(const a of node.children){const c=sequence(a,2),name=oid(c[0]);require(c[1].tag===49&&c[1].children.length===1);
  if(name===OID.friendly){require(out.alias===undefined);out.alias=bmp(c[1].children[0]);}
  else if(name===OID.keyId){require(out.localId===undefined);out.localId=b64(octets(c[1].children[0]));}
 }
 return out;
}

/** PBES2 is the only permitted bag encryption scheme. PBKDF2 work is bounded
 * before WebCrypto is called; implicit SHA-1 PRFs and legacy PKCS#12 ciphers
 * fail closed rather than weakening a current PQ Mail export's protection.
 */
async function decrypt(node,cipher,password){
 const outer=algorithm(node);require(outer.oid===OID.pbes2);const p=sequence(outer.params,2),kdf=algorithm(p[0]),enc=algorithm(p[1]);require(kdf.oid===OID.pbkdf2);
 const args=sequence(kdf.params);require(args.length===3||args.length===4);const salt=octets(args[0]),iterations=integer(args[1]);require(salt.length>=8&&salt.length<=64&&iterations>=1000);
 const keyLength=enc.oid===OID.aes256?32:enc.oid===OID.aes128?16:0;require(keyLength>0);let prf;
 if(args.length===4){require(integer(args[2],64)===keyLength);prf=algorithm(args[3]);}else prf=algorithm(args[2]);
 const hash=prf.oid===OID.hmac256?'SHA-256':prf.oid===OID.hmac384?'SHA-384':prf.oid===OID.hmac512?'SHA-512':null;require(hash&&(!prf.params||(prf.params.tag===5&&prf.params.bytes.length===0)));
 const iv=octets(enc.params);require(iv.length===16&&cipher.length>0&&cipher.length<=LIMIT&&cipher.length%16===0);
 const utf8=new TextEncoder().encode(password);let key;
 try{key=await crypto.subtle.importKey('raw',utf8,'PBKDF2',false,['deriveKey']);const aes=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations,hash},key,{name:'AES-CBC',length:keyLength*8},false,['decrypt']);return new Uint8Array(await crypto.subtle.decrypt({name:'AES-CBC',iv},aes,cipher));}
 finally{utf8.fill(0);key=null;}
}
function metadata(certificate){
 const cert=sequence(parse(certificate),3),tbs=sequence(cert[0]),extensions=tbs.filter(x=>x.tag===163);require(extensions.length===1&&extensions[0].children.length===1);
 const found=sequence(extensions[0].children[0]).filter(x=>{const e=sequence(x);return e.length>=2&&oid(e[0])===OID.metadata;});require(found.length===1);
 const ext=sequence(found[0]);require(ext.length===2||ext.length===3);if(ext.length===3)require(ext[1].tag===1&&ext[1].bytes.length===1&&ext[1].bytes[0]===0);
 // X.509 extnValue wraps DER OCTET STRING(metadata), whose contents are the
 // two existing public keyrings. Do not regenerate self-signatures/fingerprints.
 const outer=parse(octets(ext.at(-1))),inner=parse(octets(outer)),rings=sequence(inner,2);
 return {modern:b64(octets(rings[0])),compatibility:b64(octets(rings[1]))};
}

export async function decodePqMailP12({p12,password},{verifyMac}={}){
 require(typeof password==='string'&&password.length>0&&password.length<=1024&&typeof verifyMac==='function');
 const raw=unbase64(p12);let safe;
 try{
  const root=sequence(parse(raw),3);require(integer(root[0],3)===3);const content=sequence(root[1],2);require(oid(content[0])===OID.data);safe=octets(explicit(content[1]));
  const mac=sequence(root[2]);require(mac.length===2||mac.length===3);const digest=sequence(mac[0],2),macAlg=algorithm(digest[0]);require([OID.sha1,OID.sha256].includes(macAlg.oid)&&(!macAlg.params||(macAlg.params.tag===5&&macAlg.params.bytes.length===0)));const hash=macAlg.oid===OID.sha1?'SHA-1':'SHA-256';
  const salt=octets(mac[1]),expected=octets(digest[1]),iterations=mac.length===3?integer(mac[2]):1;require(salt.length>=8&&salt.length<=64&&expected.length===(hash==='SHA-1'?20:32)&&iterations>=1);
  const verified=await verifyMac({data:b64(safe),salt:b64(salt),iterations,mac:b64(expected),password,hash});require(verified?.verified===true);
  const keys=new Map(),certificates=new Map();let bags=0;
  for(const ci of sequence(parse(safe))){
   const c=sequence(ci,2),type=oid(c[0]);let plain;
   try{
    if(type===OID.data)plain=octets(explicit(c[1]));
    else if(type===OID.encrypted){const encrypted=sequence(explicit(c[1]),2);require(integer(encrypted[0],0)===0);const info=sequence(encrypted[1],3);require(oid(info[0])===OID.data);plain=await decrypt(info[1],octets(info[2],true),password);}
    else fail();
    for(const bag of sequence(parse(plain))){
     require(++bags<=96);const fields=sequence(bag);require(fields.length===2||fields.length===3);const kind=oid(fields[0]),value=explicit(fields[1]),attrs=attributes(fields[2]);
     if(kind===OID.keyBag){
      const encrypted=sequence(value,2);let pkcs8;
      try{pkcs8=await decrypt(encrypted[0],octets(encrypted[1]),password);require(sequence(parse(pkcs8)).length>=3);
       if(attrs.alias?.startsWith('pgp5-')){require(!keys.has(attrs.alias));keys.set(attrs.alias,{alias:attrs.alias,pkcs8:b64(pkcs8),localId:attrs.localId});}
      }finally{pkcs8?.fill(0);}
     }else if(kind===OID.certBag){
      const cert=sequence(value,2);require(oid(cert[0])===OID.x509);const bytes=octets(explicit(cert[1]));sequence(parse(bytes),3);
      if(attrs.alias?.startsWith('pgp5-')){require(!certificates.has(attrs.alias));certificates.set(attrs.alias,{certificate:b64(bytes),localId:attrs.localId});}
     }else fail();
    }
   }finally{plain?.fill(0);}
  }
  const names=['cert-ml','cert-ed','sign-ml','sign-ed','kem-ml','kem-x','v4-sign','v4-ml','v4-x','v4-ec'].map(x=>'pgp5-'+x);
  require(keys.size===names.length&&certificates.size===names.length);const result=[];
  for(const alias of names){const key=keys.get(alias),cert=certificates.get(alias);require(key&&cert&&key.localId&&key.localId===cert.localId);result.push({alias,pkcs8:key.pkcs8,certificate:cert.certificate});}
  const rings=metadata(unbase64(certificates.get('pgp5-cert-ed').certificate));return {keys:result,...rings};
 }finally{raw.fill(0);safe?.fill(0);}
}
