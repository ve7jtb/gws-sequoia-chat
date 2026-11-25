// Deliberately narrow offline X.509 validator for SCP11 device chains. This is
// not a Web PKI verifier: no network/AIA downloads, user roots, or TOFU. The
// caller supplies an immutable trust anchor and optional untrusted intermediates.
export const bytes = x => new Uint8Array(x);
export const join = (...xs) => {const out=new Uint8Array(xs.reduce((n,x)=>n+x.length,0));let p=0;for(const x of xs){out.set(x,p);p+=x.length;}return out;};
export const hex = b => Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
export const same = (a,b) => a.length===b.length && a.every((v,i)=>v===b[i]);
export const sha256 = async b => bytes(await crypto.subtle.digest('SHA-256',b));
export const unbase64 = s => Uint8Array.from(atob(s),c=>c.charCodeAt(0));

// Preserve exact encoded slices for signatures and issuer/subject matching.
// Reject indefinite, nonminimal and oversized lengths before allocating data.
export function elements(input){
 const b=bytes(input),out=[];let p=0;
 if(b.length>65536)throw Error('Certificate/TLV input too large');
 while(p<b.length){const start=p;let tag=b[p++];if((tag&31)===31){let n=0;do{if(p>=b.length||++n>2)throw Error('Invalid tag');tag=tag*256+b[p];}while(b[p++]&128);}
  if(p>=b.length)throw Error('Missing length');let n=b[p++];if(n&128){const k=n&127;if(!k||k>3||p+k>b.length||b[p]===0)throw Error('Invalid DER length');n=0;for(let i=0;i<k;i++)n=n*256+b[p++];if(n<128)throw Error('Nonminimal DER length');}
  if(p+n>b.length)throw Error('Truncated DER/TLV');out.push({tag,value:b.slice(p,p+n),raw:b.slice(start,p+n)});p+=n;if(out.length>256)throw Error('Too many elements');
 }return out;
}
function one(b,tag){const a=elements(b);if(a.length!==1||a[0].tag!==tag)throw Error('Unexpected certificate structure');return a[0];}
function integer(b){if(!b.length||b.length>4||b[0]&128)throw Error('Invalid positive integer');return b.reduce((n,x)=>n*256+x,0);}
function time(t){
 const s=new TextDecoder().decode(t.value);let m,y;
 if(t.tag===23&&(m=/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)))y=+m[1]+(+m[1]>=50?1900:2000);
 else if(t.tag===24&&(m=/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)))y=+m[1];
 else throw Error('Unsupported certificate time');
 const d=new Date(0);d.setUTCFullYear(y,+m[2]-1,+m[3]);d.setUTCHours(+m[4],+m[5],+m[6],0);
 if(d.getUTCFullYear()!==y||d.getUTCMonth()!==+m[2]-1||d.getUTCDate()!==+m[3]||d.getUTCHours()!==+m[4]||d.getUTCMinutes()!==+m[5]||d.getUTCSeconds()!==+m[6])throw Error('Invalid certificate time');return +d;
}
export function parseCertificate(der){
 const c=elements(one(der,48).value);if(c.length!==3||c[0].tag!==48||c[1].tag!==48||c[2].tag!==3||c[2].value[0]!==0)throw Error('Invalid certificate');
 const t=elements(c[0].value);let i=t[0].tag===0xa0?1:0;
 if(i&&integer(one(t[0].value,2).value)!==2)throw Error('Expected X.509 v3');
 if(t.length<i+6)throw Error('Truncated certificate');
 const serial=t[i++];if(serial.tag!==2||!serial.value.length||serial.value[0]&128)throw Error('Invalid certificate serial');
 if(!same(t[i++].raw,c[1].raw))throw Error('Certificate algorithm mismatch');
 const issuer=t[i++],validity=elements(t[i++].value),subject=t[i++],spki=t[i++];
 if(issuer.tag!==48||subject.tag!==48||spki.tag!==48||validity.length!==2)throw Error('Invalid certificate fields');
 const ext=new Map();for(;i<t.length;i++){if(t[i].tag!==0xa3)throw Error('Unsupported certificate field');for(const e of elements(one(t[i].value,48).value)){const a=elements(e.value);if(e.tag!==48||a[0]?.tag!==6)throw Error('Invalid extension');const id=hex(a[0].value);if(ext.has(id))throw Error('Duplicate extension');let j=1,critical=false;if(a[j]?.tag===1){if(a[j].value.length!==1||a[j].value[0]!==255)throw Error('Invalid critical boolean');critical=true;j++;}if(a.length!==j+1||a[j].tag!==4)throw Error('Invalid extension value');if(critical&&!['551d13','551d0f','551d20'].includes(id))throw Error('Unsupported critical certificate extension');ext.set(id,a[j].value);}}
 // Constraints requiring general RFC5280 policy/name processing are outside
 // this narrow manufacturer profile, even if incorrectly marked noncritical.
 for(const id of ['551d1e','551d21','551d24','551d36'])if(ext.has(id))throw Error('Unsupported certificate constraint');
 // CertificatePolicies is critical on Yubico SD issuers. Support only the
 // three published SD policy OIDs, with no qualifiers or policy mapping.
 let policies=null;if(ext.has('551d20')){policies=elements(one(ext.get('551d20'),48).value).map(p=>{const a=elements(p.value);if(p.tag!==48||a.length!==1||a[0].tag!==6)throw Error('Unsupported certificate policy');const id=hex(a[0].value);if(!['2a864886fc6b64000a02011e','2a864886fc6b64000a020132','2a864886fc6b64000a02010a'].includes(id))throw Error('Unknown Secure Domain policy');return id;});if(!policies.length)throw Error('Empty certificate policies');}
 let ca=false,pathLen=Infinity;const bc=ext.get('551d13');if(bc){const a=elements(one(bc,48).value);let j=0;if(a[0]?.tag===1){if(a[0].value.length!==1||a[0].value[0]!==255)throw Error('Invalid CA constraint');ca=true;j++;}if(a[j]?.tag===2){pathLen=integer(a[j++].value);}if(j!==a.length||!ca&&pathLen!==Infinity)throw Error('Invalid basic constraints');}
 let usage=null;if(ext.has('551d0f')){const b=one(ext.get('551d0f'),3).value;if(b.length<2||b[0]>7)throw Error('Invalid key usage');usage=b[1];}
 return {der:bytes(der),tbs:c[0].raw,algorithm:elements(c[1].value),signature:c[2].value.slice(1),issuer:issuer.raw,subject:subject.raw,spki:spki.raw,notBefore:time(validity[0]),notAfter:time(validity[1]),ca,pathLen,usage,policies};
}
const algorithms={'2a864886f70d01010b':['RSASSA-PKCS1-v1_5','SHA-256'],'2a864886f70d01010c':['RSASSA-PKCS1-v1_5','SHA-384'],'2a864886f70d01010d':['RSASSA-PKCS1-v1_5','SHA-512'],'2a8648ce3d040302':['ECDSA','SHA-256'],'2a8648ce3d040303':['ECDSA','SHA-384']};
async function verify(child,parent){
 const a=child.algorithm;if(a[0]?.tag!==6)throw Error('Missing signature algorithm');const alg=algorithms[hex(a[0].value)];if(!alg)throw Error('Unsupported certificate signature algorithm');
 let keyAlg={name:alg[0],hash:alg[1]},sig=child.signature;
 if(alg[0]==='ECDSA'){
  const pub=elements(one(parent.spki,48).value),params=elements(pub[0].value);const curve={'2a8648ce3d030107':['P-256',32],'2b81040022':['P-384',48]}[hex(params[1]?.value||[])];if(!curve)throw Error('Unsupported issuer curve');keyAlg={name:'ECDSA',namedCurve:curve[0]};
  const ints=elements(one(sig,48).value);if(ints.length!==2)throw Error('Invalid ECDSA signature');sig=new Uint8Array(curve[1]*2);ints.forEach((x,i)=>{if(x.tag!==2||!x.value.length||x.value[0]&128)throw Error('Invalid signature integer');let v=x.value;if(v[0]===0)v=v.slice(1);if(v.length>curve[1])throw Error('Oversized signature');sig.set(v,(i+1)*curve[1]-v.length);});
 }
 if(a.length>2||a.length===2&&(alg[0]!=='RSASSA-PKCS1-v1_5'||a[1].tag!==5||a[1].value.length))throw Error('Unsupported signature parameters');
 const key=await crypto.subtle.importKey('spki',parent.spki,keyAlg,false,['verify']);return crypto.subtle.verify({name:alg[0],hash:alg[1]},key,sig,child.tbs);
}
// Only the pinned root can terminate a chain. Supplied card certificates and
// bundled intermediates remain untrusted until every signature is verified.
export async function validateChain(cardDer,{root,rootSha256,intermediates=[],requiredPolicyOids=null},now=Date.now()){
 if(hex(await sha256(root))!==rootSha256)throw Error('Pinned root hash mismatch');
 if(!cardDer.length||cardDer.length>8)throw Error('Invalid card certificate count');
 const anchor=parseCertificate(root),card=cardDer.map(parseCertificate),pool=[...card,...intermediates.map(parseCertificate),anchor];
 const leaf=card.at(-1);if(leaf.ca||leaf.usage===null||!(leaf.usage&8))throw Error('SCP leaf must permit key agreement');
 const valid=c=>{if(now<c.notBefore||now>c.notAfter)throw Error('Expired or not-yet-valid device certificate');};
 async function walk(c,seen,below,policies,policySeen){valid(c);
  if(c.policies){policies=policies?policies.filter(p=>c.policies.includes(p)):c.policies;policySeen=true;if(!policies.length)return false;}
  if(same(c.der,anchor.der))return !requiredPolicyOids||policySeen;if(seen.length>=7)throw Error('Certificate chain too deep');
  for(const p of pool){if(seen.some(x=>same(x,p.der))||!same(c.issuer,p.subject)||!p.ca||p.usage===null||!(p.usage&4)||p.pathLen<below)continue;
   try{valid(p);if(await verify(c,p)&&await walk(p,[...seen,c.der],below+(c.ca?1:0),policies,policySeen))return true;}catch{/* Try only another signed issuer path, never another trust root. */}
  }return false;
 }
 if(!await walk(leaf,[],0,requiredPolicyOids,false))throw Error('Device certificate is not trusted by the pinned Yubico root');
 const p=elements(one(leaf.spki,48).value),a=elements(p[0].value);if(hex(a[0]?.value||[])!=='2a8648ce3d0201'||hex(a[1]?.value||[])!=='2a8648ce3d030107'||p[1]?.tag!==3||p[1].value.length!==66||p[1].value[0]!==0||p[1].value[1]!==4)throw Error('SCP11 requires a P-256 device key');
 return {publicKey:p[1].value.slice(1),certificateSha256:hex(await sha256(leaf.der)),rootSha256};
}
