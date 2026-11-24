// MIME runs in a disposable worker. Binary strings below preserve octets: they
// must never be decoded as UTF-8 and re-encoded before signature verification.
import PostalMime from './vendor/postal-mime/postal-mime.js';
export const LIMIT=262144;
export function bytes64(value){if(typeof value!=='string'||value.length>400000)throw Error('Oversize input');return Uint8Array.from(atob(value),c=>c.charCodeAt(0));}
export function b64(bytes){let s='';for(let i=0;i<bytes.length;i+=8192)s+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(s);}
const octets=s=>Uint8Array.from(s,c=>c.charCodeAt(0));
function binary(bytes){let s='';for(let i=0;i<bytes.length;i+=8192)s+=String.fromCharCode(...bytes.subarray(i,i+8192));return s;}
export function entity(bytes){
 if(bytes.length>LIMIT)throw Error('MIME exceeds 256 KiB');
 const raw=binary(bytes).replace(/\r?\n/g,'\r\n'),end=raw.indexOf('\r\n\r\n');
 if(end<0||end>32768)throw Error('Missing or oversized MIME headers');
 const headers=new Map();
 for(const line of raw.slice(0,end).replace(/\r\n[ \t]+/g,' ').split('\r\n')){
  const m=/^([!-9;-~]+):[ \t]*(.*)$/.exec(line);if(!m)throw Error('Malformed MIME header');
  const key=m[1].toLowerCase();if(headers.has(key)&&['content-type','content-transfer-encoding','from','to'].includes(key))throw Error('Ambiguous MIME header');headers.set(key,m[2]);
 }
 const ct=headers.get('content-type')||'text/plain',type=ct.split(';')[0].trim().toLowerCase();
 const param=name=>{const matches=[...ct.matchAll(new RegExp(';\\s*'+name+'\\s*=\\s*(?:"([^"\\r\\n]*)"|([^;\\s]+))','gi'))];if(matches.length>1)throw Error('Duplicate MIME parameter');return matches[0]?(matches[0][1]??matches[0][2]):'';};
 return {raw,headers,type,param,body:raw.slice(end+4)};
}
function parts(e){
 const boundary=e.param('boundary');if(!boundary||boundary.length>70||!/^[\x20-\x7e]+$/.test(boundary))throw Error('Invalid MIME boundary');
 const escaped=boundary.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
 const matches=[...e.body.matchAll(new RegExp('(?:^|\\r\\n)--'+escaped+'(--)?[ \\t]*(?:\\r\\n|$)','g'))];
 if(matches.length<2||matches.length>64||matches[0][1]||!matches.at(-1)[1]||matches.slice(0,-1).some(m=>m[1]))throw Error('Ambiguous MIME framing');
 return matches.slice(0,-1).map((m,i)=>octets(e.body.slice(m.index+m[0].length,matches[i+1].index)));
}
function decoded(e){
 const enc=(e.headers.get('content-transfer-encoding')||'7bit').toLowerCase();
 if(enc==='base64')return bytes64(e.body.replace(/\s/g,''));
 if(['7bit','8bit','binary'].includes(enc))return octets(e.body);
 if(enc==='quoted-printable')return octets(e.body.replace(/=\r\n/g,'').replace(/=([0-9a-f]{2})/gi,(_,h)=>String.fromCharCode(parseInt(h,16))));
 throw Error('Unsupported transfer encoding');
}
export function envelope(bytes){
 const e=entity(bytes);
 if(e.type==='multipart/signed'){
  if(e.param('protocol').toLowerCase()!=='application/pgp-signature')return {kind:'unsupported'};
  const p=parts(e);if(p.length!==2)throw Error('Malformed signed envelope');const sig=entity(p[1]);if(sig.type!=='application/pgp-signature')throw Error('Missing signature');
  return {kind:'signed',payload:p[0],signature:decoded(sig)};
 }
 if(['multipart/encrypted','multipart/mixed'].includes(e.type)){
  const p=parts(e).map(entity),controls=p.filter(x=>x.type==='application/pgp-encrypted');
  if(e.type==='multipart/encrypted'||controls.length){
   if(p.length!==2||controls.length!==1||binary(decoded(controls[0])).trim()!=='Version: 1')throw Error('Malformed encrypted envelope');
   const cipher=p.find(x=>x!==controls[0]);
   if(e.type==='multipart/encrypted'){
    if(p[0]!==controls[0]||cipher.type!=='application/octet-stream'||e.param('protocol').toLowerCase()!=='application/pgp-encrypted')throw Error('Unsupported encrypted envelope');
   }else{
    if(cipher.type==='application/octet-stream'&&(cipher.headers.get('content-transfer-encoding')||'').trim().toLowerCase()==='base64'){
     // Gmail also rewrites the root of binary/base64 PGP/MIME to mixed. Only
     // this exact two-leaf octet-stream shape admits binary content: never
     // reinterpret arbitrary text/plain, nested MIME or extra attachments.
     // Remove MIME whitespace from the encoded representation, require normal
     // padding and zero unused pad bits, then preserve every decoded octet.
     // Trimming binary ciphertext would corrupt a trailing space/tab/newline.
     const encoded=cipher.body.replace(/[ \t\r\n]/g,'');
     if(!encoded||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))throw Error('Invalid rewritten ciphertext base64');
     const data=bytes64(encoded);
     if(!data.length||data.length>LIMIT||b64(data)!==encoded)throw Error('Invalid rewritten ciphertext base64');
     // MIME shape never establishes authenticity. The existing native/WASM
     // path must still validate packets, AEAD, recipient, signature and trust.
     return {kind:'encrypted',cipher:data};
    }
    // Gmail may rewrite the root to mixed and the armored leaf to text/plain.
    // Accept only that exact two-leaf shape, never surrounding ordinary content.
    const armor=binary(decoded(cipher)).trim();
    if(!['text/plain','application/octet-stream'].includes(cipher.type)||!/^[\x00-\x7f]*$/.test(armor)||!armor.startsWith('-----BEGIN PGP MESSAGE-----\r\n')||!armor.endsWith('-----END PGP MESSAGE-----')||armor.split('-----BEGIN PGP MESSAGE-----').length!==2||armor.split('-----END PGP MESSAGE-----').length!==2)throw Error('Ambiguous rewritten encryption');
   }
   return {kind:'encrypted',cipher:decoded(cipher)};
  }
 }
 return {kind:'ordinary'};
}
export async function parse(bytes){
 if(bytes.length>LIMIT)throw Error('MIME exceeds 256 KiB');
 return PostalMime.parse(bytes,{attachmentEncoding:'base64',maxNestingDepth:16,maxHeadersSize:32768,maxPartCount:64,forceRfc822Attachments:true});
}
function display(mail){
 let budget=131072,omitted=0;const attachments=[];
 for(const a of mail.attachments||[]){const data=bytes64(a.content);if(data.length>budget||attachments.length===10){omitted++;continue;}budget-=data.length;attachments.push({name:(a.filename||'attachment.bin').replace(/.*[/\\]/,'').replace(/[\x00-\x1f\x7f]/g,'_').slice(0,150),size:data.length,data:a.content});}
 return {subject:(mail.subject||'(No subject)').slice(0,1000),sender:mail.from?.address||'',text:(mail.text||'').slice(0,32768),html:(mail.html||'').slice(0,32768),attachments,omittedAttachments:omitted};
}
export async function readMessage(packet,material,verify){
 const raw=bytes64(packet.raw),outer=await parse(raw);
 let shape=packet.encrypted?{kind:'signed',payload:raw,signature:bytes64(packet.signature)}:envelope(raw);
 if(shape.kind==='encrypted')return {encrypted:true,cipher:b64(shape.cipher)};
 const content=shape.kind==='signed'?await parse(shape.payload):outer;
 const result={...display(content),subject:outer.subject||'(No subject)',sender:outer.from?.address||'',encrypted:!!packet.encrypted,verified:false,signatureStatus:shape.kind==='unsupported'?'unsupported':'not-signed',certificateTrust:'not-applicable',signatures:[],certificateActions:[],notice:'Outer email headers are not authenticated. Attached certificates are never saved or trusted automatically.'};
 if(shape.kind!=='signed'){if(/multipart\/signed|BEGIN PGP SIGNED MESSAGE/i.test(binary(raw)))result.signatureStatus='unsupported';return result;}
 const certificates=[...material.certificates];let used=certificates.reduce((n,c)=>n+c.length,0);
 for(const a of content.attachments||[])if(a.mimeType==='application/pgp-keys'&&certificates.length<32&&used+a.content.length<=280000){certificates.push(a.content);used+=a.content.length;}
 // LibrePGP v5 inline signatures bind literal metadata separately from the
 // payload. Never try the detached transcript after inline verification fails.
 const metadata=packet.encrypted&&packet.literalMetadata?{literalMetadata:packet.literalMetadata}:{};
 const {signatures}=await verify({payload:b64(shape.payload),signature:b64(shape.signature),certificates,...metadata});
 const fromHeaders=outer.headers.filter(h=>h.key.toLowerCase()==='from');
 const email=fromHeaders.length===1&&!/[;,]/.test(fromHeaders[0].value.replace(/"[^"]*"/g,''))?(outer.from?.address||'').toLowerCase():'';
 // A valid signature must carry the current self-certified sender mailbox on
 // the certificate actually used. An older saved same-primary binding cannot
 // bless an attached certificate whose mailbox was revoked or expired. Invalid
 // candidates retain only the separate non-authenticating saved-trust indicator.
 // Only a valid signature returns its canonical public certificate for an
 // explicit save/trust action. Invalid-signature candidates never carry it.
 for(const sig of signatures){sig.trusted=!!sig.fingerprint&&material.bindings.some(b=>b.fingerprint.toUpperCase()===sig.fingerprint&&b.email.toLowerCase()===email)&&(sig.status!=='valid'||(sig.emails||[]).some(e=>e.toLowerCase()===email));if(sig.status==='valid'&&sig.certificate)result.certificateActions.push({fingerprint:sig.fingerprint,email,canTrust:(sig.emails||[]).some(e=>e.toLowerCase()===email),saved:material.saved.includes(sig.fingerprint),trusted:sig.trusted,algorithm:sig.algorithm,certificate:sig.certificate});delete sig.certificate;delete sig.emails;}
 result.signatures=signatures;result.signatureStatus=signatures.every(s=>s.status==='valid')?'valid':signatures.some(s=>s.status==='invalid')?'invalid':'unknown-key';
 result.certificateTrust=signatures.every(s=>s.trusted)?'trusted':signatures.some(s=>!s.fingerprint)?'unknown':'untrusted';result.verified=result.signatureStatus==='valid';
 result.warning=result.signatureStatus==='invalid'?'WARNING: Invalid signature. This message may have been altered or forged. Saved certificate trust does not authenticate it.':
  (result.verified&&signatures.some(s=>s.pqSigning===false)?'WARNING: This valid signature uses a classical algorithm and is not post-quantum resistant.':'');
 if(packet.encrypted){
  // Encrypted messages must match the explicitly selected trusted peer and our
  // own recipient, not just an arbitrary cryptographically valid attachment.
  if(!result.verified||signatures.length!==1||signatures[0].fingerprint!==packet.expectedFingerprint||email!==packet.expectedEmail.toLowerCase()||(outer.to||[]).length!==1||outer.to[0].address?.toLowerCase()!==packet.recipient.toLowerCase()||!signatures[0].trusted)throw Error('Decrypted bundle failed sender, recipient, signature or trust checks');
  result.notice='Authenticated encryption; signature verified by baseline Sequoia WASM.';
 }
 return result;
}
// Compose both alternatives and attachments in the IWA. Base64 keeps arbitrary
// bytes and UTF-8 text out of MIME delimiters; random boundaries cannot collide.
export function composeMime({sender,recipient,subject,body,html,attachments}){
 const address=s=>{if(typeof s!=='string'||!/^[^\s<>@]+@[^\s<>@]+$/.test(s)||/[\r\n\x00-\x1f]/.test(s))throw Error('Invalid mailbox');return s;};
 address(sender);address(recipient);if(!subject||subject.length>500||/[\r\n\x00-\x1f]/.test(subject))throw Error('Invalid subject');
 if(!Array.isArray(attachments)||attachments.length>10)throw Error('Too many attachments');let total=0;
 const utf=s=>new TextEncoder().encode(s),encoded=s=>b64(utf(s)),lines=s=>s.match(/.{1,76}/g)?.join('\r\n')||'';
 // RFC 2047 encoded words stay below 75 characters without splitting UTF-8.
 const words=[];let word='';for(const c of subject){if(utf(word+c).length>42){words.push('=?UTF-8?B?'+encoded(word)+'?=');word='';}word+=c;}if(word)words.push('=?UTF-8?B?'+encoded(word)+'?=');
 const mix='sq-'+crypto.randomUUID(),alt='sq-'+crypto.randomUUID();
 const leaf=(type,data,extra='')=>'Content-Type: '+type+'\r\nContent-Transfer-Encoding: base64\r\n'+extra+'\r\n'+lines(data)+'\r\n';
 let content=html?'Content-Type: multipart/alternative; boundary="'+alt+'"\r\n\r\n--'+alt+'\r\n'+leaf('text/plain; charset=utf-8',encoded(body))+'\r\n--'+alt+'\r\n'+leaf('text/html; charset=utf-8',encoded(html))+'\r\n--'+alt+'--\r\n':leaf('text/plain; charset=utf-8',encoded(body));
 if(attachments.length){let mixed='Content-Type: multipart/mixed; boundary="'+mix+'"\r\n\r\n--'+mix+'\r\n'+content;
  for(const a of attachments){if(!a.name||a.name.length>150||/[\x00-\x1f\x7f/\\]/.test(a.name))throw Error('Invalid attachment name');total+=bytes64(a.data).length;if(total>131072)throw Error('Attachments exceed 128 KiB');mixed+='\r\n--'+mix+'\r\n'+leaf('application/octet-stream',a.data,"Content-Disposition: attachment; filename*=UTF-8''"+encodeURIComponent(a.name).replace(/'/g,'%27')+'\r\n');}content=mixed+'\r\n--'+mix+'--\r\n';}
 const raw=utf('From: '+sender+'\r\nTo: '+recipient+'\r\nSubject: '+words.join('\r\n ')+'\r\nMIME-Version: 1.0\r\n'+content);if(raw.length>LIMIT)throw Error('Encoded MIME exceeds 256 KiB');return b64(raw);
}
