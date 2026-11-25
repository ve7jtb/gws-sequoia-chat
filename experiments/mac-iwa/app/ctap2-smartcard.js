// Narrow CTAP2 client for the IWA's existing vault credentials. This is not a
// general WebAuthn broker: no reset, credential management,
// configuration, PIN changes, or arbitrary relying-party requests are exposed.
// Protocol references: FIDO CTAP2.2 NFC transport, PIN/UV protocol 2, hmac-secret;
// WebAuthn PRF hashes "WebAuthn PRF\0" plus the caller's input before CTAP.
const te=new TextEncoder(),td=new TextDecoder('utf-8',{fatal:true});
const cat=(...xs)=>{const b=new Uint8Array(xs.reduce((n,x)=>n+x.length,0));let o=0;for(const x of xs){b.set(x,o);o+=x.length;}return b;};
const random=n=>crypto.getRandomValues(new Uint8Array(n));
const hash=async b=>new Uint8Array(await crypto.subtle.digest('SHA-256',b));
const equal=(a,b)=>a instanceof Uint8Array&&b instanceof Uint8Array&&a.length===b.length&&a.every((v,i)=>v===b[i]);
const map=(...pairs)=>new Map(pairs);
export const extensionRp=()=>`chrome-extension://${typeof EXTENSION_ID==='string'?EXTENSION_ID:'bfofmobbkplpofnjjlcikmamjngbmcpp'}`;
// New direct CTAP credentials use the complete signed IWA origin as RP scope.
// It is stable across updates signed by the same publisher key. Legacy wrappers
// keep their explicit original RP; changing their RP would change the credential.
export function packageRp(){const id=globalThis.IWA_BUNDLE_ID;if(typeof id!=='string'||! /^[a-z2-7]{56}$/.test(id))throw Error('Missing signed IWA package ID');return 'isolated-app://'+id;}
export function checkRp(rp){if(![packageRp(),packageRp().slice('isolated-app://'.length),extensionRp(),'ve7jtb.github.io'].includes(rp))throw Error('Unsupported vault RP ID.');return rp;}

// A bounded definite-length CBOR codec. Maps stay Maps so integer COSE/CTAP
// keys cannot collide with strings or JavaScript prototype properties.
export function encode(v){
 const head=(m,n)=>n<24?new Uint8Array([m*32+n]):n<256?new Uint8Array([m*32+24,n]):n<65536?new Uint8Array([m*32+25,n>>8,n&255]):n<=0xffffffff?new Uint8Array([m*32+26,n>>>24,n>>>16&255,n>>>8&255,n&255]):(()=>{throw Error('CBOR value too large');})();
 if(Number.isSafeInteger(v))return head(v<0?1:0,v<0?-1-v:v);
 if(v===true||v===false)return new Uint8Array([v?245:244]);
 if(v instanceof Uint8Array)return cat(head(2,v.length),v);
 if(typeof v==='string'){const s=te.encode(v);return cat(head(3,s.length),s);}
 if(Array.isArray(v))return cat(head(4,v.length),...v.map(encode));
 if(v instanceof Map){const entries=[...v].map(([k,x])=>[encode(k),encode(x)]).sort((a,b)=>{if(a[0].length!==b[0].length)return a[0].length-b[0].length;for(let i=0;i<a[0].length;i++)if(a[0][i]!==b[0][i])return a[0][i]-b[0][i];return 0;});return cat(head(5,v.size),...entries.flat());}
 throw Error('Unsupported CBOR value');
}
export function decode(bytes, prefix=false){
 const b=new Uint8Array(bytes);let o=0,items=0;
 if(b.length>65536)throw Error('CBOR response too large');
 const take=n=>{if(o+n>b.length)throw Error('Truncated CBOR');const v=b.slice(o,o+n);o+=n;return v;};
 function read(depth=0){
  if(depth>12||++items>2048)throw Error('CBOR nesting/items exceeded');
  const h=take(1)[0],m=h>>5,a=h&31;
  if(m===7&&[20,21].includes(a))return a===21;
  let n=a;if(a>=24){if(![24,25,26,27].includes(a))throw Error('Indefinite CBOR not allowed');n=0;for(const x of take(2**(a-24)))n=n*256+x;if(!Number.isSafeInteger(n))throw Error('Unsafe CBOR integer');}
  if(m===0)return n;if(m===1)return -1-n;
  if(m===2)return take(n);if(m===3)return td.decode(take(n));
  if(n>1024)throw Error('CBOR collection too large');
  if(m===4)return Array.from({length:n},()=>read(depth+1));
  if(m===5){const out=new Map();for(let i=0;i<n;i++){const k=read(depth+1);if(!['number','string'].includes(typeof k)||out.has(k))throw Error('Duplicate/invalid CBOR key');out.set(k,read(depth+1));}return out;}
  throw Error('Unsupported CBOR type');
 }
 const value=read();if(prefix)return {value,length:o};if(o!==b.length)throw Error('Trailing CBOR');return value;
}

// ISO7816 command/response chaining is separate from CTAP keepalive (9100).
// Each continuation is bounded; a PIN failure is never retried or sent to a
// second reader. The underlying PIV selector checks serial in the transaction.
export async function exchange(conn,cla,ins,p1,data=new Uint8Array(),{signal,progress=()=>{}}={}){
 const deadline=Date.now()+90000;let total=0;
 const guard=()=>{if(signal?.aborted||Date.now()>deadline)throw Error('FIDO operation cancelled or timed out. No retry.');};
 async function tx(a){guard();const b=new Uint8Array(await conn.transmit(a));guard();if(b.length<2)throw Error('Truncated FIDO APDU');return {data:b.slice(0,-2),sw:b.at(-2)*256+b.at(-1)};}
 let off=0;
 while(data.length-off>250){const r=await tx(cat(new Uint8Array([cla|16,ins,p1,0,250]),data.slice(off,off+250)));if(r.sw!==0x9000||r.data.length)throw Error('FIDO command chaining rejected');off+=250;}
 const tail=data.slice(off);let r=await tx(cat(new Uint8Array([cla,ins,p1,0]),tail.length?cat(new Uint8Array([tail.length]),tail):new Uint8Array(),new Uint8Array([0]))),parts=[];
 for(let i=0;i<1024;i++){
  total+=r.data.length;if(total>65536)throw Error('FIDO response too large');
  if(r.sw===0x9100){progress(r.data[0]===2?'Touch the YubiKey to authorize FIDO vault access.':'YubiKey is processing the FIDO request…');await new Promise(resolve=>setTimeout(resolve,100));r=await tx(new Uint8Array([0x80,0x11,0,0,0]));continue;}
  parts.push(r.data);if((r.sw>>8)===0x61){r=await tx(new Uint8Array([0,0xc0,0,0,r.sw&255]));continue;}
  if(r.sw!==0x9000)throw Error(`FIDO APDU failed: SW=${r.sw.toString(16)}. No retry.`);
  return cat(...parts);
 }
 throw Error('FIDO continuation limit reached');
}
const CREATE_AUTHORITY=Symbol("explicit package-scoped credential creation");
const statusNames={0x2e:'No matching credential for this RP ID',0x31:'Incorrect FIDO PIN',0x32:'FIDO PIN blocked',0x34:'FIDO PIN temporarily blocked',0x2f:'User presence timed out',0x27:'Operation denied',0x36:'FIDO PIN required'};
export async function command(conn,cmd,args,options){
 // Enforce the narrow command set even if a future UI caller is compromised.
 if((![2,4,6].includes(cmd)&&!(cmd===1&&options?.creationAuthority===CREATE_AUTHORITY))||cmd===6&&![1,2,9].includes(args?.get(2)))throw Error('Forbidden CTAP command');
 const response=await exchange(conn,0x80,0x10,0x80,cat(new Uint8Array([cmd]),args?encode(args):new Uint8Array()),options);
 if(!response.length)throw Error('Missing CTAP status');
 if(response[0]){const error=Error((statusNames[response[0]]||`CTAP status 0x${response[0].toString(16)}`)+'. No automatic retry.');error.ctapStatus=response[0];throw error;}
 const value=decode(response.slice(1));if(!(value instanceof Map))throw Error('Expected CTAP response map');return value;
}
export async function session(serial,fn,{piv=globalThis.SequoiaSmartCardPiv,...options}={}){
 if(!/^[1-9][0-9]{0,9}$/.test(String(serial)))throw Error('Enter the expected YubiKey serial before FIDO access.');
 return piv.withPivSession(String(serial),async(conn,info)=>{
  const version=await exchange(conn,0,0xa4,4,new Uint8Array([0xa0,0,0,6,0x47,0x2f,0,1]),options);
  if(!['U2F_V2','FIDO_2_0'].includes(td.decode(version)))throw Error('Unexpected FIDO applet response');
  const getInfo=await command(conn,4,undefined,options);
  return fn(conn,getInfo,info);
 });
}
export async function getInfo(serial,options={}){
 return session(serial,async(conn,info,device)=>{
  const protocols=info.get(6)||[];
  const retries=protocols.includes(2)?(await command(conn,6,map([1,2],[2,1]),options)).get(3):null;
  return {serial:device.serial,reader:device.reader,versions:info.get(1),extensions:info.get(2),options:Object.fromEntries(info.get(4)||[]),pinUvProtocols:protocols,pinRetries:retries};
 },options);
}

// WebCrypto CBC includes PKCS#7, whereas CTAP encrypts aligned blocks without
// padding. Encryption drops its extra padding block. Decryption appends a
// correctly encrypted full padding block, then lets WebCrypto remove only it.
export async function rawCbc(key,iv,data,decrypt=false){
 if(!data.length||data.length%16||iv.length!==16)throw Error('Invalid CTAP CBC length');
 const k=await crypto.subtle.importKey('raw',key,'AES-CBC',false,['encrypt','decrypt']);
 if(!decrypt)return new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC',iv},k,data)).slice(0,data.length);
 const padding=new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC',iv:data.slice(-16)},k,new Uint8Array(16).fill(16))).slice(0,16);
 return new Uint8Array(await crypto.subtle.decrypt({name:'AES-CBC',iv},k,cat(data,padding)));
}
const mac=async(key,data)=>new Uint8Array(await crypto.subtle.sign('HMAC',await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']),data));
export const prfSalt=input=>hash(cat(te.encode('WebAuthn PRF\0'),input));
async function agreement(peer){
 if(!(peer instanceof Map)||peer.get(1)!==2||peer.get(-1)!==1||peer.get(-2)?.length!==32||peer.get(-3)?.length!==32)throw Error('Invalid authenticator ECDH key');
 const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const pub=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey));
 const remote=await crypto.subtle.importKey('raw',cat(new Uint8Array([4]),peer.get(-2),peer.get(-3)),{name:'ECDH',namedCurve:'P-256'},false,[]);
 const z=new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:remote},pair.privateKey,256));
 try{
  const base=await crypto.subtle.importKey('raw',z,'HKDF',false,['deriveBits']);
  const derive=async label=>new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(32),info:te.encode(label)},base,256));
  return {publicKey:map([1,2],[3,-25],[-1,1],[-2,pub.slice(1,33)],[-3,pub.slice(33)]),hmac:await derive('CTAP2 HMAC key'),aes:await derive('CTAP2 AES key')};
 }finally{z.fill(0);}
}
const encrypt=async(k,data)=>{const iv=random(16);return cat(iv,await rawCbc(k.aes,iv,data));};
const decrypt=async(k,data)=>{if(!(data instanceof Uint8Array)||data.length<32)throw Error('Invalid encrypted CTAP response');return rawCbc(k.aes,data.slice(0,16),data.slice(16),true);};

// The authenticated vault envelope is the final proof that PRF matched. This
// method is not advertised as verification of arbitrary WebAuthn assertions.
// Existing wrappers keep their original binding bytes (HKDF/AAD depends on them).
export function evaluate(input,promptPin,options={}){return operate(input,promptPin,options);}
// Creation is a distinct opt-in entry point. It can target only this signed
// package RP, never legacy scopes, and requires a new random user handle.
export function createCredential(input,promptPin,options={}){
 if(input.rpId!==packageRp()||input.credentialId)throw Error('Creation requires this IWA package RP');
 if(!(input.userId instanceof Uint8Array)||input.userId.length!==32||typeof input.name!=='string'||!input.name.trim()||input.name.length>80)throw Error('Invalid new credential identity');
 return operate(input,promptPin,{...options,creationAuthority:CREATE_AUTHORITY});
}
// Separate test credentials are never reused as vault credentials. The caller
// persists only the public descriptor and opaque authenticator key handle.
export function createPreviewSign(input,promptPin,options={}){
 if(input.rpId!==packageRp()||input.userId?.length!==32)throw Error('Invalid previewSign test scope');
 return operate({...input,salt:new Uint8Array(32)},promptPin,{...options,creationAuthority:CREATE_AUTHORITY,previewMode:'create'});
}
export function signPreview(input,promptPin,options={}){
 if(input.rpId!==packageRp()||!input.credentialId?.length||!input.preview?.keyHandle?.length||input.preview?.digest?.length!==32)throw Error('Invalid previewSign test inputs');
 return operate({...input,salt:new Uint8Array(32)},promptPin,{...options,previewMode:'sign'});
}
export function attestedKey(auth){
 if(!(auth instanceof Uint8Array)||auth.length<56||!(auth[32]&0x40))throw Error('Missing attested key');
 const n=auth[53]*256+auth[54];if(!n||n>4096||auth.length<=55+n)throw Error('Invalid attested key length');
 const key=decode(auth.slice(55+n),true);return {id:auth.slice(55,55+n),key:key.value,end:55+n+key.length};
}
async function operate({serial,rpId,credentialId,salt,userId,name,preview},promptPin,options={}){
 const creating=options.creationAuthority===CREATE_AUTHORITY;
 checkRp(rpId);
 if(!(salt instanceof Uint8Array)||salt.length!==32||credentialId&&(!(credentialId instanceof Uint8Array)||credentialId.length>1024))throw Error('Invalid vault PRF input');
 return session(serial,async(conn,info)=>{
  if(options.previewMode&&!(info.get(2)||[]).includes('previewSign'))throw Error('This key does not advertise previewSign.');
  if(!(info.get(6)||[]).includes(2)||!(info.get(2)||[]).includes('hmac-secret')||info.get(4)?.get('pinUvAuthToken')!==true||info.get(4)?.get('clientPin')!==true)throw Error('Requires hmac-secret and configured FIDO PIN with PIN/UV protocol 2.');
  if(creating&&!options.previewMode&&(!(info.get(2)||[]).includes('hmac-secret-mc')||info.get(4)?.get('rk')!==true))throw Error('Creation requires discoverable credentials and hmac-secret-mc; no credential was created.');
  const retries=(await command(conn,6,map([1,2],[2,1]),options)).get(3);
  if(!Number.isInteger(retries)||retries<1)throw Error('FIDO PIN unavailable or blocked.');
  let k,token,pinBytes,pinHash,secret;
  try{
   const peer=(await command(conn,6,map([1,2],[2,2]),options)).get(1);k=await agreement(peer);
   let pin=await promptPin({serial,rpId,retries});
   if(options.signal?.aborted)throw Error('FIDO operation cancelled before PIN submission');
   pinBytes=te.encode(pin.normalize('NFC'));pin='';
   if(pinBytes.length<4||pinBytes.length>63||pinBytes.includes(0))throw Error('FIDO PIN must encode to 4–63 UTF-8 bytes.');
   pinHash=(await hash(pinBytes)).slice(0,16);pinBytes.fill(0);
   // Scope this transient token to exactly one operation and this RP. No legacy
   // broad PIN token and no credential-management permissions are requested.
   const t=await command(conn,6,map([1,2],[2,9],[3,k.publicKey],[6,await encrypt(k,pinHash)],[9,creating?1:2],[10,rpId]),options);
   token=await decrypt(k,t.get(2));if(token.length!==32)throw Error('Invalid PIN/UV token');
   const clientHash=random(32),saltEnc=await encrypt(k,await prfSalt(salt));
   const hmacInput=map([1,k.publicKey],[2,saltEnc],[3,await mac(k.hmac,saltEnc)],[4,2]);
   const authParam=await mac(token,clientHash);
   let auth,id,ext;
   if(creating){
    // Random userId prevents replacement of another instance's discoverable
    // credential. PRF evaluation at creation avoids an extra assertion/touch.
    const args=map([1,clientHash],[2,map(['id',rpId],['name','Sequoia IWA vault'])],[3,map(['id',userId],['name',name],['displayName',name])],[4,[map(['type','public-key'],['alg',-7])]],[6,map(['hmac-secret',true],['hmac-secret-mc',hmacInput])],[7,map(['rk',true])],[8,authParam],[9,2]);
    if(options.previewMode){args.set(6,map(['previewSign',map([3,[-65539]],[4,5])]));args.set(7,map(['rk',false]));}
    options.progress?.(options.previewMode?'Touch the YubiKey to create the separate previewSign test credential.':'Touch the YubiKey to create ONE discoverable package-scoped PRF credential.');
    await options.beforeCreate?.();
    const a=await command(conn,1,args,options);auth=a.get(2);
    if(!(auth instanceof Uint8Array)||auth.length<56||(auth[32]&0xc5)!==0xc5||!equal(auth.slice(0,32),await hash(te.encode(rpId))))throw Error('Invalid creation response; do not repeat creation.');
    const n=auth[53]*256+auth[54];if(!n||n>1024||auth.length<55+n)throw Error('Invalid new credential ID; do not repeat creation.');
    id=auth.slice(55,55+n);
    // Persist the public recovery descriptor before further parsing. A later
    // failure can evaluate this exact credential, never create another one.
    await options.created?.(id);
    const publicKey=decode(auth.slice(55+n),true);
    if(!(publicKey.value instanceof Map)||publicKey.value.get(-2)?.length!==32||publicKey.value.get(-3)?.length!==32||publicKey.value.get(1)!==2||publicKey.value.get(3)!==-7||publicKey.value.get(-1)!==1)throw Error('Unexpected new credential algorithm');
    ext=decode(auth.slice(55+n+publicKey.length));
    if(options.previewMode){
     if(ext.get('previewSign')?.get(3)!==-65539)throw Error('Unexpected previewSign algorithm');
     const inner=decode(a.get(6)?.get('previewSign')?.get(7));
     const signing=attestedKey(inner.get(2));
     return {credentialId:id,credentialKey:publicKey.value,keyHandle:signing.id,publicKey:signing.key};
    }
    if(ext.get('hmac-secret')!==true)throw Error('Authenticator did not enable hmac-secret');
    secret=await decrypt(k,ext.get('hmac-secret-mc'));
   }else{
    const args=map([1,rpId],[2,clientHash],[4,map(['hmac-secret',hmacInput])],[5,map(['up',true])],[6,authParam],[7,2]);
    if(options.previewMode)args.set(4,map(['previewSign',map([2,preview.keyHandle],[6,preview.digest],[7,preview.args])]));
    if(credentialId?.length)args.set(3,[map(['type','public-key'],['id',credentialId])]);
    options.progress?.('Touch the YubiKey for FIDO user presence.');
    const a=await command(conn,2,args,options);auth=a.get(2);id=a.get(1)?.get('id');
    if((a.get(5)||1)!==1)throw Error('Multiple existing credentials match. Import the vault backup with its enrolled credential ID; no credential was created.');
    if(!(id instanceof Uint8Array)||!id.length||credentialId?.length&&!equal(id,credentialId))throw Error('Unexpected FIDO credential');
    if(!(auth instanceof Uint8Array)||auth.length<38||!equal(auth.slice(0,32),await hash(te.encode(rpId)))||(auth[32]&0xc5)!==0x85)throw Error('Invalid RP binding, user verification/presence, or extension flags');
    if(!(a.get(3) instanceof Uint8Array)||!a.get(3).length)throw Error('Missing assertion signature');
    ext=decode(auth.slice(37));if(options.previewMode){const signature=ext.get('previewSign')?.get(6);if(!(signature instanceof Uint8Array)||!signature.length)throw Error('Missing previewSign signature');return {signature,authData:auth,assertionSignature:a.get(3),clientHash};}secret=await decrypt(k,ext.get('hmac-secret'));
   }
   if(secret.length!==32)throw Error('Invalid PRF result length');
   if(options.signal?.aborted)throw Error('FIDO result cancelled');
   const result={credentialId:id,secret};secret=null;return result;
  }finally{pinBytes?.fill(0);pinHash?.fill(0);token?.fill(0);k?.hmac.fill(0);k?.aes.fill(0);secret?.fill(0);}
 },options);
}
