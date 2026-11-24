// The native public transport reports what it actually read from a card. WASM
// separately authenticates the compressed bundle and derives its expected key
// hashes. Joining those two results is evidence at import, never permission to
// sign or decrypt: the native private-operation path repeats its own checks.
const clone=value=>structuredClone(value);
const fail=()=>{throw Error('The signed bundle does not match the connected YubiKey public keys. No PIN was requested.');};
const exact=(value,fields)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join('|')===[...fields].sort().join('|');
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const serial=value=>typeof value==='string'&&/^[1-9][0-9]{0,9}$/.test(value)&&Number(value)<=0x7fffffff;
const SLOTS=['9a','9c','9d','9e',...Array.from({length:20},(_,i)=>(0x82+i).toString(16))];

/** Validate a complete fixed-slot snapshot; missing entries are not empty slots.
 * A null hash means that the native public reader positively found no key.
 * Require all 24 slots and reject duplicate/unknown entries so partial reads
 * cannot be mistaken for evidence that every manifest component was checked.
 */
export function validatePublicSnapshot(value,{bundle=false}={}){
 const fields=['format','version','serial','slots','warnings',...(bundle?['bundle','generation']:[])];
 if(!exact(value,fields)||value.format!=='sequoia-iwa-public-snapshot'||value.version!==1||!serial(value.serial)||!Array.isArray(value.slots)||value.slots.length!==SLOTS.length||!Array.isArray(value.warnings)||value.warnings.length>16)fail();
 if(value.warnings.some(w=>typeof w!=='string'||!w.length||w.length>500||/[\x00-\x1f\x7f]/.test(w)))fail();
 const seen=new Set();
 for(const entry of value.slots){
  if(!exact(entry,['slot','publicKeySha256'])||!SLOTS.includes(entry.slot)||seen.has(entry.slot)||(entry.publicKeySha256!==null&&!digest(entry.publicKeySha256)))fail();
  seen.add(entry.slot);
 }
 if(bundle){
  if(!Number.isSafeInteger(value.generation)||value.generation<1||typeof value.bundle!=='string'||!value.bundle.length||value.bundle.length>87384)fail();
  let decoded;try{decoded=atob(value.bundle);}catch(_){fail();}
  if(btoa(decoded)!==value.bundle||decoded.length>65536||!decoded.startsWith('PQMZIP01'))fail();
 }
 return clone(value);
}

/** Match every signed component, including certification/compatibility keys.
 * The caller must obtain `verified` from the bundled WASM inspector, or an
 * integrity-checked store entry created by that inspector. Browser metadata
 * never becomes native slot authority and cannot choose an executable path.
 */
export function matchBundlePublicKeys(verified,snapshot,{fromCard=false}={}){
 const live=validatePublicSnapshot(snapshot,{bundle:fromCard});
 if(verified?.format!=='sequoia-iwa-identity-preview'||verified.version!==1||verified.bundleSignatureVerified!==true||!digest(verified.bundleHash)||verified.serial!==live.serial||!Array.isArray(verified.slots)||!verified.slots.length)fail();
 const expected=new Set();
 for(const entry of verified.slots){
  if(!SLOTS.includes(entry.slot)||expected.has(entry.slot)||!digest(entry.publicKeySha256))fail();
  expected.add(entry.slot);
  if(live.slots.find(s=>s.slot===entry.slot)?.publicKeySha256!==entry.publicKeySha256)fail();
 }
 const result=clone(verified);
 result.liveKeysMatched=true;
 if(fromCard){result.source='yubikey';result.generation=live.generation;}
 // Replace the inspector's offline status once evidence has been collected;
 // retaining it verbatim would contradict the newly matched status. Other
 // format/recovery warnings remain visible and never disappear on matching.
 const offlineWarning='File freshness is not established; live public keys have not been checked.';
 result.warnings=[...new Set([...result.warnings.filter(w=>w!==offlineWarning),...live.warnings])];
 if(!fromCard)result.warnings.push('File freshness is not established; live public keys matched at import.');
 return result;
}

/** Keep the native frame checksum and WASM-authenticated content bound together.
 * Neither a filename nor a caller-supplied hash substitutes for hashing the
 * exact compressed bytes that were passed into the disposable WASM worker.
 */
export async function parseCardBundle(snapshot,inspect,{compatibilityCertificate}={}){
 const live=validatePublicSnapshot(snapshot,{bundle:true});
 const verified=await inspect(live.bundle,compatibilityCertificate?{compatibilityCertificate}:undefined);
 const raw=Uint8Array.from(atob(live.bundle),c=>c.charCodeAt(0));
 const hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(b=>b.toString(16).padStart(2,'0')).join('');
 if(verified?.bundleHash!==hash)fail();
 return matchBundlePublicKeys(verified,live,{fromCard:true});
}

/** Authenticate an encrypted companion without decrypting it or requesting a
 * PIN. The browser persists only ciphertext and its authenticated public view.
 * Its separate record keeps the ordinary card bundle's compatibility views.
 */
export async function parseCardCompanion(read,inspect){
 if(!read||read.format!=='sequoia-iwa-companion'||read.version!==1||!serial(String(read.serial))||typeof read.encoded!=='string'||!read.publicKeys||typeof read.certificate!=='string')fail();
 const descriptor={encoded:read.encoded,serial:Number(read.serial),publicKeys:clone(read.publicKeys),certificate:read.certificate};
 const verified=await inspect(descriptor);
 const raw=Uint8Array.from(atob(descriptor.encoded),c=>c.charCodeAt(0));
 const hash=async bytes=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
 if(verified?.format!=='sequoia-iwa-companion'||verified.version!==1||String(verified.serial)!==String(read.serial)||verified.companionHash!==await hash(raw)||!Array.isArray(verified.components)||!verified.wrapping)fail();
 // The authenticated public certificate becomes the exact selected view. It is
 // also the public cache needed by ultra-compact companions on the next host.
 descriptor.certificate=verified.certificate;
 const slots=new Map();
 for(const part of [...verified.components,{role:'companion wrapping',algorithm:'ECDH-P384',storage:'piv',slot:verified.wrapping.slot,publicKey:verified.wrapping.publicKey}]){
  if(part.storage!=='piv')continue;
  if(!SLOTS.includes(part.slot)||descriptor.publicKeys[part.slot]!==part.publicKey)fail();
  const publicKeySha256=await hash(Uint8Array.from(atob(part.publicKey),c=>c.charCodeAt(0)));
  const previous=slots.get(part.slot);
  if(previous&&previous.publicKeySha256!==publicKeySha256)fail();
  if(previous)previous.role+=' / '+part.role;
  else slots.set(part.slot,{role:part.role,slot:part.slot,algorithm:part.algorithm,publicKeySha256});
 }
 return {format:'sequoia-iwa-companion-preview',version:1,source:'yubikey',serial:String(verified.serial),bundleHash:verified.companionHash,generation:0,
  certificates:[{kind:'openpgp',label:'Encrypted companion · '+verified.profile,certificate:verified.certificate,profile:verified.profile,components:clone(verified.components)}],
  slots:[...slots.values()],bundleSignatureVerified:true,liveKeysMatched:true,
  warnings:['The hybrid algorithms protect messages; software companion components do not have hardware private-key isolation. Plaintext keys exist only during an operation in a disposable worker.'],companion:descriptor};
}
