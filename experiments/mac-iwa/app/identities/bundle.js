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
export async function parseCardBundle(snapshot,inspect){
 const live=validatePublicSnapshot(snapshot,{bundle:true});
 const verified=await inspect(live.bundle);
 const raw=Uint8Array.from(atob(live.bundle),c=>c.charCodeAt(0));
 const hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(b=>b.toString(16).padStart(2,'0')).join('');
 if(verified?.bundleHash!==hash)fail();
 return matchBundlePublicKeys(verified,live,{fromCard:true});
}
