// Own public identities are an inventory, not a source of native authority.
// This separate IndexedDB record cannot select a device, choose an executable,
// grant contact trust, or turn an imported certificate into a private key.
import {createIndexedDbStorage} from '../certificates/store.js';
import {matchBundlePublicKeys} from './bundle.js';

const FORMAT='sequoia-iwa-identities',VERSION=1,MAX_IDENTITIES=16,MAX_CERT_BYTES=262144,MAX_TOTAL_BYTES=1048576;
const SNAPSHOT='sequoia-iwa-identity-preview',REVIEW_TTL=10*60*1000;
const clone=value=>structuredClone(value),encoder=new TextEncoder();
const fail=message=>{throw Error(message);};
const object=value=>!!value&&typeof value==='object'&&!Array.isArray(value);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function keys(value,expected){
 if(!object(value)||Object.keys(value).sort().join('|')!==[...expected].sort().join('|'))fail('Invalid own-identity record');
}
function text(value,limit){
 if(typeof value!=='string'||!value.length||value.length>limit||/[\x00-\x1f\x7f]/.test(value))fail('Invalid own-identity text');
 return value;
}
function bytes(value){
 if(typeof value!=='string'||!value.length||value.length>349528||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))fail('Invalid public certificate encoding');
 let raw;try{raw=atob(value);}catch(_){fail('Invalid public certificate encoding');}
 if(btoa(raw)!==value||raw.length>MAX_CERT_BYTES)fail('Invalid public certificate encoding');
 return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
function digest(value){if(typeof value!=='string'||! /^[a-f0-9]{64}$/.test(value))fail('Invalid public identity digest');return value;}
function fingerprint(value){if(typeof value!=='string'||! /^(?:[A-F0-9]{40}|[A-F0-9]{64})$/.test(value))fail('Full public fingerprint required');return value;}
function email(value){
 if(typeof value!=='string'||value.length>320||! /^[^\s<>@,;\x00-\x1f\x7f]+@[^\s<>@,;\x00-\x1f\x7f]+$/.test(value))fail('Invalid certified email');
 return value.toLowerCase();
}
// Stable hashes detect accidental/stale metadata substitutions. They do not
// authenticate an imported bundle: the bundled WASM parser does that before
// producing a snapshot. Live hardware matching and private-operation native
// authorization remain separate from this public inventory.
function sorted(value){return Array.isArray(value)?value.map(sorted):object(value)?Object.fromEntries(Object.keys(value).sort().map(k=>[k,sorted(value[k])])):value;}
const hash=async value=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',value))].map(b=>b.toString(16).padStart(2,'0')).join('');
const sourceHash=async value=>hash(encoder.encode(JSON.stringify(sorted(value))));
function empty(){return {format:FORMAT,version:VERSION,revision:0,records:[]};}

/** Bound the public bundle review at the WASM/storage boundary.
 * Slot strings are display metadata only. Nothing in this module passes them
 * to a signer, decapsulator, command line, or hardware selection API.
 */
function bundle(value){
 keys(value,['format','version','source','serial','bundleHash','generation','certificates','slots','bundleSignatureVerified','liveKeysMatched','warnings']);
 if(value.format!==SNAPSHOT||value.version!==1||!['yubikey','file'].includes(value.source)||typeof value.serial!=='string'||! /^[1-9][0-9]{0,9}$/.test(value.serial)||Number(value.serial)>0xffffffff||!Number.isSafeInteger(value.generation)||(value.source==='yubikey'?value.generation<1:value.generation!==0)||value.bundleSignatureVerified!==true||typeof value.liveKeysMatched!=='boolean'||(value.source==='yubikey'&&!value.liveKeysMatched))fail('Unsupported verified identity snapshot');
 digest(value.bundleHash);
 if(!Array.isArray(value.certificates)||!value.certificates.length||value.certificates.length>8||!Array.isArray(value.slots)||!value.slots.length||value.slots.length>24||!Array.isArray(value.warnings)||value.warnings.length>16)fail('Identity snapshot limit exceeded');
 const labels=new Set();let size=0;
 for(const item of value.certificates){
  keys(item,['kind','label','certificate']);if(item.kind!=='openpgp')fail('Unsupported identity certificate type');
  text(item.label,100);if(labels.has(item.label))fail('Duplicate identity certificate label');labels.add(item.label);size+=bytes(item.certificate).length;
 }
 if(size>MAX_TOTAL_BYTES)fail('Public identity storage limit exceeded');
 const slots=new Set();
 for(const item of value.slots){
  keys(item,['role','slot','algorithm','publicKeySha256']);text(item.role,80);text(item.algorithm,80);digest(item.publicKeySha256);
  if(typeof item.slot!=='string'||! /^(?:9[acde]|8[2-9a-f]|9[0-5])$/.test(item.slot)||slots.has(item.slot))fail('Invalid or duplicate public slot mapping');slots.add(item.slot);
 }
 value.warnings.forEach(w=>text(w,500));return clone(value);
}
function source(value){
 if(value?.format===SNAPSHOT)return bundle(value);
 keys(value,['format','version','certificate']);
 if(value.format!=='sequoia-iwa-public-identity'||value.version!==1)fail('Unsupported public identity');
 bytes(value.certificate);return clone(value);
}
function validate(value){
 if(value===null)return empty();
 keys(value,['format','version','revision','records']);
 if(value.format!==FORMAT||value.version!==VERSION||!Number.isSafeInteger(value.revision)||value.revision<0||!Array.isArray(value.records)||value.records.length>MAX_IDENTITIES)fail('Unsupported own-identity store');
 let size=0;const ids=new Set();
 for(const record of value.records){
  keys(record,['id','source','sourceHash']);text(record.id,100);digest(record.sourceHash);
  if(ids.has(record.id))fail('Duplicate own identity');ids.add(record.id);
  const item=source(record.source);size+=item.certificates?item.certificates.reduce((n,c)=>n+bytes(c.certificate).length,0):bytes(item.certificate).length;
 }
 if(size>MAX_TOTAL_BYTES)fail('Public identity storage limit exceeded');return clone(value);
}

/** Public inventory plus a short-lived, explicit review/commit transaction.
 * Callers supply only the bundled WASM inspector. Staged reviews stay in memory
 * and are consumed once; their captured revision prevents another window from
 * silently replacing the state the user has just reviewed.
 */
export function createIdentityStore({inspect,storage=createIndexedDbStorage({name:'sequoia-iwa-identities'}),now=Date.now}={}){
 if(typeof inspect!=='function'||typeof storage?.read!=='function'||typeof storage?.compareAndSwap!=='function'||typeof now!=='function')fail('Identity inspector and storage required');
 const reviews=new Map(),load=async()=>validate(await storage.read());
 async function certificate(raw,label){
  bytes(raw);const info=await inspect(raw);
  keys(info,['certificate','fingerprint','version','algorithms','emails','hybridContact']);
  fingerprint(info.fingerprint);
  if(![4,6].includes(info.version)||info.fingerprint.length!==(info.version===4?40:64)||typeof info.hybridContact!=='boolean'||!Array.isArray(info.algorithms)||info.algorithms.length>32||!Array.isArray(info.emails)||info.emails.length>256)fail('Invalid public identity inspection');
  info.algorithms.forEach(a=>text(a,128));
  return {label,certificate:info.certificate,fingerprint:info.fingerprint,version:info.version,algorithms:clone(info.algorithms),emails:[...new Set(info.emails.map(email))].sort(),certificateHash:await hash(bytes(info.certificate))};
 }
 async function inspectSource(raw){
  const value=source(raw),certificates=[];
  for(const c of value.certificates||[{label:'Imported public certificate',certificate:value.certificate}])certificates.push(await certificate(c.certificate,c.label));
  // v4 hybrid/classical views deliberately share a primary fingerprint. Exact
  // packet hashes distinguish those views; repeated identical bytes are a bug
  // or ambiguous import and are rejected instead of inventing another role.
  if(new Set(certificates.map(c=>c.certificateHash)).size!==certificates.length)fail('Duplicate public certificate in identity');
  const hardware=value.format===SNAPSHOT;
  return {id:hardware?'yubikey:'+value.serial:'certificate:'+certificates[0].certificateHash,source:hardware?value.source:'certificate-file',serial:hardware?value.serial:null,generation:hardware?value.generation:null,bundleHash:hardware?value.bundleHash:null,certificates,slots:hardware?clone(value.slots):[],bundleSignatureVerified:hardware,liveKeysMatched:hardware&&value.liveKeysMatched,warnings:hardware?clone(value.warnings):[]};
 }
 async function inventory(state){
  const identities=[];
  for(const record of state.records){
   if(await sourceHash(record.source)!==record.sourceHash)fail('Saved identity integrity check failed');
   const identity=await inspectSource(record.source);if(identity.id!==record.id)fail('Saved identity identifier mismatch');identities.push(identity);
  }
  return {identities,revision:state.revision};
 }
 async function preview(raw,expectedRevision){
  const state=await load();
  // A hardware-match review starts from a particular saved record. Never
  // attach that old record to a newer revision after asynchronous inspection;
  // otherwise a removed/replaced identity could be resurrected by this review.
  if(expectedRevision!==undefined&&state.revision!==expectedRevision)fail('Own identities changed during hardware matching; review again');
  const value=source(raw),identity=await inspectSource(value),digest=await sourceHash(value),previous=state.records.find(r=>r.id===identity.id);
  // Canonicalize a standalone OpenPGP import so armor/line-ending variants do
  // not create duplicate identities. The verified bundle itself remains intact.
  if(value.format!==SNAPSHOT)value.certificate=identity.certificates[0].certificate;
  for(const [key,entry] of reviews)if(now()-entry.created>REVIEW_TTL)reviews.delete(key);
  if(reviews.size>=8)fail('Too many pending identity reviews; close and reopen this screen');
  const token=crypto.randomUUID(),review={token,revision:state.revision,identity,replacesExisting:!!previous,unchanged:!!previous&&previous.sourceHash===(value.format===SNAPSHOT?digest:await sourceHash(value))};
  reviews.set(token,{created:now(),review:clone(review),source:value});return clone(review);
 }
 return {
  async previewCertificate(raw){return preview({format:'sequoia-iwa-public-identity',version:1,certificate:raw});},
  async previewBundle(raw){return preview(bundle(raw));},
  async previewLiveMatch(id,snapshot){
   // An offline file import can later gain public hardware evidence. Read and
   // integrity-check the stored record first; never accept a UI-supplied slot
   // map as the object whose hashes will be matched or persisted.
   const state=await load();await inventory(state);
   const record=state.records.find(r=>r.id===id);
   if(!record||record.source.format!==SNAPSHOT)fail('Select a signed certificate bundle first');
   return preview(matchBundlePublicKeys(record.source,snapshot),state.revision);
  },
  async list(){return inventory(await load());},
  cancel(review){if(typeof review?.token==='string')reviews.delete(review.token);},
  async save(review,confirmed){
   if(confirmed!==true)fail('Explicit identity review confirmation required');
   const entry=reviews.get(review?.token);reviews.delete(review?.token);
   if(!entry||now()-entry.created>REVIEW_TTL||!same(review,entry.review))fail('Identity review expired or changed; review again');
   const state=await load();if(state.revision!==review.revision)fail('Own identities changed in another window; review again');
   // Re-inspect before writing: a certificate expiring during the review must
   // not retain a misleading current email/algorithm presentation on commit.
   const identity=await inspectSource(entry.source);if(!same(identity,review.identity))fail('Public certificate policy changed; review again');
   const next=clone(state),record={id:identity.id,source:clone(entry.source),sourceHash:await sourceHash(entry.source)},index=next.records.findIndex(r=>r.id===record.id);
   if(index<0)next.records.push(record);else next.records[index]=record;
   next.revision++;validate(next);await storage.compareAndSwap(state.revision,next);return inventory(next);
  },
  async remove(id,confirmed,expectedRevision){
   if(confirmed!==true)fail('Explicit identity removal confirmation required');text(id,100);
   const state=await load();
   // Bind removal to the inventory displayed in its confirmation dialog. A
   // delayed BroadcastChannel notification must not let an old confirmation
   // delete a newer same-serial bundle saved by a different app window.
   if(!Number.isSafeInteger(expectedRevision)||expectedRevision<0||state.revision!==expectedRevision)fail('Own identities changed since removal review; review again');
   const next=clone(state);if(!next.records.some(r=>r.id===id))fail('Saved own identity no longer exists');
   next.records=next.records.filter(r=>r.id!==id);next.revision++;await storage.compareAndSwap(state.revision,next);return inventory(next);
  }
 };
}
