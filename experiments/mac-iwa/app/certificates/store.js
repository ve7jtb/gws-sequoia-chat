// Public certificates and explicit email/full-fingerprint trust belong to this
// signed IWA origin. IndexedDB contains no signing secrets, PINs or OAuth tokens.
// The inspector is the bundled Sequoia WASM policy engine, not a native service.
const FORMAT='sequoia-iwa-certificates',VERSION=1,MAX_CERTS=24,MAX_BYTES=200000,MAX_BINDINGS=256;
const clone=value=>structuredClone(value), encoder=new TextEncoder();
const fail=message=>{throw Error(message);};
const object=value=>!!value&&typeof value==='object'&&!Array.isArray(value);
function keys(value,expected) {
 if(!object(value)||Object.keys(value).sort().join('|')!==[...expected].sort().join('|'))fail('Invalid certificate-store record');
}
function fingerprint(value) {
 if(typeof value!=='string'||! /^(?:[A-F0-9]{40}|[A-F0-9]{64})$/.test(value))fail('Full primary fingerprint required');
 return value;
}
function email(value) {
 if(typeof value!=='string'||value.length>320||! /^[^\s<>@,;\x00-\x1f\x7f]+@[^\s<>@,;\x00-\x1f\x7f]+$/.test(value))fail('One valid email address required');
 return value.toLowerCase();
}
function bytes(value) {
 if(typeof value!=='string'||!value.length||value.length>349528||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))fail('Invalid certificate encoding');
 let decoded;try{decoded=atob(value);}catch(_){fail('Invalid certificate encoding');}
 if(btoa(decoded)!==value||decoded.length>262144)fail('Invalid certificate encoding');
 return Uint8Array.from(decoded,c=>c.charCodeAt(0));
}
const hash=async value=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',value))].map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
const idFor=async(address,fp)=>hash(encoder.encode(address+fp));
// Native migration uses sorted UTF-8 JSON (ensure_ascii=False). Recompute the
// snapshot checksum before presenting/committing a migration, rather than using
// an arbitrary source label as an idempotency marker. This is corruption/replay
// binding, not authentication of native data or a replacement for user review.
function sorted(value){return Array.isArray(value)?value.map(sorted):object(value)?Object.fromEntries(Object.keys(value).sort().map(k=>[k,sorted(value[k])])):value;}
export async function migrationDigest(snapshot){
 const {sourceDigest,...body}=snapshot;
 return (await hash(encoder.encode(JSON.stringify(sorted(body))))).toLowerCase();
}
function empty(){return {format:FORMAT,version:VERSION,revision:0,records:[],migration:null};}
function validate(value) {
 if(value===null)return empty();
 keys(value,['format','version','revision','records','migration']);
 if(value.format!==FORMAT||value.version!==VERSION||!Number.isSafeInteger(value.revision)||value.revision<0||!Array.isArray(value.records)||value.records.length>MAX_CERTS)fail('Unsupported certificate store');
 if(value.migration!==null){keys(value.migration,['sourceDigest']);if(! /^[a-f0-9]{64}$/.test(value.migration.sourceDigest))fail('Invalid migration marker');}
 let total=0,bindings=0;const seen=new Set();
 for(const record of value.records){
  keys(record,['fingerprint','certificate','certificateHash','trustedEmails']);
  fingerprint(record.fingerprint);if(seen.has(record.fingerprint))fail('Duplicate certificate');seen.add(record.fingerprint);
  total+=bytes(record.certificate).length;
  if(typeof record.certificateHash!=='string'||! /^[A-F0-9]{64}$/.test(record.certificateHash)||!Array.isArray(record.trustedEmails))fail('Invalid certificate record');
  const addresses=new Set();for(const address of record.trustedEmails){if(email(address)!==address||addresses.has(address))fail('Invalid trust binding');addresses.add(address);bindings++;}
 }
 if(total>MAX_BYTES||bindings>MAX_BINDINGS)fail('Certificate or trust storage limit exceeded');
 return clone(value);
}

/** A tiny injectable backend makes races/failures testable without a browser. */
export function createMemoryStorage(initial=null) {
 let value=initial===null?null:clone(initial);
 return {
  async read(){return value===null?null:clone(value);},
  async compareAndSwap(expected,next){
   if((value?.revision||0)!==expected)fail('Certificate store changed in another window; review again.');
   value=clone(next);
  }
 };
}

/** Store one versioned record in one read/write transaction.
 * All WASM parsing and hashing completes before opening a transaction. No await
 * may let IndexedDB commit between checking the revision and writing the record.
 * A stale window gets an error; it never overwrites another window's trust.
 */
export function createIndexedDbStorage({indexedDB:factory=globalThis.indexedDB,name='sequoia-iwa-certificates'}={}) {
 if(!factory)fail('IndexedDB is required for certificate storage');
 const database=()=>new Promise((resolve,reject)=>{
  const request=factory.open(name,1);
  request.onupgradeneeded=()=>{if(!request.result.objectStoreNames.contains('state'))request.result.createObjectStore('state');};
  request.onerror=()=>reject(Error('Cannot open certificate storage'));
  request.onblocked=()=>reject(Error('Close another IWA window to upgrade certificate storage'));
  request.onsuccess=()=>{const db=request.result;db.onversionchange=()=>db.close();resolve(db);};
 });
 return {
  async read(){
   const db=await database();
   try{return await new Promise((resolve,reject)=>{
    const tx=db.transaction('state','readonly'),request=tx.objectStore('state').get('current');let value=null;
    request.onsuccess=()=>{value=request.result??null;};
    tx.oncomplete=()=>resolve(value);tx.onerror=tx.onabort=()=>reject(Error('Cannot read certificate storage'));
   });}finally{db.close();}
  },
  async compareAndSwap(expected,next){
   const copy=clone(next),db=await database();
   try{return await new Promise((resolve,reject)=>{
    const tx=db.transaction('state','readwrite'),store=tx.objectStore('state'),request=store.get('current');let conflict=false;
    request.onsuccess=()=>{
     if((request.result?.revision||0)!==expected){conflict=true;tx.abort();return;}
     store.put(copy,'current');
    };
    tx.oncomplete=()=>resolve();
    tx.onerror=tx.onabort=()=>reject(Error(conflict?'Certificate store changed in another window; review again.':'Certificate storage write failed; no changes committed.'));
   });}finally{db.close();}
  }
 };
}

export function createCertificateStore({inspect,storage=createIndexedDbStorage()}={}) {
 if(typeof inspect!=='function'||typeof storage?.read!=='function'||typeof storage?.compareAndSwap!=='function')fail('Certificate inspector and storage required');
 const load=async()=>validate(await storage.read());
 async function preview(certificate){
  bytes(certificate);
  // Treat even worker results as bounded data. The parser canonicalizes public
  // packets, and its current self-certified email list is the only trust source.
  const info=await inspect(certificate);
  keys(info,['certificate','fingerprint','version','algorithms','emails','hybridContact']);
  fingerprint(info.fingerprint);
  if(![4,6].includes(info.version)||info.fingerprint.length!==(info.version===4?40:64)||typeof info.hybridContact!=='boolean'||!Array.isArray(info.emails)||info.emails.length>256||!Array.isArray(info.algorithms)||info.algorithms.length>32||info.algorithms.some(a=>typeof a!=='string'||a.length>128))fail('Invalid certificate inspection');
  const addresses=[...new Set(info.emails.map(email))].sort();
  if(info.hybridContact&&(info.version!==6||!addresses.length))fail('Invalid hybrid contact');
  return {...clone(info),emails:addresses,certificateHash:await hash(bytes(info.certificate))};
 }
 async function inspected(state){
  const result=[];
  for(const record of state.records){
   const info=await preview(record.certificate);
   if(info.fingerprint!==record.fingerprint||info.certificateHash!==record.certificateHash||info.certificate!==record.certificate)fail('Saved certificate integrity check failed');
   result.push({record,info});
  }
  return result;
 }
 async function inventory(state){
  const certificates=[],contacts=[];
  for(const {record,info} of await inspected(state)){
   certificates.push({fingerprint:info.fingerprint,version:info.version,algorithms:info.algorithms,emails:info.emails,trustedEmails:[...record.trustedEmails],hybridContact:info.hybridContact});
   // Retain stale trust in the inventory for explicit removal, but never offer
   // an expired/revoked mailbox or unusable encryption key for a new operation.
   if(info.hybridContact)for(const address of record.trustedEmails.filter(e=>info.emails.includes(e))){
    contacts.push({id:await idFor(address,info.fingerprint),email:address,fingerprint:info.fingerprint,certificate:info.certificate,certificateHash:info.certificateHash,revision:state.revision});
   }
  }
  contacts.sort((a,b)=>a.email.localeCompare(b.email)||a.fingerprint.localeCompare(b.fingerprint));
  return {certificates,contacts,revision:state.revision,migration:clone(state.migration)};
 }
 async function commit(state,next){
  // Never retry a failed CAS automatically: the user reviewed a particular
  // certificate/trust state, not arbitrary changes made by a second window.
  next.revision=state.revision+1;validate(next);
  await storage.compareAndSwap(state.revision,next);
  return inventory(next);
 }
 function insert(state,info){
  let record=state.records.find(r=>r.fingerprint===info.fingerprint);
  if(record&&record.certificate!==info.certificate)fail('Certificate changed for this fingerprint. Remove the saved certificate and review the update before trusting it.');
  if(!record){record={fingerprint:info.fingerprint,certificate:info.certificate,certificateHash:info.certificateHash,trustedEmails:[]};state.records.push(record);}
  return record;
 }
 const confirmed=value=>{if(value!==true)fail('Explicit certificate review confirmation required');};
 return {
  preview,
  async get(fp){
   fingerprint(fp);const state=await load();
   const item=(await inspected(state)).find(x=>x.info.fingerprint===fp);
   if(!item)fail('Saved certificate no longer exists');
   return clone(item.info);
  },
  async list(){return inventory(await load());},
  async material(){
   const state=await load(),items=await inspected(state),bindings=[];
   for(const {record,info} of items)for(const address of record.trustedEmails)if(info.emails.includes(address))bindings.push({email:address,fingerprint:info.fingerprint});
   return {certificates:items.map(x=>x.info.certificate),saved:items.map(x=>x.info.fingerprint),bindings,revision:state.revision};
  },
  async assertRevision(revision){
   // An asynchronous verifier can finish after another window removes trust.
   // Its signature remains mathematical evidence, but it must not display a
   // stale trusted badge or offer a save/trust action from an obsolete review.
   if(!Number.isSafeInteger(revision)||revision<0||(await load()).revision!==revision)fail('Certificate trust changed during verification; open the message again.');
   return true;
  },
  async save(certificate){
   const state=await load(),info=await preview(certificate),next=clone(state);insert(next,info);
   return commit(state,next); // Saving alone never adds an email trust binding.
  },
  async trust(certificate,address,fp,confirmation){
   confirmed(confirmation);fingerprint(fp);address=email(address);
   const state=await load(),info=await preview(certificate);
   if(info.fingerprint!==fp||!info.emails.includes(address))fail('Email is not currently self-certified by this certificate');
   const next=clone(state),record=insert(next,info);
   if(!record.trustedEmails.includes(address))record.trustedEmails.push(address);
   record.trustedEmails.sort();return commit(state,next);
  },
  async untrust(fp,address,confirmation){
   confirmed(confirmation);fingerprint(fp);address=email(address);
   const state=await load(),next=clone(state),record=next.records.find(r=>r.fingerprint===fp);
   if(!record)fail('Saved certificate no longer exists');
   record.trustedEmails=record.trustedEmails.filter(e=>e!==address);
   return commit(state,next);
  },
  async remove(fp,confirmation){
   confirmed(confirmation);fingerprint(fp);
   const state=await load(),next=clone(state);
   if(!next.records.some(r=>r.fingerprint===fp))fail('Saved certificate no longer exists');
   next.records=next.records.filter(r=>r.fingerprint!==fp);
   // Keep the migration marker: deletion must not resurrect legacy trust at
   // restart merely because the old native store still contains the certificate.
   return commit(state,next);
  },
  async trustedContact(id){
   if(typeof id!=='string'||! /^[A-Fa-f0-9]{64}$/.test(id))fail('Select a trusted contact');
   const item=(await inventory(await load())).contacts.find(c=>c.id===id.toUpperCase());
   if(!item)fail('Trusted contact is unavailable or no longer valid');
   return item;
  },
  async assertContact(snapshot){
   keys(snapshot,['id','email','fingerprint','certificate','certificateHash','revision']);
   const item=await this.trustedContact(snapshot.id);
   // The revision catches remove-and-retrust races, including ABA changes back
   // to the same fingerprint. Exact certificate hash and bytes bind the content.
   if(Object.keys(item).some(k=>item[k]!==snapshot[k]))fail('Recipient trust or certificate changed; prepare and review again.');
   return item;
  },
  async importLegacy(snapshot,confirmation){
   confirmed(confirmation);
   keys(snapshot,['version','certificates','saved','bindings','sourceDigest']);
   if(snapshot.version!==1||! /^[a-f0-9]{64}$/.test(snapshot.sourceDigest)||!Array.isArray(snapshot.certificates)||snapshot.certificates.length>MAX_CERTS||!Array.isArray(snapshot.saved)||!Array.isArray(snapshot.bindings)||snapshot.bindings.length>MAX_BINDINGS)fail('Invalid native migration snapshot');
   if(snapshot.certificates.reduce((n,c)=>n+bytes(c).length,0)>MAX_BYTES)fail('Migration certificate limit exceeded');
   if(await migrationDigest(snapshot)!==snapshot.sourceDigest)fail('Native migration snapshot checksum mismatch');
   const state=await load();
   // A migration is an explicit one-time transition. A later native snapshot,
   // even with new trust, cannot overwrite browser-owned decisions silently.
   if(state.migration){
    if(state.migration.sourceDigest!==snapshot.sourceDigest)fail('Native migration already completed; import individual certificates instead.');
    return inventory(state);
   }
   const next=clone(state),parsed=new Map();
   for(const certificate of snapshot.certificates){
    const info=await preview(certificate);
    if(parsed.has(info.fingerprint))fail('Duplicate certificate in migration');
    parsed.set(info.fingerprint,info);insert(next,info);
   }
   if(snapshot.saved.length!==parsed.size||new Set(snapshot.saved).size!==parsed.size||snapshot.saved.some(fp=>!parsed.has(fingerprint(fp))))fail('Migration fingerprint mismatch');
   const seen=new Set();
   for(const binding of snapshot.bindings){
    keys(binding,['email','fingerprint']);const fp=fingerprint(binding.fingerprint),address=email(binding.email),info=parsed.get(fp);
    if(!info||!info.emails.includes(address))fail('Migration trust lacks a current self-certified mailbox');
    const key=address+'\0'+fp;if(seen.has(key))continue;seen.add(key);
    const record=next.records.find(r=>r.fingerprint===fp);if(!record.trustedEmails.includes(address))record.trustedEmails.push(address);
    record.trustedEmails.sort();
   }
   next.migration={sourceDigest:snapshot.sourceDigest};return commit(state,next);
  }
 };
}
