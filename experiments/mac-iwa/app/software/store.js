// Software identities are authenticated records INSIDE the existing encrypted
// vault. This module never opens IndexedDB or a native connection itself. Its
// injected access service owns encryption/CAS persistence and lock epochs.
const KIND='software OpenPGP identity',MAX_SECRET=349528;
const ordered=v=>Array.isArray(v)?v.map(ordered):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,ordered(v[k])])):v;
const same=(a,b)=>JSON.stringify(ordered(a))===JSON.stringify(ordered(b));
const fields=(v,names)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...names].sort().join(',');
const hex=(s,n)=>typeof s==='string'&&new RegExp('^[A-F0-9]{'+n+'}$').test(s);
const hash=async value=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',value))].map(x=>x.toString(16).padStart(2,'0')).join('');
const bytes=s=>Uint8Array.from(atob(s),x=>x.charCodeAt(0));
function canonical(s,max){try{if(typeof s!=='string'||!s||s.length>max)throw Error();const value=bytes(s);let text='';for(const x of value)text+=String.fromCharCode(x);if(btoa(text)!==s)throw Error();return value;}catch(_){throw Error('Invalid software identity encoding.');}}
function credentials(secret,password){canonical(secret,MAX_SECRET);if(typeof password!=='string'||!password.length||new TextEncoder().encode(password).length>1024)throw Error('Enter the OpenPGP identity password (at most 1024 UTF-8 bytes).');}
function mailbox(value){if(typeof value!=='string'||value.length>320||!/^[^\s<>@,;]+@[^\s<>@,;]+$/.test(value)||/[<>;,\x00-\x1f\x7f]/.test(value))throw Error('A configured account email is required.');return value.toLowerCase();}
function label(value){if(typeof value!=='string'||!value.trim()||value.trim().length>100||/[\x00-\x1f\x7f]/.test(value))throw Error('Enter a software identity name of 1–100 characters.');return value.trim();}
async function publicMetadata(value){
 const allowed=['supported','version','certificate','certificateHash','fingerprint','emails','signingFingerprint','recipientKey','algorithms','hybridContact'];
 if(!value||Object.keys(value).some(k=>!allowed.includes(k)))throw Error('Invalid software public metadata.');
 if(!value||value.supported!==true||value.version!==6||!hex(value.fingerprint,64)||!hex(value.signingFingerprint,64)||!hex(value.recipientKey,64)||typeof value.certificateHash!=='string'||!/^[a-f0-9]{64}$/.test(value.certificateHash)||!Array.isArray(value.emails)||!value.emails.length||value.emails.length>64||!Array.isArray(value.algorithms)||value.algorithms.length>16||value.algorithms.some(x=>typeof x!=='string'||x.length>100))throw Error('A current Level 3 v6 software OpenPGP identity is required.');
 const raw=canonical(value.certificate,90000);if(await hash(raw)!==value.certificateHash)throw Error('Software public certificate hash mismatch.');
 const emails=value.emails.map(mailbox);if(new Set(emails).size!==emails.length)throw Error('Duplicate software identity email.');
 // Only this explicit public subset can enter chooser state or emitted events.
 return {certificate:value.certificate,certificateHash:value.certificateHash,fingerprint:value.fingerprint,emails,signingFingerprint:value.signingFingerprint,recipientKey:value.recipientKey,algorithms:[...value.algorithms]};
}
function itemShape(item){
 if(!fields(item,['id','name','kind','version','encryptedSecret','password','public'])||item.kind!==KIND||item.version!==1||typeof item.id!=='string'||!/^[a-f0-9-]{36}$/.test(item.id))throw Error('Stored software identity is malformed.');
 label(item.name);credentials(item.encryptedSecret,item.password);if(!fields(item.public,['certificate','certificateHash','fingerprint','emails','signingFingerprint','recipientKey','algorithms']))throw Error('Invalid stored software public metadata.');return item;
}
export function softwareIdentityBinding(snapshot){return {provider:'software',vaultId:snapshot.vaultId,identityId:snapshot.identityId,fingerprint:snapshot.fingerprint,certificateHash:snapshot.certificateHash,email:snapshot.email};}

/** access.snapshot() is closure-private and may contain vault item secrets.
 * Public callers see only the explicit snapshots constructed below. Every
 * asynchronous boundary rechecks the local epoch and durable vault revision.
 * A lock, replace/remove, other-window commit or failed write invalidates prior
 * operation reviews, including remove-and-reimport of the same fingerprint.
 */
export function createSoftwareIdentityStore({access,inspectPublic,cryptoCall,changed=()=>{},clock=()=>Date.now()}){
 const active=new Set(),grants=new Map();let mutation=false;
 const current=()=>{const s=access.snapshot();if(!s?.unlocked||!s.vaultId||!Number.isSafeInteger(s.revision)||!Number.isSafeInteger(s.epoch)||!Array.isArray(s.items))throw Error('Unlock the credential vault before using software identities.');return s;};
 const marker=s=>({vaultId:s.vaultId,revision:s.revision,epoch:s.epoch});
 async function check(s){const now=current();if(!same(marker(now),marker(s)))throw Error('Software identity vault changed; start again.');await access.assertCurrent(marker(s));if(!same(marker(current()),marker(s)))throw Error('Software identity vault changed; start again.');}
 function recordsIn(s){const records=s.items.filter(x=>x?.kind===KIND);if(records.length>16||new Set(records.map(x=>x.id)).size!==records.length)throw Error('Invalid software identity inventory.');return records.map(itemShape);}
 function snapshot(s,item,info,email){return {provider:'software',id:'software:'+item.id,identityId:item.id,vaultId:s.vaultId,revision:s.revision,epoch:s.epoch,name:item.name,...info,email};}
 async function withController(signal,fn){const c=new AbortController();active.add(c);const abort=()=>c.abort();signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)c.abort();try{if(c.signal.aborted)throw Error('Software operation cancelled.');return await fn(c.signal);}finally{signal?.removeEventListener('abort',abort);active.delete(c);}}
 async function list(account){
  account=mailbox(account);if(!access.snapshot()?.unlocked)return {choices:[],revision:0};const s=current(),choices=[];await check(s);
  for(const item of recordsIn(s)){
   // Re-check public expiration/revocation and key use each time; an old vault
   // entry cannot revive a now-unusable certificate merely by remaining saved.
   const inspected=await inspectPublic(item.public.certificate);await check(s);if(!inspected.supported)continue;
   const info=await publicMetadata(inspected);if(!same(info,item.public))throw Error('Saved software public identity changed.');
   if(info.emails.includes(account))choices.push(snapshot(s,item,info,account));
  }
  await check(s);return {choices,revision:s.revision};
 }
 async function get(id,account){const s=(await list(account)).choices.find(x=>x.id===id);if(!s)throw Error('Select an unlocked software identity for this account.');return s;}
 async function assert(snapshot){if(!snapshot||!same(await get(snapshot.id,snapshot.email),snapshot))throw Error('Software identity changed; prepare or open the message again.');return true;}
 async function records(){if(!access.snapshot()?.unlocked)return [];const s=current();await check(s);const rows=[];for(const item of recordsIn(s)){const info=await publicMetadata({supported:true,version:6,...item.public});await check(s);rows.push(snapshot(s,item,info,info.emails[0]));}return rows;}
 async function importIdentity(value,account,{signal}={}){
  if(mutation)throw Error('Another software identity change is in progress.');mutation=true;
  try{return await withController(signal,async signal=>{
   if(!fields(value,['name','encryptedSecret','password']))throw Error('Invalid software identity import.');
   const name=label(value.name);credentials(value.encryptedSecret,value.password);account=mailbox(account);
   const s=current();await check(s);const existing=recordsIn(s);if(existing.length>=16)throw Error('Maximum 16 software identities per vault.');
   const inspected=await cryptoCall('inspect',{encryptedSecret:value.encryptedSecret,password:value.password},{signal});await check(s);if(signal.aborted)throw Error('Software import cancelled.');
   const info=await publicMetadata(inspected);await check(s);if(!info.emails.includes(account))throw Error('Software certificate does not certify the configured account.');
   if(existing.some(x=>x.public.fingerprint===info.fingerprint))throw Error('This software identity is already saved in the vault.');
   const item={id:crypto.randomUUID(),name,kind:KIND,version:1,encryptedSecret:value.encryptedSecret,password:value.password,public:info};
   await access.replaceItems([...s.items,item],marker(s),{signal});grants.clear();changed();return get('software:'+item.id,account);
  });}finally{mutation=false;}
 }
 async function remove(snapshot,{signal}={}){
  if(mutation)throw Error('Another software identity change is in progress.');mutation=true;
  try{return await withController(signal,async signal=>{
   const s=current();await check(s);const item=recordsIn(s).find(x=>x.id===snapshot?.identityId);
   // Removal accepts expired entries through records(), but requires the same
   // saved public content and vault revision the user reviewed.
   if(!item||!same(marker(snapshot),marker(s))||snapshot.provider!=='software'||snapshot.id!=='software:'+item.id||snapshot.fingerprint!==item.public.fingerprint||snapshot.certificateHash!==item.public.certificateHash)throw Error('Software removal review is stale.');
   await access.replaceItems(s.items.filter(x=>x.id!==item.id),marker(s),{signal});grants.clear();changed();return true;
  });}finally{mutation=false;}
 }
 async function validateMaterial(material,selected,kind){
  await assert(selected);if(!material||!same(material.identity,softwareIdentityBinding(selected))||!/^[a-f0-9]{48}$/.test(material.review))throw Error('Software identity material changed.');
  if(kind==='signing'?(material.senderCertificate!==selected.certificate||material.senderEmail!==selected.email||material.signingFingerprint!==selected.signingFingerprint):(material.recipientCertificate!==selected.certificate||material.recipientKey!==selected.recipientKey))throw Error('Software operation certificate changed.');
  return material;
 }
 function native(selected){return async(op,request,{signal}={})=>withController(signal,async signal=>{
  await assert(selected);if(signal.aborted)throw Error('Software operation cancelled.');
  if(op==='chat-selected-signing-material'||op==='chat-selected-decryption-material'){
   const signing=op==='chat-selected-signing-material';
   if(!fields(request,signing?['identity']:['identity','service'])||!same(request.identity,softwareIdentityBinding(selected))||(!signing&&!['Gmail','Chat','Hardware test'].includes(request.service)))throw Error('Invalid software material request.');
   // Limit outstanding grants and expire them. A random one-use identifier is
   // never interchangeable with a native grant or another provider's identity.
   for(const [id,g] of grants)if(g.expires<clock())grants.delete(id);
   if(grants.size>=16)throw Error('Too many pending software operations.');
   const review=[...crypto.getRandomValues(new Uint8Array(24))].map(x=>x.toString(16).padStart(2,'0')).join('');
   grants.set(review,{selected:structuredClone(selected),kind:signing?'sign':'decapsulate',service:request.service,expires:clock()+120000});
   return signing?{identity:softwareIdentityBinding(selected),review,senderEmail:selected.email,senderCertificate:selected.certificate,signingFingerprint:selected.signingFingerprint}:{identity:softwareIdentityBinding(selected),review,recipientCertificate:selected.certificate,recipientKey:selected.recipientKey};
  }
  const signing=op==='chat-sign-digest';if(!signing&&op!=='chat-decapsulate-components')throw Error('Unsupported software operation; no native fallback.');
  const grant=grants.get(request?.review);grants.delete(request?.review);
  if(!grant||grant.expires<clock()||grant.expires-clock()>120000||!same(grant.selected,selected)||grant.kind!==(signing?'sign':'decapsulate'))throw Error('Software operation review expired or already used.');
  const allowed=signing?['review','requestId','signingFingerprint','hashAlgorithm','digest']:['review','service','requestId','cipherHash','recipientKey','mlkemCiphertext','x25519Ephemeral'];
  if(!fields(request,allowed)||!hex(request.requestId,64)||(signing?(request.signingFingerprint!==selected.signingFingerprint||request.hashAlgorithm!==10):(request.recipientKey!==selected.recipientKey||request.service!==grant.service)))throw Error('Software operation binding mismatch.');
  const s=current();await check(s);const item=recordsIn(s).find(x=>x.id===selected.identityId);if(!item)throw Error('Software identity removed.');
  const {review,service,...component}=request;const input={encryptedSecret:item.encryptedSecret,password:item.password,request:component};let result;
  try{result=await cryptoCall(signing?'sign':'decapsulate',input,{signal});await assert(selected);if(signal.aborted)throw Error('Software operation cancelled.');
   const expected=signing?[...Object.keys(component),'ed25519','mldsa65']:[...Object.keys(component),'mlkemSecret','x25519Secret'];
   if(!fields(result,expected)||Object.keys(component).some(k=>result[k]!==component[k]))throw Error('Software response binding mismatch.');
   for(const [name,length] of signing?[['ed25519',64],['mldsa65',3309]]:[['mlkemSecret',32],['x25519Secret',32]]){const value=canonical(result[name],Math.ceil(length/3)*4);if(value.length!==length||(!signing&&name==='x25519Secret'&&!value.some(Boolean)))throw Error('Invalid software component response.');}
   return result;
  }catch(e){if(result&&!signing){delete result.mlkemSecret;delete result.x25519Secret;}throw e;}
  finally{input.password='';input.encryptedSecret='';}
 });}
 return {list,get,assert,records,import:importIdentity,remove,native,nativeBinding:softwareIdentityBinding,validateMaterial,
  cancel(){grants.clear();for(const controller of active)controller.abort();}};
}
