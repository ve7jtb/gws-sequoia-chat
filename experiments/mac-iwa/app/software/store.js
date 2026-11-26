// Software identities are authenticated records INSIDE the existing encrypted
// vault. This module never opens IndexedDB or a native connection itself. Its
// injected access service owns encryption/CAS persistence and lock epochs.
const KIND='software OpenPGP identity',MAX_SECRET=349528;
export const SOFTWARE_PROFILES=Object.freeze(['level3','level5','level3-v4-hybrid','level3-v4-classical','level5-v4-hybrid','level5-v4-classical','level3-v5-hybrid']);
const profileVersion=profile=>profile.includes('-v4-')?4:profile.includes('-v5-')?5:6;
const randomPassword=()=>btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
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
 const allowed=['supported','version','certificate','certificateHash','fingerprint','emails','signingFingerprint','recipientKey','algorithms','hybridContact','encryptionSupported','profile','signingAlgorithm','encryptionAlgorithm','pqSigning','pqEncryption'];
 if(!value||Object.keys(value).some(k=>!allowed.includes(k)))throw Error('Invalid software public metadata.');
 const version=value.version,profile=value.profile||'level3',fingerprintSize=version===4?40:64;
 if(value.supported!==true||!SOFTWARE_PROFILES.includes(profile)||version!==profileVersion(profile)||!hex(value.fingerprint,fingerprintSize)||!hex(value.signingFingerprint,fingerprintSize)||!hex(value.recipientKey,fingerprintSize)||typeof value.certificateHash!=='string'||!/^[a-f0-9]{64}$/.test(value.certificateHash)||!Array.isArray(value.emails)||!value.emails.length||value.emails.length>64||!Array.isArray(value.algorithms)||value.algorithms.length>16||value.algorithms.some(x=>typeof x!=='string'||x.length>100))throw Error('A current supported software OpenPGP identity is required.');
 const raw=canonical(value.certificate,90000);if(await hash(raw)!==value.certificateHash)throw Error('Software public certificate hash mismatch.');
 const emails=value.emails.map(mailbox);if(new Set(emails).size!==emails.length)throw Error('Duplicate software identity email.');
 const pqSigning=value.pqSigning??true,pqEncryption=value.pqEncryption??true;
 if(typeof pqSigning!=='boolean'||typeof pqEncryption!=='boolean'||pqSigning!==(version===6)||pqEncryption!==!profile.endsWith('-classical'))throw Error('Software profile capabilities do not match its certificate.');
 const signingAlgorithm=value.signingAlgorithm||'ML-DSA-65 + Ed25519',encryptionAlgorithm=value.encryptionAlgorithm||'ML-KEM-768 + X25519';
 for(const name of [signingAlgorithm,encryptionAlgorithm])if(typeof name!=='string'||!name||name.length>100)throw Error('Invalid software algorithm metadata.');
 // Only this explicit public subset can enter chooser state or emitted events.
 // The profile comes from authenticated public parsing, never a filename or a
 // UI selection. Classical compatibility carries explicit warning capabilities.
 return {version,profile,signingAlgorithm,encryptionAlgorithm,pqSigning,pqEncryption,certificate:value.certificate,certificateHash:value.certificateHash,fingerprint:value.fingerprint,emails,signingFingerprint:value.signingFingerprint,recipientKey:value.recipientKey,algorithms:[...value.algorithms]};
}
function itemShape(item){
 if(!fields(item,['id','name','kind','version','encryptedSecret','password','public',...(item?.hardware?['hardware']:[])])||item.kind!==KIND||![1,2].includes(item.version)||typeof item.id!=='string'||!/^[a-f0-9-]{36}$/.test(item.id))throw Error('Stored software identity is malformed.');
 label(item.name);
 if(item.hardware){
  const h=item.hardware;if(!fields(h,['serial','slots','verified','privateRemoved'])||!/^[1-9][0-9]{5,9}$/.test(h.serial)||h.verified!==true||typeof h.privateRemoved!=='boolean'||!Array.isArray(h.slots)||h.slots.length!==6)throw Error('Invalid hardware backup binding.');
  for(const k of h.slots)if(!fields(k,['slot','publicKeySha256'])||!['86','87','9c','84','9d','85'].includes(k.slot)||!/^[a-f0-9]{64}$/.test(k.publicKeySha256))throw Error('Invalid hardware slot binding.');
  if(new Set(h.slots.map(k=>k.slot)).size!==6)throw Error('Duplicate hardware slot binding.');
  if(h.privateRemoved){if(item.encryptedSecret!==''||item.password!=='')throw Error('Removed private keys remain in record.');}else credentials(item.encryptedSecret,item.password);
 }else credentials(item.encryptedSecret,item.password);
 const old=['certificate','certificateHash','fingerprint','emails','signingFingerprint','recipientKey','algorithms'];
 if(!fields(item.public,item.version===1?old:[...old,'version','profile','signingAlgorithm','encryptionAlgorithm','pqSigning','pqEncryption']))throw Error('Invalid stored software public metadata.');return item;
}
// Existing 0.17 records gain the explicitly defined Level 3 v6 metadata only
// after their certificate is independently re-inspected. No disk rewrite is
// needed just to list a vault and older encrypted backups keep working.
async function savedMetadata(item){return publicMetadata({supported:true,version:6,...item.public});}
async function matchesSaved(info,item){
 if(item.version===1){const legacy=Object.fromEntries(Object.keys(item.public).map(k=>[k,info[k]]));return info.version===6&&info.profile==='level3'&&same(legacy,item.public);}
 return same(info,await savedMetadata(item));
}
export function softwareIdentityBinding(snapshot){return {provider:'software',vaultId:snapshot.vaultId,identityId:snapshot.identityId,fingerprint:snapshot.fingerprint,certificateHash:snapshot.certificateHash,email:snapshot.email};}

/** access.snapshot() is closure-private and may contain vault item secrets.
 * Public callers see only the explicit snapshots constructed below. Every
 * asynchronous boundary rechecks the local epoch and durable vault revision.
 * A lock, replace/remove, other-window commit or failed write invalidates prior
 * operation reviews, including remove-and-reimport of the same fingerprint.
 */
export function createSoftwareIdentityStore({access,inspectPublic,cryptoCall,hardwareCall,changed=()=>{},clock=()=>Date.now()}){
 const active=new Set(),grants=new Map();let mutation=false;
 const current=()=>{const s=access.snapshot();if(!s?.unlocked||!s.vaultId||!Number.isSafeInteger(s.revision)||!Number.isSafeInteger(s.epoch)||!Array.isArray(s.items))throw Error('Unlock the credential vault before using software identities.');return s;};
 const marker=s=>({vaultId:s.vaultId,revision:s.revision,epoch:s.epoch});
 async function check(s){const now=current();if(!same(marker(now),marker(s)))throw Error('Software identity vault changed; start again.');await access.assertCurrent(marker(s));if(!same(marker(current()),marker(s)))throw Error('Software identity vault changed; start again.');}
 function recordsIn(s){const records=s.items.filter(x=>x?.kind===KIND);if(records.length>16||new Set(records.map(x=>x.id)).size!==records.length)throw Error('Invalid software identity inventory.');return records.map(itemShape);}
 function snapshot(s,item,info,email){return {provider:'software',id:'software:'+item.id,identityId:item.id,vaultId:s.vaultId,revision:s.revision,epoch:s.epoch,name:item.name,...info,email,...(item.hardware?{hardware:structuredClone(item.hardware)}:{})};}
 async function withController(signal,fn){const c=new AbortController();active.add(c);const abort=()=>c.abort();signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)c.abort();try{if(c.signal.aborted)throw Error('Software operation cancelled.');return await fn(c.signal);}finally{signal?.removeEventListener('abort',abort);active.delete(c);}}
 async function list(account){
  account=mailbox(account);if(!access.snapshot()?.unlocked)return {choices:[],revision:0};const s=current(),choices=[];await check(s);
  for(const item of recordsIn(s)){
   // Re-check public expiration/revocation and key use each time; an old vault
   // entry cannot revive a now-unusable certificate merely by remaining saved.
   const inspected=await inspectPublic(item.public.certificate);await check(s);if(!inspected.supported)continue;
   const info=await publicMetadata(inspected);if(!await matchesSaved(info,item))throw Error('Saved software public identity changed.');
   if(info.emails.includes(account))choices.push(snapshot(s,item,info,account));
  }
  await check(s);return {choices,revision:s.revision};
 }
 async function get(id,account){const s=(await list(account)).choices.find(x=>x.id===id);if(!s)throw Error('Select an unlocked software identity for this account.');return s;}
 async function assert(snapshot){if(!snapshot||!same(await get(snapshot.id,snapshot.email),snapshot))throw Error('Software identity changed; prepare or open the message again.');return true;}
 async function records(){if(!access.snapshot()?.unlocked)return [];const s=current();await check(s);const rows=[];for(const item of recordsIn(s)){const info=await savedMetadata(item);await check(s);rows.push(snapshot(s,item,info,info.emails[0]));}return rows;}
 async function importIdentity(value,account,{signal}={}){
  if(mutation)throw Error('Another software identity change is in progress.');mutation=true;
  try{return await withController(signal,async signal=>{
   if(!fields(value,['name','encryptedSecret','password']))throw Error('Invalid software identity import.');
   const name=label(value.name);credentials(value.encryptedSecret,value.password);account=mailbox(account);
   const s=current();await check(s);const existing=recordsIn(s);if(existing.length>=16)throw Error('Maximum 16 software identities per vault.');
   const inspected=await cryptoCall('inspect',{encryptedSecret:value.encryptedSecret,password:value.password},{signal});await check(s);if(signal.aborted)throw Error('Software import cancelled.');
   const info=await publicMetadata(inspected);await check(s);if(!info.emails.includes(account))throw Error('Software certificate does not certify the configured account.');
   if(existing.some(x=>x.public.certificateHash===info.certificateHash))throw Error('This software identity is already saved in the vault.');
   const item={id:crypto.randomUUID(),name,kind:KIND,version:2,encryptedSecret:value.encryptedSecret,password:value.password,public:info};
   await access.replaceItems([...s.items,item],marker(s),{signal});grants.clear();changed();return get('software:'+item.id,account);
  });}finally{mutation=false;}
 }
 /** Generate/import conversion outputs are encrypted before they leave WASM.
  * A fresh random file password is never shown or exported and lives only in
  * the vault. Compatibility views are independent entries with explicit labels;
  * the existing v6 default is not replaced by importing an older certificate.
  */
 async function savePrepared(source,name,password,account,s,signal){
  if(!source||Object.keys(source).some(k=>!['encryptedSecret','public','compatibility'].includes(k)))throw Error('Invalid software creation response.');
  const variants=[source,...(source.compatibility||[])];if(!Array.isArray(source.compatibility||[])||variants.length>4)throw Error('Invalid software certificate set.');
  const existing=recordsIn(s),created=[];if(existing.length+variants.length>16)throw Error('Maximum 16 software identities per vault.');
  for(const value of variants){
   credentials(value.encryptedSecret,password);const info=await publicMetadata(value.public);await check(s);
   const independent=await publicMetadata(await inspectPublic(info.certificate));await check(s);
   if(!same(info,independent)||!info.emails.includes(account))throw Error('Created software certificate does not match the configured account.');
   if([...existing,...created].some(x=>x.public.certificateHash===info.certificateHash))throw Error('This software identity is already saved in the vault.');
   created.push({id:crypto.randomUUID(),name:created.length?label(name.slice(0,72)+' · '+info.profile):name,kind:KIND,version:2,encryptedSecret:value.encryptedSecret,password,public:info});
  }
  if(signal.aborted)throw Error('Software creation cancelled.');await access.replaceItems([...s.items,...created],marker(s),{signal});grants.clear();changed();return get('software:'+created[0].id,account);
 }
 async function createIdentity(value,account,{signal}={}){
  if(mutation)throw Error('Another software identity change is in progress.');mutation=true;
  try{return await withController(signal,async signal=>{
   if(!fields(value,['name','profile'])||!SOFTWARE_PROFILES.includes(value.profile))throw Error('Select a supported software profile.');
   const name=label(value.name);account=mailbox(account);const s=current();await check(s);let password=randomPassword(),result;
   try{result=await cryptoCall('generate',{profile:value.profile,email:account,name,password},{signal});await check(s);if(result.public?.profile&&result.public.profile!==value.profile)throw Error('Generated profile does not match the request.');return await savePrepared(result,name,password,account,s,signal);}
   finally{password='';if(result){result.encryptedSecret='';if(result.compatibility)for(const child of result.compatibility)child.encryptedSecret='';}}
  });}finally{mutation=false;}
 }
 async function importP12(value,account,{signal}={}){
  if(mutation)throw Error('Another software identity change is in progress.');mutation=true;
  try{return await withController(signal,async signal=>{
   if(!fields(value,['name','p12','password']))throw Error('Invalid PKCS#12 import.');const name=label(value.name);canonical(value.p12,1398104);credentials(btoa('password check'),value.password);account=mailbox(account);
   const s=current();await check(s);let newPassword=randomPassword(),result;
   try{result=await cryptoCall('import-p12',{p12:value.p12,password:value.password,newPassword},{signal});await check(s);return await savePrepared(result,name,newPassword,account,s,signal);}
   finally{newPassword='';if(result){result.encryptedSecret='';if(result.compatibility)for(const child of result.compatibility)child.encryptedSecret='';}}
  });}finally{mutation=false;}
 }
 async function exportIdentity(selected,newPassword,{signal}={}){
  if(selected.hardware?.privateRemoved)throw Error('Private keys are on the YubiKey only; export the public certificate instead.');
  if(typeof newPassword!=='string'||newPassword.length<12||new TextEncoder().encode(newPassword).length>1024)throw Error('Use an export password of at least 12 characters (at most 1024 UTF-8 bytes).');
  return withController(signal,async signal=>{
   await assert(selected);const s=current();await check(s);const item=recordsIn(s).find(x=>x.id===selected.identityId);if(!item)throw Error('Software identity removed.');
   const input={encryptedSecret:item.encryptedSecret,password:item.password,newPassword};let result;
   try{result=await cryptoCall('export',input,{signal});await assert(selected);if(signal.aborted)throw Error('Software export cancelled.');
    if(!fields(result,['encryptedSecret','public']))throw Error('Invalid encrypted identity export.');canonical(result.encryptedSecret,MAX_SECRET);
    if(!await matchesSaved(await publicMetadata(result.public),item))throw Error('Encrypted export changed the certificate.');await assert(selected);
    // Only password-encrypted OpenPGP bytes leave this service. The original
    // vault password, raw keys and encrypted vault record are never exported.
    return {encryptedSecret:result.encryptedSecret,fingerprint:selected.fingerprint,profile:selected.profile,version:selected.version};
   }finally{input.password='';input.newPassword='';input.encryptedSecret='';if(result)result.encryptedSecret='';}
  });
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
   return signing?{softwareProfile:selected.profile,version:selected.version,identity:softwareIdentityBinding(selected),review,senderEmail:selected.email,senderCertificate:selected.certificate,signingFingerprint:selected.signingFingerprint}:{softwareProfile:selected.profile,version:selected.version,identity:softwareIdentityBinding(selected),review,recipientCertificate:selected.certificate,recipientKey:selected.recipientKey};
  }
  const signing=op==='chat-sign-digest';if(!signing&&op!=='chat-decapsulate-components')throw Error('Unsupported software operation; no native fallback.');
  const grant=grants.get(request?.review);grants.delete(request?.review);
  if(!grant||grant.expires<clock()||grant.expires-clock()>120000||!same(grant.selected,selected)||grant.kind!==(signing?'sign':'decapsulate'))throw Error('Software operation review expired or already used.');
  const allowed=signing?['review','requestId','signingFingerprint','hashAlgorithm','digest',...(selected.version===5?['inlineDigest']:[])]:['review','service','requestId','cipherHash','recipientKey','mlkemCiphertext','x25519Ephemeral'];
  if(!fields(request,allowed)||!hex(request.requestId,64)||(signing?(request.signingFingerprint!==selected.signingFingerprint||request.hashAlgorithm!==10):(request.recipientKey!==selected.recipientKey||request.service!==grant.service)))throw Error('Software operation binding mismatch.');
  const s=current();await check(s);const item=recordsIn(s).find(x=>x.id===selected.identityId);if(!item)throw Error('Software identity removed.');
  const {review,service,...component}=request;const input={encryptedSecret:item.encryptedSecret,password:item.password,request:component};let result;
  try{result=item.hardware?.privateRemoved?await hardwareCall(signing?'sign':'decapsulate',component,{...item.hardware,certificate:selected.certificate},{signal,guard:()=>assert(selected)}):await cryptoCall(signing?'sign':'decapsulate',input,{signal});await assert(selected);if(signal.aborted)throw Error('Software operation cancelled.');
   const expected=signing?[...Object.keys(component),'ed25519','mldsa65',...(selected.version===5?['inlineEd25519']:[])]:[...Object.keys(component),'mlkemSecret','x25519Secret'];
   if(!fields(result,expected)||Object.keys(component).some(k=>result[k]!==component[k]))throw Error('Software response binding mismatch.');
   const modern=selected.version===6,level5=selected.profile==='level5',p521=selected.profile.startsWith('level5-');
   const sizes=signing?[['ed25519',modern?(level5?114:64):(p521?132:64)],['mldsa65',modern?(level5?4627:3309):0],...(selected.version===5?[['inlineEd25519',64]]:[])]:[['mlkemSecret',selected.pqEncryption?32:0],['x25519Secret',level5?56:(!selected.pqEncryption&&p521?66:32)]];
   for(const [name,length] of sizes){if(length===0){if(result[name]!=='')throw Error('Unexpected composite component.');continue;}const value=canonical(result[name],Math.ceil(length/3)*4);if(value.length!==length||(!signing&&name==='x25519Secret'&&!value.some(Boolean)))throw Error('Invalid software component response.');}
   return result;
  }catch(e){if(result&&!signing){delete result.mlkemSecret;delete result.x25519Secret;}throw e;}
  finally{input.password='';input.encryptedSecret='';}
 });}
 // Provisioning material is released only after the card-plan confirmation.
 // It is never persisted separately or exported as a download. Every asynchronous
 // step rechecks the vault generation, including the worker response.
 async function backupMaterial(selected,plan,{signal}={}){
  return withController(signal,async signal=>{
   await assert(selected);if(selected.profile!=='level3'||selected.hardware?.privateRemoved)throw Error('Native backup requires existing Level 3 software keys.');
   const s=current(),item=recordsIn(s).find(x=>x.id===selected.identityId);await check(s);
   const input={encryptedSecret:item.encryptedSecret,password:item.password};let result;const out=[];
   try{
    result=await cryptoCall('backup-material',input,{signal});await assert(selected);
    if(result.certificateHash!==selected.certificateHash||!Array.isArray(result.keys)||result.keys.length!==6)throw Error('Backup source changed.');
    for(const key of plan.keys){const k=result.keys.find(x=>x.slot===key.slot);if(!k||k.algorithm!==key.component)throw Error('Backup component mismatch.');
     const seed=canonical(k.seed,88);out.push({slot:k.slot,algorithm:k.algorithm,seed,publicKey:null});
     if(seed.length!==(key.component==='ML-KEM-768'?64:32))throw Error('Invalid private seed length.');out.at(-1).publicKey=canonical(k.publicKey,3000);}
    return out;
   }catch(error){for(const key of out)key.seed.fill(0);throw error;}finally{input.password='';input.encryptedSecret='';for(const k of result?.keys||[])k.seed='';}
  });
 }
 async function saveHardware(selected,plan,proof){
  await assert(selected);const s=current();await check(s);
  if(proof.publicKeysMatch!==true||proof.signingVerified!==true||proof.decryptionVerified!==true||!Array.isArray(proof.slots))throw Error('Verified hardware proof required.');
  const item=recordsIn(s).find(x=>x.id===selected.identityId);
  const replacement={...item,hardware:{serial:plan.serial,slots:proof.slots,verified:true,privateRemoved:false}};itemShape(replacement);
  await access.replaceItems(s.items.map(x=>x===item?replacement:x),marker(s),{signal:new AbortController().signal});grants.clear();changed();
  return {identity:await get(selected.id,selected.email)};
 }
 async function assertHardware(handle){const selected=handle?.identity;await assert(selected);if(!selected.hardware?.verified)throw Error('No verified hardware identity.');}
 async function removePrivate(selected,handle){
  await assertHardware(handle);if(!same(selected,handle.identity))throw Error('Hardware removal review changed.');
  const s=current();await check(s);const item=recordsIn(s).find(x=>x.id===selected.identityId);
  // This atomic replacement retains the certificate and card mapping. Old
  // exported backups are independent and may still contain the secret packets.
  const replacement={...item,encryptedSecret:'',password:'',hardware:{...item.hardware,privateRemoved:true}};
  itemShape(replacement);await access.replaceItems(s.items.map(x=>x===item?replacement:x),marker(s),{signal:new AbortController().signal});grants.clear();changed();
 }
 return {list,get,assert,records,backupMaterial,saveHardware,assertHardware,removePrivate,import:importIdentity,create:createIdentity,importP12,export:exportIdentity,remove,native,nativeBinding:softwareIdentityBinding,validateMaterial,
  cancel(){grants.clear();for(const controller of active)controller.abort();}};
}
