// Resolve a usable own identity from the IWA's public inventory. Stored slot
// labels are never authority: native preparation independently authenticates
// the live signed bundle and derives its supported hardware mapping.
const ordered=v=>Array.isArray(v)?v.map(ordered):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,ordered(v[k])])):v;
const same=(a,b)=>JSON.stringify(ordered(a))===JSON.stringify(ordered(b));
const hash=async bytes=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
const fail=message=>{throw Error(message);};
export function nativeIdentity(snapshot){
 return {serial:snapshot.serial,bundleHash:snapshot.bundleHash,fingerprint:snapshot.fingerprint,
  certificateHash:snapshot.certificateHash,email:snapshot.email,
  // A v5 compatibility view is local rather than stored in the normal bundle;
  // ultra-compact companions also require the exact verified public cache. The
  // native verifier treats these bytes as untrusted and matches their keys to
  // the fresh authenticated card manifest before permitting any private work.
  ...((snapshot.version===5||snapshot.companion)?{certificate:snapshot.certificate}:{})};
}

/** A selection is a revision-bound public snapshot, not a native grant.
 * Re-read it before PIN submission, after a private operation, and before send
 * or export. Removing/replacing an identity in another window invalidates an
 * earlier review even if its serial or primary fingerprint stays the same.
 */
export function createIdentitySelection({store,inspect,match}){
 async function list(account){
  if(typeof account!=='string'||!account.includes('@'))fail('A configured sending account is required.');
  const inventory=await store.list(),choices=[];
  for(const identity of inventory.identities){
   if(!identity.serial||!identity.bundleSignatureVerified||!identity.liveKeysMatched)continue;
   for(const certificate of identity.certificates){
    if(![4,5,6].includes(certificate.version))continue;
    const info=await inspect(certificate.certificate);
    // The public parser determines the certificate's supported packet profile.
    // Selection never turns that metadata into card authority: native material
    // preparation independently re-reads the signed manifest and every component.
    if(!info.supported||!info.emails.includes(account.toLowerCase()))continue;
    const version=info.version??certificate.version;
    if(version!==certificate.version||info.fingerprint.length!==(version===4?40:64))fail('Saved own certificate version changed.');
    if(info.fingerprint!==certificate.fingerprint||info.certificateHash!==certificate.certificateHash)fail('Saved own certificate integrity check failed.');
    const id=await hash(new TextEncoder().encode(identity.id+'\n'+certificate.certificateHash+'\n'+account.toLowerCase()));
    choices.push({id,identityId:identity.id,revision:inventory.revision,serial:identity.serial,
     bundleHash:identity.bundleHash,certificate:info.certificate,certificateHash:info.certificateHash,
     fingerprint:info.fingerprint,email:account.toLowerCase(),signingFingerprint:info.signingFingerprint,
     recipientKey:info.recipientKey,algorithms:info.algorithms,slots:identity.slots,
     version,profile:info.profile||certificate.profile||'level3',
     signingAlgorithm:info.signingAlgorithm||info.algorithms[0],
     encryptionAlgorithm:info.encryptionAlgorithm||info.algorithms.at(-1),
     pqSigning:info.pqSigning??version===6,pqEncryption:info.pqEncryption??info.hybridContact,
     ...(certificate.components?{components:certificate.components}:{}),
     ...(identity.companion?{companion:identity.companion}:{}),
     custody:identity.companion?'hardware-companion':'hardware'});
   }
  }
  return {choices,revision:inventory.revision};
 }
 async function get(id,account){
  const selected=(await list(account)).choices.find(c=>c.id===id);
  if(!selected)fail('Select a saved supported YubiKey identity for this account. Restore its certificate bundle in Identities first.');
  return selected;
 }
 async function assert(snapshot){
  if(!snapshot||!same(await get(snapshot.id,snapshot.email),snapshot))fail('Own identity changed; prepare or open the message again.');
  return true;
 }
 return {
  list,get,assert,nativeBinding:nativeIdentity,
  async validateMaterial(material,snapshot,kind){
   await assert(snapshot);
   if(!material||!same(material.identity,nativeIdentity(snapshot)))fail('Native identity selection changed.');
   const raw=kind==='signing'?material.senderCertificate:material.recipientCertificate;
   const inspected=await inspect(raw);
   if(inspected.certificateHash!==snapshot.certificateHash||inspected.fingerprint!==snapshot.fingerprint||
      !inspected.supported||!inspected.emails.includes(snapshot.email))fail('Native certificate differs from the selected identity.');
   // Material profile labels are rechecked against authenticated public parsing.
   // They only permit the matching browser wire protocol; they never choose a
   // native slot or allow a signature request to change its algorithm.
   if(material.hardwareProfile!==undefined&&material.hardwareProfile!==snapshot.profile)fail('Native hardware profile differs from the selected identity.');
   if(kind==='signing'?(material.senderEmail!==snapshot.email||material.signingFingerprint!==snapshot.signingFingerprint):material.recipientKey!==snapshot.recipientKey)fail('Native operation key differs from the selected identity.');
   await assert(snapshot);return material;
  },
  async match(cipher,account){
   const {choices}=await list(account);
   if(!choices.length)fail('Restore a supported identity for this account in Identities before decrypting.');
   // The public-only WASM matcher sees every candidate certificate, never an
   // authenticator or PIN. Its named recipient fingerprint determines the set
   // to present; multiple devices holding that public key require user choice.
   const result=await match({cipher,candidates:choices.map(c=>({id:c.id,certificate:c.certificate}))});
   const cipherHash=await hash(Uint8Array.from(atob(cipher),c=>c.charCodeAt(0)));
   if(result.cipherHash!==cipherHash||!Array.isArray(result.matches))fail('Recipient match is not bound to this message.');
   const matched=[];
   for(const found of result.matches){
    const selected=choices.find(c=>c.id===found.id);
    if(!selected||matched.some(c=>c.id===found.id)||selected.fingerprint!==found.fingerprint||selected.certificateHash!==found.certificateHash||selected.recipientKey!==found.recipientKey||found.recipientKey!==result.recipientKey)fail('Invalid recipient identity match.');
    await assert(selected);matched.push(selected);
   }
   if(!matched.length)fail('No saved YubiKey identity matches this encrypted message. Restore the recipient’s certificate bundle first.');
   return {choices:matched,cipherHash,recipientKey:result.recipientKey};
  }
 };
}
