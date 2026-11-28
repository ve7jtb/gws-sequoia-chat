// A PQ-capable YubiKey must never silently acquire a classical vault wrapper.
// Firmware 5 is the only supported classical fallback. Unknown versions fail
// closed; existing wrappers can still be unlocked for a verified migration.
export function vaultPolicy(version){
 if(/^5\./.test(version))return 'classical';
 if(/^[6-9]\./.test(version))return 'hybrid';
 throw Error('Unsupported YubiKey firmware for new vault wrapping');
}
export async function prepareVaultMaterial({serial,piv,inspectBundle,inspectIdentity,parseCardBundle,store}){
 const caps=await piv.readVaultMaterialViaSmartCard({serial,capabilitiesOnly:true});
 if(vaultPolicy(caps.version)==='classical'){
  const material=await piv.readVaultMaterialViaSmartCard({serial:caps.serial});
  if(material.classical?.algorithm!=='ECDH-P384')throw Error('Older YubiKey needs an existing P-384 wrapping key');
  return {...material,certificate:'',classicalAllowed:true};
 }
 // Native Level 5 uses authenticated PIV metadata for the two vault keys.
 // A null result means slot 9D advertises ML-KEM-768; use the existing v6 path.
 const level5=await piv.readVaultMaterialViaSmartCard({serial:caps.serial,level5Only:true});
 if(level5)return {serial:caps.serial,level5,classicalAllowed:false};
 // Public restoration is mandatory for YK6. Verify signature, serial, every
 // mapped live key and exact certificate profile before saving any inventory.
 const live=await piv.readMappedBundleViaSmartCard(caps.serial,inspectBundle);
 const bundle=await parseCardBundle(live,inspectBundle);
 const candidates=[];
 for(const c of bundle.certificates){
  const info=await inspectIdentity(c.certificate);
  if(info.supported&&info.version===6&&info.profile==='level3'&&info.recipientKey)candidates.push(info);
 }
 if(candidates.length!==1)throw Error('YK6 requires one supported native Level 3 hybrid vault certificate; no classical fallback.');
 const info=candidates[0];
 // Recovery verifies the live bundle without populating the instance being restored.
 if(store){
  const review=await store.previewBundle(bundle);
  if(review.unchanged)store.cancel(review);else await store.save(review,true);
 }
 return {serial:bundle.serial,certificate:info.certificate,classical:null,classicalAllowed:false,
  identity:{...info,serial:bundle.serial,bundleHash:bundle.bundleHash,slots:bundle.slots}};
}

// A saved wrapper pins the recipient subkey fingerprint and card serial. That
// fingerprint covers both public components. The verified bundle inspector
// derives the PIV slot hashes from the same certificate's signed components.
export async function prepareLevel3VaultUnlock({serial,recipientKey,piv,inspectBundle,inspectIdentity,progress}){
 if(!/^[1-9][0-9]{0,9}$/.test(serial)||!(/^[A-F0-9]{64}$/).test(recipientKey))
  throw Error('Missing enrolled Level 3 vault binding; PIN not submitted.');
 const {bundle}=await piv.readLevel3VaultBundle(serial,progress);
 progress?.({stage:'verify'});
 const verified=await inspectBundle(bundle);
 if(verified.bundleSignatureVerified!==true||verified.serial!==serial)throw Error('Invalid signed vault bundle; PIN not submitted.');
 const entries=verified.certificates.filter(entry=>entry.kind==='openpgp'&&entry.profile==='level3');
 if(entries.length!==1)throw Error('Missing unique Level 3 vault certificate; PIN not submitted.');
 const info=await inspectIdentity(entries[0].certificate);
 if(!info.supported||info.version!==6||info.profile!=='level3'||info.recipientKey!==recipientKey)
  throw Error('Hybrid vault recipient changed; PIN not submitted.');
 const slots=['9d','85'].map(slot=>{
  const matches=verified.slots.filter(key=>key.slot===slot);
  if(matches.length!==1||!(/^[a-f0-9]{64}$/).test(matches[0].publicKeySha256))
   throw Error('Invalid signed vault slot mapping; PIN not submitted.');
  return {slot,publicKeySha256:matches[0].publicKeySha256};
 });
 progress?.({stage:'prepare'});
 return {...info,serial,slots,bundleHash:verified.bundleHash};
}
