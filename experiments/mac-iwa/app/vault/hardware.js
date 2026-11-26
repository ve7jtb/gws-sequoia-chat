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
 // Public restoration is mandatory for YK6. Verify signature, serial, every
 // mapped live key and exact certificate profile before saving any inventory.
 const live=await piv.readPublicSnapshotViaSmartCard(caps.serial,true,inspectBundle);
 const bundle=await parseCardBundle(live,inspectBundle);
 const candidates=[];
 for(const c of bundle.certificates){
  const info=await inspectIdentity(c.certificate);
  if(info.supported&&info.version===6&&info.profile==='level3'&&info.recipientKey)candidates.push(info);
 }
 if(candidates.length!==1)throw Error('YK6 requires one supported native Level 3 hybrid vault certificate; no classical fallback.');
 const info=candidates[0];
 const review=await store.previewBundle(bundle);
 if(review.unchanged)store.cancel(review);else await store.save(review,true);
 return {serial:bundle.serial,certificate:info.certificate,classical:null,classicalAllowed:false,
  identity:{...info,serial:bundle.serial,bundleHash:bundle.bundleHash,slots:bundle.slots}};
}
