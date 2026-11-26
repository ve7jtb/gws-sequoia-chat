// Public-only preflight for optional software-key backup. This module never
// receives a seed, PIN or management key and never generates/imports a key.
// Plans must be regenerated against the live card before any future write;
// a reviewed plan is not itself authorization to overwrite an occupied slot.
const L3=Object.freeze([
 {role:'certification',component:'ML-DSA-65',slot:'86',touch:'always'},
 {role:'certification',component:'Ed25519',slot:'87',touch:'never'},
 {role:'signing',component:'ML-DSA-65',slot:'9c',touch:'always'},
 {role:'signing',component:'Ed25519',slot:'84',touch:'never'},
 {role:'encryption',component:'ML-KEM-768',slot:'9d',touch:'always'},
 {role:'encryption',component:'X25519',slot:'85',touch:'never'},
]);
// Standard user PIV slots only. F9 is the factory attestation slot and is not
// considered user provisioning. PIN/management-key references are not key slots.
export const USER_PIV_SLOTS=Object.freeze(['9a','9c','9d','9e',...Array.from({length:20},(_,i)=>(0x82+i).toString(16))]);
export function planPivBackup({profile,serial,expectedSerial,slots,supportedAlgorithms}){
 if(!/^[1-9][0-9]{5,9}$/.test(serial)||(expectedSerial!==undefined&&serial!==expectedSerial))throw Error('Connected YubiKey does not match the selected backup device.');
 // Do not import the supported half of a composite and quietly omit the other
 // half. In particular YK6 PIV does not currently advertise Ed448 or X448.
 if(profile!=='level3')throw Error('This native backup plan supports Level 3 v6 only. Level 5 Ed448/X448 requires native support or an explicitly reviewed encrypted companion.');
 if(!Array.isArray(slots)||!Array.isArray(supportedAlgorithms))throw Error('Complete live capability and slot inventory required.');
 const seen=new Set();for(const s of slots){if(!s||!USER_PIV_SLOTS.includes(s.slot)||seen.has(s.slot))throw Error('Ambiguous slot inventory.');seen.add(s.slot);}
 if(seen.size!==USER_PIV_SLOTS.length)throw Error('All 24 user PIV slots must be inspected.');
 for(const slot of slots){
  // Refuse even unrelated occupied slots: this is backup to a completely empty
  // card, never augmentation of an existing installation or a reset operation.
  if(slot.keyPresent!==false||slot.certificatePresent!==false)throw Error('YubiKey is not empty: slot '+slot.slot+'.');
 }
 for(const key of L3){
  if(!supportedAlgorithms.includes(key.component))throw Error('Card does not support '+key.component+' import.');
  const slot=slots.find(s=>s.slot===key.slot);
  // Missing metadata, read errors and certificate-only occupancy are not empty.
  if(!slot||slot.keyPresent!==false||slot.certificatePresent!==false)throw Error('Backup requires verified empty slot '+key.slot+'.');
 }
 return {version:1,serial,profile,operation:'import-existing-software-keys',keys:L3.map(k=>({...k,pin:'always'}))};
}
