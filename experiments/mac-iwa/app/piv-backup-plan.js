import {LEVEL3_SMIME_SLOTS} from './vault/level3-smime-keys.js';
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
export function planPivBackup(request){
 return planLevel3Provisioning({...request,mode:'backup',includeSmime:false,includeExperimentalNist:false});
}

/** For fresh writes, bind the layout to an independently verified empty inventory. */
export function planLevel3Provisioning({slots,supportedAlgorithms,...options}){
 const plan=level3Layout(options);
 if(!Array.isArray(slots)||!Array.isArray(supportedAlgorithms))throw Error('Complete live capability and slot inventory required.');
 const seen=new Set();for(const s of slots){if(!s||!USER_PIV_SLOTS.includes(s.slot)||seen.has(s.slot))throw Error('Ambiguous slot inventory.');seen.add(s.slot);}
 if(seen.size!==USER_PIV_SLOTS.length)throw Error('All 24 user PIV slots must be inspected.');
 for(const slot of slots){
  // Refuse even unrelated occupied slots: this is backup to a completely empty
  // card, never augmentation of an existing installation or a reset operation.
  if(slot.keyPresent!==false||slot.certificatePresent!==false)throw Error('YubiKey is not empty: slot '+slot.slot+'.');
 }
 for(const key of plan.keys){
  if(!supportedAlgorithms.includes(key.component))throw Error('Card does not support '+key.component+' for the selected provisioning mode.');
 }
 return plan;
}

// Certificate-only recovery verifies each occupied slot against this layout.
export function level3Layout({profile,serial,expectedSerial,
 mode='backup',includeSmime=false,includeExperimentalNist=false,includeSsh=false}){
 if(!['backup','on-card'].includes(mode)||typeof includeSmime!=='boolean'||typeof includeExperimentalNist!=='boolean'||typeof includeSsh!=='boolean')
  throw Error('Unknown Level 3 provisioning option.');
 if(!/^[1-9][0-9]{5,9}$/.test(serial)||(expectedSerial!==undefined&&serial!==expectedSerial))throw Error('Connected YubiKey does not match the selected backup device.');
 // Do not import the supported half of a composite and quietly omit the other
 // half. In particular YK6 PIV does not currently advertise Ed448 or X448.
 if(profile!=='level3')throw Error('This native backup plan supports Level 3 v6 only. Level 5 Ed448/X448 requires native support or an explicitly reviewed encrypted companion.');
 const keys=[...L3];
 // The message component slots are shared between the optional S/MIME and
 // experimental OpenPGP views. P-384 signing and agreement remain distinct.
 if(includeSmime||includeExperimentalNist)keys.push(
  {role:'signing',component:'P-384',slot:LEVEL3_SMIME_SLOTS.signing,touch:'never'},
  {role:'encryption',component:'P-384',slot:LEVEL3_SMIME_SLOTS.agreement,touch:'never'},
 );
 // The draft certificate gets its own certification pair. Neither its PQ
 // nor its traditional component can be the message signer or RFC 9980 CA.
 if(includeExperimentalNist)keys.push(
  {role:'nist-certification',component:'ML-DSA-65',slot:'8a',touch:'always'},
  {role:'nist-certification',component:'P-384',slot:'8b',touch:'never'},
 );
 // Independent SSH pair: the PQ component enforces user presence.
 if(includeSsh)keys.push({role:'ssh-signing',component:'ML-DSA-44',slot:'8c',touch:'always'},
  {role:'ssh-signing',component:'Ed25519',slot:'8d',touch:'never'});
 const plan={version:1,serial,profile,operation:mode==='backup'
  ?'import-existing-software-keys':'generate-on-card',keys:keys.map(k=>({...k,pin:'always'}))};
 // Leave the existing six-key import plan byte-for-byte compatible.
 if(mode==='on-card'||includeSmime||includeExperimentalNist)plan.certificates={
  defaultOpenPgp:'rfc9980',
  rfc9980:{certification:['86','87'],signing:['9c','84'],encryption:['9d','85']},
  ...(includeSmime?{smime:{pure:{signing:['9c'],encryption:['9d']},
   hybrid:{signing:['9c',LEVEL3_SMIME_SLOTS.signing],encryption:['9d',LEVEL3_SMIME_SLOTS.agreement]}}}:{}),
  ...(includeExperimentalNist?{experimentalNist:{draft:5,signatureAlgorithm:41,kemAlgorithm:37,
   certification:['8a','8b'],signing:['9c',LEVEL3_SMIME_SLOTS.signing],encryption:['9d',LEVEL3_SMIME_SLOTS.agreement]}}:{}),
 };
 if(includeSsh)plan.ssh={algorithm:'ssh-mldsa44-ed25519',signing:['8c','8d']};
 return plan;
}
