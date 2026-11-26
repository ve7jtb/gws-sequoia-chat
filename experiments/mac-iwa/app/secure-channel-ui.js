// Application adapter only. The secure-channel/ directory has no dependency on
// this UI, localStorage, mail identities, browser globals or a native helper.
import {openSecureConnection} from './secure-channel/scp11.js';
import {unbase64} from './secure-channel/certificates.js';
const KEY='sequoia_secure_yubikey_connection';
// Compile-time pin: modifying the JSON alone cannot substitute a new root.
const ROOT='62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8';
// Temporary certificate pin, not an independently authenticated manufacturer root.
const BETA_ROOT='e4e054c35c106f51541775d04da2055ca0190c84c1647719133acc6484ea0a54';
const BETA_KEY='sequoia_secure_yubikey_beta_pin';
let required=true,beta=false,active=0;
const trustPromises=new Map();
try{required=localStorage.getItem(KEY)!=='off';}catch{/* Fail closed: new instances require SCP even if preferences cannot be read. */}
const checkbox=document.getElementById('secure-yubikey-connection');
try{beta=localStorage.getItem(BETA_KEY)==='enabled';}catch{/* Production trust is the default. */}
const betaCheckbox=document.getElementById('secure-yubikey-beta');
betaCheckbox.checked=beta;
const status=document.getElementById('secure-yubikey-status');
const report=text=>{status.textContent=(beta?'BETA TEST PIN — manufacturer root not verified. ':'')+text;};
const release=()=>{active--;checkbox.disabled=betaCheckbox.disabled=active>0;};
// Freeze the trust choice for the entire card transaction, including asynchronous
// certificate loading. A checkbox change can never change an in-flight anchor.
betaCheckbox.addEventListener('change',()=>{
 if(active){betaCheckbox.checked=beta;return;}
 beta=betaCheckbox.checked;
 try{localStorage.setItem(BETA_KEY,beta?'enabled':'off');}catch{/* Applies to this window only. */}
 report('Trust selection changed; device not yet authenticated.');
});
checkbox.checked=required;
report(required?'Secure channel required for Web Smart Card; device not yet authenticated.':'Secure channel off. Card traffic is not protected by SCP.');
checkbox.addEventListener('change',()=>{
 if(active){checkbox.checked=required;return;}
 required=checkbox.checked;
 try{localStorage.setItem(KEY,required?'required':'off');}catch{report('Setting applies to this window only; preferences could not be saved.');return;}
 report(required?'Secure channel required for Web Smart Card; device not yet authenticated.':'Secure channel off. Card traffic is not protected by SCP.');
});
async function trust(){
 // Roots/intermediates are signed application assets, never fetched from the
 // card, a remote URL or the operating system's mutable certificate store.
 const selected=beta?'beta':'production',pin=beta?BETA_ROOT:ROOT;
 // Explicit selection, never an automatic retry with a weaker trust anchor.
 if(!trustPromises.has(selected))trustPromises.set(selected,fetch(new URL(beta?'./secure-channel/beta-sd-trust.json':'./secure-channel/yubico-trust.json',import.meta.url)).then(r=>{if(!r.ok)throw Error('Pinned trust store unavailable');return r.json();}).then(t=>{if(t.rootSha256!==pin)throw Error('Unexpected trust-store pin');return {root:unbase64(t.root),rootSha256:pin,requiredPolicyOids:['2a864886fc6b64000a02011e','2a864886fc6b64000a020132','2a864886fc6b64000a02010a'],intermediates:t.intermediates.map(unbase64)};}));
 return trustPromises.get(selected);
}
globalThis.SequoiaSecureChannel={
 isRequired:()=>required,
 // Acquiring the policy locks the checkbox for the entire card transaction.
 // A later UI change cannot downgrade an operation between PIN and signature.
 async acquire(conn){
  active++;checkbox.disabled=betaCheckbox.disabled=true;let secure;
  if(!required)return {connection:conn,close(){release();}};
  try{secure=await openSecureConnection(conn,{trust:await trust(),onStatus:report});return {connection:secure,close(){secure.close();release();report('Secure session closed. SCP11b remains required for the next operation.');}};}
  catch(e){release();report('Secure connection refused: '+e.message);throw e;}
 }
};
