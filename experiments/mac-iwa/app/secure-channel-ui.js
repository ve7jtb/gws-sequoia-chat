// Application adapter only. The secure-channel/ directory has no dependency on
// this UI, localStorage, mail identities, browser globals or a native helper.
import {openSecureConnection} from './secure-channel/scp11.js';
import {unbase64} from './secure-channel/certificates.js';
const KEY='sequoia_secure_yubikey_connection';
// Compile-time pin: modifying the JSON alone cannot substitute a new root.
const ROOT='62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8';
let required=false,active=0,trustPromise;
try{required=localStorage.getItem(KEY)==='required';}catch{/* Default remains opt-in on a first installation. */}
const checkbox=document.getElementById('secure-yubikey-connection');
const status=document.getElementById('secure-yubikey-status');
const report=text=>{status.textContent=text;};
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
 trustPromise??=fetch(new URL('./secure-channel/yubico-trust.json',import.meta.url)).then(r=>{if(!r.ok)throw Error('Pinned trust store unavailable');return r.json();}).then(t=>{if(t.rootSha256!==ROOT)throw Error('Unexpected trust-store pin');return {root:unbase64(t.root),rootSha256:ROOT,requiredPolicyOids:['2a864886fc6b64000a02011e','2a864886fc6b64000a020132','2a864886fc6b64000a02010a'],intermediates:t.intermediates.map(unbase64)};});return trustPromise;
}
globalThis.SequoiaSecureChannel={
 isRequired:()=>required,
 // Acquiring the policy locks the checkbox for the entire card transaction.
 // A later UI change cannot downgrade an operation between PIN and signature.
 async acquire(conn){
  active++;checkbox.disabled=true;let secure;
  if(!required)return {connection:conn,close(){active--;checkbox.disabled=active>0;}};
  try{secure=await openSecureConnection(conn,{trust:await trust(),onStatus:report});return {connection:secure,close(){secure.close();active--;checkbox.disabled=active>0;report('Secure session closed. SCP11b remains required for the next operation.');}};}
  catch(e){active--;checkbox.disabled=active>0;report('Secure connection refused: '+e.message);throw e;}
 }
};
