// Select a custody provider explicitly. Hardware snapshots keep their original
// shape and native authorization; a software failure must never try a YubiKey.
// Only public metadata crosses this selector. Secret files/passwords belong to
// the encrypted vault and the software provider's one-operation worker.
const fail=message=>{throw Error(message);};
const digest=async value=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',
 Uint8Array.from(atob(value),c=>c.charCodeAt(0))))].map(b=>b.toString(16).padStart(2,'0')).join('');
export const isSoftware=identity=>identity?.provider==='software';

export function createProviderSelection({hardware,software,match}){
 const provider=snapshot=>{
  if(isSoftware(snapshot))return software()||fail('Unlock the software identity vault first.');
  if(snapshot&&Object.hasOwn(snapshot,'provider'))fail('Unknown identity provider.');
  return hardware;
 };
 async function list(account){
  const card=await hardware.list(account),local=software()?await software().list(account):{choices:[],revision:0};
  const choices=[...card.choices,...local.choices];
  if(new Set(choices.map(c=>c.id)).size!==choices.length)fail('Ambiguous identity identifier.');
  return {choices,revision:{hardware:card.revision,software:local.revision}};
 }
 const assert=snapshot=>provider(snapshot).assert(snapshot);
 return {
  list,assert,
  async get(id,account){
   const value=(await list(account)).choices.find(c=>c.id===id);
   if(!value)fail('Select a matching saved YubiKey identity, or unlock and import a software OpenPGP identity.');
   await assert(value);return value;
  },
  nativeBinding:snapshot=>provider(snapshot).nativeBinding(snapshot),
  validateMaterial:(material,snapshot,kind)=>provider(snapshot).validateMaterial(material,snapshot,kind),
  async match(cipher,account){
   const {choices}=await list(account);
   if(!choices.length)fail('Unlock a software identity or restore a matching YubiKey identity before decrypting.');
   const result=await match({cipher,candidates:choices.map(c=>({id:c.id,certificate:c.certificate}))});
   const cipherHash=await digest(cipher),matched=[];
   if(result.cipherHash!==cipherHash||!Array.isArray(result.matches))fail('Recipient match is not bound to this message.');
   for(const found of result.matches){
    const selected=choices.find(c=>c.id===found.id);
    if(!selected||matched.some(c=>c.id===found.id)||selected.fingerprint!==found.fingerprint||
       selected.certificateHash!==found.certificateHash||selected.recipientKey!==found.recipientKey||
       found.recipientKey!==result.recipientKey)fail('Invalid recipient identity match.');
    await assert(selected);matched.push(selected);
   }
   if(!matched.length)fail('No unlocked software identity or saved YubiKey identity matches this message.');
   // Identical public keys in two custody providers require a user choice. Do
   // not prefer software silently or retry a failed hardware key in software.
   return {choices:matched,cipherHash,recipientKey:result.recipientKey};
  }
 };
}
