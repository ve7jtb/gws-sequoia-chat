// Reviewed Level 3 software-key import over the existing SCP transport.
// No reset, key generation, PIN change, or management-key change is exposed.
import {USER_PIV_SLOTS} from './piv-backup-plan.js';
import {smartcardSigningInput} from './identities/client.js';
const algorithms={'ML-DSA-65':[0xe3,9,32,1952],'Ed25519':[0xe0,7,32,32],'ML-KEM-768':[0xe6,10,64,1184],'X25519':[0xe1,8,32,32]};
const join=(...parts)=>{const out=new Uint8Array(parts.reduce((n,b)=>n+b.length,0));let at=0;for(const b of parts){out.set(b,at);at+=b.length;}return out;};
const equal=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const hash=async b=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',b))].map(v=>v.toString(16).padStart(2,'0')).join('');
const api=()=>{if(!globalThis.SequoiaSecureChannel?.isRequired())throw Error('Key import requires SCP11b.');if(!globalThis.SequoiaSmartCardPiv)throw Error('Web Smart Card required.');return globalThis.SequoiaSmartCardPiv;};
// AES-ECB for one management challenge block, built using WebCrypto CBC with
// a zero IV. Append a valid padding block for decryption; do not strip bytes
// from unverified ciphertext or use padding errors as authentication success.
async function block(key,data,decrypt=false){
 if(data.length!==16)throw Error('Invalid management challenge');
 const k=await crypto.subtle.importKey('raw',key,'AES-CBC',false,['encrypt','decrypt']),zero=new Uint8Array(16);
 if(!decrypt)return new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC',iv:zero},k,data)).slice(0,16);
 const pad=new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC',iv:data},k,new Uint8Array(16).fill(16))).slice(0,16);
 return new Uint8Array(await crypto.subtle.decrypt({name:'AES-CBC',iv:zero},k,join(data,pad)));
}
export function createPivImporter({promptManagement}){
 const p=api(),tlv=p.encodeBerTlv;
 const tx=async(conn,ins,p1,p2,data)=>{const r=await p.transmitCommandChained(conn,ins,p1,p2,data);if(r.sw!==0x9000)throw Error('PIV command '+ins.toString(16)+' failed: SW='+r.sw.toString(16));return r.data;};
 async function inspect(){const s=await p.inspectEmptyPivCandidate();return {...s,supportedAlgorithms:s.version?.startsWith('6.')?Object.keys(algorithms):[]};}
 async function emptyInside(conn,plan){
  for(const slot of USER_PIV_SLOTS){
   const id=parseInt(slot,16),r=await p.transmitChained(conn,p.buildGetMetadataApdu(id));
   if(![0x6a88,0x6a82].includes(r.sw))throw Error('Card is not verifiably empty: '+slot);
   const object=({'9a':0x5fc105,'9c':0x5fc10a,'9d':0x5fc10b,'9e':0x5fc101})[slot]??(0x5fc10d+id-0x82);
   const c=await p.transmitChained(conn,p.buildGetDataApdu(object));
   if(![0x6a88,0x6a82].includes(c.sw))throw Error('Certificate slot is not verifiably empty: '+slot);
  }
 }
 async function authenticate(conn,guard){
  const m=await p.transmitChained(conn,p.buildGetMetadataApdu(0x9b));if(m.sw!==0x9000)throw Error('Management-key metadata unavailable');
  const type=p.parseBerTlv(m.data).get(1)?.[0],length={8:16,10:24,12:32}[type];if(!length)throw Error('AES management key required; no settings changed.');
  let entered=await promptManagement(length),key,witness,plain,challenge,expected;
  try{
   if(typeof entered!=='string'||!new RegExp('^[a-fA-F0-9]{'+length*2+'}$').test(entered))throw Error('Management key must be '+length+' bytes in hex.');
   await guard();key=Uint8Array.from(entered.match(/../g),v=>parseInt(v,16));entered='';
   const first=await tx(conn,0x87,type,0x9b,tlv(0x7c,tlv(0x80,new Uint8Array())));
   witness=p.parseBerTlv(p.parseBerTlv(first).get(0x7c)).get(0x80);plain=await block(key,witness,true);challenge=crypto.getRandomValues(new Uint8Array(16));
   const second=await tx(conn,0x87,type,0x9b,tlv(0x7c,join(tlv(0x80,plain),tlv(0x81,challenge))));
   const response=p.parseBerTlv(p.parseBerTlv(second).get(0x7c)).get(0x82);expected=await block(key,challenge);
   if(!response||!equal(response,expected))throw Error('Management authentication failed.');
  }finally{entered='';for(const b of [key,witness,plain,challenge,expected])b?.fill(0);}
 }
 async function metadata(conn,key){
  const data=await p.transmitChained(conn,p.buildGetMetadataApdu(parseInt(key.slot,16)));if(data.sw!==0x9000)throw Error('Imported key metadata missing: '+key.slot);
  const m=p.parseSlotMetadata(data.data),def=algorithms[key.algorithm];
  let fields=p.parseBerTlv(m.publicKeyBytes);if(fields.has(0x7f49))fields=p.parseBerTlv(fields.get(0x7f49));
  const raw=fields.get(0x86)||fields.get(0x87)||fields.get(0x88);
  if(m.algorithmId!==def[0]||!raw||!equal(raw,key.publicKey)||m.pinPolicy!=='always'||m.touchPolicy!==(key.slot==='86'||key.slot==='9c'||key.slot==='9d'?'always':'never'))throw Error('Imported public key or PIN policy mismatch: '+key.slot);
  return {slot:key.slot,publicKeySha256:await hash(p.pivMetadataToSpki(m))};
 }
 let verifiedSlots=null;
 async function importAll(plan,material,{guard,completed,signal}){
  verifiedSlots=null;
  for(const target of plan.keys){const k=material.find(k=>k.slot===target.slot),d=algorithms[target.component];if(!k||k.algorithm!==target.component||k.seed.length!==d[2]||k.publicKey.length!==d[3])throw Error('Invalid source component');}
  await p.withPivSession(plan.serial,async(conn,info)=>{
   if(!info.version?.startsWith('6.'))throw Error('PQC YubiKey required.');
   await emptyInside(conn,plan);await guard();await authenticate(conn,guard);await guard();
   const matches=[];
   for(const target of plan.keys){
    if(signal?.aborted)throw Error('Import cancelled; preserve journal and software keys.');await guard();
    const k=material.find(k=>k.slot===target.slot),d=algorithms[k.algorithm];
    const payload=join(tlv(d[1],k.seed),tlv(0xaa,new Uint8Array([3])),tlv(0xab,new Uint8Array([target.touch==='always'?2:1])));
    try{await tx(conn,0xfe,d[0],parseInt(k.slot,16),payload);}finally{payload.fill(0);}
    await completed(k.slot);matches.push(await metadata(conn,k));
   }
   verifiedSlots=matches;
  });
 }
 return {inspect,importAll,getSlots(){if(!verifiedSlots)throw Error('Imports have not been verified.');return structuredClone(verifiedSlots);}};
}
// Private operations for a vault-authenticated hardware binding use the same
// live key hashes, serial checks and masked PIN dialog as existing card keys.
export async function operateImportedKey(op,request,binding,{signal,guard}={}){
 // A dialog can remain open while the vault locks or the account changes.
 // Revalidate after it returns, before the card sees any PIN bytes.
 const check=async()=>{if(signal?.aborted)throw Error('Operation cancelled');if(typeof guard!=='function')throw Error('Vault operation guard required');await guard();if(signal?.aborted)throw Error('Operation cancelled');};
 await check();const p=api();
 const prompt=async details=>{await check();const pin=await globalThis.hardwareTransport.promptPin(details);await check();return pin;};
 if(op==='sign'){
  const {mu}=await smartcardSigningInput({certificate:binding.certificate,signingFingerprint:request.signingFingerprint,digest:request.digest});
  return p.signDigestViaSmartCard({...request,mu},binding,prompt);
 }
 if(op==='decapsulate')return p.decapsulateComponentsViaSmartCard(request,binding,prompt);
 throw Error('Unsupported imported-key operation');
}
