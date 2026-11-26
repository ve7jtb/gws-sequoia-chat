// Reviewed Level 3 key import and generation over SCP11b.
// PIV management authentication authorizes empty-slot writes only.
import {USER_PIV_SLOTS} from './piv-backup-plan.js';
import {smartcardSigningInput} from './identities/client.js';
const algorithms={'ML-DSA-65':[0xe3,9,32,1952],'Ed25519':[0xe0,7,32,32],'ML-KEM-768':[0xe6,10,64,1184],'X25519':[0xe1,8,32,32],'P-384':[0x14,6,48,97]};
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
 async function inspect(serial){const s=await p.inspectEmptyPivCandidate(serial);return {...s,supportedAlgorithms:s.version?.startsWith('6.')?Object.keys(algorithms):[]};}
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
 function readRaw(data){
  let fields=p.parseBerTlv(data);
  if(fields.has(0x7f49))fields=p.parseBerTlv(fields.get(0x7f49));
  return fields.get(0x86)||fields.get(0x87)||fields.get(0x88);
 }
 async function metadata(conn,target,expected,origin){
  const data=await p.transmitChained(conn,p.buildGetMetadataApdu(parseInt(target.slot,16)));
  if(data.sw!==0x9000)throw Error('Provisioned key metadata missing: '+target.slot);
  const live=p.parseSlotMetadata(data.data),def=algorithms[target.component];
  const raw=readRaw(live.publicKeyBytes);
  if(live.algorithmId!==def[0]||raw?.length!==def[3]||!equal(raw,expected)||
     live.pinPolicy!==target.pin||live.touchPolicy!==target.touch||live.origin!==origin)
   throw Error('Public key, origin or policy mismatch in slot '+target.slot.toUpperCase()+'.');
  return {slot:target.slot,component:target.component,pin:live.pinPolicy,touch:live.touchPolicy,
   origin:live.origin,publicKey:raw,publicKeySha256:await hash(p.pivMetadataToSpki(live))};
 }
 let verified=null;
 async function writeAll(plan,material,{guard,completed,attempting,signal},mode){
  verified=null;
  const expectedOperation=mode==='generate'?'generate-on-card':'import-existing-software-keys';
  if(!plan||plan.operation!==expectedOperation||plan.profile!=='level3'||
     !/^[1-9][0-9]{5,9}$/.test(plan.serial)||!Array.isArray(plan.keys)||
     ![6,8,10].includes(plan.keys.length)||new Set(plan.keys.map(key=>key.slot)).size!==plan.keys.length||
     plan.keys.some(key=>!USER_PIV_SLOTS.includes(key.slot)||!Object.hasOwn(algorithms,key.component)||
      key.pin!=='always'||!['always','never'].includes(key.touch))||
     typeof guard!=='function'||typeof completed!=='function')throw Error('A reviewed Level 3 slot plan is required.');
  if(mode==='import'&&(!Array.isArray(material)||material.length!==plan.keys.length))
   throw Error('Incomplete software key material.');
  for(const target of mode==='import'?plan.keys:[]){
   const k=material.find(k=>k.slot===target.slot),d=algorithms[target.component];
   if(!k||k.algorithm!==target.component||!(k.seed instanceof Uint8Array)||k.seed.length!==d[2]||
      !(k.publicKey instanceof Uint8Array)||k.publicKey.length!==d[3])throw Error('Invalid source component.');
  }
  await p.withPivSession(plan.serial,async(conn,info)=>{
   const version=await p.provisioningFirmware(conn,info);
   if(!version?.startsWith('6.'))throw Error('PQC YubiKey required.');
   // An unauthenticated absent-slot response throws here. It must never be
   // treated as proof that overwriting a card slot is safe.
   await emptyInside(conn,plan);
   await guard();
   await authenticate(conn,guard);
   await guard();
   const matches=[];
   for(const target of plan.keys){
    if(signal?.aborted)throw Error('Provisioning cancelled; preserve the journal.');
    await guard();
    const definition=algorithms[target.component],slot=parseInt(target.slot,16);
    const policy=[tlv(0xaa,new Uint8Array([3])),tlv(0xab,new Uint8Array([target.touch==='always'?2:1]))];
    let expected;
    await attempting?.(target.slot);
    await guard();
    if(mode==='generate'){
     const response=await tx(conn,0x47,0,slot,tlv(0xac,join(tlv(0x80,new Uint8Array([definition[0]])),...policy)));
     await completed(target.slot);
     expected=readRaw(response);
     if(expected?.length!==definition[3])throw Error('Generated public key response could not be verified.');
    }else{
     const key=material.find(key=>key.slot===target.slot);
     const scalar=tlv(definition[1],key.seed);
     const payload=join(scalar,...policy);
     try{await tx(conn,0xfe,definition[0],slot,payload);}
     finally{scalar.fill(0);payload.fill(0);}
     await completed(target.slot);
     expected=key.publicKey;
    }
    matches.push(await metadata(conn,target,expected,mode==='generate'?'generated':'imported'));
   }
   verified={serial:plan.serial,operation:plan.operation,rows:matches};
  });
 }
 async function readPublicKeys(plan){
  if(!verified||plan.serial!==verified.serial||plan.operation!==verified.operation||plan.keys.length!==verified.rows.length)
   throw Error('No matching verified provisioning readback.');
  return p.withPivSession(plan.serial,async conn=>{
   const current=[];
   for(const target of plan.keys){
    const saved=verified.rows.find(key=>key.slot===target.slot);
    if(!saved)throw Error('Unreviewed slot.');
    current.push(await metadata(conn,target,saved.publicKey,saved.origin));
   }
   return current;
  });
 }
 return {
  inspect,readPublicKeys,
  importAll:(plan,material,options)=>writeAll(plan,material,options,'import'),
  generateAll:(plan,options)=>writeAll(plan,[],options,'generate'),
  getSlots(){
   if(!verified)throw Error('Slot writes have not been verified.');
   return verified.rows.map(({slot,publicKeySha256})=>({slot,publicKeySha256}));
  },
 };
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
