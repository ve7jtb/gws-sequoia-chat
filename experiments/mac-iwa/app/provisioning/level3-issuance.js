// Both custody paths present public readback and a signer. Private material,
// PINs and the card management key are outside this certificate coordinator.
import {issueLevel3Smime} from './smime-certificates.js';
import {issueExperimentalNistV6} from './nist-v6-certificates.js';

const x509MlDsa65='2.16.840.1.101.3.4.3.18';
const x509Composite='1.3.6.1.5.5.7.6.46';

export async function issueProvisionedLevel3({plan,email,aliases,provider,verify,
 rfc9980,guard,now=Date.now()}){
 if(plan?.profile!=='level3'||plan.certificates?.defaultOpenPgp!=='rfc9980'||
    !['import-existing-software-keys','generate-on-card'].includes(plan.operation)||
    typeof guard!=='function'||typeof rfc9980!=='function')
  throw Error('A reviewed Level 3 certificate plan is required.');
 if(provider?.serial!==plan.serial||provider.operation!==plan.operation)
  throw Error('Certificate signer does not match the reviewed card or provisioning mode.');

 const mappings=plan.certificates;
 await guard();
 const rows=await provider.readPublicKeys(plan);
 await guard();
 if(!Array.isArray(rows)||rows.length!==plan.keys.length)
  throw Error('Incomplete public key readback.');
 const bySlot=new Map(rows.map(row=>[row.slot,row]));
 if(bySlot.size!==rows.length)throw Error('Duplicate public key readback slot.');
 for(const expected of plan.keys){
  const live=bySlot.get(expected.slot);
  if(!live||live.component!==expected.component||live.pin!==expected.pin||
     live.touch!==expected.touch||!(live.publicKey instanceof Uint8Array)||
     (plan.operation==='generate-on-card'&&live.origin!=='generated')||
     (plan.operation==='import-existing-software-keys'&&live.origin!=='imported'))
   throw Error('Public key or policy readback mismatch in slot '+expected.slot.toUpperCase()+'.');
 }
 const publicKey=slot=>{
  const key=bySlot.get(slot)?.publicKey;
  if(!key)throw Error('Certificate plan references an unverified slot.');
  return key.slice();
 };
 const pair=([pq,ec])=>({pq:publicKey(pq),ec:publicKey(ec)});
 async function request(payload){
  await guard();
  if(!payload.slots.length||payload.slots.some(slot=>!bySlot.has(slot)))
   throw Error('Certificate signing role is outside the reviewed slots.');
  const result=await provider.sign({...payload,slots:[...payload.slots],serial:plan.serial});
  await guard();
  return result;
 }

 // Certify the RFC 9980 identity first and preserve it as the default even
 // when both optional certificate families are provisioned.
 const standard=await rfc9980({
  email,aliases,publicKeys:Object.fromEntries(Object.entries(mappings.rfc9980).map(([role,slots])=>[role,slots.map(publicKey)])),
  sign:({role,digest})=>{
   if(role!=='certification'&&role!=='signing')throw Error('Invalid RFC 9980 signing role.');
   return request({format:'rfc9980',role,slots:mappings.rfc9980[role],digest});
  },
 });
 await guard();
 if(!(standard instanceof Uint8Array)||standard.length===0)throw Error('RFC 9980 certificate verification failed.');
 const result={defaultOpenPgp:'rfc9980',rfc9980:standard};

 if(mappings.smime){
  const {pure,hybrid}=mappings.smime;
  result.smime=await issueLevel3Smime({
   email,aliases,now,
   keys:{mlDsa:publicKey(pure.signing[0]),mlKem:publicKey(pure.encryption[0]),
    ecSign:publicKey(hybrid.signing[1]),ecAgree:publicKey(hybrid.encryption[1])},
   sign:({algorithm,tbs})=>{
    if(algorithm!==x509MlDsa65&&algorithm!==x509Composite)throw Error('Unsupported S/MIME certificate signer.');
    return request({format:'smime',role:'signing',slots:algorithm===x509MlDsa65?pure.signing:hybrid.signing,algorithm,tbs});
   },
   verify:verify.smime,
  });
 }
 if(mappings.experimentalNist){
  const nist=mappings.experimentalNist;
  if(nist.draft!==5||nist.signatureAlgorithm!==41||nist.kemAlgorithm!==37)
   throw Error('Unsupported experimental OpenPGP certificate revision.');
  result.experimentalNist=await issueExperimentalNistV6({
   email,created:Math.floor(now/1000),keys:{
    certification:pair(nist.certification),signing:pair(nist.signing),encryption:pair(nist.encryption),
   },
   sign:({role,digest})=>request({format:'openpgp-nist-draft-05',role,slots:nist[role],digest}),
   verify:verify.experimentalNist,
  });
 }
 await guard();
 return result;
}
