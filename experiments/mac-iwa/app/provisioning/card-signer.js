import {shake256} from '../vendor/hashes/sha3.js';
import {p384} from '../vendor/curves/nist.js';

const text=new TextEncoder();
const compositeOid='1.3.6.1.5.5.7.6.46';
const pureOid='2.16.840.1.101.3.4.3.18';
const label=text.encode('COMPSIG-MLDSA65-ECDSA-P384-SHA512');

function join(...parts){
 const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));
 let offset=0;
 for(const p of parts){out.set(p,offset);offset+=p.length;}
 return out;
}
const hash=async(algorithm,input)=>new Uint8Array(await crypto.subtle.digest(algorithm,input));
const mu=(key,context,message)=>shake256(join(shake256(key,{dkLen:64}),Uint8Array.of(0,context.length),context,message),{dkLen:64});

// Composite S/MIME executes both component operations over the exact LAMPS
// transcript. Verification uses the same transcript and the reviewed keys.
export async function smimeSignatureInput(algorithm,tbs){
 if(algorithm===pureOid)return {context:new Uint8Array(),message:tbs};
 if(algorithm!==compositeOid)throw Error('Unsupported S/MIME certificate signer.');
 const message=join(text.encode('CompositeAlgorithmSignatures2025'),label,Uint8Array.of(0),
  await hash('SHA-512',tbs));
 return {context:label,message,ecDigest:await hash('SHA-384',message)};
}

// The certificate builders name reviewed roles, never a freely selected
// private slot. Enforce that slot mapping again at the card boundary.
export function createLevel3CardSigner({piv,plan,readback,promptPin,guard}){
 const identity={serial:plan.serial,slots:readback.map(({slot,publicKeySha256})=>({slot,publicKeySha256}))};

 return async function sign(request){
  const {format,role,slots,serial}=request;
  let expected,context=new Uint8Array(),message=request.digest,ecDigest;
  if(format==='smime'){
   if(role!=='signing'||!(request.tbs instanceof Uint8Array)||request.tbs.length>32768)
    throw Error('Invalid S/MIME certificate signing request.');
   const smime=plan.certificates.smime;
   expected=request.algorithm===pureOid?smime?.pure.signing:smime?.hybrid.signing;
   ({context,message,ecDigest}=await smimeSignatureInput(request.algorithm,request.tbs));
  }else if(format==='openpgp-nist-draft-05'||format==='rfc9980'){
   if(!['certification','signing'].includes(role)||!(message instanceof Uint8Array)||message.length!==64)
    throw Error('Invalid OpenPGP certificate signing request.');
   expected=(format==='rfc9980'?plan.certificates.rfc9980:plan.certificates.experimentalNist)?.[role];
   // P-384 ECDSA takes the leftmost 384 bits of the OpenPGP digest.
   if(format==='openpgp-nist-draft-05')ecDigest=message.slice(0,48);
  }
  if(!expected||!Array.isArray(slots)||serial!==plan.serial||slots.join()!==expected.join())
   throw Error('Certificate signing request does not match the reviewed roles.');
  const pq=readback.find(row=>row.slot===slots[0]&&row.component==='ML-DSA-65');
  if(!pq||pq.publicKey.length!==1952)throw Error('Missing reviewed ML-DSA-65 key.');
  const components=[{slot:pq.slot,algorithm:0xe3,input:mu(pq.publicKey,context,message)}];
  if(slots.length===2){
   const traditional=readback.find(row=>row.slot===slots[1]);
   const ed=format==='rfc9980';
   if(traditional?.component!==(ed?'Ed25519':'P-384'))
    throw Error('Wrong reviewed traditional signing key.');
   components.push({slot:traditional.slot,algorithm:ed?0xe0:0x14,input:ed?message:ecDigest});
  }
  await guard();
  const [mldsa,traditional]=await piv.signProvisioningComponents(identity,components,promptPin,guard);
  if(format==='smime')return traditional?join(mldsa,traditional):mldsa;
  if(format==='rfc9980')return {mldsa,ed25519:traditional};
  return {mldsa,ecdsa:p384.Signature.fromBytes(traditional,'der').toBytes('compact')};
 };
}
