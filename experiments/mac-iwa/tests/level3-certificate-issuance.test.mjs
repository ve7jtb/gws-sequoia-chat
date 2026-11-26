import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,generateKeyPairSync,sign,verify,X509Certificate} from 'node:crypto';
import {p384} from '@noble/curves/nist.js';
import {issueLevel3Smime} from '../app/provisioning/smime-certificates.js';
import {issueExperimentalNistV6} from '../app/provisioning/nist-v6-certificates.js';

const spki=key=>key.export({format:'der',type:'spki'});
const pqKey=()=>generateKeyPairSync('ml-dsa-65');
const kemKey=()=>generateKeyPairSync('ml-kem-768');
const ecKey=()=>generateKeyPairSync('ec',{namedCurve:'secp384r1'});
const testAddress='level3@example.invalid';

test('Level 3 S/MIME issuer creates four certificates and verifies the signer on each',async()=>{
 const ml=pqKey(),kem=kemKey(),ec=ecKey(),ecdh=ecKey();
 const keys={mlDsa:spki(ml.publicKey).subarray(-1952),mlKem:spki(kem.publicKey).subarray(-1184),
  ecSign:spki(ec.publicKey).subarray(-97),ecAgree:spki(ecdh.publicKey).subarray(-97)};
 const calls=[];
 // Bouncy Castle's composite format uses a DER ECDSA signature after ML-DSA.
 // Stub only the composition step here; the pure certificate is verified by X509Certificate.
 const input={email:testAddress,aliases:['alias@example.invalid'],keys,sign:async({algorithm,tbs})=>{
  calls.push(algorithm);
  if(algorithm.endsWith('.18'))return sign(null,tbs,ml.privateKey);
  return Buffer.concat([sign(null,tbs,ml.privateKey),sign('sha384',tbs,ec.privateKey)]);
 },verify:async({algorithm,tbs,signature,publicKey})=>{
  if(algorithm.endsWith('.18'))return verify(null,tbs,createPublicKey({key:Buffer.from(publicKey),format:'der',type:'spki'}),signature);
  return verify(null,tbs,ml.publicKey,signature.slice(0,3309))&&verify('sha384',tbs,ec.publicKey,signature.slice(3309));
 }};
 const out=await issueLevel3Smime(input);
 assert.deepEqual(calls,['2.16.840.1.101.3.4.3.18','2.16.840.1.101.3.4.3.18','1.3.6.1.5.5.7.6.46','1.3.6.1.5.5.7.6.46']);
 const signing=new X509Certificate(out.pure.signing);
 const encryption=new X509Certificate(out.pure.encryption);
 assert(signing.verify(ml.publicKey));
 assert(encryption.verify(ml.publicKey));
 assert.match(signing.subjectAltName,/alias@example.invalid/);
 assert.deepEqual(signing.keyUsage,['1.3.6.1.5.5.7.3.4']);
 for(const certificate of Object.values(out.hybrid))assert.match(new X509Certificate(certificate).subject,/level3@example.invalid/);
 await assert.rejects(issueLevel3Smime({...input,verify:async()=>false}),/verification failed/);
});

test('draft-05 OpenPGP v6 issuer uses a separate certification key and signing-subkey back signature',async()=>{
 const ca=pqKey(),signer=pqKey(),kem=kemKey();
 const caScalar=p384.utils.randomSecretKey(),signScalar=p384.utils.randomSecretKey(),kemScalar=p384.utils.randomSecretKey();
 const keys={certification:{ec:p384.getPublicKey(caScalar,false),pq:spki(ca.publicKey).subarray(-1952)},
  signing:{ec:p384.getPublicKey(signScalar,false),pq:spki(signer.publicKey).subarray(-1952)},
  encryption:{ec:p384.getPublicKey(kemScalar,false),pq:spki(kem.publicKey).subarray(-1184)}};
 const roles=[];
 const req={email:testAddress,keys,sign:async({role,digest})=>{
  roles.push(role);
  const primary=role==='certification';
  return {ecdsa:p384.sign(digest,primary?caScalar:signScalar,{prehash:false,format:'compact'}),
   mldsa:sign(null,digest,(primary?ca:signer).privateKey)};
 },verify:async({role,digest,publicKey,ecdsa,mldsa})=>
  p384.verify(ecdsa,digest,publicKey.ec,{prehash:false,format:'compact'})&&
  verify(null,digest,(role==='certification'?ca:signer).publicKey,mldsa)};
 try{
  const result=await issueExperimentalNistV6(req);
  assert.deepEqual(roles,['certification','certification','signing','certification','certification']);
  const cert=Buffer.from(result.certificate),tags=[];
  for(let offset=0;offset<cert.length;){
   const tag=cert[offset++]&63,start=cert[offset++];
   const size=start<192?start:((start-192)<<8)+cert[offset++]+192;
   const body=cert.subarray(offset,offset+size);offset+=size;
   tags.push(tag);
   if(tag===6){
    assert.equal(body[0],6);assert.equal(body[5],41);
    const length=Buffer.alloc(4);length.writeUInt32BE(body.length);
    const fingerprint=createHash('sha256').update(Buffer.from([0x9b])).update(length).update(body).digest();
    assert.deepEqual(Buffer.from(result.certificationFingerprint),fingerprint);
   }
  }
  assert.deepEqual(tags,[6,2,13,2,14,2,14,2]);
  await assert.rejects(issueExperimentalNistV6({...req,keys:{...keys,certification:keys.signing}}),/distinct/);
 }finally{caScalar.fill(0);signScalar.fill(0);kemScalar.fill(0);}
});

test('new RFC 9980 v6 certificate passes independent Sequoia policy inspection',async()=>{
 const fs=await import('node:fs');
 const {default:init,inspect_identity}=await import('../wasm/pkg/sequoia_iwa_verify.js');
 const {issueRfc9980V6}=await import('../app/provisioning/nist-v6-certificates.js');
 await init({module_or_path:fs.readFileSync(new URL('../wasm/pkg/sequoia_iwa_verify_bg.wasm',import.meta.url))});
 const ca=pqKey(),signer=pqKey(),kem=kemKey();
 const caEd=generateKeyPairSync('ed25519'),signEd=generateKeyPairSync('ed25519'),kemX=generateKeyPairSync('x25519');
 const keys={certification:{ec:spki(caEd.publicKey).subarray(-32),pq:spki(ca.publicKey).subarray(-1952)},
  signing:{ec:spki(signEd.publicKey).subarray(-32),pq:spki(signer.publicKey).subarray(-1952)},
  encryption:{ec:spki(kemX.publicKey).subarray(-32),pq:spki(kem.publicKey).subarray(-1184)}};
 const byRole=role=>role==='certification'?[ca,caEd]:[signer,signEd];
 const {certificate}=await issueRfc9980V6({email:testAddress,keys,
  sign:async({role,digest})=>{
   const [ml,ed]=byRole(role);
   return {mldsa:sign(null,digest,ml.privateKey),ed25519:sign(null,digest,ed.privateKey)};
  },
  verify:async({role,digest,mldsa,ed25519})=>{
   const [ml,ed]=byRole(role);
   return verify(null,digest,ml.publicKey,mldsa)&&verify(null,digest,ed.publicKey,ed25519);
  },
 });
 const result=JSON.parse(inspect_identity(JSON.stringify({certificate:Buffer.from(certificate).toString('base64')})));
 assert.equal(result.supported,true);
 assert.equal(result.profile,'level3');
 assert.deepEqual(result.emails,[testAddress]);
});
