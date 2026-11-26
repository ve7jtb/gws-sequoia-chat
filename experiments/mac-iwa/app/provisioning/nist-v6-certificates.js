// RFC 9980 and experimental NIST/Brainpool draft-05 v6 certificate assembly.
// The selected software or hardware provider signs only the digest for the
// specified role and verifies both returned components before assembly.
const octets=(...values)=>Uint8Array.of(...values);
function join(...pieces){
 const result=new Uint8Array(pieces.reduce((sum,piece)=>sum+piece.length,0));
 let offset=0;
 for(const piece of pieces){result.set(piece,offset);offset+=piece.length;}
 return result;
}
const u32=value=>octets(value>>>24,value>>>16,value>>>8,value);
const framed=(tag,body)=>join(octets(tag),u32(body.length),body);
function length(value){
 if(value<192)return octets(value);
 if(value<8384){const n=value-192;return octets((n>>>8)+192,n);}
 return join(octets(255),u32(value));
}
const packet=(id,body)=>join(octets(0xc0|id),length(body.length),body);
const subpacket=(id,body)=>join(length(body.length+1),octets(id),body);
const hash=async(algorithm,value)=>new Uint8Array(await crypto.subtle.digest(algorithm,value));
const equal=(a,b)=>a.length===b.length&&a.every((byte,index)=>byte===b[index]);
const keyBytes=(key,length,label,point=false)=>{
 if(!(key instanceof Uint8Array)||key.length!==length||(point&&key[0]!==4))
  throw Error('Invalid '+label+' public key.');
 return key;
};

async function issueV6({email,keys,sign,verify,created=Math.floor(Date.now()/1000)},nist){
 if(typeof email!=='string'||email.length>254||!/^[^\s<>@,;]+@[^\s<>@,;]+$/.test(email)||
    /[^\x21-\x7e]/.test(email)||!Number.isInteger(created)||created<0||created>0xffffffff||
    typeof sign!=='function'||typeof verify!=='function')throw Error('Invalid OpenPGP v6 issuance request.');
 const certification=keys.certification, signing=keys.signing, encryption=keys.encryption;
 const certEc=keyBytes(certification.ec,nist?97:32,'certification traditional',nist);
 const certPq=keyBytes(certification.pq,1952,'certification ML-DSA-65');
 const signEc=keyBytes(signing.ec,nist?97:32,'signing traditional',nist);
 const signPq=keyBytes(signing.pq,1952,'signing ML-DSA-65');
 const kemEc=keyBytes(encryption.ec,nist?97:32,'agreement traditional',nist);
 const kemPq=keyBytes(encryption.pq,1184,'ML-KEM-768');
 if(equal(certPq,signPq)||equal(certEc,signEc)||equal(certEc,kemEc)||equal(signEc,kemEc))
  throw Error('Certification, signing and agreement components must use distinct keys.');
 const keyPacket=(id,ec,pq)=>join(octets(6),u32(created),framed(id,join(ec,pq)));
 const signatureAlgorithm=nist?41:30;
 const primary=keyPacket(signatureAlgorithm,certEc,certPq);
 const signingSubkey=keyPacket(signatureAlgorithm,signEc,signPq);
 const encryptionSubkey=keyPacket(nist?37:35,kemEc,kemPq);
 const keyFrame=key=>framed(0x9b,key);
 const primaryFrame=keyFrame(primary);
 const certificationFingerprint=await hash('SHA-256',primaryFrame);
 const signingFingerprint=await hash('SHA-256',keyFrame(signingSubkey));
 const userId=new TextEncoder().encode(email);

 // RFC 9580 v6 SHA-512 signatures use a 32-byte salt at the start of
 // hashing. Draft-05 places the fixed-width ECDSA signature before ML-DSA.
 async function signature(type,role,data,extras=[]){
  const fingerprint=role==='certification'?certificationFingerprint:signingFingerprint;
  const publicKey=role==='certification'?certification:signing;
  const salt=crypto.getRandomValues(new Uint8Array(32));
  const hashed=join(subpacket(2,u32(created)),subpacket(33,join(octets(6),fingerprint)),...extras);
  const header=join(octets(6,type,signatureAlgorithm,10),u32(hashed.length),hashed);
  const digest=await hash('SHA-512',join(salt,data,header,octets(6,255),u32(header.length)));
  const result=await sign({role,digest});
  const traditional=nist?result?.ecdsa:result?.ed25519;
  if(!(traditional instanceof Uint8Array)||traditional.length!==(nist?96:64)||
     !(result.mldsa instanceof Uint8Array)||result.mldsa.length!==3309||
     await verify({role,digest,publicKey,...result})!==true)
   throw Error('OpenPGP v6 certificate signature verification failed.');
  return join(header,u32(0),digest.slice(0,2),octets(salt.length),salt,traditional,result.mldsa);
 }

 const certFlags=subpacket(27,octets(1));
 const direct=await signature(0x1f,'certification',primaryFrame,[certFlags]);
 const uid=await signature(0x13,'certification',join(primaryFrame,framed(0xb4,userId)),[certFlags]);
 const signingBinding=join(primaryFrame,keyFrame(signingSubkey));
 const back=await signature(0x19,'signing',signingBinding);
 const boundSigner=await signature(0x18,'certification',signingBinding,[subpacket(27,octets(2)),subpacket(32,back)]);
 const boundKem=await signature(0x18,'certification',join(primaryFrame,keyFrame(encryptionSubkey)),[subpacket(27,octets(0x0c))]);
 return {
  certificate:join(packet(6,primary),packet(2,direct),packet(13,userId),packet(2,uid),
   packet(14,signingSubkey),packet(2,boundSigner),packet(14,encryptionSubkey),packet(2,boundKem)),
  certificationFingerprint,signingFingerprint,
  encryptionFingerprint:await hash('SHA-256',keyFrame(encryptionSubkey)),
 };
}

export const issueExperimentalNistV6=request=>issueV6(request,true);
export const issueRfc9980V6=request=>issueV6(request,false);
