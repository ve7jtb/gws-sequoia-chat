// Public X.509 certificate assembly for the two Level 3 S/MIME profiles.
// Both software and on-card issuance supply the same sign/verify interface.
// Its signer performs the selected complete signature algorithm over TBS DER.
const pqSign='2.16.840.1.101.3.4.3.18';
const pqKem='2.16.840.1.101.3.4.4.2';
const hybridSign='1.3.6.1.5.5.7.6.46';
const hybridKem='1.3.6.1.5.5.7.6.60';
const text=new TextEncoder();

function join(...parts){
 const out=new Uint8Array(parts.reduce((length,part)=>length+part.length,0));
 let offset=0;
 for(const part of parts){out.set(part,offset);offset+=part.length;}
 return out;
}

function der(tag,...parts){
 const content=join(...parts);
 const n=content.length;
 const length=n<128?[n]:n<256?[0x81,n]:[0x82,n>>8,n&255];
 if(n>65535)throw Error('DER value too large.');
 return join(Uint8Array.of(tag,...length),content);
}

function oid(value){
 const [a,b,...arcs]=value.split('.').map(Number);
 const content=[];
 for(const arc of [40*a+b,...arcs]){
  const groups=[arc&127];
  for(let n=arc>>>7;n;n>>>=7)groups.unshift((n&127)|128);
  content.push(...groups);
 }
 return der(6,Uint8Array.from(content));
}

const seq=(...parts)=>der(0x30,...parts);
const algorithm=value=>seq(oid(value));
const bitString=(value,unused=0)=>der(3,Uint8Array.of(unused),value);
const spki=(algorithmOid,value)=>seq(algorithm(algorithmOid),bitString(value));

function requireKey(value,length,name,point=false){
 if(!(value instanceof Uint8Array)||value.length!==length||(point&&value[0]!==4))
  throw Error('Invalid '+name+' public key.');
 return value;
}

function serial(){
 const value=crypto.getRandomValues(new Uint8Array(20));
 // A positive, nonzero serial with a minimal, fixed-length DER encoding.
 value[0]=(value[0]&63)|64;
 return der(2,value);
}

function time(value){
 const date=new Date(value);
 const year=date.getUTCFullYear();
 const digits=date.toISOString().replace(/[-:T]/g,'').slice(0,14);
 return der(year>=1950&&year<2050?0x17:0x18,text.encode((year>=1950&&year<2050?digits.slice(2):digits)+'Z'));
}

function extension(id,value,critical=false){
 return seq(oid(id),...(critical?[der(1,Uint8Array.of(255))]:[]),der(4,value));
}

function addresses(email,aliases){
 if(!Array.isArray(aliases)||aliases.length>4)throw Error('At most four additional S/MIME addresses are supported.');
 const names=[email,...aliases];
 if(new Set(names.map(name=>String(name).toLowerCase())).size!==names.length||
    names.some(name=>typeof name!=='string'||name.length>254||
     !/^[^\s<>@,;]+@[^\s<>@,;]+$/.test(name)||/[^\x21-\x7e]/.test(name)))
  throw Error('Use distinct ASCII mail addresses for S/MIME.');
 return names;
}

function tbsCertificate(names,publicKey,signatureOid,signing,now){
 const name=seq(der(0x31,seq(oid('2.5.4.3'),der(0x0c,text.encode(names[0])))));
 return seq(der(0xa0,der(2,Uint8Array.of(2))),serial(),algorithm(signatureOid),name,
  seq(time(now-60_000),time(now+365*86_400_000)),name,publicKey,
  der(0xa3,seq(
   extension('2.5.29.19',seq(),true),
   extension('2.5.29.15',bitString(Uint8Array.of(signing?0x80:0x20),signing?7:5),true),
   extension('2.5.29.37',seq(oid('1.3.6.1.5.5.7.3.4'))),
   extension('2.5.29.17',seq(...names.map(name=>der(0x81,text.encode(name))))),
  )));
}

export async function issueLevel3Smime({email,aliases=[],keys,sign,verify,now=Date.now()}){
 const names=addresses(email,aliases);
 const mlDsa=requireKey(keys.mlDsa,1952,'ML-DSA-65');
 const mlKem=requireKey(keys.mlKem,1184,'ML-KEM-768');
 const ecSign=requireKey(keys.ecSign,97,'ECDSA P-384',true);
 const ecAgree=requireKey(keys.ecAgree,97,'ECDH P-384',true);
 if(ecSign.every((byte,index)=>byte===ecAgree[index]))throw Error('P-384 signing and agreement require different keys.');
 if(!Number.isSafeInteger(now)||typeof sign!=='function'||typeof verify!=='function')
  throw Error('A certificate signer and verifier are required.');

 async function pair(signatureOid,signingKey,encryptionKey,signatureLength){
  async function issue(subjectKey,signing){
   const tbs=tbsCertificate(names,subjectKey,signatureOid,signing,now);
   const signature=await sign({algorithm:signatureOid,tbs});
   if(!(signature instanceof Uint8Array)||(signatureLength===3309?signature.length!==3309:
       signature.length<3317||signature.length>3413||signature[3309]!==0x30)||
      await verify({algorithm:signatureOid,tbs,signature,publicKey:signingKey})!==true)
    throw Error('S/MIME certificate signature verification failed.');
   return seq(tbs,algorithm(signatureOid),bitString(signature));
  }
  return {signing:await issue(signingKey,true),encryption:await issue(encryptionKey,false)};
 }

 // Composite SPKI uses the concatenated PQ and traditional public encodings.
 return {
  pure:await pair(pqSign,spki(pqSign,mlDsa),spki(pqKem,mlKem),3309),
  hybrid:await pair(hybridSign,spki(hybridSign,join(mlDsa,ecSign)),
   spki(hybridKem,join(mlKem,ecAgree)),null),
 };
}
