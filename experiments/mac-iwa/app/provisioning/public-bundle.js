// The bundle and the PIV storage objects contain only public data. Both
// formats are shared with the existing PQ Mail bundle readers.
const encode=new TextEncoder();
const ascii=value=>encode.encode(value);
const u32=value=>Uint8Array.of(value>>>24,value>>>16,value>>>8,value);
const blob=value=>join(u32(value.length),value);
const maxSize=65536;
const chunkSize=2048;
export const PROVISIONING_BUNDLE_BANK=0x5f5000;

function join(...parts){
 const bytes=new Uint8Array(parts.reduce((size,part)=>size+part.length,0));
 let offset=0;
 for(const part of parts){bytes.set(part,offset);offset+=part.length;}
 return bytes;
}

export async function encodeLevel3ProvisioningBundle(plan,certificates,sign){
 const {smime,rfc9980,experimentalNist}=certificates;
 if(!smime?.pure||!smime.hybrid)throw Error('Both S/MIME profiles are required in the certificate bundle.');
 const profile=(cert,openPgp)=>join(u32(Number(plan.serial)),Uint8Array.of(0x9c,0x83,0x9d,0x82),
  blob(cert.signing),blob(cert.encryption),blob(openPgp),blob(new Uint8Array()));
 const profiles=join(u32(2),profile(smime.pure,rfc9980),profile(smime.hybrid,new Uint8Array()));
 // The experimental certificate can be recovered as signed public data.
 // Readers without draft-05 support must not activate that optional view.
 const extensions=experimentalNist?join(u32(1),
  blob(ascii('https://github.com/ve7jtb/pq-mail/spec/certificate-set/v1')),Uint8Array.of(0),
  blob(join(u32(1),u32(1),blob(ascii('https://github.com/ve7jtb/pq-mail/spec/openpgp-nist-draft-05')),
   u32(7),blob(experimentalNist.certificate)))):new Uint8Array();
 const payload=join(ascii(experimentalNist?'PQMAILB3':'PQMAILB2'),profiles,extensions);
 // A full pair of v6 certificate views plus the four S/MIME certificates
 // can exceed 64 KiB before compression. Card storage keeps its 64 KiB cap.
 const expandedLimit=experimentalNist?80*1024:maxSize;
 if(payload.length+20+3309>expandedLimit)throw Error('Expanded public certificate bundle exceeds the size limit.');
 const signature=await sign(payload);
 const envelope=join(ascii('PQMAILS1'),blob(payload),u32(0),blob(signature));
 if(envelope.length>expandedLimit)throw Error('Expanded public certificate bundle exceeds the size limit.');
 const compressed=await new Response(new Blob([envelope]).stream().pipeThrough(new CompressionStream('deflate'))).arrayBuffer();
 const stored=join(ascii('PQMZIP01'),u32(envelope.length),new Uint8Array(compressed));
 if(stored.length>maxSize)throw Error('Compressed public certificate bundle exceeds the size limit.');
 return stored;
}

export async function provisioningBundleObjects(bundle){
 if(!(bundle instanceof Uint8Array)||bundle.length<=12||bundle.length>maxSize||
    new TextDecoder().decode(bundle.subarray(0,8))!=='PQMZIP01')
  throw Error('A valid compressed certificate bundle is required.');
 // Fresh cards start at generation 1. The index commits the bundle after all
 // chunks are acknowledged and read back under the management session.
 const generation=join(u32(0),u32(1));
 const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',bundle));
 const chunks=[];
 for(let offset=0;offset<bundle.length;offset+=chunkSize){
  const index=chunks.length;
  chunks.push({tag:PROVISIONING_BUNDLE_BANK+1+index,bytes:join(ascii('PQMCHK01'),generation,u32(index),bundle.subarray(offset,offset+chunkSize))});
 }
 return [...chunks,{tag:PROVISIONING_BUNDLE_BANK,bytes:join(ascii('PQMIDX01'),generation,u32(bundle.length),digest)}];
}
