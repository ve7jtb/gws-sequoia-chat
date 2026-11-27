// Private component records live only inside the authenticated vault. Public
// SSH mappings never contain seeds. Each component has an independent seed.
export function validateSshKeys(keys){
 if(!keys||keys.version!==1||keys.entropy!=='prf-mixed-v1'||Object.keys(keys).sort().join()!=='ed,entropy,pq,version')throw Error('Invalid SSH key record');
 for(const [role,slot,algorithm,size] of [['pq','8c','ML-DSA-44',1312],['ed','8d','Ed25519',32]]){
  const k=keys[role];
  if(!k||Object.keys(k).sort().join()!=='algorithm,publicKey,seed,slot'||k.slot!==slot||k.algorithm!==algorithm)throw Error('Invalid SSH component');
  for(const [name,n] of [['seed',32],['publicKey',size]]){
   if(typeof k[name]!=='string'||atob(k[name]).length!==n||btoa(atob(k[name]))!==k[name])throw Error('Invalid SSH key encoding');
  }
 }
 return keys;
}
// An SSH public key is the algorithm string followed by one concatenated
// composite public-key string. It contains no SSH certificate or CA signature.
export function sshPublicLine(pq,ed){
 if(pq.length!==1312||ed.length!==32)throw Error('Invalid SSH public components');
 const string=b=>{const out=new Uint8Array(4+b.length);new DataView(out.buffer).setUint32(0,b.length);out.set(b,4);return out;};
 const algorithm='ssh-mldsa44-ed25519',name=string(new TextEncoder().encode(algorithm));
 const composite=new Uint8Array(pq.length+ed.length);composite.set(pq);composite.set(ed,pq.length);
 const key=string(composite),out=new Uint8Array(name.length+key.length);out.set(name);out.set(key,name.length);
 return algorithm+' '+btoa(String.fromCharCode(...out));
}
