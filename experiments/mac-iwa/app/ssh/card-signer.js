import {shake256} from '../vendor/hashes/sha3.js';
const text=new TextEncoder(),label=text.encode('COMPSIG-MLDSA44-Ed25519-SHA512');
const join=(...parts)=>{const out=new Uint8Array(parts.reduce((n,b)=>n+b.length,0));let n=0;for(const p of parts){out.set(p,n);n+=p.length;}return out;};
const hash=async b=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',b))].map(x=>x.toString(16).padStart(2,'0')).join('');
const tlv=(tag,b)=>join(Uint8Array.of(tag),b.length<128?Uint8Array.of(b.length):b.length<256?Uint8Array.of(0x81,b.length):Uint8Array.of(0x82,b.length>>8,b.length&255),b);
function components(blob){
 const v=new DataView(blob.buffer,blob.byteOffset,blob.byteLength),n=v.getUint32(0);
 if(n!==19||new TextDecoder().decode(blob.slice(4,4+n))!=='ssh-mldsa44-ed25519'||v.getUint32(4+n)!==1344||blob.length!==8+n+1344)throw Error('Invalid SSH composite public key');
 return {ml:blob.slice(8+n,8+n+1312),ed:blob.slice(8+n+1312)};
}
export async function signCardSsh({identity,publicKey,message,piv,promptPin,guard,onProgress=()=>{}}){
 guard();const {ml,ed}=components(publicKey);
 // Tie the SSH public representation to the authenticated slot hashes BEFORE
 // asking for a PIN. A stale/mismatched saved mapping must not sign anything.
 const spkis=[tlv(0x30,join(Uint8Array.from([0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x11]),tlv(3,join(Uint8Array.of(0),ml)))),tlv(0x30,join(Uint8Array.from([0x30,5,6,3,0x2b,0x65,0x70]),tlv(3,join(Uint8Array.of(0),ed))))];
 for(const [i,slot]of ['8c','8d'].entries()){if(identity.slots.find(k=>k.slot===slot)?.publicKeySha256!==await hash(spkis[i]))throw Error('SSH public key and card mapping differ.');guard();}
 const digest=new Uint8Array(await crypto.subtle.digest('SHA-512',message));guard();
 const representative=join(text.encode('CompositeAlgorithmSignatures2025'),label,Uint8Array.of(0),digest);
 const mu=shake256(join(shake256(ml,{dkLen:64}),Uint8Array.of(0,label.length),label,representative),{dkLen:64});
 const [pq,traditional]=await piv.signSshComponents(identity,[{slot:'8c',algorithm:0xe2,input:mu},{slot:'8d',algorithm:0xe0,input:representative}],promptPin,guard,({slot,touchPolicy})=>onProgress(touchPolicy==='never'?'Signing with slot '+slot.toUpperCase()+'…':'Touch the YubiKey when it flashes — SSH slot '+slot.toUpperCase()+'.'),({instruction})=>onProgress('Still waiting for the YubiKey: '+instruction+'. No retry has been made.'));
 guard();if(pq.length!==2420||traditional.length!==64)throw Error('Invalid SSH card response');return join(pq,traditional);
}
