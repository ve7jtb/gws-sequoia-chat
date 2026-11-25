import test from 'node:test';
import assert from 'node:assert/strict';
import {derive,verify} from '../app/preview-sign.js';
import {p256} from '../app/vendor/curves/nist.js';
const raw=h=>new Uint8Array(Buffer.from(h,'hex'));
const cose=h=>{const b=raw(h);return new Map([[1,2],[-1,1],[-2,b.slice(1,33)],[-3,b.slice(33)]]);};
// Independent published python-fido2 ARKG vector, also used by Yubico's Rust
// device test. This detects domain-label, HKDF and scalar-reduction mistakes.
test('ARKG public derivation matches Yubico reference vector',()=>{
 const master=new Map([[-3,-7],[-1,cose('046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7')],[-2,cose('04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35')]]);
 const result=derive(master,raw('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),new TextEncoder().encode('ARKG-P256.test vectors'));
 assert.equal(Buffer.from(result.publicKey).toString('hex'),'04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd');
});
test('signature verification rejects altered data',()=>{
 const key=new Uint8Array(32).fill(1),message=new Uint8Array([1,2,3]);
 const signature=p256.sign(message,key,{format:'der'}),pub=p256.getPublicKey(key,false);
 assert.equal(verify(signature,message,pub),true);assert.equal(verify(signature,new Uint8Array([1,2,4]),pub),false);
});
