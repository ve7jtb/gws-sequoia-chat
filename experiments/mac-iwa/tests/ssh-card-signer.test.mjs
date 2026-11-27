import test from 'node:test';import assert from 'node:assert/strict';
import {signCardSsh} from '../app/ssh/card-signer.js';import {sshPublicLine} from '../app/vault/ssh-keys.js';
const concat=(...v)=>Uint8Array.from(v.flatMap(x=>[...x]));
const hash=async b=>Buffer.from(await crypto.subtle.digest('SHA-256',b)).toString('hex');
test('SSH card signer binds slots before PIN and prepares composite context',async()=>{
 const ml=new Uint8Array(1312).fill(7),ed=new Uint8Array(32).fill(9),publicKey=Uint8Array.from(Buffer.from(sshPublicLine(ml,ed).split(' ')[1],'base64'));
 // Independently encoded SPKIs: the live-card API checks these same hashes
 // against metadata before VERIFY. No APDU or physical device is used here.
 const mlSpki=concat([0x30,0x82,5,0x32,0x30,0x0b,6,9,0x60,0x86,0x48,1,0x65,3,4,3,0x11,3,0x82,5,0x21,0],ml);
 const edSpki=concat([0x30,0x2a,0x30,5,6,3,0x2b,0x65,0x70,3,0x21,0],ed);
 const identity={serial:'12345678',slots:[{slot:'8c',publicKeySha256:await hash(mlSpki)},{slot:'8d',publicKeySha256:await hash(edSpki)}]};let calls=0;
 const args={identity,publicKey,message:new TextEncoder().encode('SSH transcript'),guard(){},promptPin(){throw Error('No physical PIN allowed in this test')},piv:{async signSshComponents(id,components){calls++;assert.equal(id.serial,identity.serial);assert.deepEqual(components.map(c=>[c.slot,c.algorithm,c.input.length]),[['8c',0xe2,64],['8d',0xe0,127]]);assert.equal(new TextDecoder().decode(components[1].input.slice(0,62)),'CompositeAlgorithmSignatures2025COMPSIG-MLDSA44-Ed25519-SHA512');assert.equal(components[1].input[62],0);return [new Uint8Array(2420),new Uint8Array(64)];}}};
 assert.equal((await signCardSsh(args)).length,2484);assert.equal(calls,1);
 await assert.rejects(signCardSsh({...args,identity:{...identity,slots:identity.slots.map(k=>({...k,publicKeySha256:'0'.repeat(64)}))}}),/differ/);assert.equal(calls,1);
});
