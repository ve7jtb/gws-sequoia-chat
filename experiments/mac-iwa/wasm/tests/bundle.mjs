// Exercise the actual browser-target module against public-only BC vectors.
// No native bridge, token, filesystem identity store or private key is used.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {inflateSync,deflateSync} from 'node:zlib';
const variant=process.argv[2]||'pkg';
assert(['pkg','pkg-wide'].includes(variant));
const wasm=await import(new URL(`../${variant}/sequoia_iwa_verify.js`,import.meta.url));
await wasm.default({module_or_path:fs.readFileSync(new URL(`../${variant}/sequoia_iwa_verify_bg.wasm`,import.meta.url))});
const fixture={
 ...JSON.parse(fs.readFileSync(new URL('../../crypto/tests/data/restore-level3.json',import.meta.url))),
 ...JSON.parse(fs.readFileSync(new URL('./data/restore-formats.json',import.meta.url))),
};
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const inspect=bytes=>JSON.parse(wasm.inspect_bundle(JSON.stringify({bundle:bytes.toString('base64')})));
const compress=bytes=>{
 const header=Buffer.alloc(12);header.write('PQMZIP01');header.writeUInt32BE(bytes.length,8);
 return Buffer.concat([header,deflateSync(bytes)]);
};
for(const name of ['pure','hybrid']){
 const stored=Buffer.from(fixture[name],'base64'),preview=inspect(stored);
 assert.deepEqual(Object.keys(preview).sort(),['format','version','source','serial','bundleHash','generation','certificates','slots','bundleSignatureVerified','liveKeysMatched','warnings'].sort());
 assert.equal(preview.serial,'123456');assert.equal(preview.source,'file');assert.equal(preview.generation,0);
 assert.equal(preview.bundleHash,digest(stored));assert.equal(preview.bundleSignatureVerified,true);assert.equal(preview.liveKeysMatched,false);
 assert.equal(preview.certificates.length,3);assert.equal(preview.slots.length,10);
 for(const slot of preview.slots)assert.equal(slot.publicKeySha256,digest(Buffer.from(fixture.keys[slot.slot],'base64')));
 const identity=JSON.parse(wasm.inspect_identity(JSON.stringify({certificate:preview.certificates[0].certificate})));
 assert.equal(identity.fingerprint,fixture.fingerprint.toUpperCase());assert.equal(identity.supported,true);
 const expanded=inflateSync(stored.subarray(12)),signatureStart=12+expanded.readUInt32BE(8)+8;
 for(const offset of [24,signatureStart,...(name==='hybrid'?[signatureStart+3310,expanded.length-1]:[])]){
  const altered=Buffer.from(expanded);altered[offset]^=1;
  assert.throws(()=>inspect(compress(altered)),/Public bundle inspection rejected/);
 }
 for(const bad of [Buffer.concat([stored,Buffer.from([0])]),stored.subarray(0,-1),expanded])assert.throws(()=>inspect(bad));
 const unsupported=Buffer.from(expanded);unsupported.writeUInt32BE(17,20);
 assert.throws(()=>inspect(compress(unsupported)));
 console.log(`PASS ${variant} ${name}: complete public profile and both signature components; no live-key claim`);
}
const legacy=inspect(compress(Buffer.from(fixture.legacy,'base64')));
assert.equal(legacy.certificates.length,1);assert.equal(legacy.slots.length,6);assert.equal(legacy.warnings.length,3);
assert.equal(legacy.liveKeysMatched,false);
assert.throws(()=>inspect(Buffer.alloc(65537)));
assert.throws(()=>wasm.inspect_bundle(JSON.stringify({bundle:fixture.hybrid,liveKeysMatched:true})));
const bomb=compress(Buffer.alloc(65537));bomb.writeUInt32BE(65536,8);assert.throws(()=>inspect(bomb));
console.log(`PASS ${variant} compressed legacy, unsupported profile, oversize/bomb and authority injection rejection`);
