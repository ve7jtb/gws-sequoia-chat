// Exercise the shipped WASM parser with all three real public certificate views
// emitted by the adapter's read-only fixture restore. The fixture directory has
// no private keys and can be produced using a public-only mock Card transport.
// This test deliberately never connects a physical YubiKey or changes trust.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import init,{inspect_public} from '../app/wasm/sequoia_iwa_verify.js';
import {createIdentityStore} from '../app/identities/store.js';
import {createMemoryStorage} from '../app/certificates/store.js';

const directory=process.env.IWA_IDENTITY_PUBLIC_FIXTURES;
assert(directory,'IWA_IDENTITY_PUBLIC_FIXTURES must name a restored public fixture directory');
await init({module_or_path:fs.readFileSync(new URL('../app/wasm/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const inspect=certificate=>JSON.parse(inspect_public(JSON.stringify({certificate})));
const metadata=JSON.parse(fs.readFileSync(path.join(directory,'identity.json')));
assert.equal(metadata.format,'sequoia-pqmail-piv-public');assert.equal(metadata.bundleSignatureVerified,true);
const certificates=[['openpgp-v6.asc','OpenPGP v6'],['openpgp-v4-hybrid.asc','OpenPGP v4 hybrid'],['openpgp-v4-classical.asc','OpenPGP v4 classical']].map(([name,label])=>({kind:'openpgp',label,certificate:fs.readFileSync(path.join(directory,name)).toString('base64')}));
const roles=[['9c','OpenPGP signing','ML-DSA-65'],['84','OpenPGP signing','Ed25519'],['9d','OpenPGP decryption','ML-KEM-768'],['85','OpenPGP decryption','X25519'],['86','OpenPGP certification','ML-DSA-65'],['87','OpenPGP certification','Ed25519'],['88','Classical signing','Ed25519'],['89','Classical decryption','X25519'],['83','S/MIME signing','ECDSA P-384'],['82','S/MIME decryption','ECDH P-384']];
const snapshot={format:'sequoia-iwa-identity-preview',version:1,source:'yubikey',serial:String(metadata.serial),bundleHash:createHash('sha256').update(fs.readFileSync(path.join(directory,'certificate-bundle.pqmzip'))).digest('hex'),generation:metadata.generation,certificates,slots:roles.map(([slot,role,algorithm])=>({slot,role,algorithm,publicKeySha256:metadata.publicKeySha256[slot]})),bundleSignatureVerified:true,liveKeysMatched:true,warnings:metadata.warnings};
const storage=createMemoryStorage(),store=createIdentityStore({inspect,storage}),review=await store.previewBundle(snapshot);
assert.deepEqual(review.identity.certificates.map(c=>c.version),[6,4,4]);
assert.equal(review.identity.certificates[0].fingerprint,metadata.fingerprint);
assert.equal(review.identity.certificates[1].fingerprint,metadata.compatibilityFingerprint);
assert.equal(review.identity.certificates[2].fingerprint,metadata.compatibilityFingerprint);
assert.notEqual(review.identity.certificates[1].certificateHash,review.identity.certificates[2].certificateHash);
assert.equal(review.identity.slots.length,10);assert.equal(await storage.read(),null);
await store.save(review,true);const reopened=createIdentityStore({inspect,storage});
assert.deepEqual(await reopened.list(),await store.list());
// A standalone import has canonical public bytes but no hardware ownership
// evidence, even when its fingerprint happens to match a stored bundle view.
const single=await reopened.previewCertificate(certificates[0].certificate);
assert.equal(single.identity.serial,null);assert.deepEqual(single.identity.slots,[]);assert.equal(single.identity.liveKeysMatched,false);
await reopened.save(single,true);assert.equal((await reopened.list()).identities.length,2);
console.log('PASS actual WASM own identities: v6 + v4 hybrid/classical same-primary views, ten public slot mappings, reviewed atomic persistence, restart, and unmapped standalone import');
