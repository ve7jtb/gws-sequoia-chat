// Exercise the shipped browser-target inspector, then drive the certificate
// store with its real results. The native fixture executable generates only
// disposable software keys in a private temporary directory, removed in finally.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import init,{inspect_public} from '../pkg/sequoia_iwa_verify.js';
import {createCertificateStore,createMemoryStorage,migrationDigest} from '../../app/certificates/store.js';
await init({module_or_path:fs.readFileSync(new URL('../pkg/sequoia_iwa_verify_bg.wasm',import.meta.url))});
const fixture=process.env.IWA_SIGNING_FIXTURE_BIN,publicFixtures=process.env.IWA_PUBLIC_TEST_FIXTURES;
assert(fixture&&publicFixtures,'IWA_SIGNING_FIXTURE_BIN and IWA_PUBLIC_TEST_FIXTURES required');
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'iwa-public-certificate-test-'));
try{
 const generated=spawnSync(fixture,['generate',directory],{encoding:'utf8'});assert.equal(generated.status,0,generated.stderr);
 const own=fs.readFileSync(path.join(directory,'sender-public.pgp')),peer=fs.readFileSync(path.join(directory,'recipient-public.pgp'));
 const secret=fs.readFileSync(path.join(directory,'sender-secret.pgp'));
 const inspect=certificate=>JSON.parse(inspect_public(JSON.stringify({certificate})));
 const inspected=inspect(own.toString('base64'));
 assert.equal(inspected.version,6);assert.equal(inspected.fingerprint.length,64);assert.equal(inspected.hybridContact,true);
 assert.deepEqual(inspected.emails,['test@example.invalid']);assert.deepEqual(Buffer.from(inspected.certificate,'base64'),own);
 assert.throws(()=>inspect(secret.toString('base64')));
 assert.throws(()=>inspect(Buffer.concat([own,peer]).toString('base64')));
 assert.throws(()=>inspect(Buffer.from('not a certificate').toString('base64')));
 assert.throws(()=>inspect(''));assert.throws(()=>inspect(Buffer.alloc(262145).toString('base64')));
 assert.throws(()=>inspect_public(JSON.stringify({certificate:own.toString('base64'),trusted:true})));
 const armored='-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n'+own.toString('base64').match(/.{1,64}/g).join('\n')+'\n-----END PGP PUBLIC KEY BLOCK-----\n';
 assert.equal(inspect(Buffer.from(armored).toString('base64')).certificate,inspected.certificate);
 assert.throws(()=>inspect(Buffer.from(armored+armored).toString('base64')));
 const v4=JSON.parse(fs.readFileSync(path.join(publicFixtures,'v4.json'))).certificates[0];
 const classical=inspect(v4);assert.equal(classical.version,4);assert.equal(classical.fingerprint.length,40);assert.equal(classical.hybridContact,false);
 const storage=createMemoryStorage(),store=createCertificateStore({inspect,storage});
 await store.save(v4);assert.deepEqual((await store.material()).bindings,[]);
 const trusted=await store.trust(own.toString('base64'),'test@example.invalid',inspected.fingerprint,true);
 assert.equal(trusted.contacts.length,1);const snapshot=trusted.contacts[0];assert.equal(snapshot.certificate,inspected.certificate);
 assert.deepEqual(await store.assertContact(snapshot),snapshot);
 await assert.rejects(store.trust(own.toString('base64'),'forged@example.invalid',inspected.fingerprint,true));
 const reopened=createCertificateStore({inspect,storage});assert.equal((await reopened.trustedContact(snapshot.id)).fingerprint,inspected.fingerprint);
 await reopened.untrust(inspected.fingerprint,'test@example.invalid',true);await assert.rejects(store.assertContact(snapshot));
 const migration={version:1,certificates:[v4,own.toString('base64')],saved:[classical.fingerprint,inspected.fingerprint],bindings:[{email:'test@example.invalid',fingerprint:inspected.fingerprint}]};migration.sourceDigest=await migrationDigest(migration);
 const migrated=createCertificateStore({inspect,storage:createMemoryStorage()});await migrated.importLegacy(migration,true);
 assert.equal((await migrated.list()).contacts.length,1);assert.equal((await migrated.list()).certificates.length,2);
 console.log('PASS real WASM certificate inspection/store: v4/v6 policy, canonical armor, secret/multiple-certificate rejection, exact email trust, persistence, stale snapshot rejection, and reviewed migration');
}finally{
 // Cleanup is limited to this freshly generated disposable directory. It never
 // references an installed application identity or the user's certificate store.
 fs.rmSync(directory,{recursive:true,force:true});
}
