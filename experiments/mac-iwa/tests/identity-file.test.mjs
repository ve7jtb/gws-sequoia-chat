// File classification is a bounded routing decision only. Authentication and
// public-only packet checks remain in the native bundle reader / WASM inspector.
import test from 'node:test';
import assert from 'node:assert/strict';
import {identityFileKind} from '../app/identities/ui.js';
const bytes=text=>new TextEncoder().encode(text);
test('signed bundle magic chooses verified bundle reader regardless of filename',()=>{
 assert.equal(identityFileKind(bytes('PQMZIP01synthetic payload')),'bundle');
 assert.throws(()=>identityFileKind(bytes('PQMAILS1synthetic payload')),/older uncompressed/);
 assert.equal(identityFileKind(bytes('-----BEGIN PGP PUBLIC KEY BLOCK-----')),'certificate');
 // A secret key or invalid file is never guessed safe; the public-only parser
 // receives it and must reject it before a review or persistent write occurs.
 assert.equal(identityFileKind(bytes('-----BEGIN PGP PRIVATE KEY BLOCK-----')),'certificate');
});
test('empty files, oversized certificates and oversized compressed bundles are rejected',()=>{
 assert.throws(()=>identityFileKind(new Uint8Array()),/Choose/);
 assert.throws(()=>identityFileKind(new Uint8Array(262145)),/Choose/);
 const large=new Uint8Array(65537);large.set(bytes('PQMZIP01'));
 assert.throws(()=>identityFileKind(large),/64 KiB/);
 assert.throws(()=>identityFileKind('PQMZIP01'),/Choose/);
});
