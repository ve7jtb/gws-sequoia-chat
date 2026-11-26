import test from 'node:test';import assert from 'node:assert/strict';
import {silentDiscovery} from '../app/ctap-discovery.js';
test('silent discovery sets UP and UV false and sends no PIN auth',async()=>{
 const id=new Uint8Array([1]);assert.equal(await silentDiscovery(async args=>{
 assert.equal(args.get(5).get('uv'),false);assert.equal(args.get(5).get('up'),false);assert.equal(args.has(6),false);
 return new Map([[1,new Map([['id',id]])]]);},'rp',new Uint8Array(32)),id);
});
test('hidden credential policy requires authenticated discovery, not creation',async()=>{
 for(const ctapStatus of [0x2e,0x36,0x3b,0x2b])assert.equal(await silentDiscovery(async()=>{throw {ctapStatus};},'rp',new Uint8Array(32)),null);
});
test('transport failure stops discovery',async()=>{await assert.rejects(silentDiscovery(async()=>{throw Error('lost');},'rp',new Uint8Array(32)),/lost/);});
