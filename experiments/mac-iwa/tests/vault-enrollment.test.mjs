import test from 'node:test';
import assert from 'node:assert/strict';
import {discoverOrCreate,hasMatchingPiv} from '../app/vault/enrollment.js';
test('existing credential is reused without creation or confirmation',async()=>{
 const r=await discoverOrCreate({assertExisting:async()=>42,createNew:()=>assert.fail(),confirmCreate:()=>assert.fail()});assert.deepEqual(r,{result:42,created:false});
});
test('only explicit no-credential and approval permit creation',async()=>{
 const r=await discoverOrCreate({assertExisting:async()=>{throw {ctapStatus:0x2e};},confirmCreate:()=>true,createNew:async()=>7});assert.equal(r.created,true);
 await assert.rejects(discoverOrCreate({assertExisting:async()=>{throw {ctapStatus:0x2e};},confirmCreate:()=>false,createNew:()=>assert.fail()}),/cancelled/);
});
test('PIN errors and transport errors never create',async()=>{
 for(const error of [Object.assign(Error('PIN'),{ctapStatus:0x31}),Error('transport'),Error('cancelled')])await assert.rejects(discoverOrCreate({assertExisting:async()=>{throw error;},confirmCreate:()=>assert.fail(),createNew:()=>assert.fail()}));
});
test('PIV offer requires wrapping material on the matching key',()=>{
 assert.equal(hasMatchingPiv({serial:'123',classical:{}},'123'),true);
 assert.equal(hasMatchingPiv({serial:'456',classical:{}},'123'),false);
 assert.equal(hasMatchingPiv({serial:'123'},'123'),false);
});
