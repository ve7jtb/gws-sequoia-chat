// Device selection is public-only and serial-explicit; enumeration never writes
// the helper's default vault configuration or chooses an arbitrary first card.
import test from 'node:test';import assert from 'node:assert/strict';
import {discoverIdentityDevices} from '../app/identities/devices.js';
test('discovery returns distinct canonical serials with no configuration side effects',async()=>{
 const calls=[];const devices=await discoverIdentityDevices(async(...args)=>{calls.push(args);return {devices:[{serial:'123'},{serial:'456'}]};});
 assert.deepEqual(devices,[{serial:'123'},{serial:'456'}]);assert.deepEqual(calls,[['chat-identity-devices']]);
});
test('empty, duplicate and malformed enumeration cannot select a fallback device',async()=>{
 for(const result of [{devices:[]},{devices:[{serial:'123'},{serial:'123'}]},{devices:[{serial:'0'}]},{devices:[{serial:'4294967296'}]},{devices:[{serial:123}]},{devices:[{serial:'123',pin:'no'}]},{devices:[{serial:'123'}],defaultSerial:'123'}])await assert.rejects(discoverIdentityDevices(async()=>result));
});
