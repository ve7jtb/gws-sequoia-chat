// Run the actual page-side worker coordinator with a fake worker-session import.
// This seam checks provider dispatch before any Native Messaging or worker call;
// real component transport and crypto have their own integration tests.
import test from 'node:test';import assert from 'node:assert/strict';import vm from 'node:vm';import fs from 'node:fs';
const source=fs.readFileSync(new URL('../app/message-client.js',import.meta.url),'utf8');
function harness(){
 const calls=[],states=[],workers=[];
 const context={Error,AbortController,setTimeout,clearTimeout,busy:false,decryptionAbort:null,
  operationBusy:active=>states.push(active),nativeRequest:async()=>{calls.push('native');return {hardware:true};},
  Worker:class{constructor(url,options){workers.push({url,options});}},
  loadModule:async path=>{assert.equal(path,'./decryption-session.js');calls.push('load');return {decryptWithHardware:async options=>{options.createWorker();return options.native('component',{});}};}};
 vm.createContext(context);vm.runInContext(source.replaceAll('import(','loadModule('),context);
 return {calls,states,workers,context,run:options=>context.decryptInIwa(options)};
}
test('software decryption without its provider fails before worker, busy state or native call',async()=>{
 for(const native of [undefined,null,false,{}]){const h=harness();await assert.rejects(h.run({identity:{provider:'software'},native}),/no native fallback/);
 assert.deepEqual(h.calls,[]);assert.deepEqual(h.workers,[]);assert.deepEqual(h.states,[]);}
});
test('software decryption uses its explicit provider and cleans up on refusal without fallback',async()=>{
 const h=harness();let attempts=0;await assert.rejects(h.run({identity:{provider:'software'},native:async()=>{attempts++;throw Error('Locked software vault');}}),/Locked/);
 assert.equal(attempts,1);assert.deepEqual(h.calls,['load']);assert.deepEqual(h.states,[true,false]);assert.equal(h.context.decryptionAbort,null);
 assert.equal(h.workers[0].url,'/decryption-worker.js');assert.equal(h.workers[0].options.type,'module');
});
test('legacy hardware coordinator retains its explicit native path',async()=>{
 const h=harness(),result=await h.run({identity:{serial:'123'}});assert.equal(result.hardware,true);assert.deepEqual(h.calls,['load','native']);assert.deepEqual(h.states,[true,false]);
});
