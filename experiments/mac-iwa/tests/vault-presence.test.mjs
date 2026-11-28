import test from 'node:test';
import assert from 'node:assert/strict';
import {createVaultPresenceMonitor,monitoredVaultSerial} from '../app/vault/presence.js';

function fixture(probe){
 let time=0,nextId=0;
 const timers=new Map(),locks=[],probes=[];
 const monitor=createVaultPresenceMonitor({
  probe:serial=>{probes.push(serial);return probe(serial,time);},
  onTimeout:serial=>locks.push({serial,time}),
  now:()=>time,
  setTimer(fn,delay){const id=++nextId;timers.set(id,{fn,time:time+delay});return id;},
  clearTimer:id=>timers.delete(id),
 });
 async function advance(target){
  const next=()=>[...timers.entries()].sort((a,b)=>a[1].time-b[1].time)[0];
  for(let item=next();item&&item[1].time<=target;item=next()){
   const [id,event]=item;
   timers.delete(id);time=event.time;event.fn();
   // Let async probes settle before choosing the next event.
   await Promise.resolve();
  }
  time=target;
 }
 return {monitor,advance,locks,probes,setTime:ms=>{time=ms;}};
}

test('only an authenticated presence timestamp extends the deadline for the actual unlock serial',async()=>{
 let attached=true;
 const f=fixture((serial,now)=>attached?now:false);
 f.monitor.start('41088108');
 await f.advance(10_000);
 attached=false;
 await f.advance(39_999);
 assert.equal(f.monitor.serial,'41088108');
 assert.deepEqual(f.monitor.snapshot(),{serial:'41088108',lastSeen:10_000});
 await f.advance(40_000);
 assert.deepEqual(f.locks,[{serial:'41088108',time:40_000}]);
 assert(f.probes.every(serial=>serial==='41088108'));
});

test('reconnecting within the grace period keeps the vault unlocked',async()=>{
 let attached=false;
 const f=fixture((serial,now)=>attached?now:false);
 f.monitor.start('41088353');
 await f.advance(22_000);
 attached=true;
 await f.advance(37_000);
 assert.equal(f.monitor.snapshot().lastSeen,35_000);
 assert.deepEqual(f.locks,[]);
});

test('an unresolved or late probe cannot prevent removal lock or affect a later session',async()=>{
 let complete;
 const f=fixture(()=>new Promise(resolve=>{complete=resolve;}));
 f.monitor.start('41088108');
 await f.advance(30_000);
 assert.deepEqual(f.locks,[{serial:'41088108',time:30_000}]);
 f.monitor.start('41088353');
 complete(30_000);
 await Promise.resolve();
 assert.deepEqual(f.monitor.snapshot(),{serial:'41088353',lastSeen:30_000});
 assert.equal(f.probes.length,1);
});

test('a stalled browser and restore handoff retain the original deadline',()=>{
 const f=fixture(()=>false);
 f.setTime(24_000);
 f.monitor.start('41088108',5_000);
 f.setTime(35_001);
 assert.equal(f.monitor.check(),false);
 assert.deepEqual(f.locks,[{serial:'41088108',time:35_001}]);
});

test('presence monitoring requires an SCP11b-enabled direct Web Smart Card session',()=>{
 const secure={SequoiaSecureChannel:{isRequired:()=>true}};
 assert.equal(monitoredVaultSerial('41088108',secure),'41088108');
 for(const [serial,scope] of [['41088108',{}],[undefined,secure]])
  assert.equal(monitoredVaultSerial(serial,scope),null);
});
