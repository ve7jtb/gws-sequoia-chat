import test from 'node:test';
import assert from 'node:assert/strict';
import {renderVaultUnlockTiming,startVaultUnlockTiming} from '../app/vault/unlock-timing.js';

test('Level 3 timing retains stages and stops as soon as the modal opens',()=>{
 let result,clock=100;
 const timer=startVaultUnlockTiming({started:clock,serial:'41088108',scpRequired:true,
  now:()=>clock,report:trace=>{result=trace;}});
 clock=120;timer.record({stage:'finding'});
 clock=290;timer.record({stage:'found',serial:'41088108'});
 clock=650;timer.record({stage:'bundle'});
 clock=910;timer.record({stage:'verify'});
 clock=1020;timer.record({stage:'prepare'});
 clock=1050;timer.record({stage:'slot',slot:'9d'});
 clock=1100;timer.record({stage:'slot-verified',slot:'9d'});
 clock=1110;timer.record({stage:'slot',slot:'85'});
 clock=1150;timer.record({stage:'slot-verified',slot:'85'});
 clock=1195;timer.record({stage:'pin-shown',scpRequired:true});
 clock=20000;timer.finish();
 assert.equal(result.pinMs,1095);
 assert.equal(result.scpRequiredAtPin,true);
 assert.deepEqual(result.events.map(({ms})=>ms),[0,20,190,550,810,920,950,1000,1010,1050,1095]);
 const summary={},pre={},panel={hidden:true,querySelector:selector=>selector==='summary'?summary:pre};
 renderVaultUnlockTiming(panel,result);
 assert.equal(panel.hidden,false);
 assert.match(summary.textContent,/1\.095 s to PIN/);
 assert.match(pre.textContent,/SCP11b required at PIN prompt/);
 assert.match(pre.textContent,/1\.095 s  PIV PIN dialog opened$/);
});

test('an attempt that ends before the modal has no click-to-PIN measurement',()=>{
 let result,clock=0;
 const timer=startVaultUnlockTiming({started:clock,serial:'123',scpRequired:true,
  now:()=>clock,report:trace=>{result=trace;}});
 clock=35;timer.record({stage:'finding'});
 clock=120;timer.finish();
 clock=150;timer.record({stage:'pin-shown',scpRequired:true});
 assert.equal(result.pinMs,null);
 assert.equal(result.scpRequiredAtPin,null);
 assert.equal(result.events.at(-1).label,'Attempt ended before the PIN dialog opened');
});
