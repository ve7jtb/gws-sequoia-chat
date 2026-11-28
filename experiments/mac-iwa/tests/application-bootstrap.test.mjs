import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../app/application-bootstrap.js',import.meta.url),'utf8');
function run(pending){
 const loaded=[];let opened=0,policy;const screen={hidden:true};
 const window={openEncryptedBackup:async()=>{opened++;}};
 const context={window,localStorage:{getItem:()=>pending},location:{hash:''},
  trustedTypes:{createPolicy:(name,rules)=>{assert.equal(name,'sequoia-application-bootstrap');policy=rules;return {createScriptURL:url=>({trusted:rules.createScriptURL(url)})};}},
  document:{getElementById:id=>{assert.equal(id,'application-screen');return screen;},createElement:()=>({set src(v){assert.equal(typeof v,'object');this.url=v.trusted;}}),head:{append:script=>{loaded.push(script.url);queueMicrotask(()=>script.onload());}}}};
 vm.createContext(context);return {done:vm.runInContext('(async()=>{'+source+'})()',context),loaded,opened:()=>opened,screen,start:()=>window.startIwaApplicationAfterRestore(),clear:()=>{pending=null;},policy:()=>policy};
}
test('IWA bootstrap uses only allowlisted TrustedScriptURL assets in order',async()=>{
 const f=run(null);await f.done;assert.equal(f.loaded[0],'/config.js');assert(f.loaded.includes('/app.js'));assert.equal(f.loaded.at(-1),'/backup-ui.js');assert.equal(f.opened(),0);assert.equal(f.screen.hidden,false);assert(f.loaded.indexOf('/startup-ui.js')>f.loaded.indexOf('/hardware-transport.js'));
 for(const url of ['https://attacker.invalid/code.js','/other.js','/app.js?replace=1'])assert.throws(()=>f.policy().createScriptURL(url));
});
test('partial restore loads only recovery and card transport until readback clears the marker',async()=>{
 const f=run('pending-digest');await f.done;
 assert.equal(f.opened(),1);assert.equal(f.screen.hidden,true);
 assert.deepEqual(f.loaded,['/config.js','/secure-channel-ui.js','/smartcard-piv.js','/hardware-transport.js','/backup-ui.js']);
 assert.throws(f.start,/Complete the encrypted restore/);
 f.clear();await Promise.all([f.start(),f.start()]);
 assert.equal(f.loaded.filter(url=>url==='/vault-ui.js').length,1);
 assert.equal(f.screen.hidden,true);
});

// Exercise the actual production loader: isolated secure-channel unit tests
// cannot detect a module that was accidentally omitted from startup.
test('secure-channel policy loads before every card operation entry point',async()=>{
 const f=run(null);await f.done;
 const secure=f.loaded.indexOf('/secure-channel-ui.js');assert(secure>=0);
 for(const entry of ['/app.js','/ctap2-ui.js','/vault-ui.js','/smartcard-piv.js','/hardware-transport.js']){
  assert(f.loaded.indexOf(entry)>secure,entry+' must wait for secure-channel policy');
 }
 assert.match(source,/"src": "\/secure-channel-ui.js", "module": true/);
});
