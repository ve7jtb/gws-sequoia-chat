import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../app/application-bootstrap.js',import.meta.url),'utf8');
function run(pending){
 const loaded=[];let redirect,policy;
 const context={localStorage:{getItem:()=>pending},location:{replace:url=>redirect=url},
  trustedTypes:{createPolicy:(name,rules)=>{assert.equal(name,'sequoia-application-bootstrap');policy=rules;return {createScriptURL:url=>({trusted:rules.createScriptURL(url)})};}},
  document:{createElement:()=>({set src(v){assert.equal(typeof v,'object');this.url=v.trusted;}}),head:{append:script=>{loaded.push(script.url);queueMicrotask(()=>script.onload());}}}};
 vm.createContext(context);return {done:vm.runInContext('(async()=>{'+source+'})()',context),loaded,redirect:()=>redirect,policy:()=>policy};
}
test('IWA bootstrap uses only allowlisted TrustedScriptURL assets in order',async()=>{
 const f=run(null);await f.done;assert.equal(f.loaded[0],'/config.js');assert(f.loaded.includes('/app.js'));assert.equal(f.loaded.at(-1),'/google-transport.js');
 for(const url of ['https://attacker.invalid/code.js','/other.js','/app.js?replace=1'])assert.throws(()=>f.policy().createScriptURL(url));
});
test('partial restoration redirects before loading any mail or vault code',async()=>{
 const f=run('pending-digest');await f.done;assert.equal(f.redirect(),'/backup.html');assert.deepEqual(f.loaded,[]);assert.equal(f.policy(),undefined);
});
