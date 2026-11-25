import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// Exercise the actual dialog controller with a minimal DOM, without a card,
// browser credentials, PIN logging or any private-key operation.
function harness(){
 const nodes=new Map();
 const el=id=>{if(!nodes.has(id)){const n=new EventTarget();Object.assign(n,{value:'',hidden:false,open:false,textContent:'',options:[{},{}],focus(){},showModal(){this.open=true;},close(){this.open=false;}});nodes.set(id,n);}return nodes.get(id);};
 const context=vm.createContext({document:{getElementById:el},window:new EventTarget(),packageRp:()=> 'package',extensionRp:()=> 'legacy',AbortController,Error,console,localStorage:{getItem:()=>null,setItem(){}}});
 const source=readFileSync(new URL('../app/ctap2-ui.js',import.meta.url),'utf8').replace(/^import .*;$/gm,'');
 vm.runInContext(source,context);return {el,context,run:s=>vm.runInContext(s,context)};
}
test('PIN is cleared while touch/progress modal stays visible until vault completion',async()=>{
 const h=harness();h.run('globalThis.controller=new AbortController();');
 const pending=h.run("promptPin({serial:'123',rpId:'package',retries:8},controller.signal,true)");
 assert.match(h.el('fido-pin-title').textContent,/create/);
 h.el('fido-pin-input').value='test-only';h.el('fido-pin-ok').dispatchEvent(new Event('click'));
 assert.equal(await pending,'test-only');assert.equal(h.el('fido-pin-input').value,'');
 assert.equal(h.el('fido-pin-dialog').open,true);assert.equal(h.el('fido-pin-entry').hidden,true);
 assert.match(h.el('fido-pin-title').textContent,/Touch/);assert.equal(h.el('fido-pin-wait').hidden,false);
 h.run("progress('PRF received. Checking the encrypted vault…')");assert.equal(h.el('fido-pin-done').hidden,true);
 h.run("complete('Vault unlocked successfully. You may remove the key.')");assert.equal(h.el('fido-pin-done').hidden,false);assert.equal(h.el('fido-pin-wait').hidden,true);
 h.el('fido-pin-done').onclick();assert.equal(h.el('fido-pin-dialog').open,false);
});
test('failure is explicit and never displayed as successful vault unlock',()=>{
 const h=harness();h.el('fido-pin-dialog').showModal();h.run("complete('No matching credential. No automatic retry.',false)");
 assert.match(h.el('fido-pin-title').textContent,/stopped/);assert.match(h.el('fido-pin-progress').textContent,/No matching/);
 assert.equal(h.el('fido-pin-done').hidden,false);assert.equal(h.el('fido-pin-wait').hidden,true);
});

test('preflight failures open an explicit result dialog without a PIN request',()=>{const h=harness();h.run("complete('Enter the expected YubiKey serial.',false)");assert.equal(h.el('fido-pin-dialog').open,true);assert.match(h.el('fido-pin-progress').textContent,/serial/);assert.equal(h.el('fido-pin-entry').hidden,true);});
