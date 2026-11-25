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

// Keyboard authorization must submit exactly once and must not retain handlers
// after submission/cancellation, particularly while the touch UI remains open.
test('Enter authorizes FIDO PIN and removes the handler before touch',async()=>{
 const h=harness();h.run('globalThis.controller=new AbortController();');
 const pending=h.run("promptPin({serial:'123',rpId:'package',retries:8},controller.signal)");
 const input=h.el('fido-pin-input');input.value='test-only';
 const key=(extra={})=>Object.assign(new Event('keydown',{cancelable:true}),{key:'Enter',...extra});
 for(const extra of [{repeat:true},{isComposing:true}]){input.dispatchEvent(key(extra));assert.equal(input.value,'test-only');}
 const enter=key();input.dispatchEvent(enter);assert.equal(enter.defaultPrevented,true);
 assert.equal(await pending,'test-only');assert.equal(input.value,'');
 assert.match(h.el('fido-pin-title').textContent,/Touch/);
 const again=key();input.dispatchEvent(again);assert.equal(again.defaultPrevented,false);
 // Reopening and cancelling must also remove the keyboard handler.
 const cancelled=h.run("promptPin({serial:'123',rpId:'package',retries:8},controller.signal)");
 h.run('controller.abort()');await assert.rejects(cancelled,/cancelled/);
 const after=key();input.dispatchEvent(after);assert.equal(after.defaultPrevented,false);
});
