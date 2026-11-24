// Exercise the real application's dispatch/locking prefix, with browser APIs
// replaced by narrow fakes. This catches accidental routing back through native
// Gmail/Chat when adding the new offline digest-signing operation.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../app/app.js',import.meta.url),'utf8');
function app(){
 const nodes=new Map(),native=[],google=[],buttons=[{}];let unlocked=true;
 const node=id=>{if(!nodes.has(id))nodes.set(id,{value:id==='transport'?'mail':'',classList:{toggle(){}}});return nodes.get(id);};
 const context={Promise,Error,document:{getElementById:node,querySelectorAll:()=>buttons},EXTENSION_ID:'test-extension',
  window:{vaultGate(){if(!unlocked)throw Error('Locked vault');}},chrome:{runtime:{connect(){
   const listeners=[];
   return {disconnect(){},onMessage:{addListener:f=>listeners.push(f)},onDisconnect:{addListener(){}},
    postMessage(request){native.push(request);queueMicrotask(()=>listeners.forEach(f=>f({type:'result',data:{ok:true}})));}};
  }}}};
 context.window.googleTransport={handles:op=>op==='chat-mail-prepare',async call(op,data,send,identity){google.push({op,data,identity});return send('chat-selected-signing-material',{});}};
 vm.createContext(context);vm.runInContext(source.slice(0,source.indexOf('function event(')),context);
 vm.runInContext("ownEmail='test@example.invalid';accountSnapshot={email:ownEmail,revision:'synthetic'};accountSettings={assert:s=>s.email};contacts=[];",context);
 return {context,native,google,buttons,lock:()=>{unlocked=false;}};
}
test('UI prepare uses browser transport followed by metadata-only native prepare',async()=>{
 const a=app();await a.context.call('chat-mail-prepare',{contact:'saved',subject:'test'});
 assert.equal(a.google.length,1);assert.equal(a.google[0].identity.account,'test@example.invalid');
 assert.equal(a.native.length,1);assert.equal(a.native[0].op,'chat-selected-signing-material');
 assert.equal('mime' in a.native[0],false);assert.equal(a.buttons[0].disabled,false);
});
test('a held signing lock blocks a second UI operation, but permits the owned digest callback',async()=>{
 const a=app();a.context.operationBusy(true);
 await assert.rejects(a.context.call('chat-state'),/already running/);
 await a.context.nativeRequest('chat-sign-digest',{review:'test'});
 assert.equal(a.native.length,1);assert.equal(a.native[0].op,'chat-sign-digest');
 assert.equal(a.buttons[0].disabled,true);a.context.operationBusy(false);
});
test('locking the vault before the digest callback prevents a native PIN request',async()=>{
 const a=app();a.lock();await assert.rejects(a.context.nativeRequest('chat-sign-digest',{}),/Locked vault/);
 assert.equal(a.native.length,0);
});
