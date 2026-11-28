import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {openTerminalWindow} from '../app/ssh/terminal-window.js';

test('terminal window binds only the expected popup and clears it on disposal',async t=>{
 const origin='isolated-app://ssh-test',bound=Promise.withResolvers(),resized=Promise.withResolvers();
 const popup={
  closed:false,
  close(){this.closed=true;},
  postMessage(data,target,ports){assert.equal(target,origin);assert.equal(data.type,'ssh-terminal-bind');bound.resolve(ports[0]);},
 };
 const window=Object.assign(new EventTarget(),{location:{origin},MessageChannel,setTimeout,clearTimeout,setInterval,clearInterval});
 window.open=url=>{assert.equal(url,'/ssh-terminal.html');return popup;};
 const view=openTerminalWindow({window,onInput:()=>assert.fail('No input expected'),onResize:(...size)=>resized.resolve(size),onClose:()=>assert.fail('Disposal is not an external close')});
 t.after(()=>view.dispose());
 function announce(source,eventOrigin){
  window.dispatchEvent(Object.assign(new Event('message'),{origin:eventOrigin,source,data:{type:'ssh-terminal-ready'}}));
 }
 announce(popup,'https://untrusted.invalid');
 announce({},origin);
 announce(popup,origin);
 const port=await bound.promise;
 t.after(()=>port.close());
 port.postMessage({type:'initialized'});await view.ready;
 port.postMessage({type:'resize',rows:30,cols:100});
 assert.deepEqual(await resized.promise,[30,100]);
 const status=once(port,'message');
 view.status('Connected.','ready',{login:'Post-quantum hybrid login.',transport:'Hybrid key exchange.'});
 assert.deepEqual((await status)[0],{type:'status',kind:'ready',text:'Connected.',connection:{login:'Post-quantum hybrid login.',transport:'Hybrid key exchange.'}});
 const cleared=once(port,'message');
 view.dispose();
 assert.deepEqual((await cleared)[0],{type:'clear'});
 assert.equal(popup.closed,true);
});
