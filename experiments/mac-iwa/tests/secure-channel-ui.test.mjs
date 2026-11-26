import {test} from 'node:test';
import assert from 'node:assert/strict';
// Exercise the actual UI adapter with no card. This prevents a checked toggle
// from being merely cosmetic or being downgraded while a transaction is active.
test('secure preference persists, locks during sessions and refuses unavailable trust',async()=>{
 const listeners=new Map(),checkbox={checked:false,disabled:false,addEventListener:(n,fn)=>listeners.set(n,fn)},status={textContent:''},values=new Map();
 const betaListeners=new Map(),betaCheckbox={checked:false,disabled:false,addEventListener:(n,fn)=>betaListeners.set(n,fn)};
 globalThis.document={getElementById:id=>id==='secure-yubikey-connection'?checkbox:id==='secure-yubikey-beta'?betaCheckbox:status};
 globalThis.localStorage={getItem:k=>values.get(k),setItem:(k,v)=>values.set(k,v)};
 globalThis.fetch=async()=>({ok:false});
 await import('../app/secure-channel-ui.js');const policy=globalThis.SequoiaSecureChannel;
 assert.equal(policy.isRequired(),true);assert.equal(checkbox.checked,true);assert.equal(betaCheckbox.checked,true);
 betaCheckbox.checked=false;betaListeners.get('change')();
 // An explicit user opt-out remains supported; the default itself is secure.
 checkbox.checked=false;listeners.get('change')();assert.equal(values.get('sequoia_secure_yubikey_connection'),'off');const raw={};const session=await policy.acquire(raw);assert.equal(session.connection,raw);assert.ok(checkbox.disabled);assert.ok(betaCheckbox.disabled);
 betaCheckbox.checked=true;betaListeners.get('change')();assert.equal(betaCheckbox.checked,false);
 checkbox.checked=true;listeners.get('change')();assert.equal(policy.isRequired(),false);assert.equal(checkbox.checked,false);session.close();
 checkbox.checked=true;listeners.get('change')();assert.equal(policy.isRequired(),true);assert.equal(values.get('sequoia_secure_yubikey_connection'),'required');
 let transmitted=0;await assert.rejects(policy.acquire({transmit:async()=>{transmitted++;}}),/trust store unavailable/);assert.equal(transmitted,0);assert.equal(checkbox.disabled,false);assert.match(status.textContent,/refused/);
 betaCheckbox.checked=true;betaListeners.get('change')();assert.equal(values.get('sequoia_secure_yubikey_beta_pin'),'enabled');assert.match(status.textContent,/manufacturer root not verified/);
 let fetched;globalThis.fetch=async url=>{fetched=String(url);return {ok:true,json:async()=>({rootSha256:'wrong'})};};
 await assert.rejects(policy.acquire({}),/Unexpected trust-store pin/);assert.match(fetched,/beta-sd-trust/);assert.equal(betaCheckbox.disabled,false);
 delete globalThis.document;delete globalThis.localStorage;delete globalThis.SequoiaSecureChannel;
});

test('explicit security opt-outs survive loading the preview defaults',async()=>{
 const nodes=new Map();globalThis.document={getElementById:id=>{if(!nodes.has(id))nodes.set(id,{addEventListener(){},checked:false});return nodes.get(id);}};
 globalThis.localStorage={getItem:()=> 'off'};
 await import('../app/secure-channel-ui.js?explicit-off');
 assert.equal(globalThis.SequoiaSecureChannel.isRequired(),false);
 assert.equal(nodes.get('secure-yubikey-beta').checked,false);
 delete globalThis.document;delete globalThis.localStorage;delete globalThis.SequoiaSecureChannel;
});
