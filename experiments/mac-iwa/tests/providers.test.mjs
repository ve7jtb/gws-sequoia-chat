// Custody selection is independent of worker cryptography. These synthetic
// public snapshots test routing, vault-lock behavior and recipient bindings;
// the providers never receive a PIN, a card handle or software private bytes.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createProviderSelection,isSoftware} from '../app/identities/providers.js';
const account='me@example.invalid',cipher=btoa('synthetic encrypted packet');
const fingerprint='A'.repeat(64),certificateHash='b'.repeat(64),recipientKey='C'.repeat(64);
const shared={fingerprint,certificateHash,recipientKey,email:account,certificate:btoa('public certificate')};
const hash=async text=>Buffer.from(await crypto.subtle.digest('SHA-256',Buffer.from(text,'base64'))).toString('hex');
function harness(){
 const calls=[],card={...shared,id:'card',serial:'123'},local={...shared,id:'software:abc',provider:'software',vaultId:'v'};
 let unlocked=true,invalid=false,change=result=>result;
 const provider=(name,snapshot)=>({
  list:async email=>{assert.equal(email,account);calls.push(name+':list');return {choices:[structuredClone(snapshot)],revision:name==='card'?3:4};},
  assert:async value=>{calls.push(name+':assert');assert.deepEqual(value,snapshot);if(invalid)throw Error('Identity invalidated');return true;},
  nativeBinding:value=>{calls.push(name+':binding');return {id:value.id,custody:name};},
  validateMaterial:async(value,snapshot,kind)=>{calls.push(name+':material');return {value,snapshot,kind};}
 });
 const hardware=provider('card',card),software=provider('software',local);
 const model=createProviderSelection({hardware,software:()=>unlocked?software:null,match:async request=>{
  calls.push('matcher');assert.equal(request.cipher,cipher);
  assert.deepEqual(Object.keys(request).sort(),['candidates','cipher']);
  for(const candidate of request.candidates)assert.deepEqual(Object.keys(candidate).sort(),['certificate','id']);
  return change({cipherHash:await hash(cipher),recipientKey,matches:request.candidates.map(c=>({id:c.id,fingerprint,certificateHash,recipientKey}))});
 }});
 return {model,calls,card,local,hardware,software,lock:()=>{unlocked=false;},invalidate:()=>{invalid=true;},mutate:fn=>{change=fn;}};
}
test('custody list preserves both public choices and routes each to its explicit provider',async()=>{
 const h=harness(),inventory=await h.model.list(account);assert.deepEqual(inventory.revision,{hardware:3,software:4});assert.equal(inventory.choices.length,2);
 assert.equal(isSoftware(h.card),false);assert.equal(isSoftware(h.local),true);
 assert.deepEqual(h.model.nativeBinding(h.card),{id:'card',custody:'card'});
 assert.deepEqual(h.model.nativeBinding(h.local),{id:'software:abc',custody:'software'});
 await h.model.get(h.local.id,account);await h.model.validateMaterial('public',h.local,'signing');
 assert.equal(h.calls.at(-1),'software:material');
});
test('locked software identity cannot fall back to hardware and is absent from choices',async()=>{
 const h=harness();h.lock();const listed=await h.model.list(account);assert.deepEqual(listed.choices,[h.card]);
 h.calls.length=0;await assert.rejects(async()=>h.model.assert(h.local),/Unlock/);
 assert.throws(()=>h.model.nativeBinding(h.local),/Unlock/);assert.deepEqual(h.calls,[]);
 await assert.rejects(h.model.get(h.local.id,account),/Select/);
});
test('explicit unsupported custody tags fail closed rather than becoming hardware identities',async()=>{
 const h=harness();for(const provider of ['unknown','Software',null,42]){
  const value={...h.card,provider};await assert.rejects(async()=>h.model.assert(value));
  assert.throws(()=>h.model.nativeBinding(value));
 }
 assert.ok(!h.calls.some(c=>c.startsWith('card:')));
});
test('identifier collisions stop selection before ambiguous provider dispatch',async()=>{
 const h=harness();h.local.id=h.card.id;await assert.rejects(h.model.list(account),/Ambiguous/);
 assert.ok(!h.calls.some(c=>c.endsWith(':assert')));
});
test('same recipient public key in software and hardware remains an explicit two-choice match',async()=>{
 const h=harness(),result=await h.model.match(cipher,account);
 assert.equal(result.cipherHash,await hash(cipher));assert.equal(result.recipientKey,recipientKey);
 assert.deepEqual(result.choices,[h.card,h.local]);assert.ok(h.calls.includes('card:assert'));assert.ok(h.calls.includes('software:assert'));
});
test('recipient packet, identity and key rebinding is rejected before provider use',async()=>{
 const bad=[r=>({...r,cipherHash:'0'.repeat(64)}),r=>({...r,matches:null}),r=>({...r,matches:[]}),
  r=>({...r,recipientKey:'D'.repeat(64)}),r=>({...r,matches:[r.matches[0],r.matches[0]]})];
 for(const field of ['id','fingerprint','certificateHash','recipientKey'])bad.push(r=>({...r,matches:[{...r.matches[0],[field]:'wrong'}]}));
 for(const mutate of bad){const h=harness();h.mutate(mutate);await assert.rejects(h.model.match(cipher,account));}
});
test('selection invalidation or vault lock during matching cannot return stale choices',async()=>{
 let h=harness();h.mutate(r=>{h.invalidate();return r;});await assert.rejects(h.model.match(cipher,account),/invalidated/);
 h=harness();h.mutate(r=>{h.lock();return {...r,matches:r.matches.filter(m=>m.id===h.local.id)};});await assert.rejects(h.model.match(cipher,account),/Unlock/);
});

// Transport preparation must use the selected custody provider and is local:
// no Google profile fetch, network upload, native fallback or private key is
// necessary merely to build the reviewed signing material.
import {createTransport} from '../app/google-transport.js';
function transportHarness({software=true,dispatcher=true,refuse=false,changeAccount=false}={}){
 const calls=[],selected={...shared,id:software?'software:abc':'card',...(software?{provider:'software'}:{serial:'123'})};
 const binding={id:selected.id},material={senderCertificate:shared.certificate};let valid=true;
 const forbidden=async()=>{assert.fail('Unexpected Google operation during local preparation');};
 const transport=createTransport({profile:forbidden,request:forbidden,media:forbidden});
 const native=async()=>{calls.push('native');return material;};
 const context={account,assertAccount:()=>{if(!valid)throw Error('Account changed');},
  certificateStore:{trustedContact:async id=>{assert.equal(id,'trusted-recipient');return {id};}},
  identitySelection:{get:async(id,email)=>{assert.equal(id,selected.id);assert.equal(email,account);return selected;},nativeBinding:value=>{assert.equal(value,selected);return binding;},validateMaterial:async value=>{calls.push('validate');assert.equal(value,material);}},
  composeReviews:{prepare:async(own,contact,options)=>{calls.push('prepare');assert.equal(own,material);assert.equal(options.identity,selected);return options;}}};
 if(dispatcher)context.identityRequest=value=>{assert.equal(value,selected);return async(op,data)=>{
  calls.push('provider');assert.equal(op,'chat-selected-signing-material');assert.deepEqual(data,{identity:binding});
  if(refuse)throw Error('Provider locked');if(changeAccount)valid=false;return material;
 };};
 return {calls,run:op=>transport.call(op,{contact:'trusted-recipient',identity:selected.id,subject:'Synthetic',space:'spaces/test'},native,context)};
}
test('Gmail and Chat preparation dispatch through the selected software provider without native/network calls',async()=>{
 for(const op of ['chat-mail-prepare','chat-prepare']){const h=transportHarness(),result=await h.run(op);
  assert.equal(result.service,op==='chat-mail-prepare'?'Gmail':'Chat');assert.deepEqual(h.calls,['provider','validate','prepare']);}
});
test('locked provider or changed account during material preparation never falls back or creates a review',async()=>{
 for(const options of [{refuse:true},{changeAccount:true}]){const h=transportHarness(options);await assert.rejects(h.run('chat-mail-prepare'),/locked|changed/);assert.ok(!h.calls.includes('native'));assert.ok(!h.calls.includes('prepare'));}
});
test('software identity requires an explicit software dispatcher; legacy hardware context still works',async()=>{
 let h=transportHarness({dispatcher:false});await assert.rejects(h.run('chat-mail-prepare'));assert.deepEqual(h.calls,[]);
 h=transportHarness({software:false,dispatcher:false});await h.run('chat-mail-prepare');assert.deepEqual(h.calls,['native','validate','prepare']);
});
