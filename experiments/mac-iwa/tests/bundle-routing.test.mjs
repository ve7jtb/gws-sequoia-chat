// These public stand-ins exercise the browser/native join independently of the
// Rust cryptographic fixtures. No test has a card, PIN, account or private key.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {validatePublicSnapshot,matchBundlePublicKeys,parseCardBundle,parseCardCompanion} from '../app/identities/bundle.js';
import {initializeIdentities} from '../app/identities/ui.js';
const slots=['9a','9c','9d','9e',...Array.from({length:20},(_,i)=>(0x82+i).toString(16))];
const encoded=Buffer.from('PQMZIP01synthetic public compressed bytes').toString('base64');
const sha=async raw=>Buffer.from(await crypto.subtle.digest('SHA-256',raw)).toString('hex');
const snapshot=()=>({format:'sequoia-iwa-public-snapshot',version:1,serial:'123456',slots:slots.map(slot=>({slot,publicKeySha256:['9c','84'].includes(slot)?'a'.repeat(64):null})),warnings:[]});
const inspected=()=>({format:'sequoia-iwa-identity-preview',version:1,source:'file',serial:'123456',bundleHash:'1'.repeat(64),generation:0,certificates:[],slots:['9c','84'].map(slot=>({slot,role:'signing',algorithm:'synthetic',publicKeySha256:'a'.repeat(64)})),bundleSignatureVerified:true,liveKeysMatched:false,warnings:[]});
test('offline bundle evidence becomes live only after all public components match',()=>{
 const original=inspected(),matched=matchBundlePublicKeys(original,snapshot());
 assert.equal(original.liveKeysMatched,false);assert.equal(matched.liveKeysMatched,true);
 assert.equal(matched.source,'file');assert.equal(matched.generation,0);
});
test('partial, duplicate, wrong serial and any mismatched component fail before private operations',()=>{
 const changes=[s=>s.serial='654321',s=>s.slots.pop(),s=>s.slots[0]=s.slots[1],s=>s.slots.find(v=>v.slot==='84').publicKeySha256='b'.repeat(64),s=>s.slots.find(v=>v.slot==='9c').publicKeySha256=null,s=>s.pin='forbidden',s=>s.slots[0].slot='81'];
 for(const change of changes){const s=snapshot();change(s);assert.throws(()=>matchBundlePublicKeys(inspected(),s),/does not match/);}
 const unverified=inspected();unverified.bundleSignatureVerified=false;assert.throws(()=>matchBundlePublicKeys(unverified,snapshot()));
 const duplicate=inspected();duplicate.slots.push(duplicate.slots[0]);assert.throws(()=>matchBundlePublicKeys(duplicate,snapshot()));
});
test('card framing bytes are bound to the WASM result and generation is transport metadata',async()=>{
 const s={...snapshot(),bundle:encoded,generation:7};let calls=0;
 const parsed=await parseCardBundle(s,async bundle=>{assert.equal(bundle,encoded);calls++;return {...inspected(),bundleHash:await sha(Buffer.from(bundle,'base64'))};});
 assert.equal(calls,1);assert.equal(parsed.source,'yubikey');assert.equal(parsed.generation,7);assert.equal(parsed.liveKeysMatched,true);
 await assert.rejects(parseCardBundle(s,async()=>inspected()),/does not match/);
 await assert.rejects(parseCardBundle(s,async()=>{throw Error('Invalid signature');}),/Invalid signature/);
});
test('malformed transport framing is rejected before invoking WASM',async()=>{
 let calls=0;const inspect=async()=>{calls++;return inspected();};
 for(const change of [s=>s.generation=0,s=>s.generation=Number.MAX_SAFE_INTEGER+1,s=>s.bundle='bad',s=>s.bundle+='\n',s=>s.extra=true]){
  const s={...snapshot(),bundle:encoded,generation:1};change(s);await assert.rejects(parseCardBundle(s,inspect));
 }assert.equal(calls,0);
 assert.throws(()=>validatePublicSnapshot({...snapshot(),warnings:['\n']}));
});
test('public UI has no automatic native startup or legacy native bundle parser fallback',()=>{
 const source=fs.readFileSync(new URL('../app/identities/ui.js',import.meta.url),'utf8');
 assert.doesNotMatch(source,/request\('chat-identity-(?:restore|import)'/);
 assert.match(source,/parseCardBundle\(await request\('chat-identity-bundle-read',\{serial\}\),inspectBundle,\{compatibilityCertificate\}\)/);
 assert.doesNotMatch(source,/try\{await configured\(\);\}/);
});
test('identities initialize and list saved public data with an unavailable native helper',async()=>{
 // A small DOM substitute runs the actual initialization controller. The
 // request function would fail if startup accidentally called the extension;
 // imported identity inspection and UI event handlers remain untriggered.
 const previous={document:globalThis.document,window:globalThis.window,BroadcastChannel:globalThis.BroadcastChannel};
 const nodes=new Map();
 const make=()=>({textContent:'',children:[],addEventListener(){},append(...items){this.children.push(...items);},replaceChildren(...items){this.children=items;},close(){}});
 globalThis.document={getElementById:id=>{if(!nodes.has(id))nodes.set(id,make());return nodes.get(id);},createElement:make};
 globalThis.window={addEventListener(){}};globalThis.BroadcastChannel=undefined;
 let calls=0,lists=0;
 try{
  const ui=await initializeIdentities({request:async()=>{calls++;throw Error('Native helper unavailable');},say:()=>{},isBusy:()=>false,setBusy:()=>{},identityStore:{list:async()=>{lists++;return {identities:[],revision:0};}}});
  await ui.refresh();assert.equal(calls,0);assert.equal(lists,2);
  assert.match(nodes.get('identity-current').textContent,/No hardware is contacted at startup/);
  assert.equal(nodes.get('identity-list').children.length,1);
 }finally{for(const [key,value] of Object.entries(previous)){if(value===undefined)delete globalThis[key];else globalThis[key]=value;}}
});


test('encrypted companion is independently parsed and joined to exact ciphertext and live public keys',async()=>{
 const encoded=btoa('opaque encrypted companion'),publicKey=btoa('public SPKI'),certificate=btoa('public certificate');
 const read={format:'sequoia-iwa-companion',version:1,serial:'123456',encoded,publicKeys:{'9c':publicKey,'82':publicKey},certificate};
 const checked={format:'sequoia-iwa-companion',version:1,serial:'123456',companionHash:await sha(Buffer.from(encoded,'base64')),certificate,profile:'LEVEL5_COMPANION',components:[{role:'signing-pq',algorithm:'ML-DSA-87',storage:'piv',slot:'9c',publicKey},{role:'signing-classical',algorithm:'Ed448',storage:'companion',slot:'',publicKey}],wrapping:{slot:'82',publicKey}};
 let descriptor;const preview=await parseCardCompanion(read,async input=>{descriptor=input;return structuredClone(checked);});
 assert.deepEqual(Object.keys(descriptor).sort(),['certificate','encoded','publicKeys','serial']);assert.equal(descriptor.serial,123456);
 assert.equal(preview.format,'sequoia-iwa-companion-preview');assert.equal(preview.bundleHash,checked.companionHash);assert.equal(preview.companion.encoded,encoded);assert.equal(preview.generation,0);assert.equal(preview.liveKeysMatched,true);
 assert.deepEqual(preview.slots.map(s=>s.slot),['9c','82']);assert.equal(preview.certificates[0].components[1].storage,'companion');
 for(const change of [s=>s.companionHash='f'.repeat(64),s=>s.serial='654321',s=>s.components[0].publicKey=btoa('different')]){
  const bad=structuredClone(checked);change(bad);await assert.rejects(parseCardCompanion(read,async()=>bad),/does not match/);
 }
 await assert.rejects(parseCardCompanion(read,async()=>{throw Error('Bad companion signature');}),/Bad companion signature/);
});

test('multiple-device restore remains actionable while the global operation lock is held',async()=>{
 const previous={document:globalThis.document,window:globalThis.window,BroadcastChannel:globalThis.BroadcastChannel};
 const nodes=new Map(),calls=[],messages=[];let busy=false;
 const make=()=>({textContent:'',children:[],value:'',files:[],disabled:false,listeners:new Map(),addEventListener(event,fn){this.listeners.set(event,fn);},append(...items){this.children.push(...items);},replaceChildren(...items){this.children=items;},close(){this.open=false;},showModal(){this.open=true;}});
 const node=id=>{if(!nodes.has(id))nodes.set(id,make());return nodes.get(id);};
 globalThis.document={getElementById:node,createElement:make};globalThis.window={addEventListener(){}};globalThis.BroadcastChannel=undefined;
 try{
  await initializeIdentities({request:async(op,args)=>{calls.push({op,args});if(op==='chat-identity-devices')return {devices:[{serial:'123'},{serial:'456'}]};throw Error('Read-only test boundary');},say:message=>messages.push(message),isBusy:()=>busy,setBusy:value=>{busy=value;for(const n of nodes.values())n.disabled=value;},identityStore:{list:async()=>({identities:[],revision:0})}});
  const pending=node('identity-restore').listeners.get('click')();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(busy,true);assert.equal(node('identity-device-dialog').open,true);
  assert.equal(node('identity-device-continue').disabled,false);assert.equal(node('identity-device-cancel').disabled,false);
  node('identity-device').value='456';node('identity-device-continue').listeners.get('click')();await pending;
  assert.deepEqual(calls,[{op:'chat-identity-devices',args:undefined},{op:'chat-identity-bundle-read',args:{serial:'456'}}]);
  assert.equal(busy,false);assert.equal(node('identity-device-dialog').open,false);assert.match(messages.at(-1),/Read-only test boundary/);
 }finally{for(const[key,value]of Object.entries(previous)){if(value===undefined)delete globalThis[key];else globalThis[key]=value;}}
});

test('mapped v2 snapshot must still match every signed component',()=>{
 const s=snapshot();s.version=2;s.slots=s.slots.filter(x=>['9c','84'].includes(x.slot));
 assert.equal(matchBundlePublicKeys(inspected(),s).liveKeysMatched,true);
 s.slots.pop();assert.throws(()=>matchBundlePublicKeys(inspected(),s));
 s.slots=[];assert.throws(()=>validatePublicSnapshot(s));
});
