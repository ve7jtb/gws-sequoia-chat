import test from 'node:test';import assert from 'node:assert/strict';
import {initializeSsh} from '../app/ssh/ui.js';
// Exercise unlock/lock races without any browser, network or card access.
test('SSH module remains hidden while locked and clears public state on lock',async()=>{
 const nodes=new Map(),document={getElementById(id){if(!nodes.has(id))nodes.set(id,{hidden:false,value:'',textContent:'',children:[],replaceChildren(){this.children=[];},append(x){this.children.push(x);}});return nodes.get(id);},createElement(){return {};}};
 const window=new EventTarget();let unlocked=false,reads=0;
 window.vaultIsUnlocked=()=>unlocked;window.softwareIdentities={records:async()=>{reads++;return [{id:'test',name:'SSH test',hasSshPublic:true}];}};
 const ui=initializeSsh({window,document});await ui.refresh();assert(document.getElementById('ssh-tab').hidden);assert.equal(reads,0);
 unlocked=true;await ui.refresh();assert(!document.getElementById('ssh-tab').hidden);assert.equal(document.getElementById('ssh-identities').children.length,1);
 document.getElementById('ssh-public-text').textContent='public data';unlocked=false;window.dispatchEvent(new Event('iwa-vault-locked'));
 assert(document.getElementById('ssh-tab').hidden);assert.equal(document.getElementById('ssh-public-text').textContent,'');assert.equal(document.getElementById('ssh-identities').children.length,0);
});
