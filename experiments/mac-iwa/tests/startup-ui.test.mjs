import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mountStartup} from '../app/startup-ui.js';

// Minimal DOM double exercises actual event wiring and node movement. Moving
// live nodes must preserve their identity and handlers, especially SCP controls.
function fixture(initial){
 const nodes=new Map();let state=initial;const events=new Map();
 function node(id){return {id,hidden:false,value:'',children:[],parent:null,clicks:0,
  append(n){if(n.parent)n.parent.children=n.parent.children.filter(x=>x!==n);n.parent=this;this.children.push(n);},
  before(n){n.parent=this.parent;},after(n){n.parent=this.parent;},
  scrollIntoView(options){this.scrolled=options;},focus(options){this.focused=options;},replaceChildren(){this.children=[];},click(){this.clicks++;this.onclick?.();}};}
 const doc={getElementById(id){if(!nodes.has(id))nodes.set(id,node(id));return nodes.get(id);},
  createComment:()=>node('placeholder'),createElement:()=>node('option'),
  querySelector:selector=>doc.getElementById(selector.includes('account-settings')?'account-button':'inbox-button')};
 const calls=[];const win={vaultStartupState:()=>state,addEventListener:(e,f)=>events.set(e,f),location:{assign:url=>calls.push(url)},createStartupVault:async value=>calls.push(value)};
 mountStartup(doc,win);
 return {calls,el:doc.getElementById,set(s){state=s;events.get('iwa-vault-state')();}};
}
const locked={exists:true,unlocked:false,methods:[{id:'f',name:'Security key',type:'prf'},{id:'p',name:'PIV key',type:'piv'}],defaultId:'f',status:''};
test('existing vault starts locked with FIDO/PIV selection and delegates only explicit unlock',()=>{
 const f=fixture(locked);assert.equal(f.el('workspace').hidden,true);assert.equal(f.el('startup-new').hidden,true);
 assert.equal(f.el('startup-method').children.length,2);assert.equal(f.el('vault-unlock').clicks,0);
 f.el('startup-method').value='p';f.el('startup-unlock').click();
 assert.equal(f.el('vault-methods').value,'p');assert.equal(f.el('vault-unlock').clicks,1);
});
test('startup distinguishes PIV keys with the same name by their serials',()=>{
 const methods=[
  {id:'a',name:'YubiKey',type:'piv',serial:'12345678'},
  {id:'b',name:'YubiKey',type:'piv',serial:'87654321'},
  {id:'c',name:'YubiKey SN# 99999999',type:'piv',serial:'99999999'},
 ];
 const f=fixture({...locked,methods,defaultId:'b'});
 assert.deepEqual(f.el('startup-method').children.map(option=>option.textContent),
  ['YubiKey · SN# 12345678 · PIV','YubiKey · SN# 87654321 · PIV','YubiKey SN# 99999999 · PIV']);
 assert.equal(f.el('startup-method').value,'b');
});
test('empty instance offers restore/create without automatic hardware writes',()=>{
 const f=fixture({exists:false,unlocked:false,methods:[]});assert.equal(f.el('startup-new').hidden,false);
 assert.equal(f.el('startup-login').hidden,true);f.el('startup-key').click();
 assert.equal(f.el('startup-setup').hidden,false);assert.equal(f.el('vault').hidden,true);
 assert.equal(f.el('vault-unlock').clicks,0);f.el('startup-back').click();assert.equal(f.el('startup-new').hidden,false);
});
test('unlock opens workspace once; updates preserve current view; relock hides workspace and preserves security controls',()=>{
 const f=fixture(locked),connection=f.el('connection-controls');connection.checked=true;
 f.set({...locked,unlocked:true});assert.equal(f.el('workspace').hidden,false);assert.equal(f.el('startup').hidden,true);
 assert.equal(f.el('inbox-button').clicks,1);f.el('vault').hidden=false;
 f.set({...locked,unlocked:true});assert.equal(f.el('vault').hidden,false);assert.equal(f.el('inbox-button').clicks,1);
 f.set(locked);assert.equal(f.el('workspace').hidden,true);assert.equal(f.el('connection-controls'),connection);
 assert.equal(connection.checked,true);assert.equal(connection.parent.id,'startup-connection-controls');
});
test('startup remains closed until a validated vault state is available',()=>{
 const f=fixture(undefined);assert.equal(f.el('vault-unlock').clicks,0);assert.equal(f.el('inbox-button').clicks,0);
 f.set(locked);assert.equal(f.el('workspace').hidden,true);
});

test('account setup opens its tab and visibly focuses email without saving',()=>{
 const f=fixture({...locked,unlocked:true});
 f.el('onboarding-account').click();
 assert.equal(f.el('account-button').clicks,1);
 assert.deepEqual(f.el('account-email').scrolled,{block:'center',behavior:'instant'});
 assert.deepEqual(f.el('account-email').focused,{preventScroll:true});
 assert.equal(f.el('account-review').clicks,0);
});

test('restore uses fixed navigation and creation exposes no restore management panel',async()=>{
 const f=fixture({exists:false,unlocked:false,methods:[]});
 f.el('startup-restore').click();assert.deepEqual(f.calls,['/backup.html']);f.calls.length=0;
 f.el('startup-create').click();assert.equal(f.el('vault').hidden,true);
 assert.equal(f.el('startup-name-step').hidden,false);
 f.el('startup-vault-name').value='New vault';f.el('startup-next').click();
 assert.equal(f.el('startup-protection-step').hidden,false);
 assert.equal(f.calls.length,0);
 f.el('startup-serial').value='12345678';
 await f.el('startup-existing-prf').onclick();
 assert.equal(f.calls[0].method,'existing-prf');assert.equal(f.calls[0].serial,'12345678');
 assert.equal(f.el('vault-import').clicks,0);assert.equal(f.el('vault-create-prf').clicks,0);
});
