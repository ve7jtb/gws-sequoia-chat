import {unlockMethodLabel} from './vault/labels.js';

// Startup is a presentation router, not an authorization boundary. Existing
// vault/card gates still validate every operation; no private material enters
// this module. Reuse the original controls so onboarding cannot bypass their
// confirmations, serial checks, SCP policy, or concurrent-operation guards.
export function mountStartup(doc,win){
 const el=id=>doc.getElementById(id),workspace=el('workspace'),gateway=el('startup');
 const vault=el('vault'),connection=el('connection-controls');
 const vaultHome=doc.createComment('vault home'),connectionHome=doc.createComment('connection home');
 vault.before(vaultHome);connection.before(connectionHome);
 let panel=false,previousUnlocked=false,creating=false,step=1,working=false;
 function park(){
  // Move actual nodes rather than cloning inputs or their security state.
  vaultHome.after(vault);vault.hidden=true;
 }
 function render(){
  const state=win.vaultStartupState?.();
  if(!state)return; // Fail closed while vault loading/validation is incomplete.
  workspace.hidden=!state.unlocked;gateway.hidden=state.unlocked;
  if(state.unlocked){
   if(!previousUnlocked)park();connectionHome.after(connection);
   if(!previousUnlocked){
    doc.querySelector('[data-tab="inbox"]').click();
    el('onboarding-next').hidden=!creating;
   }
   previousUnlocked=true;panel=false;el('startup-setup').hidden=true;
   return;
  }
  previousUnlocked=false;
  el('startup-connection-controls').append(connection);
  el('startup-actions').hidden=false;
  el('startup-title').textContent=state.exists?'Log in to Sequoia Chat Lab':'Welcome to Sequoia Chat Lab';
  el('startup-message').textContent=state.status||(state.exists?'Unlock your credential vault, then connect to Gmail or Chat.':'Start by restoring or creating your credential vault.');
  el('startup-login').hidden=!state.exists||panel;
  el('startup-new').hidden=state.exists||panel;
  el('startup-back').hidden=!panel;
  const select=el('startup-method'),selected=select.value;
  select.replaceChildren();
  for(const method of state.methods){
   const option=doc.createElement('option');option.value=method.id;
   option.textContent=method.type==='piv'
    ?unlockMethodLabel({...method,binding:{serial:method.serial}})
    :method.name+' · FIDO PRF';select.append(option);
  }
  select.value=state.methods.some(m=>m.id===selected)?selected:state.defaultId;
  el('startup-unlock').disabled=!state.methods.length;
  // New-vault setup has its own controls. Never expose restore/export actions
  // from the general vault-management panel during creation.
  park();el('startup-setup').hidden=!panel;
  el('startup-name-step').hidden=step!==1;
  el('startup-protection-step').hidden=step!==2;
 }
 el('startup-unlock').onclick=()=>{
  // The existing handler reloads the record before authenticating, rejects
  // missing methods, and never creates a credential as a fallback.
  el('vault-methods').value=el('startup-method').value;el('vault-unlock').click();
 };
 function setup(){creating=true;panel=true;step=1;el('startup-create-status').textContent='';render();}
 // IWA CSP forbids form submissions; use a fixed same-origin navigation target.
 el('startup-restore').onclick=()=>win.location.assign('/backup.html');
 el('startup-next').onclick=()=>{
  const name=el('startup-vault-name').value.trim();
  if(!name||name.length>80){el('startup-create-status').textContent='Enter a name (1–80 characters).';return;}
  step=2;el('startup-create-status').textContent='';render();
 };
 el('startup-previous').onclick=()=>{if(!working){step=1;render();}};
 async function bind(method){
  if(working)return;
  working=true;
  const buttons=['startup-existing-prf','startup-new-prf','startup-existing-piv','startup-back','startup-previous'];
  buttons.forEach(id=>el(id).disabled=true);
  el('startup-create-status').textContent='Verifying the unlock method. Complete the authenticator prompt.';
  try{
   // The vault service owns validation, secret handling and atomic persistence.
   // This wizard supplies public choices only and cannot create an unwrapped vault.
   await win.createStartupVault({name:el('startup-vault-name').value.trim(),serial:el('startup-serial').value.trim(),method,classical:el('startup-classical').checked});
   const state=win.vaultStartupState?.();
   el('startup-create-status').textContent=state?.unlocked?'Vault created and protected.':state?.status||'Vault creation did not complete.';
  }catch(e){el('startup-create-status').textContent=e.message;}
  finally{working=false;buttons.forEach(id=>el(id).disabled=false);}
 }
 el('startup-existing-prf').onclick=()=>bind('existing-prf');
 el('startup-new-prf').onclick=()=>bind('new-prf');
 el('startup-existing-piv').onclick=()=>bind('existing-piv');
 el('startup-create').onclick=()=>setup(false);
 el('startup-key').onclick=()=>setup(true);
 el('startup-back').onclick=()=>{creating=false;panel=false;el('startup-setup').hidden=true;render();};
 // Guidance opens existing reviewed forms; it never generates keys or saves
 // account settings automatically. Vault protection remains in the store layer.
 el('onboarding-account').onclick=()=>{
  // Selecting the tab alone leaves its form below the tall setup/header area.
  // Bring the actual input into view and move keyboard focus without changing
  // the saved account or triggering its review/save operation.
  doc.querySelector('[data-tab="account-settings"]').click();
  const input=el('account-email');
  input.scrollIntoView({block:'center',behavior:'instant'});
  input.focus({preventScroll:true});
 };
 el('onboarding-existing').onclick=()=>{
  doc.querySelector('[data-tab="identities"]').click();
  const button=el('identity-restore');if(button){button.scrollIntoView({block:'center'});button.focus();}
 };
 el('onboarding-identity').onclick=()=>{
  doc.querySelector('[data-tab="identities"]').click();
  el('software-name').scrollIntoView({block:'center'});el('software-name').focus();
 };
 el('onboarding-finish').onclick=()=>{creating=false;el('onboarding-next').hidden=true;doc.querySelector('[data-tab="inbox"]').click();};
 win.addEventListener('iwa-vault-state',render);
 render();
}
if(typeof document!=='undefined')mountStartup(document,window);
