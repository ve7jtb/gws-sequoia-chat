// Startup is a presentation router, not an authorization boundary. Existing
// vault/card gates still validate every operation; no private material enters
// this module. Reuse the original controls so onboarding cannot bypass their
// confirmations, serial checks, SCP policy, or concurrent-operation guards.
export function mountStartup(doc,win){
 const el=id=>doc.getElementById(id),workspace=el('workspace'),gateway=el('startup');
 const vault=el('vault'),connection=el('connection-controls');
 const vaultHome=doc.createComment('vault home'),connectionHome=doc.createComment('connection home');
 vault.before(vaultHome);connection.before(connectionHome);
 let panel=false,previousUnlocked=false,creating=false;
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
   option.textContent=method.name+' · '+(method.type==='piv'?'PIV':'FIDO PRF');select.append(option);
  }
  select.value=state.methods.some(m=>m.id===selected)?selected:state.defaultId;
  el('startup-unlock').disabled=!state.methods.length;
  if(panel){el('startup-panel').append(vault);vault.hidden=false;}else park();
 }
 el('startup-unlock').onclick=()=>{
  // The existing handler reloads the record before authenticating, rejects
  // missing methods, and never creates a credential as a fallback.
  el('vault-methods').value=el('startup-method').value;el('vault-unlock').click();
 };
 function setup(newKey){creating=true;panel=true;el('startup-setup').hidden=!newKey;render();}
 el('startup-create').onclick=()=>setup(false);
 el('startup-key').onclick=()=>setup(true);
 el('startup-back').onclick=()=>{creating=false;panel=false;el('startup-setup').hidden=true;render();};
 // Guidance opens existing reviewed forms; it never generates keys or saves
 // account settings automatically. Vault protection remains in the store layer.
 el('onboarding-account').onclick=()=>doc.querySelector('[data-tab="account-settings"]').click();
 el('onboarding-identity').onclick=()=>doc.querySelector('[data-tab="identities"]').click();
 el('onboarding-finish').onclick=()=>{creating=false;el('onboarding-next').hidden=true;doc.querySelector('[data-tab="inbox"]').click();};
 win.addEventListener('iwa-vault-state',render);
 render();
}
if(typeof document!=='undefined')mountStartup(document,window);
