// The backup screen must be usable while a partial restore blocks the main
// application. Both screens use this document so an unlocked vault survives
// the switch in either direction.
const common=[
 {src:'/config.js'},
 {"src": "/secure-channel-ui.js", "module": true},
 {src:'/smartcard-piv.js'}, {src:'/hardware-transport.js'},
];
const scripts=[
 {src:'/format.js'}, {src:'/message-client.js'}, {src:'/app.js'},
 {src:'/ctap2-ui.js',module:true}, {src:'/vault-ui.js',module:true}, {src:'/wasm-test.js'},
 {src:'/google-browser.js',module:true}, {src:'/google-transport.js',module:true},
 {src:'/startup-ui.js',module:true},
];
const backup={src:'/backup-ui.js',module:true};
// Keep the same fixed Trusted Types allowlist for initial and deferred load.
const allowed=new Set([...common,...scripts,backup].map(item=>item.src));
const policy=globalThis.trustedTypes?.createPolicy('sequoia-application-bootstrap',{
 createScriptURL:url=>{if(!allowed.has(url))throw Error('Unexpected application script');return url;}
});
function loadScript(item){
 return new Promise((resolve,reject)=>{
  const script=document.createElement('script');
  script.src=policy?policy.createScriptURL(item.src):item.src;
  if(item.module)script.type='module';
  script.onload=resolve;
  script.onerror=()=>reject(Error('Application module failed to load'));
  document.head.append(script);
 });
}
const pending='sequoia-complete-restore-pending';
let application;
function startApplication(){
 if(localStorage.getItem(pending))throw Error('Complete the encrypted restore first.');
 application??=(async()=>{
  for(const item of scripts)await loadScript(item);
 })();
 return application;
}
window.startIwaApplicationAfterRestore=startApplication;
for(const item of common)await loadScript(item);
const openBackup=!!localStorage.getItem(pending)||location.hash==='#backup';
if(!localStorage.getItem(pending))await startApplication();
document.getElementById('application-screen').hidden=openBackup;
await loadScript(backup);
if(openBackup)await window.openEncryptedBackup();
