// Do not load mail or vault modules against a partially restored database.
// A successful idempotent restore removes the marker after full readback.
if(localStorage.getItem("sequoia-complete-restore-pending")){
 location.replace("/backup.html");
}else{
 // Initialize secure-channel policy before any hardware or vault UI can
 // dispatch an operation. Missing policy must continue to fail closed.
 const scripts=[{"src": "/config.js", "module": false}, {"src": "/format.js", "module": false}, {"src": "/secure-channel-ui.js", "module": true}, {"src": "/message-client.js", "module": false}, {"src": "/app.js", "module": false}, {"src": "/ctap2-ui.js", "module": true}, {"src": "/vault-ui.js", "module": true}, {"src": "/wasm-test.js", "module": false}, {"src": "/smartcard-piv.js", "module": false}, {"src": "/hardware-transport.js", "module": false}, {"src": "/google-browser.js", "module": true}, {"src": "/google-transport.js", "module": true}];
 // IWA enforces Trusted Types even when an ordinary browser does not. Only
 // these fixed signed-bundle script URLs can pass; no restored setting, query
 // parameter, or remote message can choose executable code.
 const allowed=new Set(scripts.map(item=>item.src));
 const policy=globalThis.trustedTypes?.createPolicy('sequoia-application-bootstrap',{
  createScriptURL:url=>{if(!allowed.has(url))throw Error('Unexpected application script');return url;}
 });
 for(const item of scripts){await new Promise((resolve,reject)=>{const s=document.createElement("script");s.src=policy?policy.createScriptURL(item.src):item.src;if(item.module)s.type="module";s.onload=resolve;s.onerror=()=>reject(Error("Application module failed to load"));document.head.append(s);});}
}
