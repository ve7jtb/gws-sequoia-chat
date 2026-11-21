// The generated config binds this extension to one signed IWA origin.
importScripts('config.js');
let busy = false;
chrome.runtime.onConnectExternal.addListener(port => {
  const sender = port.sender;
  if (!sender || sender.origin !== IWA_ORIGIN || sender.url !== IWA_ORIGIN + '/' || sender.frameId !== 0) {
    port.disconnect(); return;
  }
  let native = null;
  port.onMessage.addListener(request => {
    // Never proxy arbitrary methods, shell commands, paths, PINs or payloads.
    if (busy || native || !request || JSON.stringify(request).length > 500000 || !['status','test','chat-state','chat-login','chat-spaces','chat-messages','chat-preview','chat-trust','chat-prepare','chat-send','chat-open'].includes(request.op)) {
      port.postMessage({type:'error',message:'Busy or unsupported operation.'}); return;
    }
    busy = true;
    native = chrome.runtime.connectNative('org.pqmail.sequoia_iwa');
    native.onMessage.addListener(reply => {
      port.postMessage(reply);
      if (reply.type !== 'progress') { native.disconnect(); native = null; busy = false; }
    });
    native.onDisconnect.addListener(() => {
      const error = chrome.runtime.lastError;
      if (native) {
        port.postMessage({type:'error',message:error ? 'Native helper disconnected; check its installation and local results.' : 'Native helper closed.'});
        native = null; busy = false;
      }
    });
    native.postMessage(request);
  });
  port.onDisconnect.addListener(() => {
    // Closing the browser never authorizes another operation. The native host
    // can finish an in-flight snapshot; its result remains local for inspection.
    if (native) native.disconnect();
    native = null; busy = false;
  });
});
