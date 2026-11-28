// This extension accepts only Google operations from the signed IWA's main frame.
importScripts('config.js','google-oauth.js','chat-media.js');

chrome.runtime.onConnectExternal.addListener(port => {
  const sender = port.sender;
  if (!sender || sender.origin !== IWA_ORIGIN || sender.url !== IWA_ORIGIN + '/' || sender.frameId !== 0) {
    port.disconnect();
    return;
  }
  let closed=false;
  port.onDisconnect.addListener(()=>{closed=true;});
  port.onMessage.addListener(request => {
    if(closed)return;
    const op = request?.op;
    if (op === 'google-oauth-test' || op === 'google-oauth-services') {
      startGoogleOAuth(port, op === 'google-oauth-services');
    } else if (op === 'google-chat-upload' || op === 'google-chat-download') {
      startChatMedia(port, request);
    } else {
      port.postMessage({type:'error',message:'Unsupported Google operation.'});
    }
  });
});
