// The generated config binds this extension to one signed IWA origin.
importScripts('config.js','prf-broker.js','google-oauth.js','chat-media.js');
// The lock belongs to a particular Native Messaging connection, not merely to
// the most recently disconnected IWA port. Split signing uses consecutive ports
// for preparation, signing and completion; delayed cleanup from the first port
// must never unlock the second port's in-flight PIN/signing operation.
let nativeOwner = null;
chrome.runtime.onConnectExternal.addListener(port => {
  const sender = port.sender;
  if (!sender || sender.origin !== IWA_ORIGIN || sender.url !== IWA_ORIGIN + '/' || sender.frameId !== 0) {
    port.disconnect(); return;
  }
  let native = null, closed = false;
  function release(connection, disconnect = true) {
    if (!connection || native !== connection) return;
    // Clear ownership before disconnect(), whose event can be delivered during
    // cleanup. A stale callback cannot close or release a newer connection.
    native = null;
    if (nativeOwner === connection) nativeOwner = null;
    if (disconnect) try { connection.disconnect(); } catch (_) {}
  }
  port.onMessage.addListener(request => {
    if (closed) return;
    if(['google-oauth-test','google-oauth-services'].includes(request?.op)){if(native||nativeOwner){port.postMessage({type:'error',message:'Another operation is in progress.'});return;}startGoogleOAuth(port,request.op==='google-oauth-services');return;}
    // Google Chat's upload response is not readable by this IWA origin under
    // CORS. Only the two bounded attachment operations use extension HTTPS;
    // ordinary Chat/Gmail REST calls and all message cryptography stay in the
    // IWA. The broker constructs its own fixed Google URLs, rejects arbitrary
    // fields, keeps the supplied access token in memory for this request only,
    // and aborts on port disconnect. It never reaches the native helper.
    if(['google-chat-upload','google-chat-download'].includes(request?.op)){
      if(native||nativeOwner){port.postMessage({type:'error',message:'Another operation is in progress.'});return;}
      startChatMedia(port,request);return;
    }
    if(request?.op==='vault-prf'){if(nativeOwner||native)return;startPrf(port,request);return;}
    // Never proxy arbitrary methods, shell commands, paths, PINs or payloads.
    // Full-ciphertext decapsulation routes are retired. Only fixed identity
    // metadata and the bounded component operation may reach the native host.
    if (nativeOwner || native || !request || JSON.stringify(request).length > 500000 || !['chat-vault-ecdh','chat-vault-material','chat-decryption-material','chat-selected-decryption-material','chat-decapsulate-components','status','test','chat-state','chat-certificate-migration','chat-identity-current','chat-identity-restore','chat-identity-import','chat-signing-material','chat-selected-signing-material','chat-sign-digest'].includes(request.op)) {
      port.postMessage({type:'error',message:'Busy or unsupported operation.'}); return;
    }
    try {
      const connection = chrome.runtime.connectNative('org.pqmail.sequoia_iwa');
      native = nativeOwner = connection;
      connection.onMessage.addListener(reply => {
        if (closed || native !== connection) return;
        try { port.postMessage(reply); }
        catch (_) { release(connection); return; }
        if (reply.type !== 'progress') release(connection);
      });
      connection.onDisconnect.addListener(() => {
        const error = chrome.runtime.lastError;
        if (native !== connection) return;
        release(connection, false);
        if (!closed) try {
          port.postMessage({type:'error',message:error ? 'Native helper disconnected; check its installation and local results.' : 'Native helper closed.'});
        } catch (_) {}
      });
      connection.postMessage(request);
    } catch (_) {
      // A synchronous connection/post failure consumes this attempt. Release
      // only this port's connection; never retry a possibly-started operation.
      release(native);
      try { port.postMessage({type:'error',message:'Native helper unavailable; no operation was retried.'}); } catch (_) {}
    }
  });
  port.onDisconnect.addListener(() => {
    // Closing the browser never authorizes another operation. The native host
    // can finish an in-flight snapshot; its result remains local for inspection.
    closed = true;
    release(native);
  });
});
