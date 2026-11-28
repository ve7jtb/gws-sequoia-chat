// Shared request lifecycle for the main app and pre-login vault recovery.
function requestCompanion(op,data,options){
 return new Promise((resolve,reject)=>{
  let port,finished=false;
  // Disconnecting abandons this request; it cannot undo an already-started
  // hardware operation. Ignore late results and never issue an automatic retry.
  const cancel=()=>finish(Error('Native operation cancelled; no retry.'));
  function finish(err,value){if(finished)return;finished=true;options.signal?.removeEventListener('abort',cancel);if(port)port.disconnect();err?reject(err):resolve(value);}
  try {
   if(options.signal?.aborted){cancel();return;}
   options.signal?.addEventListener('abort',cancel,{once:true});
   port=chrome.runtime.connect(EXTENSION_ID,{name:'sequoia-chat'});
   port.onMessage.addListener(r=>{if(r.type==='progress'){options.progress?.(r.message);return;}if(r.type==='error')finish(Error(r.message));else finish(null,r.data??r);});
   port.onDisconnect.addListener(()=>{const e=chrome.runtime.lastError;if(!finished)finish(Error(e?'Native bridge unavailable. Check the extension/helper installation.':'Connection closed; check local results before retrying.'));});
   port.postMessage({op,...data});
  }catch(_){finish(Error('Companion extension unavailable.'));}
 });
}
