// No network access, credential fields, arbitrary message data or file paths.
const $ = id => document.getElementById(id);
function call(op) {
  $('status').disabled = $('test').disabled = true;
  $('details').textContent = '';
  let finished = false;
  let port;
  const end = text => { finished = true; $('result').textContent = text; $('status').disabled = $('test').disabled = false; };
  try {
    port = chrome.runtime.connect(EXTENSION_ID, {name:'sequoia-test'});
    port.onMessage.addListener(reply => {
      if (reply.type === 'progress') { $('result').textContent = reply.message; return; }
      if (reply.type === 'error') end(reply.message);
      else if (op === 'status') end(reply.connected ? 'Expected YubiKey '+reply.serial+' is connected.' : 'Connect YubiKey '+reply.serial+' and check again.');
      else {
        end(reply.passed && reply.unchanged ? 'PASS — hybrid signing, both decryptions, and unchanged keys/policies.' : 'Test stopped or failed. Inspect the saved results before retrying.');
        $('details').textContent = JSON.stringify(reply,null,2);
      }
      port.disconnect();
    });
    port.onDisconnect.addListener(() => {
      const error = chrome.runtime.lastError;
      if (!finished) end(error ? 'Extension/helper unavailable. Check the experiment installation.' : 'Connection closed; inspect saved results.');
    });
    port.postMessage({op});
  } catch (_) { end('Companion extension unavailable. Install the matching experiment extension.'); }
}
$('status').addEventListener('click',()=>call('status'));
$('test').addEventListener('click',()=>$('confirm').showModal());
$('cancel').addEventListener('click',()=>$('confirm').close());
$('go').addEventListener('click',()=>{$('confirm').close();call('test');});
