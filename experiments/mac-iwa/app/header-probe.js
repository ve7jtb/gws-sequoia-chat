// Local-only diagnostic: no vault or privileged helper access.
let frame,nonce;const out=document.getElementById('result');
document.getElementById('start').onclick=()=>{
 frame?.remove();nonce=Array.from(crypto.getRandomValues(new Uint8Array(32)),v=>v.toString(16).padStart(2,'0')).join('');
 out.textContent='IWA crossOriginIsolated='+crossOriginIsolated+'\n';
 frame=document.createElement('iframe');frame.title='Normal iframe header fixture';
 frame.style.width='100%';frame.style.height='300px';
 frame.sandbox='allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox';
 frame.src='https://sequoia-iwa-header-test.ve7jtb.chatgpt.site/frame';
 frame.onload=()=>frame.contentWindow.postMessage({type:'init',nonce},'https://sequoia-iwa-header-test.ve7jtb.chatgpt.site');
 document.getElementById('frame').append(frame);
};
addEventListener('message',e=>{if(e.origin!=='https://sequoia-iwa-header-test.ve7jtb.chatgpt.site'||e.source!==frame?.contentWindow||e.data?.nonce!==nonce||e.data?.type!=='header-probe')return;
 const {stage,credentialless,isolated,handle,closed,pass}=e.data;
 out.textContent+=JSON.stringify({stage,credentialless,isolated,handle,closed,pass})+'\n';});
