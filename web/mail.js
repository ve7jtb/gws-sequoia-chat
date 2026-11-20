'use strict';
// Mail and Chat share the local crypto/trust boundary but have independent
// Google sessions. This script renders data only with textContent or the
// helper's sanitized HTML in an opaque, script-free sandbox frame.
let mailPage='', mailPages=[], mailNext='', mailConnected=false;
function clearMail(){mailPage='';mailPages=[];mailNext='';mailConnected=false;$('mail-account').textContent='Gmail is not connected.';$('mail-messages').replaceChildren();$('mail-query').value='';}
function composeMode(){
  const mail=$('compose-service').value==='mail';$('chat-destination').hidden=mail;$('compose-space').required=!mail;
  $('compose-notice').textContent=mail?'Gmail sends a standard signed and encrypted PGP/MIME message. The recipient needs a supported v6 hybrid certificate. Your public certificate is included inside the encrypted message.':'The public certificate and encrypted .pgp bundle are sent as two linked Chat messages. Conversation participants can see your public certificate.';
}
$('compose-service').addEventListener('change',composeMode);
async function connectMail(){
  const r=await api('mail-connect',{profile:$('profile').value});mailConnected=true;
  $('mail-account').textContent=r.email+' · '+r.profile;$('connection').textContent='Gmail · '+r.email;
  $('welcome').hidden=true;$('workspace').hidden=false;tab('mail');$('compose-service').value='mail';composeMode();
  mailPage='';mailPages=[];await loadMail();
}
async function loadMail(){
  if(!mailConnected)throw new Error('Connect Gmail first. If read/send consent is missing, choose Authorize Gmail read & send.');
  clearReader();
  const r=await api('mail-list',{query:$('mail-query').value,folder:$('mail-folder').value,pageToken:mailPage});
  mailNext=r.nextPageToken || '';$('mail-messages').replaceChildren();
  for(const item of r.messages){
    const row=node('button','',item.unread?'mail-row unread':'mail-row');
    row.append(node('span',item.from,'mail-sender'),node('span',item.subject,'mail-subject'),node('small',item.date,'mail-date'));
    row.addEventListener('click',async()=>{
      busy('Opening email…');clearReader();
      try{
        const result=await api('mail-read',{message:item.id});
        if(result.encrypted){status('Encrypted PGP/MIME message. Choose your identity and trusted sender.');requestPassword({kind:'mail-open',message:item.id});}
        else{displayMessage(result);status(result.notice);}
      }catch(e){status(e.message,true);}finally{idle();}
    });$('mail-messages').append(row);
  }
  if(!r.messages.length)$('mail-messages').append(node('p','No messages match this folder and search.','empty'));
  $('mail-newer').disabled=!mailPages.length;$('mail-older').disabled=!mailNext;
  status('Mailbox loaded. Reading does not change message flags.');
}
function displayMessage(r){
  clearReader();$('reader').hidden=false;$('reader-label').textContent=r.signatureValid?'VERIFIED MESSAGE':'UNVERIFIED EMAIL';
  $('read-subject').textContent=r.subject;$('verification').textContent=r.signatureValid?'Signature valid · Trusted hybrid signer · Decrypted':r.notice || 'Not cryptographically verified';
  $('verification').classList.toggle('unverified',!r.signatureValid);
  $('read-addresses').textContent=r.sender+' → '+r.recipient;$('read-fingerprint').textContent=r.fingerprint || 'No verified OpenPGP fingerprint';$('read-text').textContent=r.text;
  if(r.html){$('read-html').srcdoc=r.html;$('read-html').hidden=false;}
  for(const file of r.attachments){
    const bytes=Uint8Array.from(atob(file.data),c=>c.charCodeAt(0));const url=URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'}));downloads.push(url);
    const a=node('a','Save attachment: '+file.name);a.href=url;a.download=file.name;$('read-files').append(a,document.createElement('br'));
  }
  $('reader').scrollIntoView({behavior:'smooth'});
}
on('mail-connect','click',connectMail,'Connecting Gmail…');
on('mail-login','click',async()=>{
  await api('mail-login',{profile:$('profile').value});status('Complete Gmail read/send consent in Google, then click Connect / reconnect Gmail. Chat credentials are unchanged.');
},'Starting separate Gmail authorization…');
on('mail-search','submit',async()=>{mailPage='';mailPages=[];await loadMail();},'Searching Gmail…');
on('mail-refresh','click',loadMail,'Refreshing Gmail…');
on('mail-older','click',async()=>{const old=mailPage;mailPage=mailNext;try{await loadMail();mailPages.push(old);$('mail-newer').disabled=false;}catch(e){mailPage=old;throw e;}},'Loading older email…');
on('mail-newer','click',async()=>{const old=mailPage;mailPage=mailPages[mailPages.length-1];try{await loadMail();mailPages.pop();$('mail-newer').disabled=!mailPages.length;}catch(e){mailPage=old;throw e;}},'Loading newer email…');
