// The main window owns the SSH connection and vault. This view receives only
// terminal output, connection labels and transfer metadata.
export function openTerminalWindow({window,onInput,onResize,onClose,onTransfer}){
 const origin=window.location.origin;
 const popup=window.open('/ssh-terminal.html','_blank','popup,width=940,height=620');
 if(!popup)throw Error('The SSH terminal window could not open. Allow pop-ups for this app and try again.');
 const ready=Promise.withResolvers();
 let port,closed=false,initialized=false,timeout,closedCheck;
 function dispose(){
  if(closed)return;
  closed=true;
  window.clearTimeout(timeout);window.clearInterval(closedCheck);
  window.removeEventListener('message',acceptPopup);
  ready.reject(Error('SSH terminal window closed.'));
  if(port){
   // The child also clears its terminal on pagehide, even if the window
   // closes before this message can be delivered.
   port.postMessage({type:'clear'});
   port.close();
  }
  if(!popup.closed)popup.close();
 }
 function dismissed(){
  if(closed)return;
  dispose();onClose();
 }
 function acceptPopup(event){
  if(closed||port||event.origin!==origin||event.source!==popup||event.data?.type!=='ssh-terminal-ready')return;
  const channel=new window.MessageChannel();
  port=channel.port1;
  port.onmessage=({data})=>{
   if(closed)return;
   if(data?.type==='initialized'){
    initialized=true;window.clearTimeout(timeout);ready.resolve();return;
   }
   if(data?.type==='closed'){dismissed();return;}
   if(!initialized)return;
   if(data?.type==='file-transfer'&&Number.isSafeInteger(data.id)&&onTransfer){
    const {id,op,directory,name,fileId}=data;
    const validPath=typeof directory==='string'&&directory.length>0&&directory.length<=4096;
    if(op==='local'||(validPath&&(op==='browse'||(op==='get'&&typeof name==='string'&&name.length<=255)||
       (op==='put'&&typeof fileId==='string'&&fileId.length===36))))onTransfer({id,op,directory,name,fileId});
    return;
   }
   if(data?.type==='input'&&typeof data.text==='string'&&data.text.length<=65536)onInput(data.text);
   if(data?.type==='resize'&&Number.isInteger(data.rows)&&data.rows>=1&&data.rows<=1000&&Number.isInteger(data.cols)&&data.cols>=2&&data.cols<=1000)
    onResize(data.rows,data.cols);
  };
  popup.postMessage({type:'ssh-terminal-bind'},origin,[channel.port2]);
 }
 window.addEventListener('message',acceptPopup);
 timeout=window.setTimeout(()=>{
  ready.reject(Error('The SSH terminal window did not initialize.'));
  dispose();
 },8000);
 closedCheck=window.setInterval(()=>{if(popup.closed)dismissed();},500);
 function send(data){if(initialized&&!closed)port.postMessage(data);}
 return {
  ready:ready.promise,dispose,
  transferResult(id,detail){send({type:'file-transfer-result',id,...detail});},
  write(data){send({type:'output',data});},
  status(text,kind,connection){send({type:'status',text,kind,connection});},
 };
}
