import {FitAddon} from './vendor/xterm/addon-fit.js';

const node=id=>document.getElementById(id);
const opener=window.opener,origin=location.origin;
const container=node('terminal'),status=node('status');
const initialFont=14,minFont=10,maxFont=30;
let port,terminal,observer,fit,resizeFrame,closed=false;

function clearTerminal(){
 if(closed)return;
 closed=true;
 window.removeEventListener('message',bind);
 observer?.disconnect();cancelAnimationFrame(resizeFrame);
 if(terminal){terminal.reset();terminal.dispose();terminal=null;}
 // Remove the rendered cells and accessibility/clipboard surfaces as well.
 container.replaceChildren();
 for(const id of ['credential','exchange']){node(id).textContent='';node(id).hidden=true;}
 port?.close();
}

function scheduleFit(){
 if(closed||resizeFrame)return;
 resizeFrame=requestAnimationFrame(()=>{
  resizeFrame=undefined;
  const size=fit.proposeDimensions();
  if(!size)return;
  terminal.resize(Math.min(1000,size.cols),Math.min(1000,size.rows));
 });
}

function fontSize(size){
 if(!terminal)return;
 terminal.options.fontSize=Math.min(maxFont,Math.max(minFont,size));
 node('font-size').textContent=terminal.options.fontSize+' px';
 node('smaller').disabled=terminal.options.fontSize===minFont;
 node('larger').disabled=terminal.options.fontSize===maxFont;
 scheduleFit();terminal.focus();
}

function bind(event){
 if(closed||port||event.source!==opener||event.origin!==origin||event.data?.type!=='ssh-terminal-bind'||event.ports.length!==1)return;
 window.removeEventListener('message',bind);
 port=event.ports[0];
 terminal=new window.Terminal({fontSize:initialFont,scrollback:1000,disableStdin:true,allowProposedApi:false,theme:{background:'#11191d',foreground:'#edf5f5'}});
 fit=new FitAddon();
 terminal.loadAddon(fit);
 terminal.open(container);
 terminal.onData(text=>port.postMessage({type:'input',text}));
 terminal.onResize(({rows,cols})=>port.postMessage({type:'resize',rows,cols}));
 observer=new ResizeObserver(scheduleFit);observer.observe(container);
 port.onmessage=({data})=>{
  if(data?.type==='clear'){clearTerminal();return;}
  if(data?.type==='output'&&data.data instanceof Uint8Array)terminal.write(data.data);
  if(data?.type==='status'){
   status.textContent=data.text;
   terminal.options.disableStdin=data.kind!=='ready';
   if(data.connection){
    for(const [id,text] of [['credential',data.connection.login],['exchange',data.connection.transport]]){
     const label=node(id);
     label.textContent=text;label.hidden=false;label.dataset.warning=String(text.startsWith('Warning:'));
    }
    window.focus();terminal.focus();
   }
  }
 };
 node('smaller').onclick=()=>fontSize(terminal?.options.fontSize-1);
 node('larger').onclick=()=>fontSize(terminal?.options.fontSize+1);
 node('font-size').onclick=()=>fontSize(initialFont);
 port.postMessage({type:'initialized'});
 scheduleFit();
}

node('close').onclick=()=>window.close();
window.addEventListener('pagehide',()=>{
 if(!closed)port?.postMessage({type:'closed'});
 clearTerminal();
},{once:true});
if(opener){
 window.addEventListener('message',bind);
 opener.postMessage({type:'ssh-terminal-ready'},origin);
}else status.textContent='Open this window from the SSH tab.';
