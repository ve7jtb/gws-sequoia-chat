// Direct Sockets transport boundary. This probe deliberately stops before key
// exchange: a server identification line is not proof of server identity.
export function endpoint(host,port){
 if(/[\x00-\x1f\x7f]/.test(String(host)))throw Error('Invalid hostname characters.');
 host=String(host).trim();port=Number(port);
 if(!host||host.length>253||/[\s/\\@?#\x00-\x1f]/.test(host)||!Number.isInteger(port)||port<1||port>65535)throw Error('Enter a hostname or IP address and a port from 1 to 65535.');
 return {host,port};
}
export async function probe({host,port,signal,guard,Socket=globalThis.TCPSocket,timeoutMs=10000}){
 const target=endpoint(host,port);guard();
 if(typeof Socket!=='function')throw Error('Direct Sockets is unavailable in this browser.');
 if(signal?.aborted)throw Error('SSH operation cancelled.');
 let socket,reader,writer,timer,abort;
 const cancelled=new Promise((_,reject)=>{
  abort=()=>{reject(Error('SSH operation cancelled.'));try{socket?.close()?.catch(()=>{});}catch{}};
  signal?.addEventListener('abort',abort,{once:true});
  timer=setTimeout(abort,timeoutMs);
 });
 try{
  socket=new Socket(target.host,target.port);socket.closed?.catch(()=>{});
  const opened=await Promise.race([socket.opened,cancelled]);guard();
  reader=opened.readable.getReader();writer=opened.writable.getWriter();
  await Promise.race([writer.write(new TextEncoder().encode('SSH-2.0-SequoiaIWA_probe\r\n')),cancelled]);
  let line='',total=0;
  while(true){
   const {value,done}=await Promise.race([reader.read(),cancelled]);guard();
   if(done)throw Error('Server closed before sending an SSH identification.');
   for(const byte of value){
    if(++total>8192)throw Error('SSH identification exceeds the limit.');
    if(byte===10){
     const text=line.endsWith('\r')?line.slice(0,-1):line;line='';
     if(text.startsWith('SSH-')){
      if(!/^SSH-2\.0-[\x21-\x7e]+(?: [\x20-\x7e]*)?$/.test(text))throw Error('Unsupported SSH identification.');
      return {identification:text,authenticated:false};
     }
    }else{if(byte!==13&&(byte<32||byte>126))throw Error('Invalid SSH identification bytes.');line+=String.fromCharCode(byte);if(line.length>253)throw Error('SSH identification line too long.');}
   }
  }
 }finally{
  clearTimeout(timer);signal?.removeEventListener('abort',abort);
  // Release stream locks before closing so no session survives vault lock.
  if(reader){reader.cancel().catch(()=>{});reader.releaseLock();}
  writer?.releaseLock();try{await socket?.close();}catch{}
 }
}
