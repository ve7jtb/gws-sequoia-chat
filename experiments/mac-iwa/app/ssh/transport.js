import {makeProbeOffer,predictTransport} from './kex-probe.js';
// Direct Sockets transport boundary. The probe stops after the public algorithm
// proposals and before the cryptographic handshake or authentication.
export function endpoint(host,port){
 if(/[\x00-\x1f\x7f]/.test(String(host)))throw Error('Invalid hostname characters.');
 host=String(host).trim();port=Number(port);
 if(!host||host.length>253||/[\s/\\@?#\x00-\x1f]/.test(host)||!Number.isInteger(port)||port<1||port>65535)throw Error('Enter a hostname or IP address and a port from 1 to 65535.');
 return {host,port};
}
export function sshUsername(value){
 if(typeof value!=='string'||!value||value.length>256||/[\x00-\x20\x7f]/.test(value))throw Error('Enter a valid SSH username.');
 return value;
}

export async function probe({host,port,signal,guard,Socket=globalThis.TCPSocket,timeoutMs=10000}){
 const target=endpoint(host,port);guard();
 if(typeof Socket!=='function')throw Error('Direct Sockets is unavailable in this browser.');
 if(signal?.aborted)throw Error('SSH operation cancelled.');
 let socket,reader,writer,timer,abort;
 let waitingFor='a TCP connection';
 const cancelled=new Promise((_,reject)=>{
  abort=()=>reject(Error('SSH operation cancelled.'));
  signal?.addEventListener('abort',abort,{once:true});
  timer=setTimeout(()=>reject(Error('Timed out waiting for '+waitingFor+'.')),timeoutMs);
 });
 try{
  socket=new Socket(target.host,target.port);socket.closed?.catch(()=>{});
  const opened=await Promise.race([socket.opened,cancelled]);guard();
  waitingFor='the server’s SSH identification';
  reader=opened.readable.getReader();writer=opened.writable.getWriter();
  await Promise.race([writer.write(new TextEncoder().encode('SSH-2.0-SequoiaIWA_probe\r\n')),cancelled]);
  let line='',total=0,identification,remaining=new Uint8Array();
  readIdentification:while(true){
   const {value,done}=await Promise.race([reader.read(),cancelled]);guard();
   if(done)throw Error('Server closed before sending an SSH identification.');
   for(let i=0;i<value.length;i++){
    const byte=value[i];
    if(++total>8192)throw Error('SSH identification exceeds the limit.');
    if(byte===10){
     const text=line.endsWith('\r')?line.slice(0,-1):line;line='';
     if(text.startsWith('SSH-')){
      if(!/^SSH-2\.0-[\x21-\x7e]+(?: [\x20-\x7e]*)?$/.test(text))throw Error('Unsupported SSH identification.');
      identification=text;
      remaining=value.subarray(i+1);
      break readIdentification;
     }
    }else{if(byte!==13&&(byte<32||byte>126))throw Error('Invalid SSH identification bytes.');line+=String.fromCharCode(byte);if(line.length>253)throw Error('SSH identification line too long.');}
   }
  }
  waitingFor='the server’s SSH algorithm proposal';
  // Preserve bytes coalesced with the identification line, or with a previous
  // frame, and assemble each bounded packet across arbitrary stream chunks.
  async function readExact(length){
   const result=new Uint8Array(length);
   for(let filled=0;filled<length;){
    if(!remaining.length){
     const {value,done}=await Promise.race([reader.read(),cancelled]);guard();
     if(done)throw Error('Server closed before sending an SSH algorithm proposal.');
     remaining=value;
    }
    const copied=Math.min(length-filled,remaining.length);
    result.set(remaining.subarray(0,copied),filled);
    remaining=remaining.subarray(copied);filled+=copied;
   }
   return result;
  }
  await Promise.race([writer.write(makeProbeOffer()),cancelled]);guard();
  for(let i=0;i<8;i++){
   const header=await readExact(4);
   const length=new DataView(header.buffer).getUint32(0);
   if(length<12||length>35000-4||(length+4)%8)throw Error('Invalid SSH transport packet length.');
   const packet=await readExact(length),padding=packet[0];
   if(padding<4||padding>=length-1)throw Error('Invalid SSH transport packet padding.');
   // SSH_MSG_IGNORE and SSH_MSG_DEBUG may precede the proposal.
   if(packet[1]===2||packet[1]===4)continue;
   return {identification,authenticated:false,...predictTransport(packet.subarray(1,length-padding))};
  }
  throw Error('Too many SSH transport messages before algorithm negotiation.');
 }finally{
  clearTimeout(timer);signal?.removeEventListener('abort',abort);
  // Release stream locks before closing so no session survives vault lock.
  if(reader){reader.cancel().catch(()=>{});reader.releaseLock();}
  writer?.releaseLock();
  // Report the result even if Chromium has not finished closing the socket.
  try{socket?.close()?.catch(()=>{});}catch{}
 }
}
