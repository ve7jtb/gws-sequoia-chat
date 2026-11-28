import offer from './probe-offer.js';

const encoder=new TextEncoder(),decoder=new TextDecoder();
const kexInit=20;
const compression=['none'];
const aead=new Set(['aes128-gcm@openssh.com','aes256-gcm@openssh.com','chacha20-poly1305@openssh.com']);
export const usesHybridSshKex=algorithm=>algorithm==='mlkem768x25519-sha256';

// RFC 4253 KEXINIT is sent before SSH encryption begins. Exchange only the
// public proposals. The transport probe never sends a user name or a key.
export function makeProbeOffer(){
 const groups=[offer.keyExchanges,offer.hostKeys,offer.ciphers,offer.ciphers,offer.macs,offer.macs,compression,compression,[],[]];
 const lists=groups.map(group=>encoder.encode(group.join(',')));
 const payloadLength=22+lists.reduce((size,list)=>size+4+list.length,0);
 const padding=4+(8-((payloadLength+9)%8))%8;
 const packet=new Uint8Array(5+payloadLength+padding),view=new DataView(packet.buffer);
 view.setUint32(0,packet.length-4);
 packet[4]=padding;packet[5]=kexInit;
 crypto.getRandomValues(packet.subarray(6,22));
 let offset=22;
 for(const list of lists){
  view.setUint32(offset,list.length);offset+=4;
  packet.set(list,offset);offset+=list.length;
 }
 // The guess flag and reserved field stay zero.
 crypto.getRandomValues(packet.subarray(offset+5));
 return packet;
}

export function predictTransport(payload){
 if(payload[0]!==kexInit||payload.length<62)throw Error('Server did not send an SSH algorithm proposal.');
 const view=new DataView(payload.buffer,payload.byteOffset,payload.byteLength);
 const lists=[];
 let offset=17;
 for(let i=0;i<10;i++){
  if(offset+4>payload.length-5)throw Error('Invalid SSH algorithm proposal.');
  const length=view.getUint32(offset);offset+=4;
  if(length>payload.length-5-offset)throw Error('Invalid SSH algorithm proposal.');
  const text=decoder.decode(payload.subarray(offset,offset+length));offset+=length;
  const names=text?text.split(','):[];
  if(names.some(name=>!(/^[!-~]{1,64}$/).test(name)))throw Error('Invalid SSH algorithm name.');
  lists.push(names);
 }
 if(offset!==payload.length-5||payload[offset]>1)throw Error('Invalid SSH algorithm proposal.');
 const [keyExchanges,,sendCiphers,receiveCiphers,sendMacs,receiveMacs,sendCompression,receiveCompression]=lists;
 const common=(client,server)=>client.find(name=>server.includes(name));
 const keyExchange=common(offer.keyExchanges,keyExchanges);
 const clientToServer=common(offer.ciphers,sendCiphers),serverToClient=common(offer.ciphers,receiveCiphers);
 if(!keyExchange||!clientToServer||!serverToClient||
    !(aead.has(clientToServer)||common(offer.macs,sendMacs))||
    !(aead.has(serverToClient)||common(offer.macs,receiveMacs))||
    !sendCompression.includes('none')||!receiveCompression.includes('none')){
  throw Error('No compatible SSH transport algorithms were advertised.');
 }
 return {keyExchange,clientToServer,serverToClient,postQuantum:usesHybridSshKex(keyExchange)};
}
