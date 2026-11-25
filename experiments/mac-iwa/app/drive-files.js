// File transport is deliberately separate from the authenticator-encrypted
// vault backup. Its payload is the standard OpenPGP packet produced by WASM;
// Google receives neither the original files nor any private-key material.
import {DRIVE_SCOPE} from './backup-drive.js';
import {bytes64,b64,LIMIT} from './message-mime.js';
export {DRIVE_SCOPE};
const BASE='https://www.googleapis.com';
function id(value){if(typeof value!=='string'||! /^[A-Za-z0-9_-]{1,200}$/.test(value))throw Error('Invalid Drive file ID');return value;}
export function encryptedPacket(encoded){
 if(typeof encoded!=='string'||encoded.length>Math.ceil(LIMIT/3)*4)throw Error('Invalid encrypted packet size');
 const raw=bytes64(encoded);
 // This is only a transport framing check, NOT signature verification. The
 // recipient worker parses all packets, authenticates encryption and verifies
 // the signer against the explicitly selected trusted certificate on opening.
 const tag=raw[0]&64?raw[0]&63:(raw[0]>>2)&15;
 if(typeof encoded!=='string'||encoded.length>Math.ceil(LIMIT/3)*4||b64(raw)!==encoded||raw.length<4||raw.length>LIMIT||!(raw[0]&128)||tag!==1)throw Error('Expected bounded public-key encrypted OpenPGP packet');
 return raw;
}
export function createDriveFiles({fetcher=fetch,clock=()=>Date.now(),gate=()=>{}}={}){
 let token='',expires=0,epoch=0;const active=new Set();
 function clear(){epoch++;token='';expires=0;for(const c of active)c.abort();active.clear();}
 function connect(session){clear();gate();if(!session?.scope?.split(' ').includes(DRIVE_SCOPE)||typeof session.token!=='string'||!session.token||!Number.isFinite(session.expiresIn)||session.expiresIn<=0)throw Error('drive.file permission required');token=session.token;expires=clock()+session.expiresIn*1000;}
 async function request(path,{json=true,...options}={}){
  gate();if(!token||clock()>=expires){clear();throw Error('Connect Google Drive first');}
  const generation=epoch,controller=new AbortController();active.add(controller);
  const current=()=>{gate();if(generation!==epoch||clock()>=expires)throw Error('Drive session changed or expired');};
  const timer=setTimeout(()=>controller.abort(),60000);
  try{
   // Fixed API origin, no redirects, and bounded streaming prevent a Drive
   // file/metadata response from supplying a bearer-token destination or an
   // unbounded allocation. No failed request is automatically retried.
   const response=await fetcher(BASE+path,{...options,signal:controller.signal,redirect:'error',cache:'no-store',headers:{...options.headers,Authorization:'Bearer '+token}});current();
   if(!response.ok)throw Error('Drive HTTP '+response.status+'; no automatic retry');
   const reader=response.body.getReader(),parts=[];let size=0;
   try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>LIMIT)throw Error('Drive response exceeds preview limit');parts.push(value);current();}}finally{await reader.cancel();}
   current();const data=new Uint8Array(size);let offset=0;for(const part of parts){data.set(part,offset);offset+=part.length;}
   return json?JSON.parse(new TextDecoder().decode(data)):data;
  }finally{clearTimeout(timer);active.delete(controller);}
 }
 return {connect,clear,
  async list(page=''){
   if(typeof page!=='string'||page.length>4096)throw Error('Invalid Drive page token');
   const q=new URLSearchParams({q:"trashed=false and appProperties has { key='sequoiaOpenPgp' and value='1' }",fields:'files(id,name,modifiedTime,size),nextPageToken',pageSize:'100',pageToken:page,orderBy:'modifiedTime desc'});
   return request('/drive/v3/files?'+q);
  },
  async upload(cipher){
   const raw=encryptedPacket(cipher),boundary='sequoia_'+crypto.randomUUID();
   // Neutral names keep original attachment names and the protected subject
   // inside encryption. Create only: existing files/sharing are never modified.
   const metadata={name:'encrypted-'+crypto.randomUUID()+'.pgp',mimeType:'application/pgp-encrypted',appProperties:{sequoiaOpenPgp:'1'}};
   const body=new Blob(['--'+boundary+'\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n'+JSON.stringify(metadata)+'\r\n--'+boundary+'\r\nContent-Type: application/pgp-encrypted\r\n\r\n',raw,'\r\n--'+boundary+'--\r\n']);
   return request('/upload/drive/v3/files?uploadType=multipart&fields=id,name',{method:'POST',headers:{'Content-Type':'multipart/related; boundary='+boundary},body});
  },
  async download(file){
   // Check the marker before downloading. A local file ID alone cannot cause
   // arbitrary user files to be treated as one of this feature's encrypted files.
   const key=id(file),meta=await request('/drive/v3/files/'+key+'?fields=id,appProperties,size');
   if(meta.id!==key||meta.appProperties?.sequoiaOpenPgp!=='1'||! /^\d+$/.test(String(meta.size))||Number(meta.size)>LIMIT)throw Error('Not an app-created OpenPGP file within the preview limit');
   const cipher=b64(await request('/drive/v3/files/'+key+'?alt=media',{json:false}));encryptedPacket(cipher);return cipher;
  }
 };
}
