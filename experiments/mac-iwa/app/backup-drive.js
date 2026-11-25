// Drive transport accepts only sealed complete-backup envelopes. It never
// receives the vault content key, vault plaintext, PRF outputs or hardware PINs.
export const DRIVE_SCOPE='https://www.googleapis.com/auth/drive.file';
const BASE='https://www.googleapis.com',MAX=5*1024*1024;
const fileId=id=>{if(typeof id!=='string'||! /^[A-Za-z0-9_-]{1,200}$/.test(id))throw Error('Invalid Drive file ID');return id;};
export function createBackupDrive({fetcher=fetch,clock=()=>Date.now()}={}){
 let token='',expires=0,epoch=0;
 function disconnect(){token='';expires=0;epoch++;}
 function connect(session){disconnect();if(!session?.scope?.split(' ').includes(DRIVE_SCOPE)||!session.token||!Number.isFinite(session.expiresIn)||session.expiresIn<=0)throw Error('Drive permission missing');token=session.token;expires=clock()+session.expiresIn*1000;}
 async function request(path,options={}){
  if(!token||clock()>=expires)throw Error('Connect Google Drive first');const generation=epoch;
  const response=await fetcher(BASE+path,{...options,redirect:'error',cache:'no-store',headers:{...options.headers,Authorization:'Bearer '+token}});
  if(generation!==epoch)throw Error('Drive session changed');
  if(!response.ok)throw Error('Drive HTTP '+response.status+'; no automatic retry');
  // Stream-bound downloads prevent an untrusted file from exhausting memory.
  const reader=response.body.getReader();let size=0;const chunks=[];
  try{for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>MAX)throw Error('Drive backup exceeds 5 MiB');chunks.push(value);}}finally{await reader.cancel();}
  if(generation!==epoch)throw Error('Drive session changed');
  const all=new Uint8Array(size);let offset=0;for(const b of chunks){all.set(b,offset);offset+=b.length;}return JSON.parse(new TextDecoder().decode(all));
 }
 function check(box){if(box?.format!=='sequoia-complete-backup'||box.version!==2||typeof box.cipher!=='string'||JSON.stringify(box).length>MAX)throw Error('Choose an encrypted complete backup up to 5 MiB');return box;}
 return {connect,disconnect,
  async list(page=''){
   if(typeof page!=='string'||page.length>4096)throw Error('Invalid page');
   const q=new URLSearchParams({q:"trashed=false and appProperties has { key='sequoiaBackup' and value='1' }",fields:'files(id,name,modifiedTime,size),nextPageToken',pageSize:'100',orderBy:'modifiedTime desc',pageToken:page});return request('/drive/v3/files?'+q);
  },
  async upload(box){
   check(box);const boundary='sequoia_'+crypto.randomUUID(),name='sequoia-backup-'+new Date(clock()).toISOString().replace(/[:.]/g,'-')+'.encrypted.json';
   const metadata={name,mimeType:'application/octet-stream',appProperties:{sequoiaBackup:'1'}};
   const body='--'+boundary+'\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n'+JSON.stringify(metadata)+'\r\n--'+boundary+'\r\nContent-Type: application/octet-stream\r\n\r\n'+JSON.stringify(box)+'\r\n--'+boundary+'--\r\n';
   // Always create a new snapshot; never overwrite or delete an earlier backup.
   return request('/upload/drive/v3/files?uploadType=multipart&fields=id,name',{method:'POST',headers:{'Content-Type':'multipart/related; boundary='+boundary},body});
  },
  async download(id){return check(await request('/drive/v3/files/'+fileId(id)+'?alt=media'));}
 };
}
