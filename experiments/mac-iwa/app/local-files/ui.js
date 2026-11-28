export function initializeLocalFiles({window,document}){
 const $=id=>document.getElementById('local-files-'+id);
 const panel=$('tab'),picker=$('upload'),list=$('list'),status=$('status');
 let running=null;
 const downloads=new Map();

 function revoke(url){
  clearTimeout(downloads.get(url));
  downloads.delete(url);
  URL.revokeObjectURL(url);
 }
 function clear(){
  running?.abort();
  picker.value='';
  list.replaceChildren();
  status.textContent='';
  for(const url of downloads.keys())revoke(url);
  panel.hidden=true;
  document.getElementById('local-files').hidden=true;
 }
 function showDownload({name,plain}){
  try{
   const url=URL.createObjectURL(new Blob([plain],{type:'application/octet-stream'}));
   downloads.set(url,setTimeout(()=>revoke(url),30000));
   const link=document.createElement('a');
   link.href=url;
   link.download=name;
   link.click();
  }finally{plain.fill(0);}
 }
 function render(files){
  list.replaceChildren();
  for(const file of files){
   const row=document.createElement('li');
   const details=document.createElement('span');
   details.textContent=file.unreadable?'File could not be authenticated':file.name+' · '+file.size.toLocaleString()+' bytes';
   row.append(details);
   if(!file.unreadable){
    const download=document.createElement('button');
    download.textContent='Download';
    download.onclick=()=>run(async(store,signal)=>{
     const result=await store.open(file.id,signal);
     if(signal.aborted){result.plain.fill(0);return;}
     showDownload(result);
    });
    row.append(download);
   }
   const remove=document.createElement('button');
   remove.textContent='Delete';
   remove.onclick=()=>run(async(store,signal)=>{
    if(!window.confirm('Permanently delete this encrypted local file?'))return;
    await store.remove(file.id,signal);
    await refresh(store,signal);
   });
   row.append(remove);
   list.append(row);
  }
 }
 async function refresh(store,signal){
  const files=await store.list(signal);
  if(signal.aborted)return;
  render(files);
  status.textContent=files.length?'':'No local files yet.';
 }
 async function run(fn){
  if(running||!window.vaultIsUnlocked?.())return;
  running=new AbortController();
  const {signal}=running;
  $('add').disabled=true;
  status.textContent='Working…';
  try{
   await fn(window.localFiles,signal);
   if(!signal.aborted&&status.textContent==='Working…')status.textContent='';
  }catch(error){if(!signal.aborted)status.textContent=error.message;}
  finally{running=null;$('add').disabled=false;}
 }
 $('add').onclick=()=>{
  const file=picker.files[0];
  if(!file){status.textContent='Choose a file first.';return;}
  run(async(store,signal)=>{
   await store.add(file,signal);
   if(signal.aborted)return;
   picker.value='';
   await refresh(store,signal);
   if(!signal.aborted)status.textContent='File encrypted and saved.';
  });
 };
 panel.onclick=()=>run(refresh);
 window.addEventListener('iwa-vault-locked',clear);
 window.addEventListener('pagehide',clear);
 window.addEventListener('iwa-vault-unlocked',()=>{panel.hidden=false;});
 panel.hidden=!window.vaultIsUnlocked?.();
}
