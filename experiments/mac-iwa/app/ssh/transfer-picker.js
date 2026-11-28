import {maxBytes} from '../local-files/storage.js';

export function createTransferPicker({document,send}){
 const $=id=>document.getElementById('files-'+id);
 const dialog=$('dialog'),remote=$('remote'),local=$('local'),status=$('status');
 let enabled=false,sequence=0,pending,remoteRows=[],localRows=[],directory='';
 const chosenRemote=()=>remoteRows[remote.selectedIndex];
 const chosenLocal=()=>localRows[local.selectedIndex];
 function controls(){
  const idle=enabled&&!pending;
  $('open').disabled=!enabled;
  for(const id of ['browse','path','remote','local'])$(id).disabled=!idle;
  $('parent').disabled=!idle||!directory||directory==='/';
  $('folder').disabled=!idle||!chosenRemote()?.directory;
  const file=chosenRemote();
  $('get').disabled=!idle||!file||file.directory||file.size>maxBytes;
  $('put').disabled=!idle||!directory||!chosenLocal();
 }
 function options(select,rows,label){
  select.replaceChildren(...rows.map((row,index)=>{
   const option=document.createElement('option');
   option.value=String(index);
   option.textContent=label(row);
   return option;
  }));
  select.selectedIndex=-1;
 }
 function request(op,fields={}){
  if(!enabled||pending)return Promise.reject(Error('The file picker is busy.'));
  return new Promise((resolve,reject)=>{
   const id=++sequence;
   pending={id,resolve,reject};
   controls();
   send({type:'file-transfer',id,op,...fields});
  });
 }
 async function browse(target){
  const result=await request('browse',{directory:target});
  directory=result.directory;
  $('path').value=directory;
  remoteRows=result.entries;
  options(remote,remoteRows,row=>row.name+(row.directory?'/':' · '+row.size.toLocaleString()+' bytes'));
 }
 async function refreshLocal(){
  localRows=await request('local');
  options(local,localRows,row=>row.name+' · '+row.size.toLocaleString()+' bytes');
 }
 const run=async action=>{
  if(!enabled||pending)return;
  status.textContent='Working…';
  try{await action();if(status.textContent==='Working…')status.textContent='';}
  catch(error){if(enabled)status.textContent=error.message;}
  finally{controls();}
 };
 $('open').onclick=()=>{
  dialog.showModal();
  run(async()=>{await browse(directory||'.');await refreshLocal();});
 };
 $('done').onclick=()=>dialog.close();
 $('browse').onclick=()=>run(()=>browse($('path').value.trim()));
 $('path').onkeydown=event=>{if(event.key==='Enter')$('browse').click();};
 $('parent').onclick=()=>run(()=>browse(directory.slice(0,directory.lastIndexOf('/'))||'/'));
 $('folder').onclick=()=>run(async()=>{
  const row=chosenRemote();
  if(row?.directory)await browse(directory.replace(/\/$/,'')+'/'+row.name);
 });
 $('get').onclick=()=>run(async()=>{
  const row=chosenRemote();
  if(!row||row.directory||row.size>maxBytes)return;
  await request('get',{directory,name:row.name});
  status.textContent='Saved to the encrypted local store.';
  await refreshLocal();
 });
 $('put').onclick=()=>run(async()=>{
  const row=chosenLocal();
  if(!row||!directory)return;
  await request('put',{directory,fileId:row.id});
  status.textContent='Copied to the remote directory.';
  await browse(directory);
 });
 local.onchange=remote.onchange=controls;
 // Closing the picker leaves the window and any in-flight transfer alive.
 // Disconnecting the SSH terminal cancels the worker and clears both lists.
 return {
  enable(){enabled=true;controls();},
  result({id,error,result}){
   if(pending?.id!==id)return;
   const request=pending;pending=null;
   if(error)request.reject(Error(error));else request.resolve(result);
  },
  clear(){
   enabled=false;
   const request=pending;pending=null;
   request?.reject(Error('SSH connection closed.'));
   remoteRows=[];localRows=[];directory='';
   remote.replaceChildren();local.replaceChildren();$('path').value='.';
   status.textContent='';
   if(dialog.open)dialog.close();
   controls();
  },
 };
}
