// Retain only the latest operation in this window. Timings and public serials
// are diagnostic data and never enter the encrypted vault or its backups.
export function startVaultUnlockTiming({started,serial,scpRequired,now=()=>performance.now(),report}){
 const events=[{ms:0,label:'Unlock vault clicked'}];
 let pinMs=null,scpRequiredAtPin=null;
 let ended=false;
 const publish=()=>report({
  serial,scpRequired,scpRequiredAtPin,pinMs,events:events.slice(),
 });
 const append=label=>{
  const ms=Math.round(now()-started);
  events.push({ms,label});
  return ms;
 };
 publish();
 return {
  record({stage,serial:found,slot,scpRequired:required}){
   if(ended)return;
   const label=progressLabel(stage,serial,found,slot);
   if(typeof label!=='string')return;
   const ms=append(label);
   if(stage==='pin-shown'){pinMs=ms;scpRequiredAtPin=required===true;ended=true;}
   publish();
  },
  finish(){
   if(ended)return;
   ended=true;
   append('Attempt ended before the PIN dialog opened');
   publish();
  },
 };
}

function progressLabel(stage,serial,found,slot){
 switch(stage){
  case 'finding': return 'Finding key SN# '+serial;
  case 'found': return /^[1-9][0-9]{0,9}$/.test(found)?'Found YubiKey SN# '+found:null;
  case 'bundle': return 'Reading signed vault certificate bundle';
  case 'verify': return 'Verifying enrolled vault recipient';
  case 'prepare': return 'Preparing vault decryption';
  case 'slot':
  case 'slot-verified':
   return ['9d','85'].includes(slot)?(stage==='slot'?'Checking slot ':'Verified slot ')+slot.toUpperCase():null;
  case 'pin-shown': return 'PIV PIN dialog opened';
 }
}

export function renderVaultUnlockTiming(panel,{serial,scpRequired,scpRequiredAtPin,pinMs,events}){
 panel.hidden=false;
 panel.querySelector('summary').textContent=pinMs===null?'Last Level 3 unlock timing':
  'Last Level 3 unlock timing · '+(pinMs/1000).toFixed(3)+' s to PIN';
 panel.querySelector('pre').textContent=[
  'YubiKey SN# '+serial+' · '+(scpRequired?'SCP11b required':'SCP11b not required'),
  ...(scpRequiredAtPin===null?[]:[scpRequiredAtPin?'SCP11b required at PIN prompt':'SCP11b not required at PIN prompt']),
  ...events.map(event=>(event.ms/1000).toFixed(3)+' s  '+event.label),
 ].join('\n');
}
