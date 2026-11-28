// Show actual preparation stages, with no timing estimate or automatic retry.
export function showVaultUnlockProgress(panel,serial){
 const bar=panel.querySelector('progress'),status=panel.querySelector('[role=status]');
 const readers=panel.querySelector('ul'),seen=new Set();
 panel.hidden=false;
 readers.replaceChildren();
 bar.removeAttribute('value');
 status.textContent='Finding key SN# '+serial;
 return {
  update({stage,serial:found,slot}){
   if(stage==='found'){
    if(seen.has(found))return;
    seen.add(found);
    const item=panel.ownerDocument.createElement('li');
    item.textContent='Found YubiKey SN# '+found+(found===serial?' (selected)':'');
    readers.append(item);
    return;
   }
   if(stage==='bundle'){bar.value=1;status.textContent='Reading signed vault certificate bundle';}
   if(stage==='verify'){bar.value=2;status.textContent='Verifying enrolled vault recipient';}
   if(stage==='prepare'){bar.value=3;status.textContent='Preparing vault decryption';}
   if(stage==='slot'){
    const kem=slot==='9d';bar.value=kem?3:4;
    status.textContent=kem?'Checking slot 9D (ML-KEM-768)':'Checking slot 85 (X25519)';
   }
   if(stage==='slot-verified'){
    const kem=slot==='9d';bar.value=kem?4:5;
    status.textContent=kem?'Slot 9D verified':'Both vault keys verified. Enter the PIV PIN.';
   }
  },
  close(){panel.hidden=true;readers.replaceChildren();status.textContent='';},
 };
}
