export const VAULT_REMOVAL_TIMEOUT_MS=30_000;
const PROBE_INTERVAL_MS=5_000;

export function monitoredVaultSerial(serial,scope=globalThis){
 return scope.SequoiaSecureChannel?.isRequired()===true&&
  typeof serial==='string'&&/^[1-9][0-9]{0,9}$/.test(serial)?serial:null;
}

// The deadline is independent of the probe. A stalled PC/SC operation, a
// different serial, or a failed secure session cannot extend it.
export function createVaultPresenceMonitor({probe,onTimeout,now=Date.now,setTimer=setTimeout,clearTimer=clearTimeout}){
 let session=null,alarm,poll,pending=false;
 function stop(){
  session=null;
  clearTimer(alarm);
  clearTimer(poll);
 }
 function check(){
  if(!session)return false;
  if(now()<session.lastSeen+VAULT_REMOVAL_TIMEOUT_MS)return true;
  const {serial}=session;
  stop();
  onTimeout(serial);
  return false;
 }
 function armDeadline(){
  clearTimer(alarm);
  alarm=setTimer(()=>{
   if(check())armDeadline();
  },Math.max(0,session.lastSeen+VAULT_REMOVAL_TIMEOUT_MS-now()));
 }
 function schedulePoll(){
  clearTimer(poll);
  poll=setTimer(refresh,PROBE_INTERVAL_MS);
 }
 async function refresh(){
  if(!check())return;
  if(pending){schedulePoll();return;}
  const expected=session;
  pending=true;
  try{
   const present=await probe(expected.serial);
   if(session!==expected||!check())return;
   if(Number.isFinite(present)&&present<=now()&&present>expected.lastSeen){
    expected.lastSeen=present;
    armDeadline();
   }
  }catch{
   // A transient reader error leaves the last authenticated deadline intact.
  }finally{
   pending=false;
   if(session===expected)schedulePoll();
  }
 }
 return {
  start(serial,lastSeen=now()){
   stop();
   if(!serial)return;
   session={serial,lastSeen};
   if(check()){armDeadline();schedulePoll();}
  },
  get serial(){return session?.serial??null;},
  stop,check,refresh,
  snapshot:()=>check()?{...session}:null,
 };
}
