// Evaluate encrypted known_hosts records before the SSH engine authenticates.
// Host certificates require a separate CA/principal verifier; until integrated,
// fail closed instead of treating a CA key as a directly trusted server key.
const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
// Bounded wildcard matching without a backtracking regular expression. A
// malicious imported pattern such as *a*a*... must not freeze the UI thread.
function pattern(pattern,name){
 pattern=pattern.toLowerCase();name=name.toLowerCase();let p=0,n=0,star=-1,retry=0;
 while(n<name.length){
  if(p<pattern.length&&(pattern[p]==='?'||pattern[p]===name[n])){p++;n++;}
  else if(pattern[p]==='*'){star=p++;retry=n;}
  else if(star>=0){p=star+1;n=++retry;}
  else return false;
 }
 while(pattern[p]==='*')p++;return p===pattern.length;
}
const sameKey=(a,b)=>a.replace(/=+$/,'')===b.replace(/=+$/,'');
export class UnknownSshHostError extends Error{
 constructor(){super('Unknown SSH host. Import a known_hosts entry or enable trust on first use.');}
}
export async function matchesHost(hosts,host,port=22){
 const name=Number(port)===22?host:'['+host+']:'+port;
 if(hosts.startsWith('|1|')){
  const [,version,salt,expected]=hosts.split('|');
  if(version!=='1')return false;
  const key=await crypto.subtle.importKey('raw',bytes(salt),{name:'HMAC',hash:'SHA-1'},false,['sign']);
  const actual=new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(name)));
  const want=bytes(expected);let difference=actual.length^want.length;
  for(let i=0;i<actual.length;i++)difference|=actual[i]^(want[i]||0);
  return difference===0;
 }
 let matched=false;
 for(const entry of hosts.split(',')){
  const negative=entry.startsWith('!');if(pattern(negative?entry.slice(1):entry,name)){if(negative)return false;matched=true;}
 }
 return matched;
}
export async function verifyHost({entries,host,port=22,type,key,guard=()=>{}}){
 guard();if(type.includes('-cert-')||type.endsWith('-cert'))throw Error('SSH host certificates are not supported yet.');
 let matching=false,trusted=false;
 for(const record of entries){
  const entry=record.entry||record;
  // Revocation applies to the key even if it was also positively trusted by
  // another import. Never let row ordering undo a revoked-key decision.
  if(entry.marker==='@revoked'&&entry.type===type&&sameKey(entry.key,key))throw Error('SSH host key is revoked.');
  const applies=await matchesHost(entry.hosts,host,port);guard();
  if(!applies)continue;
  // A matching CA or revocation record is already a trust decision for this
  // endpoint. First-use enrollment must never bypass it.
  matching=true;
  if(!entry.marker&&entry.type===type&&sameKey(entry.key,key))trusted=true;
 }
 guard();
 if(!trusted){
  if(matching)throw Error('SSH host key changed or algorithm is not trusted.');
  throw new UnknownSshHostError();
 }
 return true;
}
