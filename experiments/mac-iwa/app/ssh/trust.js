// OpenSSH known_hosts import is explicit trust configuration, never inferred
// from an unauthenticated banner. Keep patterns, keys and comments encrypted.
import {UnknownSshHostError,verifyHost} from './host-verifier.js';
const KIND='SSH host trust';
const decode=s=>{if(typeof s!=='string'||s.length>24000||!/^[A-Za-z0-9+/]+={0,2}$/.test(s))throw Error('Invalid host public key encoding.');const b=Uint8Array.from(atob(s),c=>c.charCodeAt(0));if(btoa(String.fromCharCode(...b)).replace(/=+$/,'')!==s.replace(/=+$/,''))throw Error('Noncanonical public key.');return b;};
function algorithm(blob){if(blob.length<5)throw Error('Invalid SSH public key.');const n=new DataView(blob.buffer,blob.byteOffset,blob.byteLength).getUint32(0);if(n>100||n+4>=blob.length)throw Error('Invalid SSH key algorithm.');return new TextDecoder('utf-8',{fatal:true}).decode(blob.slice(4,4+n));}
export async function sshHostFingerprint(key){
 const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',decode(key)));
 return 'SHA256:'+btoa(String.fromCharCode(...digest)).replace(/=+$/,'');
}
export function parseKnownHosts(text){
 if(typeof text!=='string'||new TextEncoder().encode(text).length>1048576)throw Error('Choose a known_hosts file up to 1 MiB.');
 const result=[];let line=0;
 for(const raw of text.split(/\r?\n/)){
  line++;const value=raw.trim();if(!value||value.startsWith('#'))continue;
  try{
   const parts=value.split(/\s+/);let marker='';if(parts[0].startsWith('@'))marker=parts.shift();
   if(marker&&!['@revoked','@cert-authority'].includes(marker))throw Error('unsupported marker');
   const [hosts,type,key,...comment]=parts;if(!hosts||!type||!key||hosts.length>1024)throw Error('missing host or key');
   if(algorithm(decode(key))!==type)throw Error('key algorithm mismatch');
   if(hosts.startsWith('|')){const h=hosts.split('|');if(h.length!==4||h[1]!=='1'||decode(h[2]).length!==20||decode(h[3]).length!==20)throw Error('invalid hashed hostname');}
   else if(hosts.split(',').some(p=>!p||p==='!'||/[\x00-\x20|\\]/.test(p)))throw Error('invalid hostname pattern');
   result.push({hosts,type,key,marker,comment:comment.join(' ')});if(result.length>2048)throw Error('too many keys');
  }catch(e){throw Error('known_hosts line '+line+': '+e.message);}
 }
 if(!result.length)throw Error('No host keys found.');return result;
}
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
export function createSshTrustStore(access){
 let pending=null;
 const current=()=>{const s=access.snapshot();if(!s?.unlocked)throw Error('Unlock the vault first.');return s;};
 const check=async s=>{await access.assertCurrent(s);const n=current();if(n.vaultId!==s.vaultId||n.epoch!==s.epoch||n.revision!==s.revision)throw Error('SSH trust review expired.');};
 return Object.freeze({
  cancel(){pending=null;},
  async list(){const s=current();await check(s);return structuredClone(s.items.filter(x=>x.kind===KIND));},
  async pinFirstUse({host,port,type,key,guard,signal}){
   // Only an exact endpoint can be pinned. Never turn connection input into
   // a wildcard, negation, hashed record or list of known_hosts targets.
   if(!/^[a-z0-9_.:%-]{1,253}$/i.test(host)||!Number.isInteger(port)||port<1||port>65535)throw Error('Enter a literal SSH hostname or IP address to save host trust.');
   const name=host.toLowerCase(),hosts=port===22?name:'['+name+']:'+port;
   const [entry]=parseKnownHosts([hosts,type,key].join(' '));
   // The negotiated algorithm and encoded key are separate inputs. Pin only
   // the exact key displayed during review.
   if(entry.type!==type||entry.key!==key||entry.comment)throw Error('Invalid SSH host key.');
   const s=current();guard();await check(s);
   try{
    await verifyHost({entries:s.items.filter(x=>x.kind===KIND),host,port,type,key,guard});
    return;
   }catch(error){if(!(error instanceof UnknownSshHostError))throw error;}
   const items=structuredClone(s.items);
   if(items.filter(x=>x.kind===KIND).length>=4096)throw Error('SSH trust inventory limit reached.');
   items.push({id:crypto.randomUUID(),kind:KIND,name:hosts,entry});
   guard();
   // The vault's compare-and-swap rejects a conflicting write made during
   // approval instead of replacing another window's host trust records.
   await access.replaceItems(items,s,{signal,change:'ssh-first-use'});
  },
  async review(text){const s=current(),entries=parseKnownHosts(text);await check(s);pending={id:crypto.randomUUID(),vaultId:s.vaultId,revision:s.revision,epoch:s.epoch,entries};return structuredClone(pending);},
  async import(review){
   const s=current();if(!pending||!same(pending,review))throw Error('SSH trust review changed.');pending=null;if(!same([review.vaultId,review.revision,review.epoch],[s.vaultId,s.revision,s.epoch]))throw Error('SSH trust review expired.');
   await check(s);
   // Reparse the exact reviewed data rather than trusting caller-provided fields.
   const entries=parseKnownHosts(review.entries.map(e=>[e.marker,e.hosts,e.type,e.key,e.comment].filter(Boolean).join(' ')).join('\n'));
   if(!same(entries,review.entries))throw Error('SSH trust review changed.');
   const items=structuredClone(s.items);
   for(const entry of entries)if(!items.some(x=>x.kind===KIND&&same(x.entry,entry)))items.push({id:crypto.randomUUID(),kind:KIND,name:entry.hosts,entry});
   if(items.filter(x=>x.kind===KIND).length>4096)throw Error('SSH trust inventory limit reached.');
   await access.replaceItems(items,s,{signal:new AbortController().signal});
   return entries.length;
  }
 });
}
