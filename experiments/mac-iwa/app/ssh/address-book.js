import {endpoint,sshUsername} from './transport.js';

const kind='SSH saved host';

// Save connection settings and references to existing identities, keeping
// private keys, passwords, host-key trust and terminal output out of each row.
export function createSshAddressBook(access){
 function current(){
  const state=access.snapshot();
  if(!state?.unlocked)throw Error('Unlock the credential vault first.');
  return state;
 }
 const rows=state=>state.items.filter(item=>item.kind===kind);
 return Object.freeze({
  async list(){
   const state=current();
   await access.assertCurrent(state);
   return rows(state).map(({id,name,host,port,username,identityId,serial})=>({id,name,host,port,username,identityId,serial}));
  },
  async save({id='',name='',host,port,username,identityId,serial=''}){
   const target=endpoint(host,port);
   sshUsername(username);
   if(typeof identityId!=='string'||!identityId||identityId.length>128)throw Error('Select an SSH identity for this host.');
   if(typeof serial!=='string'||(serial&&!/^[1-9][0-9]{0,9}$/.test(serial)))throw Error('Select a provisioned YubiKey.');
   if(typeof name!=='string')throw Error('Enter a valid saved host name.');
   name=name.trim()||target.host;
   if(name.length>253||/[\x00-\x1f\x7f]/.test(name))throw Error('Enter a valid saved host name.');
   const state=current(),existing=id?rows(state).find(item=>item.id===id):null;
   if(id&&!existing)throw Error('The saved SSH host no longer exists.');
   if(!existing&&rows(state).length>=128)throw Error('Maximum 128 saved SSH hosts per vault.');
   const entry={kind,id:existing?.id||crypto.randomUUID(),name,...target,username,identityId,serial};
   await access.assertCurrent(state);
   const items=existing?state.items.map(item=>item===existing?entry:item):[...state.items,entry];
   await access.replaceItems(items,state,{change:'ssh-address-book'});
   return entry.id;
  },
  async remove(id){
   const state=current(),entry=rows(state).find(item=>item.id===id);
   if(!entry)throw Error('The saved SSH host no longer exists.');
   await access.assertCurrent(state);
   await access.replaceItems(state.items.filter(item=>item!==entry),state,{change:'ssh-address-book'});
  },
 });
}
