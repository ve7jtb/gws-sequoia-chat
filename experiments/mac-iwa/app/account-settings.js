// This is public account configuration, not credential storage. A single small
// origin-local record contains only a mailbox and a revision. In particular it
// cannot enroll a vault key, grant recipient trust, choose hardware slots, or
// carry OAuth tokens. Existing vault/identity IndexedDB databases are untouched.
export const ACCOUNT_SETTINGS_KEY='sequoia-iwa-public-account-v1';

export function accountEmail(value){
 if(typeof value!=='string')throw Error('Configure one Google account email in Account first.');
 const email=value.trim().toLowerCase();
 if(!email||email.length>254||! /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+$/.test(email))throw Error('Configure one Google account email in Account first.');
 const [local,domain]=email.split('@');
 if(local.length>64||local.startsWith('.')||local.endsWith('.')||local.includes('..')||domain.split('.').some(p=>!p||p.length>63||p.startsWith('-')||p.endsWith('-')))throw Error('Enter one valid account email, without a display name or header syntax.');
 return email;
}

export function createAccountSettings({storage=globalThis.localStorage,newRevision=()=>crypto.randomUUID()}={}){
 function read(){
  const raw=storage.getItem(ACCOUNT_SETTINGS_KEY);
  if(raw===null)return null;
  let record;try{if(raw.length>1024)throw Error();record=JSON.parse(raw);}catch(_){throw Error('Saved account settings are invalid. Clear this public account setting before configuring it again.');}
  if(!record||Array.isArray(record)||Object.keys(record).sort().join(',')!=='email,revision,version'||record.version!==1||typeof record.revision!=='string'||! /^[a-f0-9-]{36}$/.test(record.revision)||accountEmail(record.email)!==record.email)throw Error('Saved account settings are invalid. Clear this public account setting before configuring it again.');
  return Object.freeze(record);
 }
 function assert(snapshot){
  const current=read();
  if(!snapshot||!current||current.revision!==snapshot.revision||current.email!==snapshot.email)throw Error('Account settings changed; review the account and sign in again.');
  return current.email;
 }
 function save(email,expected,confirmed){
  if(confirmed!==true)throw Error('Review and confirm the account email first.');
  const normalized=accountEmail(email),current=read();
  // localStorage mutations are synchronous; there is no asynchronous work
  // between this revision comparison and the one-record commit. Revisions are
  // random so change-away/change-back cannot revive a stale send or dialog.
  if((current?.revision??null)!==(expected?.revision??null))throw Error('Account settings changed; review the account again.');
  const record={version:1,revision:newRevision(),email:normalized};
  storage.setItem(ACCOUNT_SETTINGS_KEY,JSON.stringify(record));return read();
 }
 return {read,assert,save,
  // This action is explicitly reviewed in the UI. It is also the recovery path
  // for a malformed public record; no encrypted vault or identity is removed.
  clear(confirmed){if(confirmed!==true)throw Error('Confirm removal of the public account setting.');storage.removeItem(ACCOUNT_SETTINGS_KEY);}
 };
}

// Legacy state is available only on the explicit migration button. Select one
// field rather than persisting that response: older helpers also return serial,
// identity and contact metadata, none of which belongs in account settings.
export function legacyAccount(snapshot){return accountEmail(snapshot?.account);}
