import test from 'node:test';
import assert from 'node:assert/strict';
import {Vault,random,b64} from '../app/vault/core.js';
import {verifyProvisioningRecovery} from '../app/vault/provisioning-recovery.js';

test('a separate enrolled YubiKey must unlock a backup containing the exact software identity',async()=>{
 const vault=new Vault(),secret=random(32);
 const w={id:crypto.randomUUID(),type:'prf',name:'Recovery',binding:{
  serial:'12345678',rpId:'isolated-app://test',credentialId:b64(random(32)),salt:b64(random(32)),
 }};
 await vault.create(w,secret);
 const item={id:crypto.randomUUID(),name:'Identity',kind:'test',encryptedSecret:'sealed',password:'local',
  public:{certificateHash:'a'.repeat(64)}};
 const stale=new Blob([JSON.stringify(vault.record)]);
 vault.data.items.push(item);
 await vault.save();
 const file=new Blob([JSON.stringify(vault.record)]);
 let assertions=0;
 const params={file,methodId:w.id,targetSerial:'87654321',sourceRecord:vault.record,item,
  assertPrf:async()=>{assertions++;return secret.slice();}};
 await assert.rejects(verifyProvisioningRecovery({...params,targetSerial:w.binding.serial}),/separate YubiKey/);
 assert.equal(assertions,0);
 await assert.rejects(verifyProvisioningRecovery({...params,file:stale}),/does not contain/);
 await verifyProvisioningRecovery(params);
 assert.equal(assertions,2);
 assert.equal(vault.unlocked,true);
});
