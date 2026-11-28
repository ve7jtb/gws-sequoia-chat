import test from 'node:test';
import assert from 'node:assert/strict';
import {decapsulate, diffieHellman, createPublicKey, generateKeyPairSync} from 'node:crypto';
import fs from 'node:fs';
import init,{vault_mlkem1024_encapsulate} from '../wasm/pkg/sequoia_iwa_verify.js';
import {wrapLevel5,openLevel5} from '../app/vault/level5.js';
import {unlockBackup} from '../app/vault/backup-unlock.js';
import {Vault} from '../app/vault/core.js';

test('Level 5 WASM and independent OpenSSL components recover the vault after lock',async()=>{
  await init({module_or_path:fs.readFileSync(new URL('../wasm/pkg/sequoia_iwa_verify_bg.wasm',import.meta.url))});
  const kem=generateKeyPairSync('ml-kem-1024');
  const ec=generateKeyPairSync('ec',{namedCurve:'secp384r1'});
  const der=key=>key.export({format:'der',type:'spki'});
  const material={serial:'123',level5:{
    kemPublic:der(kem.publicKey).subarray(-1568).toString('base64'),
    ecPublic:der(ec.publicKey).toString('base64'),
  }};
  const {binding,secret}=await wrapLevel5(material,input=>JSON.parse(vault_mlkem1024_encapsulate(JSON.stringify(input))));
  const open=(operation,b)=>{
    assert.equal(operation,'chat-vault-level5-open');
    const peer=createPublicKey({key:Buffer.from(b.ecEphemeral,'base64'),format:'der',type:'spki'});
    return {
      kemSecret:decapsulate(kem.privateKey,Buffer.from(b.kemCiphertext,'base64')).toString('base64'),
      ecSecret:diffieHellman({privateKey:ec.privateKey,publicKey:peer}).toString('base64'),
    };
  };
  const engine=new Vault();
  const id=crypto.randomUUID();
  await engine.create({id,name:'Test Level 5',type:'piv',binding},secret);
  const record=structuredClone(engine.record);
  secret.fill(0);
  engine.lock();
  await assert.rejects(engine.unlock(record,id,await openLevel5({...binding,serial:'124'},open)));
  await unlockBackup(record,id,engine,{signal:new AbortController().signal,request:open});
  assert.equal(engine.unlocked,true);
});
