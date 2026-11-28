import test from 'node:test';
import assert from 'node:assert/strict';
import {showVaultUnlockProgress} from '../app/vault/unlock-progress.js';

test('vault progress lists unique serials and advances only as checks complete',()=>{
 const bar={value:4,removeAttribute(name){delete this[name];}},status={};
 const list={items:[],replaceChildren(){this.items=[];},append(item){this.items.push(item.textContent);}};
 const panel={hidden:true,ownerDocument:{createElement:()=>({})},
  querySelector:selector=>({progress:bar,'[role=status]':status,ul:list})[selector]};
 const progress=showVaultUnlockProgress(panel,'123');
 assert.equal(panel.hidden,false);
 assert.equal(status.textContent,'Finding key SN# 123');
 assert.equal(bar.value,undefined);
 for(const serial of ['42','123','42'])progress.update({stage:'found',serial});
 assert.deepEqual(list.items,['Found YubiKey SN# 42','Found YubiKey SN# 123 (selected)']);
 progress.update({stage:'slot',slot:'9d'});
 assert.equal(status.textContent,'Checking slot 9D (ML-KEM-768)');
 progress.update({stage:'slot-verified',slot:'9d'});
 assert.equal(bar.value,4);
 progress.update({stage:'slot',slot:'85'});
 assert.equal(status.textContent,'Checking slot 85 (X25519)');
 progress.update({stage:'slot-verified',slot:'85'});
 assert.equal(bar.value,5);
 assert.match(status.textContent,/Both vault keys verified/);
 progress.close();
 assert(panel.hidden);
 assert.deepEqual(list.items,[]);
});
