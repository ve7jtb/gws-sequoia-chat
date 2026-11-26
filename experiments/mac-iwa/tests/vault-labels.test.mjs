import test from 'node:test';
import assert from 'node:assert/strict';
import {unlockMethodLabel} from '../app/vault/labels.js';

test('enrolled method shows the bound serial once without changing its saved name', () => {
  const method = {name:'YubiKey 12345678 PIV',type:'piv',binding:{serial:'12345678'}};
  assert.equal(unlockMethodLabel(method),'YubiKey SN# 12345678 PIV · PIV');
  assert.equal(method.name,'YubiKey 12345678 PIV');
  method.name='YubiKey SN# 12345678';
  assert.equal(unlockMethodLabel(method),'YubiKey SN# 12345678 · PIV');
  method.name='Travel key';
  assert.equal(unlockMethodLabel(method),'Travel key · SN# 12345678 · PIV');
  method.name='Key 123456789';
  assert.equal(unlockMethodLabel(method),'Key 123456789 · SN# 12345678 · PIV');
});
test('unbound FIDO labels retain the friendly name', () => {
  assert.equal(unlockMethodLabel({name:'Travel key',type:'prf'}),'Travel key · PRF');
});
