// Packaging checks catch long-line HTML merge conflicts that unit stubs miss.
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const html=fs.readFileSync(new URL('../app/index.html',import.meta.url),'utf8');
test('Web Smart Card and masked PIN/OAuth controls ship exactly once',()=>{
 for(const id of ['smartcard-pin-dialog','smartcard-pin-input','smartcard-check','smartcard-slots','alternate-unlock-dialog','alternate-unlock-method','google-oauth-mode','google-loopback-client','google-loopback-secret','google-loopback-start','google-loopback-link'])
  assert.equal(html.split(`id="${id}"`).length-1,1,id);
 assert.match(html,/<input[^>]*id="smartcard-pin-input"[^>]*type="password"|<input[^>]*type="password"[^>]*id="smartcard-pin-input"/);
 assert.ok(!html.includes('<<<<<<<'));
 for(const id of ['hardware-transport','identity-refresh','identity-companion-restore','account-migrate','migration-review'])
  assert.ok(!html.includes(`id="${id}"`),id);
});
