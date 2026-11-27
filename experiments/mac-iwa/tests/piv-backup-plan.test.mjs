import {test} from 'node:test';
import assert from 'node:assert/strict';
import {planPivBackup,planLevel3Provisioning,USER_PIV_SLOTS} from '../app/piv-backup-plan.js';
// Synthetic serial only: these tests perform no card discovery or mutation.
const request=()=>({profile:'level3',serial:'12345678',expectedSerial:'12345678',supportedAlgorithms:['ML-DSA-65','ML-KEM-768','Ed25519','X25519'],slots:USER_PIV_SLOTS.map(slot=>({slot,keyPresent:false,certificatePresent:false}))});
test('backup plan keeps certification, signing and encryption roles distinct',()=>{
 const r=request(),plan=planPivBackup(r);assert.equal(plan.keys.length,6);assert.equal(new Set(plan.keys.map(k=>k.slot)).size,6);
 assert(plan.keys.every(k=>k.pin==='always'));assert.equal(plan.operation,'import-existing-software-keys');
 assert.equal(plan.keys.find(k=>k.slot==='9c').touch,'always');assert.equal(plan.keys.find(k=>k.slot==='9d').touch,'always');
 assert.equal(plan.keys.find(k=>k.slot==='84').touch,'never');
});
test('unknown, occupied, certificate-only and duplicate slots refuse the entire plan',()=>{
 for(const mutate of [r=>r.slots.pop(),r=>r.slots[0].keyPresent=true,r=>r.slots[0].certificatePresent=true,r=>delete r.slots[0].keyPresent,r=>r.slots.push(r.slots[0])]){const r=request();mutate(r);assert.throws(()=>planPivBackup(r));}
});
test('wrong card or unsupported composite cannot produce a partial backup',()=>{
 for(const mutate of [r=>r.serial='87654321',r=>r.supportedAlgorithms.pop(),r=>r.profile='level5']){const r=request();mutate(r);assert.throws(()=>planPivBackup(r));}
});

test('serial is detected rather than supplied in advance; subsequent review binds it',()=>{
 const r=request();delete r.expectedSerial;assert.equal(planPivBackup(r).serial,'12345678');
 r.expectedSerial='87654321';assert.throws(()=>planPivBackup(r),/does not match/);
});
test('occupied unrelated slots reject even when every destination is empty',()=>{
 for(const slot of ['9a','9e','82','83','95']){const r=request();r.slots.find(s=>s.slot===slot).keyPresent=true;assert.throws(()=>planPivBackup(r),/not empty/);}
});

test('both modes plan the same optional NIST and S/MIME keys with RFC 9980 as default',async()=>{
 const {planLevel3Provisioning}=await import('../app/piv-backup-plan.js');
 const input=request();
 input.supportedAlgorithms.push('P-384');
 const options={...input,includeSmime:true,includeExperimentalNist:true};
 const backup=planLevel3Provisioning(options);
 const direct=planLevel3Provisioning({...options,mode:'on-card'});
 assert.equal(backup.operation,'import-existing-software-keys');
 assert.equal(direct.operation,'generate-on-card');
 assert.deepEqual(backup.keys,direct.keys);
 assert.equal(new Set(backup.keys.map(key=>key.slot)).size,10);
 const cert=backup.certificates;
 assert.equal(cert.defaultOpenPgp,'rfc9980');
 assert.deepEqual(cert.experimentalNist.certification,['8a','8b']);
 assert.deepEqual(cert.experimentalNist.signing,cert.smime.hybrid.signing);
 assert.deepEqual(cert.experimentalNist.encryption,cert.smime.hybrid.encryption);
 assert.deepEqual(cert.smime.pure,{signing:['9c'],encryption:['9d']});
 assert(!cert.experimentalNist.certification.some(slot=>cert.rfc9980.certification.includes(slot)));
 assert.equal(planPivBackup(options).keys.length,6);
 input.slots.find(slot=>slot.slot==='8a').keyPresent=true;
 assert.throws(()=>planLevel3Provisioning(options),/not empty/);
});

// SSH is independent of existing message keys and never adds a certificate.
test('SSH addition fails closed on unsupported ML-DSA-44 or occupied slots',()=>{
 const slots=USER_PIV_SLOTS.map(slot=>({slot,keyPresent:false,certificatePresent:false}));
 const input={profile:'level3',serial:'12345678',includeSmime:true,includeSsh:true,slots,supportedAlgorithms:['ML-DSA-65','ML-KEM-768','Ed25519','X25519','P-384']};
 assert.throws(()=>planLevel3Provisioning(input),/ML-DSA-44/);
 input.supportedAlgorithms.push('ML-DSA-44');
 const plan=planLevel3Provisioning(input);
 assert.deepEqual(plan.ssh.signing,['8c','8d']);assert.equal(plan.keys.length,10);
 assert.deepEqual(plan.certificates.smime.pure.signing,['9c']);
 input.slots.find(k=>k.slot==='8c').keyPresent=true;
 assert.throws(()=>planLevel3Provisioning(input),/not empty/);
});
