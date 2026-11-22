const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const ctx = { Uint8Array, Array, Map, Error, module: { exports: {} } };
ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(__dirname + '/../app/smartcard-piv.js', 'utf8'), ctx);
const piv = ctx.SequoiaSmartCardPiv;

// 1. Version & Serial parsing
assert.equal(piv.parseVersion(new Uint8Array([5, 7, 1])), '5.7.1');
assert.equal(piv.parseVersion(new Uint8Array([0, 0, 1])), '0.0.1');
assert.equal(piv.parseSerial(new Uint8Array([0x01, 0x23, 0x45, 0x67])), 0x01234567);

// 2. BER-TLV parsing with multi-byte length (e.g. 1952-byte ML-DSA-65 public key)
const bigPub = new Uint8Array(1952).fill(0xAB);
const tlv = new Uint8Array([
  0x01, 0x01, 0xE0,             // alg = Ed25519
  0x02, 0x02, 0x02, 0x03,       // PIN=once, touch=cached
  0x03, 0x01, 0x01,             // origin=generated
  0x04, 0x82, 0x07, 0xA0,       // tag 0x04, length 1952 (0x07A0)
  ...bigPub,
]);
const meta = piv.parseSlotMetadata(tlv);
assert.equal(meta.algorithm, 'Ed25519');
assert.equal(meta.pinPolicy, 'once');
assert.equal(meta.touchPolicy, 'cached');
assert.equal(meta.origin, 'generated');
assert.equal(meta.publicKeyBytes.length, 1952);
assert.equal(meta.publicKeyBytes[1951], 0xAB);

// 3. Unknown PQC algorithm ID formatted as hex
const pqcMeta = piv.parseSlotMetadata(new Uint8Array([0x01, 0x01, 0xF1, 0x02, 0x02, 0x03, 0x02]));
assert.equal(pqcMeta.algorithm, '0xf1');
assert.equal(pqcMeta.pinPolicy, 'always');
assert.equal(pqcMeta.touchPolicy, 'always');

// 4. GET RESPONSE (0x61 XX) chaining
(async () => {
  const replies = [
    new Uint8Array([0xDE, 0xAD, 0x61, 0x02]),
    new Uint8Array([0xBE, 0xEF, 0x90, 0x00]),
  ];
  const sent = [];
  const fakeConn = {
    async transmit(apdu) {
      sent.push(Array.from(apdu));
      return replies.shift();
    },
  };
  const res = await piv.transmitChained(fakeConn, piv.buildGetMetadataApdu(0x9C));
  assert.equal(res.sw, 0x9000);
  assert.deepEqual(Array.from(res.data), [0xDE, 0xAD, 0xBE, 0xEF]);
  assert.deepEqual(sent[1], [0x00, 0xC0, 0x00, 0x00, 0x02]);
  console.log('PASS smartcard-piv APDU, TLV, and GET RESPONSE chaining tests');
})();
