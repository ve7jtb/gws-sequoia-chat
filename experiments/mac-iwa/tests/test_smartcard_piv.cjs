const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');

const ctx = {
  Uint8Array, Array, Map, Error, TextEncoder,
  btoa: s => Buffer.from(s, 'binary').toString('base64'),
  atob: s => Buffer.from(s, 'base64').toString('binary'),
  crypto: webcrypto,
  module: { exports: {} },
};
ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(__dirname + '/../app/smartcard-piv.js', 'utf8'), ctx);
const piv = ctx.SequoiaSmartCardPiv;

// 1. Version, Serial & PIN metadata parsing
assert.equal(piv.parseVersion(new Uint8Array([5, 7, 1])), '5.7.1');
assert.equal(piv.parseVersion(new Uint8Array([0, 0, 1])), '0.0.1');
assert.equal(piv.parseSerial(new Uint8Array([0x01, 0x23, 0x45, 0x67])), 0x01234567);
assert.deepEqual(
  { ...piv.parsePinMetadata(new Uint8Array([0x05, 0x01, 0x01, 0x06, 0x02, 0x03, 0x03])) },
  { maximum: 3, remaining: 3 }
);

// 2. BER-TLV encode/decode with multi-byte length (1952-byte ML-DSA-65 public key)
const bigPub = new Uint8Array(1952).fill(0xAB);
const tlv = new Uint8Array([
  0x01, 0x01, 0xE0,
  0x02, 0x02, 0x02, 0x03,
  0x03, 0x01, 0x01,
  ...piv.encodeBerTlv(0x04, bigPub),
]);
const meta = piv.parseSlotMetadata(tlv);
assert.equal(meta.algorithm, 'Ed25519');
assert.equal(meta.pinPolicy, 'once');
assert.equal(meta.touchPolicy, 'cached');
assert.equal(meta.origin, 'generated');
assert.equal(meta.publicKeyBytes.length, 1952);
assert.equal(meta.publicKeyBytes[1951], 0xAB);

// 3. VERIFY PIN APDU encoding & padding
const verifyApdu = piv.buildVerifyPinApdu(new TextEncoder().encode('123456'));
assert.deepEqual(Array.from(verifyApdu), [
  0x00, 0x20, 0x00, 0x80, 0x08,
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF,
]);
assert.throws(() => piv.buildVerifyPinApdu(new TextEncoder().encode('12345')));

// 4. Command chaining for 1088-byte ML-KEM-768 ciphertext GENERAL AUTHENTICATE
const mlkemCt = new Uint8Array(1088).fill(0x5A);
const gaData = piv.buildGeneralAuthenticateData(0x85, mlkemCt);
const apdus = piv.buildChainedApdus(0x87, 0xF5, 0x9D, gaData);
assert.ok(apdus.length >= 5, '1088-byte ciphertext must be split into chained APDUs');
for (let i = 0; i < apdus.length - 1; i++) {
  assert.equal(apdus[i][0], 0x10, 'Intermediate APDU must have CLA=0x10');
  assert.equal(apdus[i][1], 0x87);
  assert.equal(apdus[i][4], 255);
}
assert.equal(apdus[apdus.length - 1][0], 0x00, 'Final APDU must have CLA=0x00');

// 5. Dynamic Auth Template response parsing
const gaResp = piv.encodeBerTlv(0x7C, piv.encodeBerTlv(0x82, new Uint8Array([1, 2, 3, 4])));
assert.deepEqual(Array.from(piv.parseGeneralAuthenticateResponse(gaResp)), [1, 2, 3, 4]);

// 6. SPKI EC uncompressed point extraction (P-256)
const fakePoint = new Uint8Array(65);
fakePoint[0] = 0x04;
fakePoint.fill(0x77, 1);
const fakeSpki = piv.encodeBerTlv(0x30, new Uint8Array([
  ...piv.encodeBerTlv(0x30, new Uint8Array([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])),
  ...piv.encodeBerTlv(0x03, new Uint8Array([0x00, ...fakePoint])),
]));
assert.deepEqual(Array.from(piv.extractEcUncompressedPointFromSpki(fakeSpki)), Array.from(fakePoint));

// 7. Command chaining + GET RESPONSE (0x61 XX) chaining
(async () => {
  const sent = [];
  const fakeConn = {
    async transmit(apdu) {
      sent.push(Array.from(apdu));
      if (apdu[0] === 0x10) return new Uint8Array([0x90, 0x00]);
      if (apdu[1] === 0x87) return new Uint8Array([0xDE, 0xAD, 0x61, 0x02]);
      if (apdu[1] === 0xC0) return new Uint8Array([0xBE, 0xEF, 0x90, 0x00]);
      throw Error('Unexpected APDU');
    },
  };
  const res = await piv.transmitCommandChained(fakeConn, 0x87, 0xF5, 0x9D, gaData);
  assert.equal(res.sw, 0x9000);
  assert.deepEqual(Array.from(res.data), [0xDE, 0xAD, 0xBE, 0xEF]);
  assert.equal(sent[sent.length - 1][1], 0xC0);

  // PIV GET METADATA EC public key (0x86 TLV & 0x7F49-wrapped) -> SPKI -> WebCrypto importKey round-trip
  for (const [curve, algId] of [['P-256', 0x11], ['P-384', 0x14]]) {
    const kp = await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: curve }, true, ['deriveBits']);
    const spkiExpected = new Uint8Array(await webcrypto.subtle.exportKey('spki', kp.publicKey));
    const point = piv.extractEcUncompressedPointFromSpki(spkiExpected);
    const tlvDirect = piv.encodeBerTlv(0x86, point);
    const tlvWrapped = piv.encodeBerTlv(0x7F49, tlvDirect);
    assert.deepEqual(Array.from(piv.extractEcPointFromPivMetadataPub(tlvDirect)), Array.from(point));
    assert.deepEqual(Array.from(piv.extractEcPointFromPivMetadataPub(tlvWrapped)), Array.from(point));
    const spkiBuilt = piv.ecUncompressedPointToSpki(point, algId);
    assert.deepEqual(Array.from(spkiBuilt), Array.from(spkiExpected));
    const imported = await webcrypto.subtle.importKey('spki', spkiBuilt, { name: 'ECDH', namedCurve: curve }, false, []);
    assert.equal(imported.type, 'public');
  }

  console.log('PASS smartcard-piv APDU, TLV, PIN, command chaining, SPKI, and GET RESPONSE tests');
})();
