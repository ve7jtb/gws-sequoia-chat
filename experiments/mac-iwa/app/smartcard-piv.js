// Web Smart Card (navigator.smartCard) YubiKey PIV transport.
// Supports read-only PIV inspection, 24-slot hardware audit (sequoia-iwa-hardware-audit v1),
// and explicit PIN-authorized PIV operations (signDigest, decapsulateComponents, classical ECDH)
// directly over PC/SC without the extension, native host, or PKCS#11.
(function(global){
'use strict';

const PIV_AID = new Uint8Array([0xA0,0x00,0x00,0x03,0x08,0x00,0x00,0x10,0x00]);
const LEVEL3_SLOTS = [
  {id:0x9C, hex:'9c', role:'Signing (ML-DSA-65)'},
  {id:0x84, hex:'84', role:'Signing (Ed25519)'},
  {id:0x9D, hex:'9d', role:'Decryption (ML-KEM-768)'},
  {id:0x85, hex:'85', role:'Decryption (X25519)'},
];
const ALL_24_SLOTS = [
  0x9A,0x9C,0x9D,0x9E,
  0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,
  0x8C,0x8D,0x8E,0x8F,0x90,0x91,0x92,0x93,0x94,0x95,
].map(id=>({id, hex:id.toString(16).padStart(2,'0')}));
const VAULT_ECDH_SLOTS = [
  0x9D,
  0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,
  0x8C,0x8D,0x8E,0x8F,0x90,0x91,0x92,0x93,0x94,0x95,
].map(id=>({id, hex:id.toString(16).padStart(2,'0')}));
const SPKI_P256_PREFIX = new Uint8Array([
  0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
  0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00,
]);
const SPKI_P384_PREFIX = new Uint8Array([
  0x30,0x76,0x30,0x10,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
  0x06,0x05,0x2B,0x81,0x04,0x00,0x22,0x03,0x62,0x00,
]);

const ALGO_NAMES = {
  0x06:'RSA-1024', 0x07:'RSA-2048', 0x05:'RSA-3072', 0x16:'RSA-4096',
  0x11:'ECCP256', 0x14:'ECCP384', 0xE0:'Ed25519', 0xE1:'X25519',
  0xE3:'ML-DSA-65', 0xE4:'ML-DSA-87', 0xE6:'ML-KEM-768', 0xE7:'ML-KEM-1024',
};
const SPKI_ALGID_DER = {
  0x11: new Uint8Array([0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07]),
  0x14: new Uint8Array([0x30,0x10,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,0x06,0x05,0x2B,0x81,0x04,0x00,0x22]),
  0xE0: new Uint8Array([0x30,0x05,0x06,0x03,0x2B,0x65,0x70]),
  0xE1: new Uint8Array([0x30,0x05,0x06,0x03,0x2B,0x65,0x6E]),
  0xE3: new Uint8Array([0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x12]),
  0xE4: new Uint8Array([0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x13]),
  0xE6: new Uint8Array([0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x02]),
  0xE7: new Uint8Array([0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x03]),
};
const PRIMARY_BUNDLE_BANK = 0x5F5000;
const MAX_PUBLIC_BUNDLE = 65536;
const MAX_SAFE_GEN = 9007199254740991;
const PIN_POLICY = {1:'never', 2:'once', 3:'always', 4:'match-once', 5:'match-always'};
const TOUCH_POLICY = {1:'never', 2:'always', 3:'cached'};
const ORIGIN_NAME = {1:'generated', 2:'imported'};

function toHex(bytes){
  return Array.from(new Uint8Array(bytes)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function toBase64(bytes){
  const b = new Uint8Array(bytes);
  let s = '';
  for(let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

function fromBase64(str){
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for(let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeBerLength(len){
  if(len < 0x80) return new Uint8Array([len]);
  if(len < 0x100) return new Uint8Array([0x81, len]);
  if(len < 0x10000) return new Uint8Array([0x82, (len >> 8) & 0xFF, len & 0xFF]);
  return new Uint8Array([0x83, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF]);
}

function encodeBerTlv(tag, value){
  const v = new Uint8Array(value);
  const tagBytes = tag > 0xFF ? new Uint8Array([(tag >> 8) & 0xFF, tag & 0xFF]) : new Uint8Array([tag]);
  const lenBytes = encodeBerLength(v.length);
  const out = new Uint8Array(tagBytes.length + lenBytes.length + v.length);
  out.set(tagBytes, 0);
  out.set(lenBytes, tagBytes.length);
  out.set(v, tagBytes.length + lenBytes.length);
  return out;
}

function concatBytes(...parts){
  const total = parts.reduce((n, p)=>n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for(const p of parts){ out.set(p, off); off += p.length; }
  return out;
}

function buildSelectPivApdu(){
  return concatBytes(new Uint8Array([0x00,0xA4,0x04,0x00,PIV_AID.length]), PIV_AID);
}

function buildGetMetadataApdu(slotId){
  return new Uint8Array([0x00,0xF7,0x00,slotId & 0xFF]);
}

function buildVerifyPinApdu(pinBytes){
  if(!pinBytes || pinBytes.length < 6 || pinBytes.length > 8){
    throw Error('PIV PIN must be 6 to 8 ASCII characters.');
  }
  const apdu = new Uint8Array(13);
  apdu.set([0x00, 0x20, 0x00, 0x80, 0x08], 0);
  apdu.fill(0xFF, 5);
  apdu.set(pinBytes, 5);
  return apdu;
}

function buildGeneralAuthenticateData(inputTag, inputBytes){
  // Dynamic Authentication Template: 7C [ 82 00 | <inputTag> <inputBytes> ]
  const inner = concatBytes(
    encodeBerTlv(0x82, new Uint8Array(0)),
    encodeBerTlv(inputTag, inputBytes)
  );
  return encodeBerTlv(0x7C, inner);
}

function buildChainedApdus(ins, p1, p2, data, maxChunk = 255){
  const payload = new Uint8Array(data || 0);
  if(payload.length === 0){
    return [new Uint8Array([0x00, ins, p1, p2, 0x00])];
  }
  const apdus = [];
  for(let off = 0; off < payload.length; off += maxChunk){
    const end = Math.min(off + maxChunk, payload.length);
    const isLast = end === payload.length;
    const chunk = payload.subarray(off, end);
    const cla = isLast ? 0x00 : 0x10;
    const apdu = new Uint8Array(5 + chunk.length + (isLast ? 1 : 0));
    apdu.set([cla, ins, p1, p2, chunk.length], 0);
    apdu.set(chunk, 5);
    if(isLast) apdu[5 + chunk.length] = 0x00; // Le=256 (0x00)
    apdus.push(apdu);
  }
  return apdus;
}

function splitSw(raw){
  const b = new Uint8Array(raw);
  if(b.length < 2) throw Error('Truncated APDU response');
  return {data:b.slice(0, b.length - 2), sw1:b[b.length - 2], sw2:b[b.length - 1]};
}

async function transmitChained(conn, apdu){
  let resp = splitSw(await conn.transmit(apdu));
  const chunks = [resp.data];
  let rounds = 0;
  while(resp.sw1 === 0x61){
    if(++rounds > 64) throw Error('Excessive GET RESPONSE chaining');
    resp = splitSw(await conn.transmit(new Uint8Array([0x00,0xC0,0x00,0x00,resp.sw2])));
    chunks.push(resp.data);
  }
  return {data: concatBytes(...chunks), sw:(resp.sw1 << 8) | resp.sw2};
}

async function transmitCommandChained(conn, ins, p1, p2, data){
  const apdus = buildChainedApdus(ins, p1, p2, data);
  let last = null;
  for(let i = 0; i < apdus.length; i++){
    const isLast = i === apdus.length - 1;
    if(!isLast){
      const r = splitSw(await conn.transmit(apdus[i]));
      const sw = (r.sw1 << 8) | r.sw2;
      if(sw !== 0x9000) return {data: r.data, sw};
    }else{
      last = await transmitChained(conn, apdus[i]);
    }
  }
  return last;
}

function parseBerTlv(bytes){
  const b = new Uint8Array(bytes);
  const out = new Map();
  let i = 0;
  while(i < b.length){
    let tag = b[i++];
    if((tag & 0x1F) === 0x1F){
      if(i >= b.length) throw Error('Truncated TLV tag');
      tag = (tag << 8) | b[i++];
    }
    if(i >= b.length) throw Error('Truncated TLV length');
    let len = b[i++];
    if(len & 0x80){
      const n = len & 0x7F;
      if(n === 0 || n > 3 || i + n > b.length) throw Error('Invalid TLV length');
      len = 0;
      for(let k = 0; k < n; k++) len = (len << 8) | b[i++];
    }
    if(i + len > b.length) throw Error('Truncated TLV value');
    out.set(tag, b.slice(i, i + len));
    i += len;
  }
  return out;
}

function parseSlotMetadata(bytes){
  const tlv = parseBerTlv(bytes);
  const algByte = tlv.get(0x01)?.[0];
  const pol = tlv.get(0x02);
  const originByte = tlv.get(0x03)?.[0];
  const pub = tlv.get(0x04) || new Uint8Array(0);
  const algorithm = algByte === undefined ? 'unknown'
    : (ALGO_NAMES[algByte] || ('0x' + algByte.toString(16).padStart(2,'0')));
  return {
    present: true,
    algorithmId: algByte ?? null,
    algorithm,
    pinPolicy: pol && pol.length >= 1 ? (PIN_POLICY[pol[0]] || ('0x' + pol[0].toString(16))) : 'unknown',
    touchPolicy: pol && pol.length >= 2 ? (TOUCH_POLICY[pol[1]] || ('0x' + pol[1].toString(16))) : 'unknown',
    origin: originByte === undefined ? 'unknown' : (ORIGIN_NAME[originByte] || ('0x' + originByte.toString(16))),
    publicKeyBytes: pub,
  };
}

function parsePinMetadata(bytes){
  const tlv = parseBerTlv(bytes);
  const retries = tlv.get(0x06);
  if(!retries || retries.length < 2) throw Error('Invalid PIV PIN metadata');
  return {maximum: retries[0], remaining: retries[1]};
}

function parseGeneralAuthenticateResponse(bytes){
  const outer = parseBerTlv(bytes);
  const body = outer.get(0x7C);
  if(!body) throw Error('Missing 0x7C Dynamic Authentication Template');
  const inner = parseBerTlv(body);
  const result = inner.get(0x82);
  if(!result) throw Error('Missing 0x82 response payload');
  return result;
}

function extractEcUncompressedPointFromSpki(spkiBytes){
  // DER SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { alg }, BIT STRING (0x03 <len> 0x00 <0x04 ...>) }
  const b = new Uint8Array(spkiBytes);
  const seq = parseBerTlv(b).get(0x30);
  if(!seq) throw Error('Invalid SPKI SEQUENCE');
  let i = 0;
  // Skip AlgorithmIdentifier SEQUENCE (tag 0x30)
  if(seq[i++] !== 0x30) throw Error('Missing SPKI AlgorithmIdentifier');
  let algLen = seq[i++];
  if(algLen & 0x80){
    const n = algLen & 0x7F;
    algLen = 0;
    for(let k = 0; k < n; k++) algLen = (algLen << 8) | seq[i++];
  }
  i += algLen;
  if(seq[i++] !== 0x03) throw Error('Missing SPKI BIT STRING');
  let bitLen = seq[i++];
  if(bitLen & 0x80){
    const n = bitLen & 0x7F;
    bitLen = 0;
    for(let k = 0; k < n; k++) bitLen = (bitLen << 8) | seq[i++];
  }
  if(bitLen < 2 || seq[i++] !== 0x00) throw Error('Invalid SPKI BIT STRING padding');
  const point = seq.slice(i, i + bitLen - 1);
  if(point[0] !== 0x04 || (point.length !== 65 && point.length !== 97)){
    throw Error('Unsupported EC point in SPKI');
  }
  return point;
}

function extractEcPointFromPivMetadataPub(pubBytes){
  const b = new Uint8Array(pubBytes || 0);
  if(b.length === 0) throw Error('Empty PIV metadata public key');
  if(b[0] === 0x04 && (b.length === 65 || b.length === 97)) return b;
  let tlv = parseBerTlv(b);
  if(tlv.has(0x7F49)) tlv = parseBerTlv(tlv.get(0x7F49));
  const point = tlv.get(0x86);
  if(!point || point[0] !== 0x04 || (point.length !== 65 && point.length !== 97)){
    throw Error('Unsupported EC public key in PIV metadata');
  }
  return point;
}

function ecUncompressedPointToSpki(point, algId){
  const p = new Uint8Array(point);
  if(algId === 0x11 && p.length === 65) return concatBytes(SPKI_P256_PREFIX, p);
  if(algId === 0x14 && p.length === 97) return concatBytes(SPKI_P384_PREFIX, p);
  throw Error('Unsupported EC algorithm or point length for SPKI');
}

function pivMetadataToSpki(parsed){
  const algDer = SPKI_ALGID_DER[parsed.algorithmId];
  if(!algDer) throw Error('Unsupported PIV algorithm for SPKI: ' + parsed.algorithm);
  let tlv = parseBerTlv(parsed.publicKeyBytes || new Uint8Array(0));
  if(tlv.has(0x7F49)) tlv = parseBerTlv(tlv.get(0x7F49));
  const raw = tlv.get(0x86) || tlv.get(0x87) || tlv.get(0x88);
  if(!raw || !raw.length) throw Error('Missing raw public key in PIV metadata');
  const bitString = encodeBerTlv(0x03, concatBytes(new Uint8Array([0x00]), raw));
  return encodeBerTlv(0x30, concatBytes(algDer, bitString));
}

function buildGetDataApdu(tag24){
  const b2 = (tag24 >> 16) & 0xFF;
  const b1 = (tag24 >> 8) & 0xFF;
  const b0 = tag24 & 0xFF;
  return new Uint8Array([0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, b2, b1, b0, 0x00]);
}

async function readPivDataObject(conn, tag24){
  const res = await transmitChained(conn, buildGetDataApdu(tag24));
  if(res.sw === 0x6A82 || res.sw === 0x6A88) return null;
  if(res.sw !== 0x9000) throw Error(`GET DATA 0x${tag24.toString(16)} failed: SW=0x${res.sw.toString(16)}`);
  const tlv = parseBerTlv(res.data);
  return tlv.get(0x53) ?? res.data;
}

function readU64BeNumber(bytes, offset){
  let n = 0n;
  for(let i = 0; i < 8; i++) n = (n << 8n) | BigInt(bytes[offset + i]);
  if(n > BigInt(MAX_SAFE_GEN)) throw Error('Public bundle generation exceeds safe integer limit');
  return Number(n);
}

function readU32Be(bytes, offset){
  return (((bytes[offset] << 24) >>> 0) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3]);
}

function asciiPrefix(bytes, len){
  let s = '';
  for(let i = 0; i < len && i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

function bytesEqual(a, b){
  if(a === b) return true;
  if(!a || !b || a.length !== b.length) return false;
  for(let i = 0; i < a.length; i++) if(a[i] !== b[i]) return false;
  return true;
}

function parseVersion(bytes){
  const b = new Uint8Array(bytes);
  if(b.length < 3) return null;
  return `${b[0]}.${b[1]}.${b[2]}`;
}

function parseSerial(bytes){
  const b = new Uint8Array(bytes);
  if(b.length < 4) return null;
  return (((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3]);
}

async function sha256Hex(bytes){
  if(!bytes || bytes.length === 0) return null;
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return toHex(digest);
}

async function withPivSession(expectedSerial, fn){
  if(!global.navigator?.smartCard){
    throw Error('Web Smart Card API (navigator.smartCard) is not available in this browser build.');
  }
  const ctx = await global.navigator.smartCard.establishContext();
  const readers = await ctx.listReaders();
  if(!readers.length) throw Error('No PC/SC smart card readers detected.');
  const ordered = [...readers.filter(r=>/yubikey/i.test(r)), ...readers.filter(r=>!/yubikey/i.test(r))];

  let lastError = null;
  for(const reader of ordered){
    let conn = null;
    let secured = null;
    let pivSelected = false;
    let operationStarted = false;
    try{
      const opened = await ctx.connect(reader, 'shared', {preferredProtocols:['t1','t0']});
      conn = opened.connection;
      const st = await conn.status();
      let result;
      let matched = true;
      await conn.startTransaction(async()=>{
        // Establish manufacturer trust before PIV selection or any PIN/private
        // operation. The wrapper renews SCP on the later CTAP applet SELECT.
        // Raw connection ownership stays here for transaction/disconnect APIs.
        if(!global.SequoiaSecureChannel && global.document?.getElementById('secure-yubikey-connection'))throw Error('Secure-channel policy is not ready');
        secured = await global.SequoiaSecureChannel?.acquire(conn);
        const channel = secured?.connection || conn;
        const sel = await transmitChained(channel, buildSelectPivApdu());
        if(sel.sw !== 0x9000) throw Error('SELECT PIV failed: SW=0x' + sel.sw.toString(16));
        pivSelected = true;
        const ver = await transmitChained(channel, new Uint8Array([0x00,0xFD,0x00,0x00]));
        const version = ver.sw === 0x9000 ? parseVersion(ver.data) : null;
        const ser = await transmitChained(channel, new Uint8Array([0x00,0xF8,0x00,0x00]));
        const serial = ser.sw === 0x9000 ? String(parseSerial(ser.data)) : null;
        if(expectedSerial && serial !== String(expectedSerial)){
          matched = false;
          return 'leave';
        }
        operationStarted = true;
        result = await fn(channel, {reader, allReaders: readers, activeProtocol: opened.activeProtocol, state: st.state, atr: toHex(st.answerToReset), version, serial});
        return 'leave';
      });
      if(matched) return result;
    }catch(e){
      lastError = e;
      // Never scan another reader or obscure an error after selecting the
      // requested device: PIN rejection/private operations must not be retried.
      if(global.SequoiaSecureChannel?.isRequired() || operationStarted || (pivSelected && !expectedSerial)) throw e;
    }finally{
      secured?.close();
      if(conn){ try{ await conn.disconnect('leave'); }catch(_){} }
    }
  }
  if(expectedSerial){
    throw Error('Expected YubiKey ' + expectedSerial + ' is not connected.');
  }
  throw lastError || Error('No compatible YubiKey PIV reader found.');
}

async function listYubiKeys(){
  if(global.SequoiaSecureChannel?.isRequired()){
    return withPivSession(null,async(_conn,info)=>[{reader:info.reader,serial:info.serial,version:info.version}]);
  }
  if(!global.navigator?.smartCard){
    throw Error('Web Smart Card API (navigator.smartCard) is not available in this browser build.');
  }
  const ctx = await global.navigator.smartCard.establishContext();
  const readers = await ctx.listReaders();
  const devices = [];
  for(const reader of readers){
    let conn = null;
    try{
      const opened = await ctx.connect(reader, 'shared', {preferredProtocols:['t1','t0']});
      conn = opened.connection;
      await conn.startTransaction(async()=>{
        const sel = await transmitChained(conn, buildSelectPivApdu());
        if(sel.sw !== 0x9000) return 'leave';
        const ver = await transmitChained(conn, new Uint8Array([0x00,0xFD,0x00,0x00]));
        const ser = await transmitChained(conn, new Uint8Array([0x00,0xF8,0x00,0x00]));
        if(ser.sw === 0x9000){
          devices.push({
            reader,
            serial: String(parseSerial(ser.data)),
            version: ver.sw === 0x9000 ? parseVersion(ver.data) : null,
          });
        }
        return 'leave';
      });
    }catch(_){
      // Ignore non-PIV readers when enumerating YubiKeys.
    }finally{
      if(conn){ try{ await conn.disconnect('leave'); }catch(_){} }
    }
  }
  return devices;
}

async function readAll24Slots(conn){
  const slots = [];
  for(const slot of ALL_24_SLOTS){
    const meta = await transmitChained(conn, buildGetMetadataApdu(slot.id));
    if(meta.sw === 0x6A88 || meta.sw === 0x6A82){
      slots.push({slot: slot.hex, publicKeySha256: null, algorithm: null, origin: null, pinPolicy: null, touchPolicy: null});
    }else if(meta.sw === 0x9000){
      const parsed = parseSlotMetadata(meta.data);
      const hash = await sha256Hex(parsed.publicKeyBytes);
      slots.push({
        slot: slot.hex,
        publicKeySha256: hash,
        algorithm: parsed.algorithm,
        origin: parsed.origin,
        pinPolicy: parsed.pinPolicy,
        touchPolicy: parsed.touchPolicy,
      });
    }else{
      throw Error('Incomplete hardware slot audit on ' + slot.hex + ': SW=0x' + meta.sw.toString(16));
    }
  }
  return slots;
}

async function readPinRetries(conn){
  const meta = await transmitChained(conn, buildGetMetadataApdu(0x80));
  if(meta.sw !== 0x9000) throw Error('Failed to read PIV PIN retries: SW=0x' + meta.sw.toString(16));
  return parsePinMetadata(meta.data);
}

async function hardwareAuditViaSmartCard(identity){
  const serial = identity?.serial ? String(identity.serial) : null;
  if(!serial) throw Error('Audit requires a hardware identity with a YubiKey serial.');
  return withPivSession(serial, async(conn, info)=>{
    const beforePin = await readPinRetries(conn);
    const first = await readAll24Slots(conn);
    const second = await readAll24Slots(conn);
    const afterPin = await readPinRetries(conn);
    if(JSON.stringify(first) !== JSON.stringify(second) ||
       beforePin.remaining !== afterPin.remaining || beforePin.maximum !== afterPin.maximum){
      throw Error('Hardware changed during audit');
    }
    const backendId = new TextEncoder().encode('web-smartcard-pcsc:' + info.reader + ':' + (info.version || ''));
    const backendHash = await sha256Hex(backendId);
    return {
      format: 'sequoia-iwa-hardware-audit',
      version: 1,
      identity: {
        serial: String(identity.serial),
        fingerprint: identity.fingerprint,
        certificateHash: identity.certificateHash,
        email: identity.email,
      },
      slots: first,
      pinRetries: beforePin,
      backendHash,
    };
  });
}

async function verifyPinOnConnection(conn, pinStr){
  const pinBytes = new TextEncoder().encode(pinStr);
  const apdu = buildVerifyPinApdu(pinBytes);
  try{
    const res = splitSw(await conn.transmit(apdu));
    const sw = (res.sw1 << 8) | res.sw2;
    if(sw === 0x9000) return;
    if((sw & 0xFFF0) === 0x63C0){
      const left = sw & 0x0F;
      throw Error(`Incorrect PIV PIN (${left} ${left === 1 ? 'retry' : 'retries'} remaining).`);
    }
    if(sw === 0x6983) throw Error('PIV PIN is blocked.');
    throw Error('PIV PIN verification failed: SW=0x' + sw.toString(16));
  }finally{
    pinBytes.fill(0);
    apdu.fill(0);
  }
}

// Compare every manifest key again inside the transaction that submits the
// PIN. This closes the device/key-swap gap between public preparation and use.
async function checkLiveKeys(conn, identity){
  if(!identity?.serial || !Array.isArray(identity.slots) || !identity.slots.length) throw Error('Authenticated hardware mapping required.');
  for(const key of identity.slots){
    const meta=await transmitChained(conn,buildGetMetadataApdu(parseInt(key.slot,16)));
    if(meta.sw!==0x9000 || await sha256Hex(pivMetadataToSpki(parseSlotMetadata(meta.data)))!==key.publicKeySha256)
      throw Error('Live public key differs from authenticated manifest; PIN not submitted.');
  }
}

async function signDigestViaSmartCard(request, identity, promptPin){
  const serial = identity?.serial ? String(identity.serial) : null;
  const digestBytes = fromBase64(request.digest);
  const muBytes = fromBase64(request.mu);
  if(muBytes.length!==64)throw Error('ML-DSA external mu required.');
  if(digestBytes.length !== 64) throw Error('Exactly one 64-byte SHA-512 digest required.');

  return withPivSession(serial, async(conn)=>{
    await checkLiveKeys(conn,identity);
    const meta9c = await transmitChained(conn, buildGetMetadataApdu(0x9C));
    if(meta9c.sw !== 0x9000) throw Error('Signing slot 9c metadata unavailable: SW=0x' + meta9c.sw.toString(16));
    const alg9c = parseSlotMetadata(meta9c.data).algorithmId;
    const meta84 = await transmitChained(conn, buildGetMetadataApdu(0x84));
    if(meta84.sw !== 0x9000) throw Error('Signing slot 84 metadata unavailable: SW=0x' + meta84.sw.toString(16));
    const alg84 = parseSlotMetadata(meta84.data).algorithmId;
    if(alg9c !== 0xE3 || alg84 !== 0xE0) throw Error('Unable to determine PIV signing slot algorithms.');

    // Authenticate the device/channel and live key before asking for its PIN.
    const pin = await promptPin({
      title: 'PIV PIN — Sign message',
      detail: `YubiKey ${serial || '(connected)'} · slots 9C (ML-DSA-65) + 84 (Ed25519). Touch if requested.`,
    });

    await verifyPinOnConnection(conn, pin);

    const ga84 = await transmitCommandChained(conn, 0x87, alg84, 0x84, buildGeneralAuthenticateData(0x81, digestBytes));
    if(ga84.sw !== 0x9000) throw Error('Ed25519 PIV sign (slot 84) failed: SW=0x' + ga84.sw.toString(16));
    const ed25519 = parseGeneralAuthenticateResponse(ga84.data);

    // PIN Always applies to each component; reuse only this operation's PIN.
    await verifyPinOnConnection(conn, pin);
    const ga9c = await transmitCommandChained(conn, 0x87, alg9c, 0x9C, buildGeneralAuthenticateData(0x88, muBytes));
    if(ga9c.sw !== 0x9000) throw Error('ML-DSA-65 PIV sign (slot 9c) failed: SW=0x' + ga9c.sw.toString(16));
    const mldsa65 = parseGeneralAuthenticateResponse(ga9c.data);

    return {
      requestId: request.requestId,
      hashAlgorithm: 10,
      signingFingerprint: request.signingFingerprint,
      digest: request.digest,
      ed25519: toBase64(ed25519),
      mldsa65: toBase64(mldsa65),
    };
  });
}

async function decapsulateComponentsViaSmartCard(request, identity, promptPin){
  const serial = identity?.serial ? String(identity.serial) : null;
  const mlkemCt = fromBase64(request.mlkemCiphertext);
  const x25519Eph = fromBase64(request.x25519Ephemeral);
  if(mlkemCt.length !== 1088) throw Error('Invalid ML-KEM-768 ciphertext size.');
  if(x25519Eph.length !== 32 || !x25519Eph.some(b=>b !== 0)) throw Error('Invalid X25519 ephemeral public key.');


  return withPivSession(serial, async(conn)=>{
    await checkLiveKeys(conn,identity);
    const meta9d = await transmitChained(conn, buildGetMetadataApdu(0x9D));
    if(meta9d.sw !== 0x9000) throw Error('Decryption slot 9d metadata unavailable: SW=0x' + meta9d.sw.toString(16));
    const alg9d = parseSlotMetadata(meta9d.data).algorithmId;
    const meta85 = await transmitChained(conn, buildGetMetadataApdu(0x85));
    if(meta85.sw !== 0x9000) throw Error('Decryption slot 85 metadata unavailable: SW=0x' + meta85.sw.toString(16));
    const alg85 = parseSlotMetadata(meta85.data).algorithmId;
    if(alg9d !== 0xE6 || alg85 !== 0xE1) throw Error('Unable to determine PIV decryption slot algorithms.');

    // Authenticate the device/channel and live key before asking for its PIN.
    const pin = await promptPin({
      title: 'PIV PIN — Decrypt',
      detail: `YubiKey ${serial || '(connected)'} · slots 9D (ML-KEM-768) + 85 (X25519). Touch if requested.`,
    });

    await verifyPinOnConnection(conn, pin);

    const ga9d = await transmitCommandChained(conn, 0x87, alg9d, 0x9D, buildGeneralAuthenticateData(0x86, mlkemCt));
    if(ga9d.sw !== 0x9000) throw Error('ML-KEM-768 PIV decapsulate (slot 9d) failed: SW=0x' + ga9d.sw.toString(16));
    const mlkemShare = parseGeneralAuthenticateResponse(ga9d.data);
    if(mlkemShare.length !== 32) throw Error('Incorrect ML-KEM-768 shared secret length.');

    await verifyPinOnConnection(conn, pin);
    const ga85 = await transmitCommandChained(conn, 0x87, alg85, 0x85, buildGeneralAuthenticateData(0x85, x25519Eph));
    if(ga85.sw !== 0x9000) throw Error('X25519 PIV ECDH (slot 85) failed: SW=0x' + ga85.sw.toString(16));
    const x25519Share = parseGeneralAuthenticateResponse(ga85.data);
    if(x25519Share.length !== 32 || !x25519Share.some(b=>b !== 0)){
      throw Error('Rejected invalid or all-zero X25519 shared secret.');
    }

    return {
      requestId: request.requestId,
      cipherHash: request.cipherHash,
      recipientKey: request.recipientKey,
      mlkemCiphertext: request.mlkemCiphertext,
      x25519Ephemeral: request.x25519Ephemeral,
      // Use the same component-response schema as the native adapter. WASM
      // rejects unknown/missing fields before combining, and the coordinator
      // drops these exact Secret-named properties after worker handoff.
      mlkemSecret: toBase64(mlkemShare),
      x25519Secret: toBase64(x25519Share),
    };
  });
}

async function readPublicSnapshotViaSmartCard(serial, includeBundle){
  return withPivSession(serial || null, async(conn, info)=>{
    const observed = new Map();
    let stored = null;
    if(includeBundle){
      const manifest = await readPivDataObject(conn, PRIMARY_BUNDLE_BANK);
      if(!manifest) throw Error('Current public bundle absent on YubiKey.');
      if(manifest.length !== 52 || asciiPrefix(manifest, 8) !== 'PQMIDX01'){
        throw Error('Invalid public bundle index on YubiKey.');
      }
      const generation = readU64BeNumber(manifest, 8);
      const size = readU32Be(manifest, 16);
      if(generation < 1 || size < 1 || size > MAX_PUBLIC_BUNDLE){
        throw Error('Public bundle index limits exceeded.');
      }
      const expectedDigest = toHex(manifest.subarray(20, 52));
      observed.set(PRIMARY_BUNDLE_BANK, manifest);
      const chunks = [];
      const count = Math.ceil(size / 2048);
      for(let i = 0; i < count; i++){
        const tag = PRIMARY_BUNDLE_BANK + 1 + i;
        const chunk = await readPivDataObject(conn, tag);
        if(!chunk) throw Error('Incomplete current public bundle on YubiKey.');
        const expectedLen = 20 + Math.min(2048, size - i * 2048);
        if(chunk.length !== expectedLen || asciiPrefix(chunk, 8) !== 'PQMCHK01'){
          throw Error('Invalid public bundle chunk on YubiKey.');
        }
        if(readU64BeNumber(chunk, 8) !== generation || readU32Be(chunk, 16) !== i){
          throw Error('Stale public bundle chunk on YubiKey.');
        }
        chunks.push(chunk.subarray(20));
        observed.set(tag, chunk);
      }
      const bundleBytes = concatBytes(...chunks);
      const actualDigest = await sha256Hex(bundleBytes);
      if(actualDigest !== expectedDigest){
        throw Error('Public bundle transport digest mismatch.');
      }
      if(asciiPrefix(bundleBytes, 8) !== 'PQMZIP01'){
        throw Error('Current compressed public bundle (PQMZIP01) required.');
      }
      stored = {generation, bundle: toBase64(bundleBytes)};
    }

    const readSlotsOnce = async()=>{
      const out = [];
      for(const slot of ALL_24_SLOTS){
        const meta = await transmitChained(conn, buildGetMetadataApdu(slot.id));
        if(meta.sw === 0x6A88 || meta.sw === 0x6A82){
          out.push({slot: slot.hex, publicKeySha256: null});
        }else if(meta.sw === 0x9000){
          const parsed = parseSlotMetadata(meta.data);
          let spki;
          try{ spki = pivMetadataToSpki(parsed); }
          catch(_){ spki = parsed.publicKeyBytes; }
          out.push({slot: slot.hex, publicKeySha256: spki.length ? await sha256Hex(spki) : null});
        }else{
          throw Error(`Slot ${slot.hex} metadata read failed: SW=0x${meta.sw.toString(16)}`);
        }
      }
      return out;
    };

    const firstSlots = await readSlotsOnce();

    // Double-read observed objects, all 24 slots, and serial to detect external mutation or device swap.
    for(const [tag, expected] of observed){
      const again = await readPivDataObject(conn, tag);
      if(!bytesEqual(again, expected)) throw Error('Public bundle changed while reading.');
    }
    const secondSlots = await readSlotsOnce();
    if(JSON.stringify(firstSlots) !== JSON.stringify(secondSlots)){
      throw Error('Public keys changed while reading.');
    }
    const ser2 = await transmitChained(conn, new Uint8Array([0x00,0xF8,0x00,0x00]));
    if(ser2.sw !== 0x9000 || String(parseSerial(ser2.data)) !== String(info.serial)){
      throw Error('Device changed during public snapshot.');
    }

    const reply = {
      format: 'sequoia-iwa-public-snapshot',
      version: 1,
      serial: String(info.serial),
      slots: firstSlots,
      warnings: [],
    };
    if(stored){
      reply.bundle = stored.bundle;
      reply.generation = stored.generation;
    }
    return reply;
  });
}

async function readClassicalVaultSlots(conn, serial){
  const found = [];
  for(const slot of VAULT_ECDH_SLOTS){
    const meta = await transmitChained(conn, buildGetMetadataApdu(slot.id));
    if(meta.sw !== 0x9000) continue;
    const parsed = parseSlotMetadata(meta.data);
    if(parsed.algorithmId !== 0x11 && parsed.algorithmId !== 0x14) continue;
    try{
      const point = extractEcPointFromPivMetadataPub(parsed.publicKeyBytes);
      const spki = ecUncompressedPointToSpki(point, parsed.algorithmId);
      const fingerprint = await sha256Hex(spki);
      found.push({
        serial: serial != null ? String(serial) : '',
        slot: slot.hex,
        algorithm: parsed.algorithmId === 0x11 ? 'ECDH-P256' : 'ECDH-P384',
        public: toBase64(spki),
        fingerprint,
      });
    }catch(_){
      // Skip slots whose metadata public key cannot be parsed as P-256/P-384.
    }
  }
  return found;
}

async function readVaultMaterialViaSmartCard(options = {}){
  return withPivSession(options.serial || null, async(conn, info)=>{
    const classicalSlots = await readClassicalVaultSlots(conn, info.serial);
    const preferredSlot = options.slot ? String(options.slot).toLowerCase() : null;
    const classical = preferredSlot
      ? (classicalSlots.find(s=>s.slot === preferredSlot) || null)
      : (classicalSlots[0] || null);
    return {
      serial: info.serial != null ? String(info.serial) : '',
      classical,
      classicalSlots,
    };
  });
}

async function ecdhViaSmartCard(request, slotHex, serial, promptPin){
  let targetSlotHex = slotHex || null;
  let targetSerial = serial || null;
  if(!targetSlotHex){
    // Resolve the exact YubiKey + PIV slot matching request.fingerprint (read-only, no PIN).
    const devices = await listYubiKeys();
    const candidates = targetSerial
      ? devices.filter(d=>String(d.serial) === String(targetSerial))
      : devices;
    let matched = null;
    for(const dev of candidates){
      const vm = await readVaultMaterialViaSmartCard({serial: dev.serial});
      const hit = vm.classicalSlots.find(s=>s.fingerprint === request.fingerprint);
      if(hit){ matched = hit; break; }
    }
    if(!matched){
      throw Error('Required classical PIV vault key not found on connected YubiKey (checked slots 9d and 82–95).');
    }
    targetSlotHex = matched.slot;
    targetSerial = matched.serial;
  }
  const slotId = parseInt(targetSlotHex, 16);
  const peerPoint = extractEcUncompressedPointFromSpki(fromBase64(request.peer));
  const algId = peerPoint.length === 65 ? 0x11 : 0x14;

  return withPivSession(targetSerial, async(conn,info)=>{
    const keys=await readClassicalVaultSlots(conn,info.serial);
    if(!keys.some(k=>k.slot===targetSlotHex&&k.fingerprint===request.fingerprint&&k.algorithm===(algId===0x11?'ECDH-P256':'ECDH-P384')))
      throw Error('Vault public key changed; PIN not submitted.');
    // Authenticate the device/channel and live key before asking for its PIN.
    const pin = await promptPin({
      title: 'PIV PIN — Unlock vault (ECDH)',
      detail: `YubiKey ${targetSerial || '(connected)'} · slot ${slotId.toString(16).toUpperCase()} (${algId === 0x11 ? 'ECDH-P256' : 'ECDH-P384'}).`,
    });

    await verifyPinOnConnection(conn, pin);
    const ga = await transmitCommandChained(conn, 0x87, algId, slotId, buildGeneralAuthenticateData(0x85, peerPoint));
    if(ga.sw !== 0x9000) throw Error('PIV ECDH failed: SW=0x' + ga.sw.toString(16));
    const secret = parseGeneralAuthenticateResponse(ga.data);
    return {secret: toBase64(secret), fingerprint: request.fingerprint};
  });
}

async function inspectPivViaSmartCard(options = {}){
  const all24 = Boolean(options.all24);
  return withPivSession(options.serial || null, async(conn, info)=>{
    const report = {...info, pinRetries: null, slots: []};
    try{ report.pinRetries = await readPinRetries(conn); }catch(_){}
    const list = all24 ? ALL_24_SLOTS : LEVEL3_SLOTS;
    for(const slot of list){
      const meta = await transmitChained(conn, buildGetMetadataApdu(slot.id));
      if(meta.sw === 0x6A88 || meta.sw === 0x6A82){
        report.slots.push({slot:slot.hex, role:slot.role||'', present:false});
      }else if(meta.sw === 0x9000){
        const parsed = parseSlotMetadata(meta.data);
        const fullHash = await sha256Hex(parsed.publicKeyBytes);
        report.slots.push({
          slot: slot.hex,
          role: slot.role || '',
          present: true,
          algorithm: parsed.algorithm,
          pinPolicy: parsed.pinPolicy,
          touchPolicy: parsed.touchPolicy,
          origin: parsed.origin,
          publicKeyLen: parsed.publicKeyBytes.length,
          publicKeySha256: fullHash ? fullHash.slice(0, 16) : null,
        });
      }else{
        report.slots.push({slot:slot.hex, role:slot.role||'', present:false, status:'SW=0x' + meta.sw.toString(16)});
      }
    }
    return report;
  });
}

function formatPivReport(r){
  const pinText = r.pinRetries ? ` · PIN retries=${r.pinRetries.remaining}/${r.pinRetries.maximum}` : '';
  const lines = [
    `Web Smart Card (direct macOS PCSC) — read-only`,
    `Reader: ${r.reader} (${r.activeProtocol}, state=${r.state})`,
    `PIV firmware: ${r.version ?? 'unavailable'} · Serial: ${r.serial ?? 'unavailable'}${pinText}`,
    `ATR: ${r.atr}`,
    '',
    'PIV slots:',
  ];
  for(const s of r.slots){
    const label = s.role ? `${s.slot} (${s.role})` : s.slot;
    if(!s.present){
      lines.push(`  ${label}: empty${s.status ? ' [' + s.status + ']' : ''}`);
    }else{
      lines.push(`  ${label}: ${s.algorithm} · ${s.origin} · PIN=${s.pinPolicy} · touch=${s.touchPolicy} · pub=${s.publicKeyLen} B · sha256=${s.publicKeySha256 || '-'}`);
    }
  }
  lines.push('', 'No PIN was requested and no key or slot state was modified.');
  return lines.join('\n');
}

const api = {
  // Shared serial-checked transaction for switching to the FIDO applet.
  withPivSession,
  encodeBerLength,
  encodeBerTlv,
  buildSelectPivApdu,
  buildGetMetadataApdu,
  buildVerifyPinApdu,
  buildGeneralAuthenticateData,
  buildChainedApdus,
  splitSw,
  transmitChained,
  transmitCommandChained,
  parseBerTlv,
  parseSlotMetadata,
  parsePinMetadata,
  parseGeneralAuthenticateResponse,
  extractEcUncompressedPointFromSpki,
  extractEcPointFromPivMetadataPub,
  ecUncompressedPointToSpki,
  pivMetadataToSpki,
  buildGetDataApdu,
  parseVersion,
  parseSerial,
  listYubiKeys,
  hardwareAuditViaSmartCard,
  signDigestViaSmartCard,
  decapsulateComponentsViaSmartCard,
  readPublicSnapshotViaSmartCard,
  readVaultMaterialViaSmartCard,
  ecdhViaSmartCard,
  inspectPivViaSmartCard,
  formatPivReport,
};
global.SequoiaSmartCardPiv = api;
if(typeof module !== 'undefined' && module.exports) module.exports = api;

if(typeof document !== 'undefined'){
  const out = document.getElementById('smartcard-results');
  const checkBtn = document.getElementById('smartcard-check');
  const slotsBtn = document.getElementById('smartcard-slots');
  if(out && checkBtn && slotsBtn){
    let busy = false;
    if(!global.navigator?.smartCard){
      out.textContent = 'Web Smart Card API is unavailable in this browser. Launch with --enable-features=IsolatedWebApps,IsolatedWebAppDevMode,SmartCard on macOS Chromium.';
    }
    const wire = (btn, all24) => btn.addEventListener('click', async()=>{
      if(busy) return;
      busy = true;
      out.textContent = all24
        ? 'Reading all 24 PIV slots via navigator.smartCard (read-only)…'
        : 'Checking YubiKey PIV via navigator.smartCard (read-only)…';
      try{
        const report = await inspectPivViaSmartCard({all24});
        out.textContent = formatPivReport(report);
      }catch(e){
        out.textContent = 'STOPPED: ' + (e?.message || String(e));
      }finally{
        busy = false;
      }
    });
    wire(checkBtn, false);
    wire(slotsBtn, true);
  }
}
})(typeof globalThis !== 'undefined' ? globalThis : window);
