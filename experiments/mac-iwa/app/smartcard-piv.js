// Read-only Web Smart Card (navigator.smartCard) YubiKey PIV inspector.
// Runs entirely in the IWA without the extension, native host, or PKCS#11.
// Strictly read-only: no PIN verification, signing, decryption, or writes.
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

const ALGO_NAMES = {
  0x06:'RSA-1024', 0x07:'RSA-2048', 0x05:'RSA-3072', 0x16:'RSA-4096',
  0x11:'ECCP256', 0x14:'ECCP384', 0xE0:'Ed25519', 0xE1:'X25519',
};
const PIN_POLICY = {1:'never', 2:'once', 3:'always', 4:'match-once', 5:'match-always'};
const TOUCH_POLICY = {1:'never', 2:'always', 3:'cached'};
const ORIGIN_NAME = {1:'generated', 2:'imported'};

function toHex(bytes){
  return Array.from(new Uint8Array(bytes)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function buildSelectPivApdu(){
  const out = new Uint8Array(5 + PIV_AID.length);
  out.set([0x00,0xA4,0x04,0x00,PIV_AID.length], 0);
  out.set(PIV_AID, 5);
  return out;
}

function buildGetMetadataApdu(slotId){
  return new Uint8Array([0x00,0xF7,0x00,slotId & 0xFF]);
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
  const total = chunks.reduce((n,c)=>n + c.length, 0);
  const data = new Uint8Array(total);
  let off = 0;
  for(const c of chunks){ data.set(c, off); off += c.length; }
  return {data, sw:(resp.sw1 << 8) | resp.sw2};
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

async function sha256Prefix(bytes){
  if(!bytes || bytes.length === 0) return null;
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return toHex(digest).slice(0, 16);
}

async function inspectPivViaSmartCard(options = {}){
  if(!global.navigator?.smartCard){
    throw Error('Web Smart Card API (navigator.smartCard) is not available in this browser build.');
  }
  const all24 = Boolean(options.all24);
  const ctx = await global.navigator.smartCard.establishContext();
  const readers = await ctx.listReaders();
  if(!readers.length) throw Error('No PC/SC smart card readers detected.');
  const reader = readers.find(r=>/yubikey/i.test(r)) || readers[0];
  const {connection, activeProtocol} = await ctx.connect(reader, 'shared', {preferredProtocols:['t1','t0']});
  try{
    const st = await connection.status();
    const report = {
      reader,
      allReaders: readers,
      activeProtocol,
      state: st.state,
      atr: toHex(st.answerToReset),
      version: null,
      serial: null,
      slots: [],
    };
    await connection.startTransaction(async()=>{
      const sel = await transmitChained(connection, buildSelectPivApdu());
      if(sel.sw !== 0x9000) throw Error('SELECT PIV failed: SW=0x' + sel.sw.toString(16));
      const ver = await transmitChained(connection, new Uint8Array([0x00,0xFD,0x00,0x00]));
      if(ver.sw === 0x9000) report.version = parseVersion(ver.data);
      const ser = await transmitChained(connection, new Uint8Array([0x00,0xF8,0x00,0x00]));
      if(ser.sw === 0x9000) report.serial = parseSerial(ser.data);

      const list = all24 ? ALL_24_SLOTS : LEVEL3_SLOTS;
      for(const slot of list){
        const meta = await transmitChained(connection, buildGetMetadataApdu(slot.id));
        if(meta.sw === 0x6A88 || meta.sw === 0x6A82){
          report.slots.push({slot:slot.hex, role:slot.role||'', present:false});
        }else if(meta.sw === 0x9000){
          const parsed = parseSlotMetadata(meta.data);
          const pubHash = await sha256Prefix(parsed.publicKeyBytes);
          report.slots.push({
            slot: slot.hex,
            role: slot.role || '',
            present: true,
            algorithm: parsed.algorithm,
            pinPolicy: parsed.pinPolicy,
            touchPolicy: parsed.touchPolicy,
            origin: parsed.origin,
            publicKeyLen: parsed.publicKeyBytes.length,
            publicKeySha256: pubHash,
          });
        }else{
          report.slots.push({slot:slot.hex, role:slot.role||'', present:false, status:'SW=0x' + meta.sw.toString(16)});
        }
      }
      return 'leave';
    });
    return report;
  }finally{
    await connection.disconnect('leave');
  }
}

function formatPivReport(r){
  const lines = [
    `Web Smart Card (direct macOS PCSC) — read-only`,
    `Reader: ${r.reader} (${r.activeProtocol}, state=${r.state})`,
    `PIV firmware: ${r.version ?? 'unavailable'} · Serial: ${r.serial ?? 'unavailable'}`,
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
  buildSelectPivApdu,
  buildGetMetadataApdu,
  splitSw,
  transmitChained,
  parseBerTlv,
  parseSlotMetadata,
  parseVersion,
  parseSerial,
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
