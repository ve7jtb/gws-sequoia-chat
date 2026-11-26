import {b64,bytes} from './core.js';

const curve = {name:'ECDH',namedCurve:'P-384'};

// Both shares and both public transcripts feed the combiner. The vault's
// existing HKDF and AEAD additionally bind the result to the vault and wrapper.
export async function combineLevel5(binding, kem, ec){
  const input = new Uint8Array(80);
  try{
    if(kem.length !== 32 || ec.length !== 48)throw Error('Invalid Level 5 vault secret length.');
    input.set(kem);
    input.set(ec,32);
    const key = await crypto.subtle.importKey('raw',input,'HKDF',false,['deriveBits']);
    const transcript = new TextEncoder().encode(JSON.stringify([
      'Sequoia IWA vault ML-KEM-1024 + P-384 v1',binding.serial,
      binding.kemCiphertext,binding.ecEphemeral,binding.kemPublic,binding.ecPublic,
    ]));
    const info = await crypto.subtle.digest('SHA-384',transcript);
    return new Uint8Array(await crypto.subtle.deriveBits({
      name:'HKDF',hash:'SHA-384',salt:new Uint8Array(48),info,
    },key,256));
  }finally{input.fill(0);kem.fill(0);ec.fill(0);}
}

export async function wrapLevel5(material, encapsulate){
  const recipient = await crypto.subtle.importKey('spki',bytes(material.level5.ecPublic),curve,false,[]);
  const ephemeral = await crypto.subtle.generateKey(curve,false,['deriveBits']);
  const ecEphemeral = b64(await crypto.subtle.exportKey('spki',ephemeral.publicKey));
  const result = await encapsulate({publicKey:material.level5.kemPublic});
  const kem = bytes(result.secret);
  delete result.secret;
  try{
    const ec = new Uint8Array(await crypto.subtle.deriveBits(
      {name:'ECDH',public:recipient},ephemeral.privateKey,384));
    const binding = {kind:'mlkem1024-p384-v1',serial:material.serial,
      ...material.level5,kemCiphertext:result.ciphertext,ecEphemeral};
    return {binding,secret:await combineLevel5(binding,kem,ec)};
  }finally{kem.fill(0);}
}

export async function openLevel5(binding,call){
  await crypto.subtle.importKey('spki',bytes(binding.ecEphemeral),curve,false,[]);
  const result = await call('chat-vault-level5-open',binding);
  try{return await combineLevel5(binding,bytes(result.kemSecret),bytes(result.ecSecret));}
  finally{delete result.kemSecret;delete result.ecSecret;}
}
