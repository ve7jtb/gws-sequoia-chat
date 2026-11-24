//! Disposable software fixtures reproduce the on-card formats without a card,
//! PIN, account or persistent private key. Hardware shares are simulated from
//! test-only keys, while the public parser and AEAD/P12 logic are production.
use super::*;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm,
};
use hmac::{Hmac, Mac};
use pgp::{
    cert::{CertBuilder, CipherSuite},
    crypto::{mpi, Signer},
    serialize::SerializeInto,
    types::{HashAlgorithm, KeyFlags},
};
use sequoia_openpgp as pgp;
use std::sync::OnceLock;

fn der(tag: u8, b: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if b.len() < 128 {
        out.push(b.len() as u8)
    } else {
        let n = (b.len() as u32).to_be_bytes();
        let first = n.iter().position(|v| *v != 0).unwrap();
        out.push(0x80 + (4 - first) as u8);
        out.extend(&n[first..]);
    }
    out.extend(b);
    out
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &parts.concat())
}
fn field(out: &mut Vec<u8>, b: &[u8]) {
    out.extend((b.len() as u32).to_be_bytes());
    out.extend(b)
}
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn data(bytes: &[u8]) -> Vec<u8> {
    seq(&[der(6, DATA), der(0xa0, &der(4, bytes))])
}
fn name(role: &str) -> Vec<u8> {
    let bmp: Vec<_> = role.bytes().flat_map(|b| [0, b]).collect();
    der(0x31, &seq(&[der(6, NAME), der(0x31, &der(0x1e, &bmp))]))
}
fn bag(kind: &[u8], role: &str, value: &[u8]) -> Vec<u8> {
    seq(&[der(6, kind), der(0xa0, value), name(role)])
}
fn p12(keys: &[(String, String, Vec<u8>, Vec<u8>)], l3: bool) -> Vec<u8> {
    let mut infos = Vec::new();
    for (role, algorithm, seed, public) in keys {
        let private = seq(&[
            der(2, &[0]),
            seq(&[der(6, &oid(algorithm).unwrap())]),
            der(4, &der(if l3 { 0x80 } else { 4 }, seed)),
        ]);
        infos.push(data(&seq(&[bag(KEY, role, &private)])));
        if !l3 {
            // These catalog carriers are not a trust source. The real private
            // acceptance check derives the key and compares the signed SPKI.
            let tbs = seq(&[
                der(2, &[1]),
                seq(&[]),
                seq(&[]),
                seq(&[]),
                seq(&[]),
                public.clone(),
            ]);
            let cert = seq(&[tbs, seq(&[]), der(3, &[0])]);
            let carrier = seq(&[
                der(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 22, 1]),
                der(0xa0, &der(4, &cert)),
            ]);
            infos.push(data(&seq(&[bag(CERT, role, &carrier)])));
        }
    }
    seq(&[der(2, &[3]), data(&seq(&infos))])
}
struct Fixture {
    descriptor: serde_json::Value,
    cert: Cert,
    shared: Vec<u8>,
    p12: Vec<u8>,
    hardware: BTreeMap<String, Vec<u8>>,
}
fn fixture(l3: bool) -> &'static Fixture {
    static L3: OnceLock<Fixture> = OnceLock::new();
    static L5: OnceLock<Fixture> = OnceLock::new();
    (if l3 {&L3}else{&L5}).get_or_init(||{
        let (cert,_)=CertBuilder::new().set_profile(pgp::Profile::RFC9580).unwrap()
            .set_cipher_suite(if l3{CipherSuite::MLDSA65_Ed25519}else{CipherSuite::MLDSA87_Ed448})
            .set_primary_key_flags(KeyFlags::empty().set_certification())
            .add_userid("Companion fixture <companion@example.invalid>").add_signing_subkey().add_transport_encryption_subkey().generate().unwrap();
        let mut hardware:BTreeMap<String,Vec<u8>>=BTreeMap::new();let mut software=Vec::new();let mut private=Vec::new();
        let aliases=if l3 {["cert-pq","sign-pq","kem-pq"]}else{["cert-ed","sign-ed","kem-x"]};
        for (i,k) in cert.keys().secret().enumerate() {
            let pair=k.key().clone().into_keypair().unwrap();
            let (pq,ec)=pair.secret().map(|m|match m{
                mpi::SecretKeyMaterial::MLDSA65_Ed25519{mldsa,eddsa}=>(mldsa.to_vec(),eddsa.to_vec()),
                mpi::SecretKeyMaterial::MLDSA87_Ed448{mldsa,eddsa}=>(mldsa.to_vec(),eddsa.to_vec()),
                mpi::SecretKeyMaterial::MLKEM768_X25519{mlkem,ecdh}=>(mlkem.to_vec(),ecdh.to_vec()),
                mpi::SecretKeyMaterial::MLKEM1024_X448{mlkem,ecdh}=>(mlkem.to_vec(),ecdh.to_vec()),_=>panic!("fixture algorithm")});
            let (pqname,ecname,pqpublic,ecpublic)=match pair.public().mpis(){
                mpi::PublicKey::MLDSA65_Ed25519{mldsa,eddsa}=>("ML-DSA-65","Ed25519",mldsa.to_vec(),eddsa.to_vec()),
                mpi::PublicKey::MLDSA87_Ed448{mldsa,eddsa}=>("ML-DSA-87","Ed448",mldsa.to_vec(),eddsa.to_vec()),
                mpi::PublicKey::MLKEM768_X25519{mlkem,ecdh}=>("ML-KEM-768","X25519",mlkem.to_vec(),ecdh.to_vec()),
                mpi::PublicKey::MLKEM1024_X448{mlkem,ecdh}=>("ML-KEM-1024","X448",mlkem.to_vec(),ecdh.to_vec()),_=>panic!("fixture algorithm")};
            let slot=if i==0{if l3{"82"}else{"86"}}else if i==1{"9c"}else{"9d"};
            hardware.insert(slot.into(),spki(if l3{ecname}else{pqname},if l3{&ecpublic}else{&pqpublic}).unwrap());
            software.push((aliases[i].into(),if l3{pqname}else{ecname}.into(),if l3{pq.clone()}else{ec.clone()},spki(if l3{pqname}else{ecname},if l3{&pqpublic}else{&ecpublic}).unwrap()));
            private.push((pq,ec));
        }
        let point=hex("04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f");
        let alg=seq(&[der(6,&hex("2a8648ce3d0201")),der(6,&hex("2b81040022"))]);
        let wrapping=seq(&[alg,der(3,&[&[0],point.as_slice()].concat())]);hardware.insert(if l3{"83"}else{"82"}.into(),wrapping);
        let slots=if l3{["82","9c","9d","83"]}else{["86","9c","9d","82"]};
        let hwroles=if l3{["certification-classical","signing-classical","decryption-classical","companion-wrap"]}else{["certification-pq","signing-pq","decryption-pq","companion-wrap"]};
        let hwalgs=if l3{["Ed25519","Ed25519","X25519","P-384"]}else{["ML-DSA-87","ML-DSA-87","ML-KEM-1024","P-384"]};
        let softroles=if l3{["certification-pq","signing-pq","decryption-pq"]}else{["certification-classical","signing-classical","decryption-classical"]};
        let digest=|b:&[u8]|Sha256::digest(b).iter().map(|b|format!("{b:02x}")).collect::<String>();
        let mut entries=Vec::new();
        for i in 0..4{entries.push(format!("{{\"role\":\"{}\",\"algorithm\":\"{}\",\"storage\":\"piv\",\"slot\":\"{}\",\"sha256\":\"{}\"}}",hwroles[i],hwalgs[i],slots[i],digest(&hardware[slots[i]])));}
        for i in 0..3{entries.push(format!("{{\"role\":\"{}\",\"algorithm\":\"{}\",\"storage\":\"companion\",\"slot\":\"\",\"sha256\":\"{}\"}}",softroles[i],software[i].1,digest(&software[i].3)));}
        let profile=if l3{"LEVEL3_POLYFILL"}else{"LEVEL5_COMPANION"};
        let manifest=format!("{{\"version\":1,\"serial\":1,\"profile\":\"{profile}\",\"components\":[{}]}}",entries.join(","));
        let public=cert.clone().strip_secret_key_material().to_vec().unwrap();let p12=p12(&software,l3);
        let mut aad=if l3{b"PQMCP003".to_vec()}else{b"PQMCP001".to_vec()};aad.extend(1u32.to_be_bytes());for slot in slots{field(&mut aad,&hardware[slot]);}field(&mut aad,&public);if l3{field(&mut aad,b"opaque anchor0");field(&mut aad,b"opaque anchor1");}field(&mut aad,manifest.as_bytes());aad.extend(point);aad.extend([3;32]);aad.extend([4;12]);
        let shared=vec![5;48];let mut h=<Hmac<Sha256>as Mac>::new_from_slice(&[3;32]).unwrap();h.update(&shared);let prk=h.finalize().into_bytes();
        let mut info=if l3{b"PQMail companion L3 P384 v1".to_vec()}else{b"PQMail companion P384 v1".to_vec()};info.extend(Sha256::digest(&aad));info.push(1);
        let mut h=<Hmac<Sha256>as Mac>::new_from_slice(&prk).unwrap();h.update(&info);let key=h.finalize().into_bytes();let mut ciphertext=Vec::new();field(&mut ciphertext,&p12);
        let tag=Aes256Gcm::new(&key).encrypt_in_place_detached((&[4;12]).into(),&aad,&mut ciphertext).unwrap();ciphertext.extend(tag);let mut body=aad;field(&mut body,&ciphertext);
        let signature=if l3 {
            use ed25519_dalek::Signer;
            let digest=sha2::Sha512::digest([b"PQMail Level3 companion signature v1".as_slice(),&body].concat());
            let mut s=ed25519_dalek::SigningKey::from_bytes(private[0].1.as_slice().try_into().unwrap()).sign(&digest).to_bytes().to_vec();
            s.extend(ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(private[0].0.as_slice().try_into().unwrap()).expanded_key().sign_deterministic(&digest,b"").unwrap().encode());s
        }else{ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(private[0].0.as_slice().try_into().unwrap()).expanded_key().sign_deterministic(&body,b"").unwrap().encode().to_vec()};
        let mut envelope=Vec::new();field(&mut envelope,&body);field(&mut envelope,&signature);
        let descriptor=serde_json::json!({"encoded":B64.encode(envelope),"serial":1,"publicKeys":hardware.iter().map(|(k,v)|(k.clone(),serde_json::Value::String(B64.encode(v)))).collect::<serde_json::Map<_,_>>(),"certificate":""});
        Fixture{descriptor,cert,shared,p12,hardware}
    })
}
fn operation(l3: bool, signing: bool) -> serde_json::Value {
    let f = fixture(l3);
    let public = f.cert.clone().strip_secret_key_material().to_vec().unwrap();
    let p = StandardPolicy::new();
    let ka = f
        .cert
        .keys()
        .secret()
        .with_policy(&p, None)
        .find(|k| {
            if signing {
                k.for_signing()
            } else {
                k.for_transport_encryption()
            }
        })
        .unwrap();
    let (request, mut response) = if signing {
        let request = serde_json::json!({"requestId":"A".repeat(64),"signingFingerprint":ka.key().fingerprint().to_hex(),"hashAlgorithm":10,"digest":B64.encode([7;64])});
        let mut pair = ka.key().clone().into_keypair().unwrap();
        let signature = pair.sign(HashAlgorithm::SHA512, &[7; 64]).unwrap();
        let (ed, ml) = match signature {
            mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa } => (eddsa.to_vec(), mldsa.to_vec()),
            mpi::Signature::MLDSA87_Ed448 { eddsa, mldsa } => (eddsa.to_vec(), mldsa.to_vec()),
            _ => panic!("signature"),
        };
        let mut response = request.clone();
        response[if l3 { "ed25519" } else { "mldsa65" }] =
            B64.encode(if l3 { ed } else { ml }).into();
        (request, response)
    } else {
        use ml_kem::TryKeyInit;
        let (ct, secret, peer, ecsecret) = match ka.key().mpis() {
            mpi::PublicKey::MLKEM768_X25519 { mlkem, .. } => {
                let ek =
                    ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(mlkem.as_ref())
                        .unwrap();
                let (ct, secret) = ek.encapsulate_deterministic((&[9; 32]).into());
                let ec = x25519_dalek::StaticSecret::from([6; 32]);
                let peer = x25519_dalek::PublicKey::from(&ec);
                let raw = public_bytes("X25519", &f.hardware["9d"]).unwrap();
                let shared = ec.diffie_hellman(&x25519_dalek::PublicKey::from(
                    <[u8; 32]>::try_from(raw).unwrap(),
                ));
                (
                    ct.to_vec(),
                    secret.to_vec(),
                    peer.as_bytes().to_vec(),
                    shared.as_bytes().to_vec(),
                )
            }
            mpi::PublicKey::MLKEM1024_X448 { mlkem, .. } => {
                let ek =
                    ml_kem::EncapsulationKey::<ml_kem::MlKem1024>::new_from_slice(mlkem.as_ref())
                        .unwrap();
                let (ct, secret) = ek.encapsulate_deterministic((&[9; 32]).into());
                let ec = cx448::x448::Secret::from([6; 56]);
                let peer = cx448::x448::PublicKey::from(&ec);
                (
                    ct.to_vec(),
                    secret.to_vec(),
                    peer.as_bytes().to_vec(),
                    vec![],
                )
            }
            _ => panic!("encryption"),
        };
        let request = serde_json::json!({"requestId":"B".repeat(64),"cipherHash":"a".repeat(64),"recipientKey":ka.key().fingerprint().to_hex(),"mlkemCiphertext":B64.encode(ct),"x25519Ephemeral":B64.encode(peer)});
        let mut response = request.clone();
        response[if l3 { "x25519Secret" } else { "mlkemSecret" }] =
            B64.encode(if l3 { ecsecret } else { secret }).into();
        (request, response)
    };
    response["companion"] = f.descriptor.clone();
    response["companionShared"] = B64.encode(&f.shared).into();
    serde_json::json!({"operation":if signing{"sign"}else{"decapsulate"},"certificate":B64.encode(public),"request":request,"response":response})
}
#[test]
fn level3_companion_sign_and_decapsulate() {
    for s in [true, false] {
        let input = operation(true, s);
        let out = complete(&input).unwrap();
        assert!(out.get("companion").is_none());
        assert_eq!(
            B64.decode(
                out[if s { "mldsa65" } else { "mlkemSecret" }]
                    .as_str()
                    .unwrap()
            )
            .unwrap()
            .len(),
            if s { 3309 } else { 32 }
        );
    }
}
#[test]
fn level5_companion_sign_and_decapsulate() {
    for s in [true, false] {
        let input = operation(false, s);
        let out = complete(&input).unwrap();
        assert!(out.get("companionShared").is_none());
        assert_eq!(
            B64.decode(
                out[if s { "ed25519" } else { "x25519Secret" }]
                    .as_str()
                    .unwrap()
            )
            .unwrap()
            .len(),
            if s { 114 } else { 56 }
        );
    }
}
#[test]
fn companion_rejects_changed_binding_share_or_hardware_signature() {
    for l3 in [true, false] {
        let original = operation(l3, true);
        assert!(complete(&original).is_ok());
        let mut v = original.clone();
        v["response"]["companionShared"] = B64.encode([8; 48]).into();
        assert!(complete(&v).is_err());
        let mut v = original.clone();
        v["response"]["digest"] = B64.encode([8; 64]).into();
        assert!(complete(&v).is_err());
        let mut v = original.clone();
        v["certificate"] = B64.encode(b"wrong cert").into();
        assert!(complete(&v).is_err());
        let mut v = original.clone();
        v["response"][if l3 { "ed25519" } else { "mldsa65" }] =
            B64.encode(vec![0; if l3 { 64 } else { 4627 }]).into();
        assert!(complete(&v).is_err());
        let mut v = original.clone();
        v["response"][if l3 { "mldsa65" } else { "ed25519" }] = "unexpected software output".into();
        assert!(complete(&v).is_err());
    }
}
#[test]
fn companion_private_bags_reject_mutated_seed_and_extra_data() {
    for l3 in [true, false] {
        let f = fixture(l3);
        let env = inspect(&f.descriptor).unwrap();
        assert_eq!(parse_p12(&f.p12, &env).unwrap().len(), 3);
        let mut bad = f.p12.clone();
        bad.push(0);
        assert!(parse_p12(&bad, &env).is_err());
        let mut bad = f.p12.clone();
        let n = bad.len();
        bad[n / 2] ^= 1;
        assert!(parse_p12(&bad, &env).is_err());
    }
}
#[test]
fn companion_compression_and_public_mutation_rejected() {
    use std::io::Write;
    for l3 in [true, false] {
        let f = fixture(l3);
        let raw = B64
            .decode(f.descriptor["encoded"].as_str().unwrap())
            .unwrap();
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&raw).unwrap();
        let compressed = z.finish().unwrap();
        let mut packed = b"PQMCZ001".to_vec();
        packed.extend((raw.len() as u32).to_be_bytes());
        packed.extend(compressed);
        let mut descriptor = f.descriptor.clone();
        descriptor["encoded"] = B64.encode(&packed).into();
        assert!(inspect(&descriptor).is_ok());
        packed.push(0);
        descriptor["encoded"] = B64.encode(&packed).into();
        assert!(inspect(&descriptor).is_err());
        let mut descriptor = f.descriptor.clone();
        descriptor["serial"] = 2.into();
        assert!(inspect(&descriptor).is_err());
        let mut raw = raw;
        let n = raw.len();
        raw[n - 1] ^= 1;
        descriptor = f.descriptor.clone();
        descriptor["encoded"] = B64.encode(raw).into();
        assert!(inspect(&descriptor).is_err());
    }
}

/// Optional read-only audit of previously saved encrypted/public hardware
/// fixtures. Nothing is connected and no private/share material is read.
#[test]
fn saved_companion_public_fixture_if_requested() {
    let Ok(path) = std::env::var("PQMAIL_COMPANION_FIXTURE") else {
        return;
    };
    let root = std::path::Path::new(&path);
    let encoded = std::fs::read(root.join("companion.pqcomp")).unwrap();
    let l3 = root.join("83.der").exists();
    let slots = if l3 {
        ["82", "9c", "9d", "83"]
    } else {
        ["86", "9c", "9d", "82"]
    };
    let keys = slots
        .into_iter()
        .map(|s| {
            (
                s.to_string(),
                std::fs::read(root.join(format!("{s}.der"))).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let serial = std::env::var("PQMAIL_COMPANION_SERIAL")
        .unwrap()
        .parse()
        .unwrap();
    let cache = std::fs::read(root.join("public.pgp")).ok();
    let env = VerifiedCompanion::parse(&encoded, serial, &keys, cache.as_deref()).unwrap();
    assert_eq!(env.components().len(), 7);
    if let Ok(path) = std::env::var("PQMAIL_COMPANION_TEST_WRAPPER_KEY") {
        // Explicit opt-in for a known disposable software fixture's wrapping
        // key; never run for a hardware/user key. No key/share is printed or
        // persisted. This checks the real Bouncy Castle BER P12 encoding.
        use p384::pkcs8::{DecodePrivateKey, DecodePublicKey};
        let encoded = Zeroizing::new(std::fs::read(path).unwrap());
        let key = p384::SecretKey::from_pkcs8_der(&encoded).unwrap();
        let peer = p384::PublicKey::from_public_key_der(env.wrapping_peer()).unwrap();
        let shared = p384::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine());
        let shared = Zeroizing::new(shared.raw_secret_bytes().to_vec());
        assert_eq!(open(&env, &shared).unwrap().len(), 3);
    }
}

fn partial(f: &Fixture, request: &serde_json::Value, signing: bool) -> serde_json::Value {
    let policy = StandardPolicy::new();
    let ka = f
        .cert
        .keys()
        .secret()
        .with_policy(&policy, None)
        .find(|k| {
            if signing {
                k.for_signing()
            } else {
                k.for_transport_encryption()
            }
        })
        .unwrap();
    let mut pair = ka.key().clone().into_keypair().unwrap();
    let l3 = f.descriptor["publicKeys"].get("83").is_some();
    let mut out = request.clone();
    if signing {
        let digest = B64.decode(request["digest"].as_str().unwrap()).unwrap();
        let (ed, ml) = match pair.sign(HashAlgorithm::SHA512, &digest).unwrap() {
            mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa } => (eddsa.to_vec(), mldsa.to_vec()),
            mpi::Signature::MLDSA87_Ed448 { eddsa, mldsa } => (eddsa.to_vec(), mldsa.to_vec()),
            _ => panic!("signature"),
        };
        out[if l3 { "ed25519" } else { "mldsa65" }] = B64.encode(if l3 { ed } else { ml }).into();
    } else {
        let secret = pair.secret().map(|m| match m {
            mpi::SecretKeyMaterial::MLKEM768_X25519 { ecdh, .. } => {
                let peer = B64
                    .decode(request["x25519Ephemeral"].as_str().unwrap())
                    .unwrap();
                let key =
                    x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(ecdh.as_ref()).unwrap());
                key.diffie_hellman(&x25519_dalek::PublicKey::from(
                    <[u8; 32]>::try_from(peer.as_slice()).unwrap(),
                ))
                .as_bytes()
                .to_vec()
            }
            mpi::SecretKeyMaterial::MLKEM1024_X448 { mlkem, .. } => {
                use ml_kem::kem::Decapsulate;
                let ct = B64
                    .decode(request["mlkemCiphertext"].as_str().unwrap())
                    .unwrap();
                ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::from_seed(
                    mlkem.as_ref().try_into().unwrap(),
                )
                .decapsulate(ct.as_slice().try_into().unwrap())
                .to_vec()
            }
            _ => panic!("decapsulation"),
        });
        out[if l3 { "x25519Secret" } else { "mlkemSecret" }] = B64.encode(secret).into();
    }
    out["companion"] = f.descriptor.clone();
    out["companionShared"] = B64.encode(&f.shared).into();
    out
}
/// Full message authentication proves the completed components are correct,
/// rather than merely the expected length. An independent Sequoia sender also
/// verifies the reverse direction through the normal IWA packet parser/KDF.
fn roundtrip(l3: bool) {
    use pgp::serialize::stream::{Encryptor, LiteralWriter, Message, Signer as StreamSigner};
    use std::io::Write;
    let f = fixture(l3);
    let public = B64.encode(f.cert.clone().strip_secret_key_material().to_vec().unwrap());
    let payload = b"Companion authenticated end-to-end message\r\n";
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as f64;
    let(pending,digest)=crate::signing::prepare(&serde_json::json!({"requestId":"C".repeat(64),"senderCertificate":public,"senderEmail":"companion@example.invalid","payload":B64.encode(payload)}),timestamp).unwrap();
    let response=complete(&serde_json::json!({"operation":"sign","certificate":public,"request":digest,"response":partial(f,&digest,true)})).unwrap();
    let signed = crate::signing::finish(pending, &response, timestamp + 1.).unwrap();
    let encrypted=crate::encrypt_public(&serde_json::json!({"senderCertificate":public,"recipientCertificate":public,"recipientFingerprint":f.cert.fingerprint().to_hex(),"recipientEmail":"companion@example.invalid","signed":signed["signed"],"payload":signed["payload"]})).unwrap();
    let policy = StandardPolicy::new();
    let ka = f
        .cert
        .keys()
        .with_policy(&policy, None)
        .for_transport_encryption()
        .next()
        .unwrap();
    let recipient = ka.key().fingerprint().to_hex();
    let mut reverse = Vec::new();
    {
        let recipients = f
            .cert
            .keys()
            .with_policy(&policy, None)
            .for_transport_encryption();
        let enc = Encryptor::for_recipients(Message::new(&mut reverse), recipients)
            .build()
            .unwrap();
        let signer = f
            .cert
            .keys()
            .secret()
            .with_policy(&policy, None)
            .for_signing()
            .next()
            .unwrap()
            .key()
            .clone()
            .into_keypair()
            .unwrap();
        let signer = StreamSigner::new(enc, signer).unwrap().build().unwrap();
        let mut literal = LiteralWriter::new(signer).build().unwrap();
        literal.write_all(payload).unwrap();
        literal.finalize().unwrap();
    }
    for cipher in [
        encrypted["cipher"].as_str().unwrap().to_string(),
        B64.encode(reverse),
    ] {
        let request = serde_json::json!({"requestId":"D".repeat(64),"cipher":cipher,"recipientCertificate":public,"recipientKey":recipient,"purpose":"message"});
        let (pending, components) = crate::decryption::prepare(&request, timestamp).unwrap();
        let response=complete(&serde_json::json!({"operation":"decapsulate","certificate":public,"request":components,"response":partial(f,&components,false)})).unwrap();
        let opened = crate::decryption::finish(pending, &response, timestamp + 1.).unwrap();
        assert_eq!(
            B64.decode(opened["raw"].as_str().unwrap()).unwrap(),
            payload
        );
        assert_eq!(crate::verify_public(&serde_json::json!({"payload":opened["raw"],"signature":opened["signature"],"certificates":[public]})).unwrap()["signatures"][0]["status"],"valid");
    }
}
#[test]
fn level3_companion_complete_message_and_independent_return() {
    roundtrip(true)
}
#[test]
fn level5_companion_complete_message_and_independent_return() {
    roundtrip(false)
}
#[test]
fn ber_container_limits_and_indefinite_support() {
    let mut deep = der(4, &[1]);
    for _ in 0..18 {
        deep = [&[0x30, 0x80][..], &deep, &[0, 0]].concat();
    }
    assert!(one(&deep, 0x30).is_err());
    assert!(one(&[0x30, 0x80, 0x04, 0x80, 0, 0, 0, 0], 0x30).is_err());
    assert!(one(&[0x30, 0x80, 4, 1, 2], 0x30).is_err());
    for l3 in [true, false] {
        let f = fixture(l3);
        let env = inspect(&f.descriptor).unwrap();
        let body = one(&f.p12, 0x30).unwrap().body;
        let ber = [&[0x30, 0x80][..], body, &[0, 0]].concat();
        assert_eq!(parse_p12(&ber, &env).unwrap().len(), 3);
    }
}

/// Export only disposable fixture envelopes and simulated operation shares for
/// the browser-WASM regression harness. This is compiled into tests only; it
/// never exports a user identity, reads a device or writes a plaintext P12.
#[test]
fn export_companion_browser_vectors_if_requested() {
    let Ok(directory) = std::env::var("PQMAIL_COMPANION_TEST_EXPORT") else {
        return;
    };
    let root = std::path::Path::new(&directory);
    std::fs::create_dir_all(root).unwrap();
    for (l3, label) in [(true, "level3"), (false, "level5")] {
        for (sign, op) in [(true, "sign"), (false, "decapsulate")] {
            let input = operation(l3, sign);
            let expected = complete(&input).unwrap();
            let vector = serde_json::json!({"testOnly":true,"input":input,"expected":expected});
            std::fs::write(
                root.join(format!("{label}-{op}.json")),
                serde_json::to_vec(&vector).unwrap(),
            )
            .unwrap();
        }
    }
}

/// Optional public-only reconstruction of an already verified hardware result.
/// A deliberately incorrect wrapping share must reach the AEAD rejection only
/// after the actual card certificate and ML-DSA signature component validate.
/// No card call, PIN, real ECDH share or private key participates in this test.
#[test]
fn saved_hardware_public_signature_reaches_aead_if_requested() -> Result<()> {
    use pgp::parse::stream::{MessageLayer, MessageStructure, VerificationHelper, VerifierBuilder};
    use std::io::Read;
    struct PublicProof {
        certificate: Cert,
        proof: Option<(String, Vec<u8>, Vec<u8>)>,
    }
    impl VerificationHelper for PublicProof {
        fn get_certs(&mut self, _: &[pgp::KeyHandle]) -> Result<Vec<Cert>> {
            Ok(vec![self.certificate.clone()])
        }
        fn check(&mut self, structure: MessageStructure) -> Result<()> {
            for layer in structure.iter() {
                if let MessageLayer::SignatureGroup { results } = layer {
                    for result in results {
                        let good = result
                            .as_ref()
                            .map_err(|_| anyhow::anyhow!("Saved signature invalid"))?;
                        ensure!(self.proof.is_none(), "Exactly one saved signature required");
                        let mpi::Signature::MLDSA87_Ed448 { mldsa, .. } = good.sig.mpis() else {
                            bail!("Level5 signature required")
                        };
                        self.proof = Some((
                            good.ka.key().fingerprint().to_hex(),
                            good.sig
                                .computed_digest()
                                .context("Verified digest missing")?
                                .to_vec(),
                            mldsa.to_vec(),
                        ));
                    }
                }
            }
            Ok(())
        }
    }
    let Ok(root) = std::env::var("PQMAIL_COMPANION_PUBLIC_TRACE") else {
        return Ok(());
    };
    let root = std::path::Path::new(&root);
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(std::env::var(
        "PQMAIL_COMPANION_STOP_REPORT",
    )?)?)?;
    let selected = report["identity"]["certificate"]
        .as_str()
        .context("Selected public certificate")?;
    let certificate = Cert::from_bytes(&B64.decode(selected)?)?;
    let signed = std::fs::read(root.join("pqmail-signed.pgp"))?;
    let policy = StandardPolicy::new();
    let mut reader = VerifierBuilder::from_bytes(&signed)?.with_policy(
        &policy,
        None,
        PublicProof {
            certificate,
            proof: None,
        },
    )?;
    let mut discard = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut discard)?;
    let (fingerprint, digest, signature) =
        reader.into_helper().proof.context("No saved signature")?;
    let keys = ["86", "9c", "9d", "82"]
        .into_iter()
        .map(|slot| {
            Ok((
                slot.to_string(),
                serde_json::Value::String(
                    B64.encode(std::fs::read(root.join(format!("{slot}.der")))?),
                ),
            ))
        })
        .collect::<Result<serde_json::Map<_, _>>>()?;
    let descriptor = serde_json::json!({"encoded":B64.encode(std::fs::read(root.join("companion.pqcomp"))?),"serial":report["identity"]["serial"],"publicKeys":keys,"certificate":selected});
    let request = serde_json::json!({"requestId":"A".repeat(64),"signingFingerprint":fingerprint,"hashAlgorithm":10,"digest":B64.encode(digest)});
    let mut response = request.clone();
    response["ed25519"] = "".into();
    response["mldsa65"] = B64.encode(signature).into();
    response["companion"] = descriptor;
    response["companionShared"] = B64.encode([1; 48]).into();
    let input = serde_json::json!({"operation":"sign","certificate":selected,"request":request,"response":response});
    let error = complete(&input).unwrap_err().to_string();
    assert_eq!(
        error, "Companion authentication failed",
        "Failure must occur at deliberately incorrect AEAD share, not public/signature validation"
    );
    if let Ok(path) = std::env::var("PQMAIL_COMPANION_PUBLIC_VECTOR") {
        std::fs::write(
            path,
            serde_json::to_vec(
                &serde_json::json!({"publicOnly":true,"deliberatelyWrongWrapShare":true,"input":input,"expectedError":"Companion authentication failed"}),
            )?,
        )?;
    }
    Ok(())
}
