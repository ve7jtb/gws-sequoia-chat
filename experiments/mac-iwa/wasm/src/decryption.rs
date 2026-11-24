//! Split-phase recipient parsing and hybrid session-key recovery in WASM.
//!
//! Only two bounded public component inputs leave this module. The native
//! helper validates its configured hardware identity and returns the component
//! shared secrets; it neither parses an OpenPGP message nor combines those
//! secrets. The exact packet, recipient and ciphertext remain in this worker
//! while PIN/touch is pending. A reply is consumed once, including on failure.
use super::{decrypt_session_mode, field, public, B64, LIMIT};
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use sequoia_openpgp as pgp;
use pgp::{crypto::{ecdh::aes_key_unwrap, mpi, SessionKey},
    packet::{key, Key}, parse::Parse, policy::StandardPolicy,
    types::{HashAlgorithm, PublicKeyAlgorithm as A, SymmetricAlgorithm as S}};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use wasm_bindgen::prelude::*;

type PublicKey = Key<key::PublicParts, key::UnspecifiedRole>;
const LIFETIME_MS: f64 = 360_000.0;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn browser_now() -> f64;
}
fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    { browser_now() }
    #[cfg(not(target_arch = "wasm32"))]
    { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as f64 }
}

/// Exact schemas reject accidental native authority fields, supplied session
/// keys, or extra algorithm/slot choices. No request can select a token slot.
fn schema(v: &serde_json::Value, expected: &[&str]) -> Result<()> {
    let object = v.as_object().context("Object required")?;
    ensure!(object.len() == expected.len() && expected.iter().all(|k| object.contains_key(*k)), "Unexpected fields");
    Ok(())
}
fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
fn decode(v: &serde_json::Value, name: &str, limit: usize) -> Result<Vec<u8>> {
    let encoded = field(v, name)?;
    ensure!(encoded.len() <= (limit + 2) / 3 * 4, "Encoded input limit");
    let bytes = B64.decode(encoded)?;
    ensure!(bytes.len() <= limit && B64.encode(&bytes) == encoded, "Noncanonical or oversized input");
    Ok(bytes)
}

struct Pending {
    started: f64,
    request: serde_json::Value,
    cipher: Vec<u8>,
    key: PublicKey,
    wrapped: Vec<u8>,
    algorithm: S,
    vault: bool,
}
thread_local! {
    // A disposable worker owns this state. It cannot be replaced while a PIN
    // operation is pending, and finalize removes it before decoding any reply.
    static PENDING: RefCell<Option<Pending>> = const { RefCell::new(None) };
}

fn prepare(v: &serde_json::Value, started: f64) -> Result<(Pending, serde_json::Value)> {
    schema(v, &["requestId", "cipher", "recipientCertificate", "recipientKey", "purpose"])?;
    ensure!(started.is_finite() && started > 0.0 && hex64(field(v, "requestId")?) && hex64(field(v, "recipientKey")?), "Invalid binding");
    let vault = match field(v, "purpose")? { "message" => false, "vault" => true, _ => bail!("Invalid purpose") };
    // Bound the certificate before parsing, and reject secret-key packets even
    // though this path should receive only the configured public identity.
    let encoded_cert = decode(v, "recipientCertificate", 65536)?;
    let cert = public(&B64.encode(encoded_cert))?;
    ensure!(cert.primary_key().key().version() == 6, "v6 recipient required");
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None)?;
    valid.alive()?;
    ensure!(!matches!(valid.revocation_status(), pgp::types::RevocationStatus::Revoked(_)), "Revoked recipient");
    let keys: Vec<_> = cert.keys().with_policy(&policy, None).alive().revoked(false)
        .for_transport_encryption().filter(|ka| ka.key().pk_algo() == A::MLKEM768_X25519)
        .map(|ka| ka.key().clone().role_into_unspecified()).collect();
    ensure!(keys.len() == 1 && keys[0].version() == 6, "One Level 3 v6 encryption key required");
    let key = keys[0].clone();
    ensure!(key.fingerprint().to_hex() == field(v, "recipientKey")?, "Wrong selected key");
    let cipher = decode(v, "cipher", if vault {16384} else {LIMIT})?;
    ensure!(!cipher.is_empty(), "Empty ciphertext");
    let pile = pgp::PacketPile::from_bytes(&cipher)?;
    let packets: Vec<_> = pile.children().collect();
    // The current IWA intentionally supports one named v6 recipient and one
    // AEAD container. Anonymous recipients, SKESKs, extra packets and legacy
    // containers fail before native PIN authorization is requested.
    ensure!(packets.len() == 2, "Exactly two packets required");
    let pk = match packets[0] {
        pgp::Packet::PKESK(pgp::packet::PKESK::V6(p)) => p,
        _ => bail!("v6 PKESK required"),
    };
    ensure!(pk.recipient() == Some(&key.fingerprint()) && pk.pk_algo() == A::MLKEM768_X25519, "Recipient mismatch");
    let algorithm = match packets[1] {
        pgp::Packet::SEIP(pgp::packet::SEIP::V2(p)) => p.symmetric_algo(),
        _ => bail!("SEIPDv2 required"),
    };
    ensure!(matches!(algorithm, S::AES128 | S::AES192 | S::AES256), "AES required");
    let (ephemeral, mlkem, wrapped) = match pk.esk() {
        mpi::Ciphertext::MLKEM768_X25519 {ecdh, mlkem, esk} => (ecdh.as_ref(), mlkem.as_ref(), esk.to_vec()),
        _ => bail!("Hybrid ciphertext required"),
    };
    ensure!(ephemeral.iter().any(|b| *b != 0), "Invalid X25519 input");
    ensure!(wrapped.len() == algorithm.key_size()? + 8, "Wrapped key length mismatch");
    let request = serde_json::json!({"requestId":v["requestId"],
        "cipherHash":format!("{:x}", Sha256::digest(&cipher)),
        "recipientKey":key.fingerprint().to_hex(),
        "mlkemCiphertext":B64.encode(mlkem), "x25519Ephemeral":B64.encode(ephemeral)});
    Ok((Pending {started, request:request.clone(), cipher, key, wrapped, algorithm, vault}, request))
}

/// Inspect only the named recipient of the supported message envelope. This
/// performs no session-key recovery and never touches the split-phase pending
/// state. It rejects hidden recipients instead of trying cards until one works.
fn named_recipient(cipher: &[u8]) -> Result<String> {
    ensure!(!cipher.is_empty() && cipher.len() <= LIMIT, "Ciphertext limit");
    let pile = pgp::PacketPile::from_bytes(cipher)?;
    let packets: Vec<_> = pile.children().collect();
    ensure!(packets.len() == 2, "Exactly one recipient and one AEAD packet required");
    let recipient = match packets[0] {
        pgp::Packet::PKESK(pgp::packet::PKESK::V6(p)) => p,
        _ => bail!("Named v6 PKESK required"),
    };
    ensure!(recipient.pk_algo() == A::MLKEM768_X25519, "Supported hybrid recipient required");
    let fingerprint = recipient.recipient().context("Hidden recipients are unsupported")?.to_hex();
    ensure!(hex64(&fingerprint), "v6 recipient fingerprint required");
    let algorithm = match packets[1] {
        pgp::Packet::SEIP(pgp::packet::SEIP::V2(p)) => p.symmetric_algo(),
        _ => bail!("SEIPDv2 required"),
    };
    ensure!(matches!(algorithm, S::AES128 | S::AES192 | S::AES256), "AES required");
    let (ephemeral, wrapped) = match recipient.esk() {
        mpi::Ciphertext::MLKEM768_X25519 {ecdh, esk, ..} => (ecdh.as_ref(), esk.as_ref()),
        _ => bail!("Hybrid ciphertext required"),
    };
    ensure!(ephemeral.iter().any(|b| *b != 0), "Invalid X25519 input");
    ensure!(wrapped.len() == algorithm.key_size()? + 8, "Wrapped key length mismatch");
    Ok(fingerprint)
}

fn matching_identities(v: &serde_json::Value) -> Result<serde_json::Value> {
    schema(v, &["cipher", "candidates"])?;
    let cipher=decode(v,"cipher",LIMIT)?;
    let recipient=named_recipient(&cipher)?;
    let candidates=v["candidates"].as_array().context("Own identities required")?;
    ensure!(candidates.len() <= 16, "Too many own identities");
    let mut matches=Vec::new(); let mut ids=std::collections::BTreeSet::new();
    for item in candidates {
        schema(item, &["id","certificate"])?;
        let id=field(item,"id")?;
        ensure!(!id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control), "Invalid identity ID");
        ensure!(ids.insert(id), "Duplicate own identity ID");
        let certificate=decode(item,"certificate",65536)?;
        let info=super::certificates::inspect_identity_value(&B64.encode(certificate))?;
        if info["supported"] != true || info["recipientKey"] != recipient {continue;}
        // Reuse the exact pre-decryption validation, so matching cannot approve
        // a recipient which the existing split-phase parser would reject. Drop
        // this local Pending immediately; no global state or private material is
        // created, and a later operation will parse its own retained ciphertext.
        prepare(&serde_json::json!({"requestId":"A".repeat(64),"cipher":v["cipher"],
            "recipientCertificate":info["certificate"],"recipientKey":recipient,"purpose":"message"}),1.0)?;
        matches.push(serde_json::json!({"id":id,"fingerprint":info["fingerprint"],
            "certificateHash":info["certificateHash"],"signingFingerprint":info["signingFingerprint"],
            "recipientKey":info["recipientKey"],"emails":info["emails"]}));
    }
    // Keep every match. Two saved identities may legitimately expose the same
    // recipient key (or two cards may hold it); only an explicit UI choice may
    // resolve that ambiguity. Array order is never an authorization decision.
    Ok(serde_json::json!({"cipherHash":format!("{:x}",Sha256::digest(&cipher)),
        "recipientKey":recipient,"matches":matches}))
}

/// Match a message to saved public identities without opening any card session.
#[wasm_bindgen]
pub fn match_recipients(input: &str) -> Result<String, JsValue> {
    let run=|| -> Result<String> {
        // Sixteen bounded 64 KiB certificates plus one message fit this outer
        // limit. Inner bounds are enforced independently before packet parsing.
        ensure!(input.len() <= 1_800_000, "Recipient matching request limit");
        Ok(serde_json::to_string(&matching_identities(&serde_json::from_str(input)?)?)?)
    };
    run().map_err(|_| JsValue::from_str("Recipient matching rejected; named Level 3 v6 recipient required"))
}

fn finish(pending: Pending, v: &serde_json::Value, now: f64) -> Result<serde_json::Value> {
    schema(v, &["requestId", "cipherHash", "recipientKey", "mlkemCiphertext", "x25519Ephemeral", "mlkemSecret", "x25519Secret"])?;
    ensure!(now.is_finite() && now >= pending.started && now - pending.started <= LIFETIME_MS, "Decryption expired");
    for name in ["requestId", "cipherHash", "recipientKey", "mlkemCiphertext", "x25519Ephemeral"] {
        ensure!(v[name] == pending.request[name], "Component response binding mismatch");
    }
    // SessionKey uses Sequoia's protected allocation and wipes on drop. The
    // browser/IPC may still hold temporary encoded copies until worker teardown;
    // this design does not promise erasure of all managed-runtime copies.
    let ml: SessionKey = decode(v, "mlkemSecret", 32)?.into();
    let ec: SessionKey = decode(v, "x25519Secret", 32)?.into();
    ensure!(ml.len() == 32 && ec.len() == 32 && ec.iter().any(|b| *b != 0), "Invalid shared secret");
    let public_ec = match pending.key.mpis() {
        mpi::PublicKey::MLKEM768_X25519 {ecdh, ..} => ecdh.as_ref(),
        _ => bail!("Unexpected public key"),
    };
    let ephemeral = decode(&pending.request, "x25519Ephemeral", 32)?;
    // This exact RFC 9980 multi_key_combine input order matches Sequoia and the
    // existing PIV adapter: ML share, EC share, ephemeral EC public key, recipient
    // EC public key, OpenPGP algorithm ID and the full domain tag. Do not replace
    // it with HKDF or omit either public-key binding.
    let mut hash = HashAlgorithm::SHA3_256.context()?.for_digest();
    hash.update(&ml); hash.update(&ec); hash.update(&ephemeral); hash.update(public_ec);
    hash.update(&[A::MLKEM768_X25519.into()]); hash.update(b"OpenPGPCompositeKDFv1\x15");
    let mut kek = SessionKey::from(vec![0; 32]); hash.digest(&mut kek)?;
    // Sequoia's RFC 3394 implementation authenticates its integrity value. A
    // substituted component (including ML-KEM implicit rejection) cannot release
    // a usable session key. The retained AEAD container is authenticated too.
    let session: SessionKey = aes_key_unwrap(S::AES256, kek.as_protected(), &pending.wrapped)?.into();
    ensure!(session.len() == pending.algorithm.key_size()?, "Session length mismatch");
    let input = serde_json::json!({"cipher":B64.encode(&pending.cipher),
        "cipherHash":pending.request["cipherHash"], "recipientKey":pending.request["recipientKey"],
        "algorithm":u8::from(pending.algorithm), "sessionKey":B64.encode(&session)});
    let mut result = decrypt_session_mode(&input, pending.vault)?;
    // Only fully authenticated content leaves WASM, never a component secret,
    // KEK or recovered AES session key. MIME/trust checks remain the next layer.
    for name in ["requestId", "cipherHash", "recipientKey"] { result[name] = pending.request[name].clone(); }
    Ok(result)
}

#[wasm_bindgen]
pub fn prepare_decryption(input: &str) -> Result<String, JsValue> {
    let run = || -> Result<String> {
        ensure!(input.len() <= 450_000, "Request too large");
        PENDING.with(|cell| {
            ensure!(cell.borrow().is_none(), "Decryption already pending");
            let (pending, request) = prepare(&serde_json::from_str(input)?, now_ms())?;
            let result = serde_json::to_string(&request)?;
            *cell.borrow_mut() = Some(pending);
            Ok(result)
        })
    };
    run().map_err(|_| JsValue::from_str("Decryption preparation rejected"))
}

#[wasm_bindgen]
pub fn finalize_decryption(input: &str) -> Result<String, JsValue> {
    let run = || -> Result<String> {
        let pending = PENDING.with(|cell| cell.borrow_mut().take()).context("No pending decryption")?;
        ensure!(input.len() <= 8192, "Component response limit");
        Ok(serde_json::to_string(&finish(pending, &serde_json::from_str(input)?, now_ms())?)?)
    };
    run().map_err(|_| JsValue::from_str("Decryption finalization rejected"))
}

#[wasm_bindgen]
pub fn cancel_decryption() { PENDING.with(|cell| { cell.borrow_mut().take(); }); }

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::{cert::{CertBuilder, CipherSuite}, serialize::{SerializeInto,
        stream::{Message, Signer, Encryptor, LiteralWriter}}};
    use ml_kem::{kem::Decapsulate, DecapsulationKey, MlKem768};
    use std::io::Write;

    struct Fixture { request: serde_json::Value, reply: serde_json::Value,
        public: String, private: String, payload: Vec<u8> }

    fn fixture(vault: bool) -> Fixture {
        // These freshly generated software keys exist only in this test. The
        // production module never imports secret key material or runs either
        // component's private algorithm: those remain native hardware calls.
        let (cert, _) = CertBuilder::new().set_profile(pgp::Profile::RFC9580).unwrap()
            .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
            .add_userid("fixture@example.invalid").add_signing_subkey()
            .add_transport_encryption_subkey().generate().unwrap();
        let policy = StandardPolicy::new();
        let recipient = cert.keys().secret().with_policy(&policy, None)
            .for_transport_encryption().next().unwrap().key().clone().into_keypair().unwrap();
        let signer = cert.keys().secret().with_policy(&policy, None)
            .for_signing().next().unwrap().key().clone().into_keypair().unwrap();
        let payload = if vault {serde_json::to_vec(&serde_json::json!({
            "purpose":"sequoia-iwa-vault-wrap-v1", "vaultId":"11111111-1111-4111-8111-111111111111",
            "wrapperId":"22222222-2222-4222-8222-222222222222", "secret":B64.encode([7;32])})).unwrap()}
            else {b"From: fixture@example.invalid\r\nTo: recipient@example.invalid\r\nSubject: split decapsulation\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSynthetic authenticated content.\r\n".to_vec()};
        let recipients = cert.keys().with_policy(&policy, None).for_transport_encryption();
        let mut cipher = Vec::new();
        {
            let encrypt = Encryptor::for_recipients(Message::new(&mut cipher), recipients).build().unwrap();
            let mut writer = if vault {LiteralWriter::new(encrypt).build().unwrap()}
                else {LiteralWriter::new(Signer::new(encrypt, signer).unwrap().build().unwrap()).build().unwrap()};
            writer.write_all(&payload).unwrap(); writer.finalize().unwrap();
        }
        let public = B64.encode(cert.clone().strip_secret_key_material().to_vec().unwrap());
        let request = serde_json::json!({"requestId":"A".repeat(64), "cipher":B64.encode(cipher),
            "recipientCertificate":public, "recipientKey":recipient.public().fingerprint().to_hex(),
            "purpose":if vault {"vault"} else {"message"}});
        let (_, mut reply) = prepare(&request, 1000.0).unwrap();
        let ec_input: [u8; 32] = B64.decode(reply["x25519Ephemeral"].as_str().unwrap()).unwrap().try_into().unwrap();
        let ml_input: [u8; 1088] = B64.decode(reply["mlkemCiphertext"].as_str().unwrap()).unwrap().try_into().unwrap();
        // Independently emulate just the two component operations from the
        // original key's private material. Sequoia itself created the packets,
        // combiner output and RFC 3394 envelope during Encryptor above.
        recipient.secret().map(|secret| {
            let mpi::SecretKeyMaterial::MLKEM768_X25519 {ecdh, mlkem} = secret else {panic!("fixture algorithm")};
            let ec_secret: [u8; 32] = ecdh.as_ref().try_into().unwrap();
            let ml = DecapsulationKey::<MlKem768>::from_seed((&mlkem[..]).try_into().unwrap())
                .decapsulate((&ml_input).into());
            reply["mlkemSecret"] = serde_json::json!(B64.encode(ml));
            reply["x25519Secret"] = serde_json::json!(B64.encode(x25519_dalek::x25519(ec_secret, ec_input)));
        });
        let private = B64.encode(cert.as_tsk().to_vec().unwrap());
        Fixture {request, reply, public, private, payload}
    }

    fn complete(f: &Fixture, request: &serde_json::Value, reply: &serde_json::Value) -> Result<serde_json::Value> {
        let (pending, _) = prepare(request, 1000.0)?;
        let _ = f; // Fixture keeps all test data scoped to this independent operation.
        finish(pending, reply, 1001.0)
    }

    #[test]
    fn split_message_recovers_sequoia_envelope_and_verifies_signature() {
        let f = fixture(false);
        let result = complete(&f, &f.request, &f.reply).unwrap();
        assert_eq!(B64.decode(result["raw"].as_str().unwrap()).unwrap(), f.payload);
        assert!(result.get("sessionKey").is_none() && result.get("mlkemSecret").is_none());
        let verify = super::super::verify_public(&serde_json::json!({"payload":result["raw"],
            "signature":result["signature"], "certificates":[f.public]})).unwrap();
        assert_eq!(verify["signatures"][0]["status"], "valid");
        // Export only a disposable test envelope/component reply when explicitly
        // requested, for exercising the exact browser-target WASM in Node.
        if let Ok(path) = std::env::var("IWA_SPLIT_DECAP_FIXTURE") {
            let vault = fixture(true);
            std::fs::write(path, serde_json::to_vec(&serde_json::json!({"request":f.request,
                "reply":f.reply,"payload":B64.encode(f.payload),"certificate":f.public,
                "vault":{"request":vault.request,"reply":vault.reply,"payload":B64.encode(vault.payload)}})).unwrap()).unwrap();
        }
    }

    #[test]
    fn split_vault_recovers_unsigned_authenticated_payload() {
        let f = fixture(true);
        let result = complete(&f, &f.request, &f.reply).unwrap();
        assert_eq!(B64.decode(result["raw"].as_str().unwrap()).unwrap(), f.payload);
        assert_eq!(result["signature"], "");
        let mut request = f.request.clone(); request["purpose"] = "message".into();
        assert!(complete(&f, &request, &f.reply).is_err(), "Unsigned vault is not a signed message");
    }

    #[test]
    fn split_rejects_changed_response_bindings_and_extra_fields() {
        let f = fixture(false);
        for name in ["requestId", "cipherHash", "recipientKey", "mlkemCiphertext", "x25519Ephemeral"] {
            let mut bad = f.reply.clone(); bad[name] = "wrong".into();
            assert!(complete(&f, &f.request, &bad).is_err(), "{name}");
        }
        let mut extra = f.reply.clone(); extra["sessionKey"] = "supplied".into();
        assert!(complete(&f, &f.request, &extra).is_err());
        for name in ["mlkemSecret", "x25519Secret"] {
            let mut short = f.reply.clone(); short[name] = B64.encode([1;31]).into();
            assert!(complete(&f, &f.request, &short).is_err());
            let mut changed = f.reply.clone(); changed[name] = B64.encode([1;32]).into();
            assert!(complete(&f, &f.request, &changed).is_err());
        }
        let mut zero = f.reply.clone(); zero["x25519Secret"] = B64.encode([0;32]).into();
        assert!(complete(&f, &f.request, &zero).is_err());
    }

    #[test]
    fn split_rejects_private_cert_wrong_recipient_purpose_and_bad_packets_before_native() {
        let f = fixture(false);
        for (name, value) in [("recipientCertificate", f.private.clone()),
            ("recipientKey", "0".repeat(64)), ("purpose", "other".into()),
            ("requestId", "a".repeat(64)), ("cipher", B64.encode(b"plaintext"))] {
            let mut bad = f.request.clone(); bad[name] = value.into();
            assert!(prepare(&bad, 1000.0).is_err(), "{name}");
        }
        let mut extra = f.request.clone(); extra["slot"] = "9d".into();
        assert!(prepare(&extra, 1000.0).is_err());
        let cipher = B64.decode(f.request["cipher"].as_str().unwrap()).unwrap();
        let pile = pgp::PacketPile::from_bytes(&cipher).unwrap();
        let mut packets: Vec<_> = pile.children().cloned().collect();
        packets.push(packets[0].clone());
        let mut extra = f.request.clone();
        extra["cipher"] = B64.encode(packets.iter().flat_map(|p| p.to_vec().unwrap()).collect::<Vec<_>>()).into();
        assert!(prepare(&extra, 1000.0).is_err());
        let pgp::Packet::PKESK(pgp::packet::PKESK::V6(pk)) = &mut packets[0] else {panic!()};
        pk.set_recipient(None); packets.pop();
        let mut anonymous = f.request.clone();
        anonymous["cipher"] = B64.encode(packets.iter().flat_map(|p| p.to_vec().unwrap()).collect::<Vec<_>>()).into();
        assert!(prepare(&anonymous, 1000.0).is_err());
    }

    #[test]
    fn split_rejects_final_aead_tag_tampering_even_with_correct_shares() {
        let f = fixture(false);
        let mut cipher = B64.decode(f.request["cipher"].as_str().unwrap()).unwrap();
        *cipher.last_mut().unwrap() ^= 1;
        let mut bad = f.request.clone(); bad["cipher"] = B64.encode(cipher).into();
        let (_, request) = prepare(&bad, 1000.0).unwrap();
        let mut reply = f.reply.clone(); reply["cipherHash"] = request["cipherHash"].clone();
        assert!(complete(&f, &bad, &reply).is_err());
    }

    #[test]
    fn split_rejects_expired_and_backwards_clock() {
        let f = fixture(false);
        for now in [999.0, 361001.0, f64::NAN] {
            let (pending, _) = prepare(&f.request, 1000.0).unwrap();
            assert!(finish(pending, &f.reply, now).is_err());
        }
    }

    #[test]
    fn public_recipient_matching_returns_all_and_only_exact_certified_matches() {
        let one=fixture(false); let other=fixture(false);
        let request=serde_json::json!({"cipher":one.request["cipher"],"candidates":[
            {"id":"wrong-device","certificate":other.public},
            {"id":"selected-device","certificate":one.public}]});
        let result=matching_identities(&request).unwrap();
        assert_eq!(result["matches"].as_array().unwrap().len(),1);
        assert_eq!(result["matches"][0]["id"],"selected-device");
        assert_eq!(result["recipientKey"],one.request["recipientKey"]);
        assert_eq!(result["cipherHash"],one.reply["cipherHash"]);
        let mut ambiguous=request.clone();
        ambiguous["candidates"][0]=serde_json::json!({"id":"another-registered-copy","certificate":one.public});
        // Neither native authority nor array order may silently resolve two
        // saved copies of the same recipient key: the UI must ask which one.
        assert_eq!(matching_identities(&ambiguous).unwrap()["matches"].as_array().unwrap().len(),2);
        let mut none=request.clone();none["candidates"]=serde_json::json!([]);
        assert_eq!(matching_identities(&none).unwrap()["matches"],serde_json::json!([]));
        assert!(PENDING.with(|cell|cell.borrow().is_none()));
    }

    #[test]
    fn public_matching_rejects_secret_and_ambiguous_input_before_hardware() {
        let f=fixture(false);
        let request=serde_json::json!({"cipher":f.request["cipher"],"candidates":[{"id":"one","certificate":f.public}]});
        let mut bad=request.clone();bad["candidates"][0]["certificate"]=f.private.into();
        assert!(matching_identities(&bad).is_err());
        let mut bad=request.clone();bad["candidates"][0]["slot"]="9d".into();
        assert!(matching_identities(&bad).is_err());
        let mut bad=request.clone();bad["candidates"].as_array_mut().unwrap().push(request["candidates"][0].clone());
        assert!(matching_identities(&bad).is_err());
        let cipher=B64.decode(f.request["cipher"].as_str().unwrap()).unwrap();
        let pile=pgp::PacketPile::from_bytes(&cipher).unwrap();
        let mut packets:Vec<_>=pile.children().cloned().collect();
        let pgp::Packet::PKESK(pgp::packet::PKESK::V6(pk))=&mut packets[0] else {panic!()};
        pk.set_recipient(None);
        let mut bad=request.clone();bad["cipher"]=B64.encode(packets.iter().flat_map(|p|p.to_vec().unwrap()).collect::<Vec<_>>()).into();
        assert!(matching_identities(&bad).is_err());
        packets.push(packets[0].clone());
        bad["cipher"]=B64.encode(packets.iter().flat_map(|p|p.to_vec().unwrap()).collect::<Vec<_>>()).into();
        assert!(matching_identities(&bad).is_err());
        let mut bad=request;bad["cipher"]=B64.encode(b"not an encrypted message").into();
        assert!(matching_identities(&bad).is_err());
    }
}
