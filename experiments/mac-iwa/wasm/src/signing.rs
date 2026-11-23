//! Split-phase, public-only OpenPGP signing for a dedicated IWA worker.
//!
//! Sequoia's synchronous `Signer` callback is deliberately suspended at its
//! digest boundary.  Preparation retains the exact MIME bytes, v6 salt, creation
//! time and signature template in this worker; the native process receives only
//! a digest and public-key/request bindings.  Finalization consumes that state
//! before inspecting the response, checks both hybrid components, and constructs
//! the OpenPGP packets locally.  No PIN or long-term secret enters this module.
use super::{current_emails, field, public, PublicVerify, B64, LIMIT};
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use sequoia_openpgp as pgp;
use pgp::{crypto::{mpi, Signer}, packet::{key, Key, Signature, signature::SignatureBuilder},
    parse::{Parse, stream::VerifierBuilder}, policy::StandardPolicy,
    serialize::SerializeInto, types::{HashAlgorithm, PublicKeyAlgorithm, SignatureType}};
use std::{cell::RefCell, io::Read};
use wasm_bindgen::prelude::*;

type PublicKey = Key<key::PublicParts, key::UnspecifiedRole>;
const HASH: HashAlgorithm = HashAlgorithm::SHA512;
// A PIN prompt plus a slow hardware operation can legitimately take several
// minutes.  This is a maximum operation lifetime, not a reusable signing grant.
const LIFETIME_MS: f64 = 360_000.0;

/// Browser time is read inside the module instead of accepting a caller-provided
/// deadline.  On native tests the standard clock supplies the same millisecond
/// representation.  A backwards clock change fails closed during finalization.
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

struct Pending {
    request_id: String,
    started: f64,
    cert: pgp::Cert,
    key: PublicKey,
    payload: Vec<u8>,
    template: SignatureBuilder,
    digest: Vec<u8>,
}
thread_local! {
    // A new worker is used for each send.  Even if its caller accidentally reuses
    // it, only one preparation is allowed and every finalize attempt consumes it.
    static PENDING: RefCell<Option<Pending>> = const { RefCell::new(None) };
}

/// The first pass lets Sequoia compute its own v6 signature digest.  Returning an
/// error at this exact callback is intentional: no fake signature is published,
/// and no home-grown reimplementation of the OpenPGP hash trailer is needed.
struct Capture { key: PublicKey, digest: Option<Vec<u8>> }
impl Signer for Capture {
    fn public(&self) -> &PublicKey { &self.key }
    fn acceptable_hashes(&self) -> &[HashAlgorithm] { &[HASH] }
    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<mpi::Signature> {
        ensure!(hash == HASH && digest.len() == 64, "Unexpected signing digest");
        ensure!(self.digest.is_none(), "Multiple signing requests");
        self.digest = Some(digest.to_vec());
        bail!("Signing suspended at native boundary")
    }
}

/// The second pass permits Sequoia to assemble the signature only if its digest
/// is byte-for-byte identical to preparation.  Hardware output is verified with
/// the selected public composite key before it can become an OpenPGP packet.
struct Complete { key: PublicKey, digest: Vec<u8>, signature: Option<mpi::Signature> }
impl Signer for Complete {
    fn public(&self) -> &PublicKey { &self.key }
    fn acceptable_hashes(&self) -> &[HashAlgorithm] { &[HASH] }
    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<mpi::Signature> {
        ensure!(hash == HASH && digest == self.digest, "Signing input changed");
        let signature = self.signature.take().context("Signature already used")?;
        self.key.verify(&signature, HASH, digest)?;
        Ok(signature)
    }
}

fn prepare(v: &serde_json::Value, started: f64) -> Result<(Pending, serde_json::Value)> {
    ensure!(started.is_finite() && started > 0.0, "Invalid clock");
    let request_id = field(v, "requestId")?;
    ensure!(request_id.len() == 64 && request_id.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)), "Invalid request identifier");
    let cert = public(field(v, "senderCertificate")?)?;
    ensure!(cert.primary_key().key().version() == 6, "v6 sender required");
    ensure!(current_emails(&cert).iter().any(|email| email == field(v, "senderEmail").unwrap_or("")), "Sender mailbox mismatch");
    let policy = StandardPolicy::new();
    let keys: Vec<_> = cert.keys().with_policy(&policy, None).alive().revoked(false)
        .for_signing().filter(|ka| ka.key().pk_algo() == PublicKeyAlgorithm::MLDSA65_Ed25519)
        .map(|ka| ka.key().clone().role_into_unspecified()).collect();
    ensure!(keys.len() == 1 && keys[0].version() == 6, "Exactly one v6 hybrid signing key required");
    let key = keys[0].clone();
    let payload = B64.decode(field(v, "payload")?)?;
    // Reserve packet overhead under the existing signed-message transport limit.
    ensure!(!payload.is_empty() && payload.len() <= LIMIT - 8192, "Signing payload limit");
    let mut capture = Capture { key: key.clone(), digest: None };
    // Explicit creation time and the retained pre_sign result ensure the second
    // pass does not generate a new salt or timestamp after a delayed PIN prompt.
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_millis(started as u64);
    let template = SignatureBuilder::new(SignatureType::Binary).set_hash_algo(HASH)
        .set_signature_creation_time(time)?.pre_sign(&capture)?;
    ensure!(template.prefix_salt().map(|s| s.len()) == Some(HASH.salt_size()?), "Missing v6 salt");
    ensure!(template.clone().sign_message(&mut capture, &payload).is_err(), "Unexpected signing completion");
    let digest = capture.digest.context("No signing digest")?;
    let reply = serde_json::json!({"requestId":request_id,"signingFingerprint":key.fingerprint().to_hex(),
        "hashAlgorithm":u8::from(HASH),"digest":B64.encode(&digest)});
    Ok((Pending { request_id:request_id.into(), started, cert, key, payload, template, digest }, reply))
}

fn finish(pending: Pending, v: &serde_json::Value, now: f64) -> Result<serde_json::Value> {
    ensure!(now.is_finite() && now >= pending.started && now - pending.started <= LIFETIME_MS, "Signing request expired");
    ensure!(field(v, "requestId")? == pending.request_id, "Request mismatch");
    ensure!(field(v, "signingFingerprint")? == pending.key.fingerprint().to_hex(), "Signing key mismatch");
    ensure!(v["hashAlgorithm"].as_u64() == Some(u8::from(HASH) as u64), "Hash algorithm mismatch");
    ensure!(B64.decode(field(v, "digest")?)? == pending.digest, "Digest mismatch");
    let ed = B64.decode(field(v, "ed25519")?)?;
    let ml = B64.decode(field(v, "mldsa65")?)?;
    ensure!(ed.len() == 64 && ml.len() == 3309, "Hybrid signature length mismatch");
    let mut complete = Complete { key:pending.key.clone(), digest:pending.digest,
        signature:Some(mpi::Signature::MLDSA65_Ed25519 {
            eddsa:Box::new(ed.as_slice().try_into()?), mldsa:Box::new(ml.as_slice().try_into()?) }) };
    let signature: Signature = pending.template.sign_message(&mut complete, &pending.payload)?;
    signature.verify_message(&pending.key, &pending.payload)?;
    // A version-6 one-pass packet carries the exact salt and issuer fingerprint
    // from this signature.  The literal packet is binary: MIME CRLF bytes are
    // preserved, not normalized or re-encoded by the OpenPGP layer.
    let onepass = pgp::packet::OnePassSig::try_from(&signature)?;
    let mut literal = pgp::packet::Literal::new(pgp::types::DataFormat::Binary);
    literal.set_body(pending.payload.clone());
    let detached = pgp::Packet::Signature(signature).to_vec()?;
    let mut signed = pgp::Packet::OnePassSig(onepass).to_vec()?;
    signed.extend(pgp::Packet::Literal(literal).to_vec()?);
    signed.extend_from_slice(&detached);
    ensure!(signed.len() <= LIMIT, "Signed packet limit");
    // Verify the finished packet stream as an independent consumer would.  This
    // catches framing/one-pass/literal mistakes in addition to component errors.
    let policy = StandardPolicy::new();
    let helper = PublicVerify { certs:vec![pending.cert.clone()], results:Vec::new() };
    let mut reader = VerifierBuilder::from_bytes(&signed)?.with_policy(&policy, None, helper)?;
    let mut recovered = Vec::new();
    reader.by_ref().take((LIMIT + 1) as u64).read_to_end(&mut recovered)?;
    let results = reader.into_helper().results;
    ensure!(recovered == pending.payload && results.len() == 1 && results[0]["status"] == "valid"
        && results[0]["signingFingerprint"] == pending.key.fingerprint().to_hex(), "Final signature verification failed");
    Ok(serde_json::json!({"requestId":pending.request_id,"signed":B64.encode(signed),
        "signature":B64.encode(detached),"payload":B64.encode(pending.payload),
        "senderCertificate":B64.encode(pending.cert.to_vec()?)}))
}

/// Start one signing operation in a dedicated worker.  Only the bounded digest
/// request is returned to JavaScript; all message-signature state remains here.
#[wasm_bindgen]
pub fn prepare_signing(input: &str) -> Result<String, JsValue> {
    let run = || -> Result<String> {
        ensure!(input.len() <= 600_000, "Request too large");
        PENDING.with(|cell| {
            ensure!(cell.borrow().is_none(), "Signing already pending");
            let v = serde_json::from_str(input)?;
            let (pending, reply) = prepare(&v, now_ms())?;
            let json = serde_json::to_string(&reply)?;
            *cell.borrow_mut() = Some(pending);
            Ok(json)
        })
    };
    run().map_err(|_| JsValue::from_str("Signing preparation rejected"))
}

/// Consume the pending operation even on malformed, stale or incorrect replies.
/// Retrying a failed signature requires a new preparation and new authorization.
#[wasm_bindgen]
pub fn finalize_signing(input: &str) -> Result<String, JsValue> {
    let run = || -> Result<String> {
        let pending = PENDING.with(|cell| cell.borrow_mut().take()).context("No pending signature")?;
        ensure!(input.len() <= 16_384, "Signature response too large");
        Ok(serde_json::to_string(&finish(pending, &serde_json::from_str(input)?, now_ms())?)?)
    };
    run().map_err(|_| JsValue::from_str("Signing finalization rejected"))
}

/// Cancellation releases the retained MIME/template immediately.  The worker is
/// terminated by its owner afterwards; JavaScript/WASM copies are not claimed to
/// have guaranteed physical erasure, and no private signing key was ever present.
#[wasm_bindgen]
pub fn cancel_signing() { PENDING.with(|cell| { cell.borrow_mut().take(); }); }
