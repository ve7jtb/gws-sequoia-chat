//! Split-phase, public-only OpenPGP signing for a dedicated IWA worker.
//!
//! Sequoia's synchronous `Signer` callback is deliberately suspended at its
//! digest boundary. Preparation retains the exact MIME bytes, version-specific salt, creation
//! time and signature template in this worker; the selected component provider receives only
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

pub(super) struct Pending {
    request_id: String,
    started: f64,
    cert: pgp::Cert,
    key: PublicKey,
    payload: Vec<u8>,
    template: SignatureBuilder,
    v4_template: Option<Signature>,
    digest: Vec<u8>,
}
thread_local! {
    // A new worker is used for each send.  Even if its caller accidentally reuses
    // it, only one preparation is allowed and every finalize attempt consumes it.
    static PENDING: RefCell<Option<Pending>> = const { RefCell::new(None) };
}

/// The first pass lets Sequoia compute its exact v4/v6 signature digest. V6
/// suspends with an intentional error; v4 retains an internal placeholder to
/// freeze its random salt notation. Neither path publishes fake signatures or
/// reimplements the OpenPGP hash trailer.
struct Capture { key: PublicKey, digest: Option<Vec<u8>> }
impl Signer for Capture {
    fn public(&self) -> &PublicKey { &self.key }
    fn acceptable_hashes(&self) -> &[HashAlgorithm] { &[HASH] }
    fn sign(&mut self, hash: HashAlgorithm, digest: &[u8]) -> Result<mpi::Signature> {
        ensure!(hash == HASH && digest.len() == 64, "Unexpected signing digest");
        ensure!(self.digest.is_none(), "Multiple signing requests");
        self.digest = Some(digest.to_vec());
        // Version-4 pre_sign always regenerates Sequoia's random salt notation.
        // Retain a complete public skeleton on that first pass so finalization
        // cannot hash a new notation after authorization. Zero MPIs are never
        // returned to JavaScript or serialized; real MPIs replace them only
        // after verification against this exact digest and selected key.
        match self.key.pk_algo() {
            PublicKeyAlgorithm::EdDSA if self.key.version()==4 => Ok(mpi::Signature::EdDSA{r:mpi::MPI::new(&[0]),s:mpi::MPI::new(&[0])}),
            PublicKeyAlgorithm::ECDSA if self.key.version()==4 => Ok(mpi::Signature::ECDSA{r:mpi::MPI::new(&[0]),s:mpi::MPI::new(&[0])}),
            _ => bail!("Signing suspended at native boundary"),
        }
    }
}

/// The second pass permits Sequoia to assemble the signature only if its digest
/// is byte-for-byte identical to preparation. Component output is verified
/// with the selected public key before it can become an OpenPGP packet.
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

pub(super) fn prepare(v: &serde_json::Value, started: f64) -> Result<(Pending, serde_json::Value)> {
    ensure!(started.is_finite() && started > 0.0, "Invalid clock");
    let request_id = field(v, "requestId")?;
    ensure!(request_id.len() == 64 && request_id.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)), "Invalid request identifier");
    let cert = public(field(v, "senderCertificate")?)?;
    ensure!(matches!(cert.primary_key().key().version(),4|6), "Supported sender version required");
    ensure!(current_emails(&cert).iter().any(|email| email == field(v, "senderEmail").unwrap_or("")), "Sender mailbox mismatch");
    let policy = StandardPolicy::new();
    let keys: Vec<_> = cert.keys().with_policy(&policy, None).alive().revoked(false)
        .for_signing().filter(|ka| super::certificates::signing_supported(ka.key()))
        .map(|ka| ka.key().clone().role_into_unspecified()).collect();
    ensure!(keys.len() == 1, "Exactly one supported signing key required");
    let key = keys[0].clone();
    let payload = B64.decode(field(v, "payload")?)?;
    // Reserve packet overhead under the existing signed-message transport limit.
    ensure!(!payload.is_empty() && payload.len() <= LIMIT - 8192, "Signing payload limit");
    let mut capture = Capture { key: key.clone(), digest: None };
    // Explicit creation time freezes the authorized timestamp. V6 retains the
    // prefix salt through pre_sign; v4 must additionally retain the completed
    // public header below because Sequoia refreshes its salt notation.
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_millis(started as u64);
    let template = SignatureBuilder::new(SignatureType::Binary).set_hash_algo(HASH)
        .set_signature_creation_time(time)?.pre_sign(&capture)?;
    // RFC 9580 v6 signatures require a fresh salt. Compatibility v4 has no
    // prefix salt; applying v6 hashing to it would create an unverifiable signature.
    if key.version()==6 { ensure!(template.prefix_salt().map(|s| s.len()) == Some(HASH.salt_size()?), "Missing v6 salt"); }
    else { ensure!(template.prefix_salt().is_none(), "Unexpected v4 salt"); }
    let captured = template.clone().sign_message(&mut capture, &payload);
    let v4_template = if key.version()==4 { Some(captured?) }
        else { ensure!(captured.is_err(), "Unexpected signing completion"); None };
    let digest = capture.digest.context("No signing digest")?;
    let reply = serde_json::json!({"requestId":request_id,"signingFingerprint":key.fingerprint().to_hex(),
        "hashAlgorithm":u8::from(HASH),"digest":B64.encode(&digest)});
    Ok((Pending { request_id:request_id.into(), started, cert, key, payload, template, v4_template, digest }, reply))
}

pub(super) fn finish(pending: Pending, v: &serde_json::Value, now: f64) -> Result<serde_json::Value> {
    let fields=["requestId","signingFingerprint","hashAlgorithm","digest","ed25519","mldsa65"];
    let object=v.as_object().context("Signature response object")?;
    ensure!(object.len()==fields.len()&&fields.iter().all(|k|object.contains_key(*k)),"Unexpected signature response fields");
    ensure!(now.is_finite() && now >= pending.started && now - pending.started <= LIFETIME_MS, "Signing request expired");
    ensure!(field(v, "requestId")? == pending.request_id, "Request mismatch");
    ensure!(field(v, "signingFingerprint")? == pending.key.fingerprint().to_hex(), "Signing key mismatch");
    ensure!(v["hashAlgorithm"].as_u64() == Some(u8::from(HASH) as u64), "Hash algorithm mismatch");
    ensure!(B64.decode(field(v, "digest")?)? == pending.digest, "Digest mismatch");
    let ed = B64.decode(field(v, "ed25519")?)?;
    let ml = B64.decode(field(v, "mldsa65")?)?;
    // Legacy component field names remain unchanged for the deployed hardware
    // bridge. The selected, authenticated public key determines their actual
    // algorithm and exact lengths; the caller never chooses a private algorithm.
    let signature=match pending.key.pk_algo() {
        PublicKeyAlgorithm::MLDSA65_Ed25519 => {
            ensure!(ed.len()==64 && ml.len()==3309,"Level 3 signature length");
            mpi::Signature::MLDSA65_Ed25519{eddsa:Box::new(ed.as_slice().try_into()?),mldsa:Box::new(ml.as_slice().try_into()?)}
        },
        PublicKeyAlgorithm::MLDSA87_Ed448 => {
            ensure!(ed.len()==114 && ml.len()==4627,"Level 5 signature length");
            mpi::Signature::MLDSA87_Ed448{eddsa:Box::new(ed.as_slice().try_into()?),mldsa:Box::new(ml.as_slice().try_into()?)}
        },
        PublicKeyAlgorithm::EdDSA => {
            ensure!(ed.len()==64 && ml.is_empty(),"Ed25519 compatibility signature length");
            mpi::Signature::EdDSA{r:mpi::MPI::new(&ed[..32]),s:mpi::MPI::new(&ed[32..])}
        },
        PublicKeyAlgorithm::ECDSA => {
            // Component widths come from the authenticated signing key, never
            // from a response length that could silently select another curve.
            let width=match pending.key.mpis(){
              mpi::PublicKey::ECDSA{curve:pgp::types::Curve::NistP384,..}=>48,
              mpi::PublicKey::ECDSA{curve:pgp::types::Curve::NistP521,..}=>66,
              _=>bail!("Unsupported ECDSA curve")};
            ensure!(ed.len()==2*width && ml.is_empty(),"ECDSA compatibility signature length");
            mpi::Signature::ECDSA{r:mpi::MPI::new(&ed[..width]),s:mpi::MPI::new(&ed[width..])}
        },
        _=>bail!("Unsupported signing key"),
    };
    let signature: Signature = if let Some(retained) = pending.v4_template {
        // Construct from the retained public header rather than calling
        // SignatureBuilder again: v4 uses a random hashed notation which must
        // remain identical to the bytes approved by the signing operation.
        pending.key.verify(&signature,HASH,&pending.digest)?;
        pgp::packet::signature::Signature4::new(retained.typ(),retained.pk_algo(),
            retained.hash_algo(),retained.hashed_area().clone(),retained.unhashed_area().clone(),
            *retained.digest_prefix(),signature).into()
    } else {
        let mut complete = Complete { key:pending.key.clone(), digest:pending.digest,signature:Some(signature) };
        pending.template.sign_message(&mut complete, &pending.payload)?
    };
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
            ensure!(cell.borrow().is_none()&&!super::libre::has_signing(), "Signing already pending");
            let v:serde_json::Value = serde_json::from_str(input)?;
            let certificate=B64.decode(field(&v,"senderCertificate")?)?;
            if super::libre::is_certificate(&certificate){return Ok(super::libre::prepare_signing(&v)?.to_string());}
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
        if super::libre::has_signing(){
            if input.len()>16384{super::libre::cancel_signing();bail!("Signature response bound");}
            let value=match serde_json::from_str(input){Ok(v)=>v,Err(e)=>{super::libre::cancel_signing();return Err(e.into())}};
            return Ok(super::libre::finalize_signing(&value)?.to_string());
        }
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
pub fn cancel_signing() { PENDING.with(|cell| { cell.borrow_mut().take(); });super::libre::cancel_signing(); }
