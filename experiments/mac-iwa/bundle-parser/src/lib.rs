// SPDX-License-Identifier: LGPL-2.0-or-later
// Public format/profile reader adapted from Sequoia's piv-adapter restore.
//! Shared, target-independent parser for signed public PQMZIP01 bundles.
//!
//! The IWA worker and native authorization path compile this same code. Input
//! is an immutable byte slice; this crate has no device, path, process, PIN,
//! private-operation or persistence interface. It authenticates the bounded
//! container, envelope and public certificate bindings under the included key.
//! Native callers independently read fresh card bytes, call this parser, and
//! match its component SPKIs against the live device before granting access.
//!
//! These profile rules originated in sequoia-pqmail-piv::restore at revision
//! 6b99afc20984e16180e5bbfbabb51d8685d247e1. RustCrypto performs envelope
//! verification; public-only cross-implementation fixtures preserve that
//! interoperability without linking the adapter's filesystem/process APIs.
//!
//! A self-contained signature authenticates consistency under the included key,
//! not ownership of a physical token or trust in an address. Every result says
//! liveKeysMatched=false. Native independently revalidates its signed bundle,
//! serial and live components before any PIN or private operation.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use flate2::{Decompress, FlushDecompress, Status};
use pgp::cert::amalgamation::key::PrimaryKey;
use pgp::{
    crypto::mpi,
    parse::Parse,
    policy::StandardPolicy,
    serialize::SerializeInto,
    types::{Curve, PublicKeyAlgorithm},
    Cert,
};
use sequoia_openpgp as pgp;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
mod der;
pub mod v5;
pub mod companion;
/// Use the browser clock in WASM and the OS clock natively. The public
/// request cannot supply its own timestamp to bypass certificate expiry.
pub fn current_time()->Result<u32>{
 #[cfg(target_arch="wasm32")] {
  let milliseconds=js_sys::Date::now();
  ensure!(milliseconds.is_finite()&&milliseconds>=0.0&&milliseconds/1000.0<=u32::MAX as f64,"Clock out of range");
  Ok((milliseconds/1000.0) as u32)
 }
 #[cfg(not(target_arch="wasm32"))] {Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs().try_into()?)}
}
const MAX: usize = 65_536;
// B3 with both complete v6 certificate views can expand above 64 KiB.
// The on-card limit and each certificate/extension field stay at 64 KiB.
const MAX_EXTENDED_ENVELOPE: usize = 80 * 1024;
struct Profile {
    serial: u32,
    slots: [u8; 4],
    sign: Vec<u8>,
    enc: Vec<u8>,
    pgp: Vec<u8>,
    compat: Vec<u8>,
}
/// Authenticated public material with no live-device or ownership claim.
/// Fields stay private so callers cannot manufacture a verified result from
/// JSON flags. The only constructor is full bounded signature verification.
pub struct VerifiedBundle {
    serial: u32,
    cert: Cert,
    compatibility: Option<Cert>,
    keys: BTreeMap<u8, Vec<u8>>,
    bundle_hash: String,
    optional_extensions: bool,
}
#[derive(Clone, Copy)]
enum Operation {
    MlDsa65,
    MlDsa87,
    MlKem768,
    MlKem1024,
    Ed25519,
    X25519,
}

/// Reconstruct canonical public SPKIs so the browser can compare their SHA-256
/// hashes with native public-slot reads. The signed bundle cannot choose a
/// native method, slot, backend or file path through these fixed algorithms.
fn public_spki(operation: Operation, raw: &[u8]) -> Result<Vec<u8>> {
    let (algorithm, size): (&[u8], usize) = match operation {
        Operation::MlDsa65 => (der::MLDSA65, 1952),
        Operation::MlDsa87 => (der::MLDSA87, 2592),
        Operation::MlKem768 => (der::MLKEM768, 1184),
        Operation::MlKem1024 => (der::MLKEM1024, 1568),
        Operation::Ed25519 => (&[0x30, 5, 6, 3, 0x2b, 0x65, 0x70], 32),
        Operation::X25519 => (&[0x30, 5, 6, 3, 0x2b, 0x65, 0x6e], 32),
    };
    ensure!(raw.len() == size, "Wrong component public key length");
    let mut bits = vec![0];
    bits.extend_from_slice(raw);
    let mut body = algorithm.to_vec();
    body.extend(der::encode(3, &bits));
    Ok(der::encode(0x30, &body))
}
/// Length-prefixed fields are bounded before allocation or slicing.
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.0.len(), "Truncated bundle field");
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn magic(&mut self, m: &[u8]) -> Result<()> {
        ensure!(self.take(m.len())? == m, "Unsupported bundle format");
        Ok(())
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }
    fn blob(&mut self) -> Result<&'a [u8]> {
        self.bounded_blob(MAX)
    }
    fn bounded_blob(&mut self, limit: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        ensure!(n <= limit, "Oversized bundle field");
        self.take(n)
    }
    fn end(self) -> Result<()> {
        ensure!(self.0.is_empty(), "Trailing bundle bytes");
        Ok(())
    }
}

/// The zlib boundary and declared size must both match exactly. The allocation
/// limit applies to decompressed data, not just the small compressed input.
fn unpack(stored: &[u8]) -> Result<Vec<u8>> {
    ensure!(stored.len() <= MAX, "Oversized stored bundle");
    let mut r = Reader(stored);
    r.magic(b"PQMZIP01")?;
    let size = r.u32()? as usize;
    ensure!((1..=MAX_EXTENDED_ENVELOPE).contains(&size), "Invalid expanded bundle size");
    let mut output = vec![0; size + 1];
    let mut z = Decompress::new(true);
    let status = z.decompress(r.0, &mut output, FlushDecompress::Finish)?;
    ensure!(
        status == Status::StreamEnd
            && z.total_out() == size as u64
            && z.total_in() == r.0.len() as u64,
        "Invalid compressed bundle boundary"
    );
    output.truncate(size);
    Ok(output)
}

fn add(keys: &mut BTreeMap<u8, Vec<u8>>, slot: u8, spki: Vec<u8>) -> Result<()> {
    if let Some(old) = keys.insert(slot, spki.clone()) {
        ensure!(old == spki, "Conflicting public keys in slot {slot:02x}");
    }
    Ok(())
}
fn x509_bindings(p: &Profile, keys: &mut BTreeMap<u8, Vec<u8>>) -> Result<bool> {
    ensure!(p.slots == [0x9c,0x83,0x9d,0x82], "Unsupported slot mapping; restore never migrates keys");
    let sign=der::certificate_spki(&p.sign)?; let enc=der::certificate_spki(&p.enc)?;
    let(sa,s)=der::spki(&sign)?; let(ea,e)=der::spki(&enc)?;
    // Select an entire supported pair, not two independently guessed algorithms.
    let (sign_op,enc_op,sign_size,enc_size,hybrid)=
      if sa==der::MLDSA65 && ea==der::MLKEM768 {(Operation::MlDsa65,Operation::MlKem768,1952,1184,false)}
      else if sa==der::MLDSA87 && ea==der::MLKEM1024 {(Operation::MlDsa87,Operation::MlKem1024,2592,1568,false)}
      else if sa==der::COMPOSITE_SIGN && ea==der::COMPOSITE_KEM {(Operation::MlDsa65,Operation::MlKem768,1952,1184,true)}
      else if sa==der::COMPOSITE_SIGN_87 && ea==der::COMPOSITE_KEM_1024 {(Operation::MlDsa87,Operation::MlKem1024,2592,1568,true)}
      else {bail!("Unsupported or mixed S/MIME bundle profile")};
    ensure!(s.len()==sign_size+if hybrid{97}else{0} && e.len()==enc_size+if hybrid{97}else{0},"Invalid composite public-key lengths");
    add(keys,0x9c,public_spki(sign_op,&s[..sign_size])?)?;
    add(keys,0x9d,public_spki(enc_op,&e[..enc_size])?)?;
    if hybrid {add(keys,0x83,der::p384(&s[sign_size..])?)?;add(keys,0x82,der::p384(&e[enc_size..])?)?;}
    Ok(hybrid)
}

/// PQ Mail's composite representative signs the SHA-512 payload digest with
/// its LAMPS domain; ML-DSA also binds that domain as its FIPS 204 context. P-384
/// ECDSA signs the SAME representative using SHA-384. Both components must
/// verify. Neither zlib integrity nor the PQ half alone authenticates a bundle.
fn verify_envelope(payload: &[u8], signature: &[u8], profile: &Profile) -> Result<()> {
    use ml_dsa::{MlDsa65,MlDsa87,Signature,VerifyingKey};
    use p384::ecdsa::{signature::Verifier,Signature as EcSignature,VerifyingKey as EcKey};
    let spki=der::certificate_spki(&profile.sign)?; let(algorithm,raw)=der::spki(&spki)?;
    let (level5,hybrid)= if algorithm==der::MLDSA65{(false,false)}
      else if algorithm==der::MLDSA87{(true,false)}
      else if algorithm==der::COMPOSITE_SIGN{(false,true)}
      else if algorithm==der::COMPOSITE_SIGN_87{(true,true)}
      else {bail!("Unsupported bundle signing algorithm")};
    let (key_size,sig_size) = if level5{(2592,4627)}else{(1952,3309)};
    ensure!(raw.len()==key_size+if hybrid{97}else{0},"Invalid signing key length");
    ensure!(if hybrid{signature.len()>sig_size && signature.len()<=sig_size+104}else{signature.len()==sig_size},"Invalid bundle signature length");
    let domain: &[u8]=if level5{b"COMPSIG-MLDSA87-ECDSA-P384-SHA512"}else{b"COMPSIG-MLDSA65-ECDSA-P384-SHA512"};
    let message=if hybrid {let mut m=b"CompositeAlgorithmSignatures2025".to_vec();m.extend(domain);m.push(0);m.extend(Sha512::digest(payload));m}else{payload.to_vec()};
    let context=if hybrid{domain}else{b""};
    // FIPS 204 parameter sets have different fixed sizes; decoding the exact
    // signature type ensures no truncation or cross-parameter interpretation.
    let valid=if level5 {
      let kb:&[u8;2592]=raw[..2592].try_into()?;let sb:&[u8;4627]=signature[..4627].try_into()?;
      VerifyingKey::<MlDsa87>::decode(kb.into()).verify_with_context(&message,context,&Signature::<MlDsa87>::decode(sb.into()).context("Invalid ML-DSA-87 signature")?)
    } else {
      let kb:&[u8;1952]=raw[..1952].try_into()?;let sb:&[u8;3309]=signature[..3309].try_into()?;
      VerifyingKey::<MlDsa65>::decode(kb.into()).verify_with_context(&message,context,&Signature::<MlDsa65>::decode(sb.into()).context("Invalid ML-DSA-65 signature")?)
    };
    ensure!(valid,"Bundle ML-DSA signature failed");
    if hybrid {EcKey::from_sec1_bytes(&raw[key_size..])?.verify(&message,&EcSignature::from_der(&signature[sig_size..])?).context("Bundle ECDSA signature failed")?;}
    Ok(())
}

/// Cert::from_bytes can accept a first certificate from an armor stream. A
/// signed profile must contain exactly one public identity, never a keyring or
/// an ignored second secret-key block; parse the full certificate stream.
fn parse_certificate(raw: &[u8]) -> Result<Cert> {
    let armor = String::from_utf8_lossy(raw);
    ensure!(
        armor.matches("-----BEGIN PGP").count() <= 1
            && !armor.contains("-----BEGIN PGP PRIVATE KEY"),
        "One public certificate required"
    );
    let mut parser = pgp::cert::CertParser::from_bytes(raw)?;
    let cert = parser.next().context("Missing certificate")??;
    ensure!(
        parser.next().is_none() && !cert.is_tsk(),
        "One public certificate required"
    );
    Ok(cert)
}

fn emails(cert: &Cert) -> Result<BTreeSet<String>> {
    let p = StandardPolicy::new();
    let valid = cert.with_policy(&p, None)?;
    let mut emails = BTreeSet::new();
    for uid in valid.userids() {
        if let Some(email) = uid.userid().email_normalized()? {
            emails.insert(email);
        }
    }
    ensure!(!emails.is_empty(), "Certificate has no certified email");
    Ok(emails)
}

/// Validate bindings under Sequoia's policy before considering any key usable.
/// Primary certification and classical keys are matched as well, so a bundle
/// cannot smuggle a different compatibility identity into the local restore.
fn pgp_bindings(
    cert: &Cert,
    compat: Option<&Cert>,
    keys: &mut BTreeMap<u8, Vec<u8>>,
) -> Result<()> {
    ensure!(
        !cert.is_tsk() && compat.is_none_or(|c| !c.is_tsk()),
        "Private key material is not allowed in a public bundle"
    );
    ensure!(
        cert.primary_key().key().version() == 6
            && compat.is_none_or(|c| c.primary_key().key().version() == 4),
        "Expected v6 identity and v4 compatibility certificate"
    );
    if matches!(cert.primary_key().key().mpis(),mpi::PublicKey::ECDSA{curve:Curve::NistP384,..}) {
        return level5_bindings(cert,compat,keys);
    }
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None)?;
    valid.alive()?;
    ensure!(
        !matches!(
            valid.revocation_status(),
            pgp::types::RevocationStatus::Revoked(_)
        ),
        "Revoked v6 certificate"
    );
    ensure!(
        valid.primary_key().for_certification(),
        "Primary key cannot certify"
    );
    let separated = !valid.primary_key().for_signing();
    let mut sign = None;
    let mut kem = None;
    let mut slots = BTreeSet::new();
    for key in cert
        .keys()
        .with_policy(&policy, None)
        .alive()
        .revoked(false)
    {
        let k = key.key();
        ensure!(k.version() == 6, "Mixed key versions");
        let components: Vec<(u8, Operation, &[u8])> = match k.mpis() {
            mpi::PublicKey::MLDSA65_Ed25519 { mldsa, eddsa } if key.primary() && separated => vec![
                (0x86, Operation::MlDsa65, mldsa.as_slice()),
                (0x87, Operation::Ed25519, eddsa.as_slice()),
            ],
            mpi::PublicKey::MLDSA65_Ed25519 { mldsa, eddsa } if key.for_signing() => {
                ensure!(sign.is_none(), "Ambiguous signing subkey");
                sign = Some(k.clone());
                vec![
                    (0x9c, Operation::MlDsa65, mldsa.as_slice()),
                    (0x84, Operation::Ed25519, eddsa.as_slice()),
                ]
            }
            mpi::PublicKey::MLKEM768_X25519 { mlkem, ecdh } if key.for_transport_encryption() => {
                ensure!(kem.is_none(), "Ambiguous encryption subkey");
                kem = Some(k.clone());
                vec![
                    (0x9d, Operation::MlKem768, mlkem.as_slice()),
                    (0x85, Operation::X25519, ecdh.as_slice()),
                ]
            }
            mpi::PublicKey::Ed25519 { a } if key.for_signing() => {
                vec![(0x88, Operation::Ed25519, a.as_slice())]
            }
            mpi::PublicKey::X25519 { u } if key.for_transport_encryption() => {
                vec![(0x89, Operation::X25519, u.as_slice())]
            }
            _ => bail!("Unsupported or wrongly flagged v6 key"),
        };
        for (slot, op, raw) in components {
            ensure!(slots.insert(slot), "Duplicate OpenPGP role");
            add(keys, slot, public_spki(op, raw)?)?;
        }
    }
    ensure!(
        if separated {
            // New cards can carry only the three RFC 9980 keys. The older
            // extended v6 profile adds both legacy keys together.
            (slots.len() == 6 && cert.keys().count() == 3 && compat.is_none())
                || (slots.len() == 8 && cert.keys().count() == 5)
        } else {
            slots.len() == 4 && cert.keys().count() == 2
        },
        "Incomplete or invalid Level 3 certificate"
    );
    if let Some(compat) = compat {
        ensure!(
            separated,
            "Legacy combined primary cannot carry separated compatibility keys"
        );
        let cv = compat.with_policy(&policy, None)?;
        cv.alive()?;
        ensure!(
            !matches!(
                cv.revocation_status(),
                pgp::types::RevocationStatus::Revoked(_)
            ),
            "Revoked v4 certificate"
        );
        let mut count = 0;
        for key in compat
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
        {
            ensure!(key.key().version() == 4, "Mixed v4 key versions");
            match key.key().mpis() {
                mpi::PublicKey::EdDSA { curve, q }
                    if key.primary() && key.for_signing() && *curve == Curve::Ed25519 =>
                {
                    ensure!(
                        q.value().len() == 33 && q.value()[0] == 0x40,
                        "Invalid legacy Ed25519 point"
                    );
                    add(
                        keys,
                        0x88,
                        public_spki(Operation::Ed25519, &q.value()[1..])?,
                    )?;
                }
                mpi::PublicKey::MLKEM768_X25519 { mlkem, ecdh }
                    if !key.primary() && key.for_transport_encryption() =>
                {
                    add(
                        keys,
                        0x9d,
                        public_spki(Operation::MlKem768, mlkem.as_slice())?,
                    )?;
                    add(keys, 0x85, public_spki(Operation::X25519, ecdh.as_slice())?)?;
                }
                mpi::PublicKey::ECDH { curve, q, .. }
                    if !key.primary()
                        && key.for_transport_encryption()
                        && *curve == Curve::Cv25519 =>
                {
                    ensure!(
                        q.value().len() == 33 && q.value()[0] == 0x40,
                        "Invalid legacy X25519 point"
                    );
                    add(keys, 0x89, public_spki(Operation::X25519, &q.value()[1..])?)?;
                }
                _ => bail!("Unsupported v4 compatibility key"),
            }
            count += 1;
        }
        ensure!(
            count == 3 && compat.keys().count() == 3,
            "Incomplete v4 compatibility bindings"
        );
        ensure!(
            emails(compat)?.is_subset(&emails(cert)?),
            "Compatibility email mismatch"
        );
    }
    emails(cert)?;
    ensure!(
        sign.is_some() && kem.is_some(),
        "Missing signing or encryption key"
    );
    Ok(())
}

/// The ordinary Level 5 card bundle uses classical P-384 OpenPGP. Its base
/// RFC 9980 hybrid identity is a separate authenticated encrypted companion.
/// Do not mistake the S/MIME ML-DSA keys for an absent OpenPGP hybrid signer.
fn level5_bindings(cert:&Cert,compat:Option<&Cert>,keys:&mut BTreeMap<u8,Vec<u8>>)->Result<()> {
 let policy=StandardPolicy::new();
 for (c,is_compat) in std::iter::once((cert,false)).chain(compat.map(|c|(c,true))) {
  let valid=c.with_policy(&policy,None)?;valid.alive()?;
  ensure!(!matches!(valid.revocation_status(),pgp::types::RevocationStatus::Revoked(_)),"Revoked Level 5 certificate");
  ensure!(valid.primary_key().for_certification(),"Primary certification flag required");
  let mut count=0;let mut roles=BTreeSet::new();
  for k in c.keys().with_policy(&policy,None).alive().revoked(false) {
   ensure!(k.key().version()==if is_compat{4}else{6},"Mixed certificate versions");
   match k.key().mpis() {
    mpi::PublicKey::ECDSA{curve:Curve::NistP384,q} if k.primary()&&k.for_signing()=>{ensure!(roles.insert("signing"),"Duplicate signing role");add(keys,if is_compat{0x88}else{0x83},der::p384(q.value())?)?;},
    mpi::PublicKey::ECDH{curve:Curve::NistP384,q,..} if !k.primary()&&k.for_transport_encryption()=>{ensure!(roles.insert("classical-decryption"),"Duplicate classical decryption role");add(keys,if is_compat{0x89}else{0x82},der::p384(q.value())?)?;},
    mpi::PublicKey::MLKEM768_X25519{mlkem,ecdh} if is_compat&&!k.primary()&&k.for_transport_encryption()=>{
      ensure!(roles.insert("hybrid-decryption"),"Duplicate hybrid decryption role");
      add(keys,0x84,public_spki(Operation::MlKem768,mlkem.as_slice())?)?;
      add(keys,0x85,public_spki(Operation::X25519,ecdh.as_slice())?)?;
    }
    _=>bail!("Unsupported Level 5 OpenPGP role")
   };count+=1;
  }
  let expected=if is_compat{3}else{2};
  ensure!(count==expected&&c.keys().count()==expected&&roles.len()==expected,"Incomplete Level 5 certificate roles");
 }
 if let Some(c)=compat {ensure!(emails(c)?.is_subset(&emails(cert)?),"Compatibility email mismatch");}
 emails(cert)?;
 // A P-384 OpenPGP pair belongs to Level 5 only if the SAME envelope also
 // authenticates ML-DSA-87/ML-KEM-1024 hardware keys; names alone are not proof.
 ensure!(der::spki(keys.get(&0x9c).context("ML-DSA slot")?)?.0==der::MLDSA87&&der::spki(keys.get(&0x9d).context("ML-KEM slot")?)?.0==der::MLKEM1024,"Level 5 S/MIME hardware bindings required");
 Ok(())
}

/// Authenticate all public bytes and role bindings. A successful result does
/// not authorize hardware use: the native caller must still match the serial
/// and every component with fresh public reads from its selected physical card.
pub fn verify(stored: &[u8]) -> Result<VerifiedBundle> {
    let bytes = unpack(stored)?;
    let mut r = Reader(&bytes);
    r.magic(b"PQMAILS1")?;
    let payload = r.bounded_blob(MAX_EXTENDED_ENVELOPE)?;
    let signer = r.u32()? as usize;
    let signature = r.blob()?;
    r.end()?;
    let mut r = Reader(payload);
    let version = r.take(8)?;
    ensure!(
        version == b"PQMAILB1" || version == b"PQMAILB2" || version == b"PQMAILB3",
        "Unsupported bundle payload"
    );
    ensure!(version == b"PQMAILB3" || bytes.len() <= MAX, "Oversized base bundle envelope");
    let count = r.u32()? as usize;
    ensure!(
        (2..=16).contains(&count) && signer < count,
        "Invalid profile count or signer"
    );
    let mut profiles = Vec::new();
    let mut keys = BTreeMap::new();
    let mut pure = false;
    let mut hybrid = false;
    for _ in 0..count {
        let p = Profile {
            serial: r.u32()?,
            slots: r.take(4)?.try_into()?,
            sign: r.blob()?.to_vec(),
            enc: r.blob()?.to_vec(),
            pgp: r.blob()?.to_vec(),
            compat: if version != b"PQMAILB1" {
                r.blob()?.to_vec()
            } else {
                Vec::new()
            },
        };
        if x509_bindings(&p, &mut keys)? {
            hybrid = true
        } else {
            pure = true
        };
        profiles.push(p);
    }
    let mut optional_extensions = false;
    if version == b"PQMAILB3" {
        // Unsupported optional extensions stay opaque. They are covered by
        // the envelope signature but never supply active roles or mappings.
        let count = r.u32()?;
        ensure!(count <= 32, "Too many bundle extensions");
        optional_extensions = count > 0;
        let mut types = BTreeSet::new();
        for _ in 0..count {
            let name = r.blob()?;
            ensure!(name.len() <= 192 && name.starts_with(b"https://") &&
                name.len() > 8 && name.iter().all(|byte| byte.is_ascii_graphic()) &&
                types.insert(name), "Invalid or duplicate bundle extension");
            ensure!(r.take(1)? == [0], "Unsupported critical bundle extension or flags");
            r.blob()?;
        }
    }
    r.end()?;
    ensure!(pure && hybrid, "Missing pure or hybrid S/MIME profile");
    let serial = profiles[0].serial;
    ensure!(
        serial > 0 && serial <= i32::MAX as u32 && profiles.iter().all(|p| p.serial == serial),
        "Conflicting bundle serials"
    );
    // Earlier profile checks establish supported algorithms and lengths.
    // This signature authenticates the payload under the included signer;
    // Native must still match that signer to the live card. Neither check
    // grants trust in the certified email addresses.
    verify_envelope(payload, signature, &profiles[signer])?;
    let pgps: Vec<_> = profiles.iter().filter(|p| !p.pgp.is_empty()).collect();
    ensure!(!pgps.is_empty(), "Bundle contains no OpenPGP identity");
    ensure!(
        pgps.iter()
            .all(|p| p.pgp == pgps[0].pgp && p.compat == pgps[0].compat),
        "Ambiguous OpenPGP profiles"
    );
    ensure!(
        profiles
            .iter()
            .all(|p| !p.pgp.is_empty() || p.compat.is_empty()),
        "Orphan compatibility certificate"
    );
    let cert = parse_certificate(&pgps[0].pgp)?;
    let compatibility = if pgps[0].compat.is_empty() {
        None
    } else {
        Some(parse_certificate(&pgps[0].compat)?)
    };
    pgp_bindings(&cert, compatibility.as_ref(), &mut keys)?;
    Ok(VerifiedBundle {
        serial,
        cert,
        compatibility,
        keys,
        bundle_hash: format!("{:x}", Sha256::digest(stored)),
        optional_extensions,
    })
}

/// Strict browser request wrapper. Native callers use `verify` directly and
/// cannot supply source/generation/live-match flags through this JSON surface.
pub fn inspect(input: &str) -> Result<String> {
    ensure!(input.len() <= 450_000, "Bundle request limit");
    let value: Value = serde_json::from_str(input)?;
    let request = value.as_object().context("Object required")?;
    ensure!(
        request.contains_key("bundle") && request.keys().all(|k|k=="bundle"||k=="compatibilityCertificate"),
        "Unexpected fields"
    );
    let encoded = value["bundle"].as_str().context("Bundle required")?;
    ensure!(encoded.len() <= 87_384, "Encoded bundle limit");
    let stored = B64.decode(encoded)?;
    ensure!(
        B64.encode(&stored) == encoded,
        "Canonical bundle encoding required"
    );
    let verified=verify(&stored)?;
    let mut preview=verified.preview()?;
    if let Some(encoded)=value.get("compatibilityCertificate") {
      let encoded=encoded.as_str().context("V5 certificate required")?;
      ensure!(encoded.len()<=349528,"V5 certificate size");
      let bytes=B64.decode(encoded)?;
      ensure!(B64.encode(&bytes)==encoded,"Canonical v5 certificate encoding");
      // Time is obtained by Sequoia's backend clock, which is also available
      // in wasm32. No time or expiry flag can be supplied by the bridge caller.
      let now=current_time()?;
      preview["certificates"].as_array_mut().context("Certificate list")?.push(verified.v5_view(&bytes,now)?);
    }
    Ok(preview.to_string())
}

impl VerifiedBundle {
    /// Serial authenticated by the signed payload, still not a presence proof.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// Every expected component, including certification and compatibility
    /// roles. Native authorization must compare complete SPKI bytes, not only
    /// the two components needed by its next private operation.
    pub fn public_keys(&self) -> &BTreeMap<u8, Vec<u8>> {
        &self.keys
    }

    /// Bind an optional, already self-certified v5 view to all of the
    /// authenticated L3 hardware components. It is a host-only public import,
    /// never a request to generate a signature or change the on-key bundle.
    pub fn v5_view(&self,bytes:&[u8],now:u32)->Result<Value>{
      ensure!(matches!(self.cert.primary_key().key().mpis(),mpi::PublicKey::MLDSA65_Ed25519{..}),"V5 import requires Level 3 hardware bundle");
      let info=v5::inspect(bytes,now)?;
      let allowed=emails(&self.cert)?;
      ensure!(info["emails"].as_array().context("V5 certified emails")?.iter().all(|e|e.as_str().is_some_and(|e|allowed.contains(e))),"V5 mailbox does not match bundle");
      let mut components=info["components"].as_array().context("V5 components")?.clone();
      for (component,slot) in components.iter_mut().zip([0x88,0x9d,0x85]) {
        let expected=self.keys.get(&slot).context("V5 hardware role missing")?;
        ensure!(B64.decode(component["publicKey"].as_str().context("V5 public key")?)?==*expected,"V5 component does not match signed bundle");
        component["slot"]=json!(format!("{slot:02x}"));component["storage"]=json!("piv");
      }
      Ok(json!({"kind":"openpgp","label":"OpenPGP v5 compatibility","certificate":info["certificate"],"profile":"level3-v5-hybrid","components":components}))
    }

    /// Public inventory representation shared by browser and native callers.
    /// This function never asserts live-key matching or file freshness. A
    /// native authority may add such evidence only after fresh physical reads.
    pub fn preview(&self) -> Result<Value> {
        let verified = self;
        let level5=matches!(verified.cert.primary_key().key().mpis(),mpi::PublicKey::ECDSA{curve:Curve::NistP384,..});
        // Every displayed certificate carries only mappings established by
        // verified packet bindings above. Native repeats this derivation from
        // fresh card bytes before accepting a selected profile.
        let component=|role:&str,algorithm:&str,slot:u8|->Result<Value>{
          let public=verified.keys.get(&slot).context("Required mapped public key missing")?;
          Ok(json!({"role":role,"algorithm":algorithm,"storage":"piv","slot":format!("{slot:02x}"),"publicKey":B64.encode(public)}))
        };
        let record=|cert:&Cert,label:&str,profile:&str,components:Vec<Value>|->Result<Value>{
          Ok(json!({"kind":"openpgp","label":label,"certificate":B64.encode(cert.armored().to_vec()?),"profile":profile,"components":components}))
        };
        let mut certificates=vec![if level5{record(&verified.cert,"OpenPGP v6 P-384 (classical)","level5-v6-classical",vec![
          component("signing-classical","ECDSA-P384",0x83)?,component("decryption-classical","ECDH-P384",0x82)?])?
        }else{record(&verified.cert,"OpenPGP v6","level3",vec![
          component("signing-pq","ML-DSA-65",0x9c)?,component("signing-classical","Ed25519",0x84)?,
          component("decryption-pq","ML-KEM-768",0x9d)?,component("decryption-classical","X25519",0x85)?])?}];
        if let Some(compatibility)=&verified.compatibility {
          let signer=component("signing-classical",if level5{"ECDSA-P384"}else{"Ed25519"},0x88)?;
          certificates.push(record(compatibility,"OpenPGP v4 hybrid",if level5{"level5-v4-hybrid-p384"}else{"level3-v4-hybrid"},vec![
            signer.clone(),component("decryption-pq","ML-KEM-768",if level5{0x84}else{0x9d})?,component("decryption-classical","X25519",0x85)?])?);
          // Retaining already certified classical subkeys never re-signs or
          // fabricates a certificate and cannot create a new hardware key.
          let classical=compatibility.clone().retain_subkeys(|key|key.key().pk_algo()==PublicKeyAlgorithm::ECDH);
          certificates.push(record(&classical,"OpenPGP v4 classical",if level5{"level5-v4-classical-p384"}else{"level3-v4-classical"},vec![
            signer,component("decryption-classical",if level5{"ECDH-P384"}else{"X25519"},0x89)?])?);
        }
        let mut slots=Vec::new();
        for(slot,public)in &verified.keys {
          let(alg,_)=der::spki(public)?;
          let algorithm=if alg==der::MLDSA65{"ML-DSA-65"}else if alg==der::MLDSA87{"ML-DSA-87"}
            else if alg==der::MLKEM768{"ML-KEM-768"}else if alg==der::MLKEM1024{"ML-KEM-1024"}
            else if alg==der::P384{"P-384"}else if alg==[0x30,5,6,3,0x2b,0x65,0x70]{"Ed25519"}else{"X25519"};
          slots.push(json!({"role":"Authenticated certificate component","slot":format!("{slot:02x}"),"algorithm":algorithm,"publicKeySha256":format!("{:x}",Sha256::digest(public))}));
        }
        let mut warnings = vec![
            "File freshness is not established; live public keys have not been checked."
                .to_string(),
        ];
        if verified.optional_extensions {
            warnings.push("This bundle contains signed optional material that is not activated by this reader.".into());
        }
        if verified.compatibility.is_none() {
            warnings.push(
                "This bundle has no v4 compatibility certificate; none was created or inferred"
                    .into(),
            );
        }
        if !level5 && !verified.keys.contains_key(&0x86) {
            warnings.push("This bundle uses the original combined certification/signing primary; newer local certificates are not present on the key".into());
        }
        Ok(json!({"format":"sequoia-iwa-identity-preview", "version":1,
        "source":"file", "serial":verified.serial.to_string(),
        "bundleHash":verified.bundle_hash, "generation":0,
        "certificates":certificates,"slots":slots,"bundleSignatureVerified":true,
        "liveKeysMatched":false,"warnings":warnings}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn level5_p384_views_and_all_hardware_roles_are_authenticated(){
      let f:Value=serde_json::from_str(include_str!("../tests/data/level5.json")).unwrap();
      let bytes=B64.decode(f["bundle"].as_str().unwrap()).unwrap();
      let verified=verify(&bytes).unwrap();let p=verified.preview().unwrap();
      assert_eq!(p["serial"],"123456");
      assert_eq!(p["certificates"].as_array().unwrap().iter().map(|v|v["profile"].as_str().unwrap()).collect::<Vec<_>>(),vec!["level5-v6-classical","level5-v4-hybrid-p384","level5-v4-classical-p384"]);
      assert_eq!(p["certificates"][0]["components"][0]["slot"],"83");
      assert_eq!(p["certificates"][1]["components"][0]["slot"],"88");
      assert_eq!(p["certificates"][1]["components"][1]["slot"],"84");
      assert_eq!(p["certificates"][2]["components"][1]["slot"],"89");
      assert_eq!(verified.public_keys().len(),8);
      // Changing compressed contents cannot leave an authenticated preview.
      let mut corrupted=bytes;let n=corrupted.len();corrupted[n/2]^=1;assert!(verify(&corrupted).is_err());
      assert!(verified.v5_view(b"not a certificate",current_time().unwrap()).is_err());
    }

    // PQ Mail/Bouncy Castle-generated public-only vectors also used by the
    // native OpenSSL adapter. No key generation, helper process or card access
    // is involved: both independent crypto backends must accept these bytes.
    fn fixture() -> Value {
        let mut fixture: Value =
            serde_json::from_str(include_str!("../../crypto/tests/data/restore-level3.json"))
                .unwrap();
        let formats: Value =
            serde_json::from_str(include_str!("../../wasm/tests/data/restore-formats.json"))
                .unwrap();
        for name in ["pure", "legacy"] {
            fixture[name] = formats[name].clone();
        }
        fixture
    }
    fn bytes(name: &str) -> Vec<u8> {
        B64.decode(fixture()[name].as_str().unwrap()).unwrap()
    }
    fn inspect_bytes(bytes: &[u8]) -> Result<Value> {
        Ok(serde_json::from_str(&inspect(
            &json!({"bundle":B64.encode(bytes)}).to_string(),
        )?)?)
    }
    fn compress(bytes: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(bytes).unwrap();
        let mut result = b"PQMZIP01".to_vec();
        result.extend((bytes.len() as u32).to_be_bytes());
        result.extend(z.finish().unwrap());
        result
    }
    fn profiles(stored: &[u8]) -> Result<Vec<Profile>> {
        let expanded = unpack(stored)?;
        let mut r = Reader(&expanded);
        r.magic(b"PQMAILS1")?;
        let mut r = Reader(r.blob()?);
        let version = r.take(8)?;
        let count = r.u32()?;
        (0..count)
            .map(|_| {
                Ok(Profile {
                    serial: r.u32()?,
                    slots: r.take(4)?.try_into()?,
                    sign: r.blob()?.to_vec(),
                    enc: r.blob()?.to_vec(),
                    pgp: r.blob()?.to_vec(),
                    compat: if version != b"PQMAILB1" {
                        r.blob()?.to_vec()
                    } else {
                        Vec::new()
                    },
                })
            })
            .collect()
    }

    #[test]
    fn bc_pure_and_composite_signatures_match_native_public_components() -> Result<()> {
        let fixture = fixture();
        for name in ["pure", "hybrid"] {
            let stored = bytes(name);
            let result = inspect_bytes(&stored)?;
            assert_eq!(result["serial"], "123456");
            assert_eq!(result["source"], "file");
            assert_eq!(result["generation"], 0);
            assert_eq!(result["bundleSignatureVerified"], true);
            assert_eq!(result["liveKeysMatched"], false);
            assert_eq!(
                result["bundleHash"],
                format!("{:x}", Sha256::digest(&stored))
            );
            assert_eq!(result["certificates"].as_array().unwrap().len(), 3);
            assert_eq!(result.as_object().unwrap().len(), 11);
            let slots = result["slots"].as_array().unwrap();
            assert_eq!(slots.len(), 10);
            for slot in slots {
                let spki = B64.decode(
                    fixture["keys"][slot["slot"].as_str().unwrap()]
                        .as_str()
                        .unwrap(),
                )?;
                assert_eq!(
                    slot["publicKeySha256"],
                    format!("{:x}", Sha256::digest(spki))
                );
            }
            let certificate =
                B64.decode(result["certificates"][0]["certificate"].as_str().unwrap())?;
            assert_eq!(
                parse_certificate(&certificate)?.fingerprint().to_hex(),
                fixture["fingerprint"].as_str().unwrap().to_uppercase()
            );
        }
        Ok(())
    }

    #[test]
    fn signed_payload_and_each_signature_half_fail_closed() -> Result<()> {
        let decoded = unpack(&bytes("hybrid"))?;
        let payload_len = u32::from_be_bytes(decoded[8..12].try_into()?) as usize;
        let sig_start = 12 + payload_len + 8;
        // Last-byte ECDSA mutation preserves its DER framing, proving that the
        // classical verifier runs even when the ML-DSA half is still valid.
        for index in [24, sig_start, sig_start + 3310, decoded.len() - 1] {
            let mut altered = decoded.clone();
            altered[index] ^= 1;
            assert!(
                inspect_bytes(&compress(&altered)).is_err(),
                "altered offset {index}"
            );
        }
        let pure = unpack(&bytes("pure"))?;
        let mut altered = pure.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(inspect_bytes(&compress(&altered)).is_err());
        Ok(())
    }

    #[test]
    fn compression_and_declared_lengths_are_exact_and_bounded() -> Result<()> {
        let original = bytes("hybrid");
        for change in 0..7 {
            let mut altered = original.clone();
            match change {
                0 => altered.push(0),
                1 => {
                    altered.pop();
                }
                2 => altered[11] ^= 1,
                3 => altered[0] ^= 1,
                4 => altered[8..12].copy_from_slice(&u32::MAX.to_be_bytes()),
                5 => altered[8..12].fill(0),
                _ => altered.extend_from_slice(&original[12..]),
            }
            assert!(
                inspect_bytes(&altered).is_err(),
                "compression mutation {change}"
            );
        }
        assert!(inspect_bytes(&vec![0; MAX + 1]).is_err());
        assert!(inspect_bytes(&[]).is_err());
        assert!(inspect_bytes(&bytes("legacy")).is_err()); // old uncompressed wrapper
        let mut bomb = compress(&vec![0; MAX + 1]);
        bomb[8..12].copy_from_slice(&(MAX as u32).to_be_bytes());
        assert!(inspect_bytes(&bomb).is_err());
        let mut decoded = unpack(&original)?;
        decoded[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(inspect_bytes(&compress(&decoded)).is_err());
        assert!(inspect("{\"bundle\":\"\",\"liveKeysMatched\":true}").is_err());
        Ok(())
    }

    #[test]
    fn supported_legacy_profile_is_explicitly_incomplete() -> Result<()> {
        // A current compressed wrapper may contain the older B1 public
        // profile. Report the actual certificate and roles, never invent v4
        // compatibility or separated certification keys that were not signed.
        let result = inspect_bytes(&compress(&bytes("legacy")))?;
        assert_eq!(result["certificates"].as_array().unwrap().len(), 1);
        assert_eq!(result["slots"].as_array().unwrap().len(), 6);
        assert_eq!(result["warnings"].as_array().unwrap().len(), 3);
        assert_eq!(result["liveKeysMatched"], false);
        Ok(())
    }

    #[test]
    fn profile_slot_algorithms_and_openpgp_component_bindings_are_fixed() -> Result<()> {
        let mut profiles = profiles(&bytes("hybrid"))?;
        let mut keys = BTreeMap::new();
        for profile in &profiles {
            x509_bindings(profile, &mut keys)?;
        }
        let profile = profiles.iter_mut().find(|p| !p.pgp.is_empty()).unwrap();
        let original = profile.slots;
        for index in 0..4 {
            profile.slots[index] ^= 1;
            assert!(x509_bindings(profile, &mut BTreeMap::new()).is_err());
            profile.slots = original;
        }
        let cert = parse_certificate(&profile.pgp)?;
        let compat = parse_certificate(&profile.compat)?;
        pgp_bindings(&cert, Some(&compat), &mut keys)?;
        // A signed X.509 or OpenPGP profile containing a different public
        // component must not win merely because its role name looks correct.
        for slot in keys.keys().copied().collect::<Vec<_>>() {
            if matches!(slot, 0x82 | 0x83) {
                continue;
            } // X.509-only P-384 roles
            let mut mismatched = keys.clone();
            mismatched.get_mut(&slot).unwrap()[20] ^= 1;
            assert!(
                pgp_bindings(&cert, Some(&compat), &mut mismatched).is_err(),
                "slot {slot:02x}"
            );
        }
        let profile = profiles
            .iter_mut()
            .find(|p| {
                let spki = der::certificate_spki(&p.sign).unwrap();
                der::spki(&spki).unwrap().0 == der::MLDSA65
            })
            .unwrap();
        let mut wrong_algorithm = profile.sign.clone();
        // Change the SPKI identifier, not the separate certificate-signature
        // identifier: the bundle authenticates the full certificate as bytes.
        let spki = der::certificate_spki(&profile.sign)?;
        let start = wrong_algorithm
            .windows(spki.len())
            .position(|w| w == spki)
            .unwrap();
        let algorithm = spki
            .windows(der::MLDSA65.len())
            .position(|w| w == der::MLDSA65)
            .unwrap();
        wrong_algorithm[start + algorithm + der::MLDSA65.len() - 1] ^= 1;
        profile.sign = wrong_algorithm;
        assert!(x509_bindings(profile, &mut BTreeMap::new()).is_err());
        Ok(())
    }

    #[test]
    fn extra_certificates_secret_packets_and_nonminimal_der_are_rejected() -> Result<()> {
        let profiles = profiles(&bytes("hybrid"))?;
        let public = &profiles.iter().find(|p| !p.pgp.is_empty()).unwrap().pgp;
        let mut keyring = public.clone();
        keyring.extend(public);
        assert!(parse_certificate(&keyring).is_err());
        let (secret, _) = pgp::cert::CertBuilder::new()
            .add_userid("fixture@example.invalid")
            .generate()?;
        assert!(parse_certificate(&secret.as_tsk().to_vec()?).is_err());
        assert!(der::whole(&[0x30, 0x80, 0, 0], 0x30).is_err());
        assert!(der::whole(&[0x30, 0x81, 0], 0x30).is_err());
        assert!(der::whole(&[0x30, 0x82, 0, 128], 0x30).is_err());
        assert!(der::whole(&[0x30, 0, 0], 0x30).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod profile_review_tests;
