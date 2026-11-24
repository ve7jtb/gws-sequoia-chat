//! Explicit LibrePGP v5 compatibility, separate from RFC 9580/9980.
//!
//! Algorithm 8 is not RFC 9980 algorithm 35. Its certificate fingerprints,
//! signature trailers and KMAC combiner have independent domain separators.
//! This bounded implementation accepts one Ed25519 primary and one
//! ML-KEM-768/X25519 encryption subkey. It never selects hardware or persists
//! seeds; software custody supplies keys only for the current worker call.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sequoia_openpgp as pgp;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::{cell::RefCell, io::Read};
use zeroize::Zeroizing;
const LIMIT: usize = 262144;
const ED_OID: &[u8] = &[9, 0x2b, 6, 1, 4, 1, 0xda, 0x47, 0x0f, 1];
const X_OID: &[u8] = &[3, 0x2b, 0x65, 0x6e];
fn txt<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().context("Missing text")
}
fn exact(v: &Value, keys: &[&str]) -> Result<()> {
    let o = v.as_object().context("Object required")?;
    ensure!(
        o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)),
        "Unexpected fields"
    );
    Ok(())
}
fn dec(v: &Value, k: &str, n: usize) -> Result<Vec<u8>> {
    let s = txt(v, k)?;
    ensure!(s.len() <= (n + 2) / 3 * 4, "Encoded limit");
    let b = B64.decode(s)?;
    ensure!(b.len() <= n && B64.encode(&b) == s, "Encoding/size");
    Ok(b)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02X}")).collect()
}
fn bind(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut v = [0; N];
    pgp::crypto::random(&mut v)?;
    Ok(v)
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace=Date,js_name=now)]
    fn browser_now() -> f64;
}
fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        browser_now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System clock")
            .as_millis() as f64
    }
}
fn time() -> u32 {
    (now_ms() / 1000.0) as u32
}
fn n(v: u64, size: usize) -> Vec<u8> {
    v.to_be_bytes()[8 - size..].to_vec()
}
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }
    fn left(&self) -> usize {
        self.b.len() - self.at
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.left(), "Truncated input");
        let b = &self.b[self.at..self.at + n];
        self.at += n;
        Ok(b)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn number(&mut self, n: usize) -> Result<u64> {
        ensure!(n <= 8, "Number limit");
        Ok(self
            .take(n)?
            .iter()
            .fold(0, |a, b| (a << 8) | u64::from(*b)))
    }
    fn rest(&mut self) -> Result<&'a [u8]> {
        self.take(self.left())
    }
}
#[derive(Clone)]
struct Packet {
    tag: u8,
    body: Vec<u8>,
}
fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    cat(&[&[0xc0 | tag, 255], &n(body.len() as u64, 4), body])
}
fn length(r: &mut Reader) -> Result<(usize, bool)> {
    let first = r.byte()?;
    Ok(match first {
        0..=191 => (first as usize, false),
        192..=223 => (
            ((first as usize - 192) << 8) + r.byte()? as usize + 192,
            false,
        ),
        255 => (r.number(4)? as usize, false),
        _ => (1usize << (first & 31), true),
    })
}
fn unarmor(b: &[u8]) -> Result<Vec<u8>> {
    ensure!(!b.is_empty() && b.len() <= LIMIT, "Input limit");
    if !b.starts_with(b"-----BEGIN PGP ") {
        return Ok(b.to_vec());
    }
    let s = std::str::from_utf8(b)?;
    ensure!(
        s.matches("-----BEGIN PGP ").count() == 1 && !s.contains("PRIVATE KEY"),
        "One public armor block"
    );
    // Armor is framing, not a signature: require exactly one complete block
    // whose closing type agrees with its opening type. In particular, never
    // silently discard a second certificate or attacker-controlled suffix.
    let mut lines = s.lines();
    let opening = lines.next().context("Armor opening")?;
    ensure!(
        [
            "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            "-----BEGIN PGP MESSAGE-----",
            "-----BEGIN PGP SIGNATURE-----"
        ]
        .contains(&opening),
        "Unsupported armor type"
    );
    let closing = opening.replacen("BEGIN", "END", 1);
    let mut data = String::new();
    let mut started = false;
    let mut ended = false;
    let mut checksum = None;
    for line in lines {
        let l = line.trim_end_matches('\r');
        if ended {
            ensure!(l.trim().is_empty(), "Trailing armor data");
            continue;
        }
        if l == closing {
            ensure!(started, "Armor body required");
            ended = true;
            continue;
        }
        if !started {
            if l.is_empty() {
                started = true;
            } else {
                ensure!(
                    l.len() <= 1024
                        && l.is_ascii()
                        && l.contains(':')
                        && !l.chars().any(char::is_control),
                    "Armor header"
                );
            }
            continue;
        }
        if l.starts_with('=') {
            ensure!(checksum.is_none() && l.len() == 5, "Armor checksum format");
            let decoded = B64.decode(&l[1..])?;
            ensure!(decoded.len() == 3, "Armor checksum size");
            checksum = Some(decoded);
            continue;
        }
        ensure!(
            checksum.is_none() && !l.is_empty() && !l.contains(':'),
            "Armor format"
        );
        data.push_str(l)
    }
    ensure!(started && ended, "Truncated armor");
    let raw = B64.decode(data)?;
    ensure!(!raw.is_empty() && raw.len() <= LIMIT, "Armor limit");
    if let Some(expected) = checksum {
        // CRC-24 detects accidental armor corruption only. Cryptographic
        // authentication remains the packet signature or encrypted-data tag.
        let mut crc = 0x00b704ceu32;
        for byte in &raw {
            crc ^= u32::from(*byte) << 16;
            for _ in 0..8 {
                crc <<= 1;
                if crc & 0x01000000 != 0 {
                    crc ^= 0x01864cfb;
                }
            }
        }
        ensure!(
            &crc.to_be_bytes()[1..] == expected,
            "Armor checksum mismatch"
        );
    }
    Ok(raw)
}
fn packets(b: &[u8]) -> Result<Vec<Packet>> {
    let mut r = Reader::new(b);
    let mut out = Vec::new();
    while r.left() > 0 {
        ensure!(out.len() < 64, "Packet count");
        let h = r.byte()?;
        ensure!(h & 128 != 0, "Packet header");
        let tag;
        let mut body = Vec::new();
        if h & 64 == 0 {
            tag = (h >> 2) & 15;
            let k = h & 3;
            ensure!(k != 3, "Unbounded packet");
            let size = r.number(1usize << k)? as usize;
            ensure!(size <= LIMIT, "Packet limit");
            body.extend(r.take(size)?)
        } else {
            tag = h & 63;
            loop {
                let (size, partial) = length(&mut r)?;
                ensure!(
                    size <= LIMIT - body.len() && (!partial || [8, 11, 18, 20].contains(&tag)),
                    "Partial limit"
                );
                body.extend(r.take(size)?);
                if !partial {
                    break;
                }
            }
        }
        if tag == 10 {
            ensure!(body == b"PGP", "Invalid marker");
            continue;
        }
        out.push(Packet { tag, body });
    }
    Ok(out)
}
fn mpi(b: &[u8]) -> Vec<u8> {
    let skip = b.iter().position(|v| *v != 0).unwrap_or(b.len());
    let bytes = &b[skip..];
    let bits = if bytes.is_empty() {
        0
    } else {
        bytes.len() * 8 - bytes[0].leading_zeros() as usize
    };
    cat(&[&n(bits as u64, 2), bytes])
}
fn read_mpi(r: &mut Reader, max: usize) -> Result<Vec<u8>> {
    let bits = r.number(2)? as usize;
    ensure!(bits <= max, "MPI limit");
    let value = r.take((bits + 7) / 8)?.to_vec();
    ensure!(
        mpi(&value) == cat(&[&n(bits as u64, 2), &value]),
        "Noncanonical MPI"
    );
    Ok(value)
}
fn fixed_mpi(r: &mut Reader, n: usize) -> Result<Vec<u8>> {
    // GnuPG serializes Ed25519 signature components as fixed-width opaque
    // strings (SOS). An initial zero byte is retained with a full-width bit
    // count, whereas conventional MPI writers drop leading zero bytes. Both
    // encodings represent the same signed 32-octet component; accept exactly
    // these two forms without relaxing integer MPI parsing for other fields.
    let bits = r.number(2)? as usize;
    ensure!(bits <= n * 8, "Signature component size");
    let b = r.take((bits + 7) / 8)?.to_vec();
    let encoded = cat(&[&self::n(bits as u64, 2), &b]);
    ensure!(
        mpi(&b) == encoded || (b.len() == n && sos(&b) == encoded),
        "Noncanonical signature component"
    );
    let mut out = vec![0; n - b.len()];
    out.extend(b);
    Ok(out)
}
fn key_hash(b: &[u8]) -> Vec<u8> {
    cat(&[&[0x9a], &n(b.len() as u64, 4), b])
}
fn fpr(b: &[u8]) -> Vec<u8> {
    Sha256::digest(key_hash(b)).to_vec()
}
fn sub(tag: u8, b: &[u8]) -> Vec<u8> {
    let len = b.len() + 1;
    let prefix = if len < 192 {
        vec![len as u8]
    } else {
        cat(&[&[255], &n(len as u64, 4)])
    };
    cat(&[&prefix, &[tag], b])
}
#[derive(Default)]
struct Policy {
    flags: u8,
    created: u32,
    expires: Option<u32>,
    key_expires: Option<u32>,
    issuer: Option<Vec<u8>>,
    aes: bool,
}
fn policy(b: &[u8]) -> Result<Policy> {
    let mut r = Reader::new(b);
    let mut p = Policy::default();
    let mut seen = std::collections::BTreeSet::new();
    while r.left() > 0 {
        let (len, partial) = length(&mut r)?;
        ensure!(!partial && len > 0 && len <= r.left(), "Subpacket limit");
        let mut s = Reader::new(r.take(len)?);
        let tag = s.byte()?;
        let body = s.rest()?;
        let kind = tag & 127;
        // A recognized numeric tag is insufficient: only semantics enforced
        // below may be critical. For example, critical notations, embedded
        // signatures and preference features cannot safely be ignored.
        ensure!(
            tag & 128 == 0 || [2, 3, 9, 11, 27, 33].contains(&kind),
            "Unknown critical subpacket"
        );
        if [2, 3, 9, 11, 27, 33].contains(&kind) {
            ensure!(seen.insert(kind), "Ambiguous policy");
        }
        match kind {
            2 => {
                ensure!(body.len() == 4, "Creation size");
                p.created = u32::from_be_bytes(body.try_into()?);
            }
            3 => {
                ensure!(body.len() == 4, "Expiry size");
                p.expires = Some(u32::from_be_bytes(body.try_into()?));
            }
            9 => {
                ensure!(body.len() == 4, "Key expiry size");
                p.key_expires = Some(u32::from_be_bytes(body.try_into()?));
            }
            11 => p.aes = body.contains(&9),
            27 => {
                ensure!(!body.is_empty(), "Flags required");
                p.flags = body[0]
            }
            33 => {
                ensure!(body.len() == 33 && body[0] == 5, "V5 full issuer");
                p.issuer = Some(body[1..].to_vec())
            }
            _ => {}
        }
    }
    Ok(p)
}
struct Sig {
    kind: u8,
    hash: u8,
    header: Vec<u8>,
    policy: Policy,
    prefix: Vec<u8>,
    raw: Vec<u8>,
}
fn signature(b: &[u8]) -> Result<Sig> {
    let mut r = Reader::new(b);
    ensure!(r.byte()? == 5, "V5 signature required");
    let kind = r.byte()?;
    ensure!(r.byte()? == 22, "Ed25519 required");
    let hash = r.byte()?;
    ensure!([8, 9, 10].contains(&hash), "Modern digest required");
    let size = r.number(2)? as usize;
    let hashed = r.take(size)?;
    let pol = policy(hashed)?;
    // The zero timestamp is a legal epoch value, so a missing creation-time
    // subpacket must not be confused with Policy's default integer value.
    let mut fields = Reader::new(hashed);
    let mut created_present = false;
    while fields.left() > 0 {
        let (len, partial) = length(&mut fields)?;
        ensure!(!partial && len > 0, "Signature policy length");
        created_present |= fields.take(len)?[0] & 127 == 2;
    }
    ensure!(created_present, "Hashed creation time required");
    let header = b[..r.at].to_vec();
    let u = r.number(2)? as usize;
    policy(r.take(u)?)?;
    let prefix = r.take(2)?.to_vec();
    let raw = cat(&[&fixed_mpi(&mut r, 32)?, &fixed_mpi(&mut r, 32)?]);
    ensure!(r.left() == 0, "Signature trailing data");
    Ok(Sig {
        kind,
        hash,
        header,
        policy: pol,
        prefix,
        raw,
    })
}
fn digest(s: &Sig, data: &[u8], metadata: Option<&[u8]>) -> Result<Vec<u8>> {
    let trailer = cat(&[&[5, 255], &n(s.header.len() as u64, 8)]);
    let input = cat(&[data, &s.header, metadata.unwrap_or(&[]), &trailer]);
    Ok(match s.hash {
        8 => Sha256::digest(input).to_vec(),
        9 => sha2::Sha384::digest(input).to_vec(),
        10 => Sha512::digest(input).to_vec(),
        _ => bail!("Digest"),
    })
}
fn verify_sig(
    s: &Sig,
    data: &[u8],
    metadata: Option<&[u8]>,
    ed: &[u8],
    fp: &[u8],
    created: u32,
) -> Result<()> {
    ensure!(
        s.policy.issuer.as_deref() == Some(fp)
            && s.policy.created >= created
            && s.policy.created <= time().saturating_add(300),
        "Signature identity/time"
    );
    if let Some(ttl) = s.policy.expires {
        ensure!(
            ttl == 0 || u64::from(s.policy.created) + u64::from(ttl) > u64::from(time()),
            "Expired signature"
        )
    }
    let d = digest(s, data, metadata)?;
    ensure!(d[..2] == s.prefix, "Digest prefix");
    let key = ed25519_dalek::VerifyingKey::from_bytes(ed.try_into()?)?;
    key.verify_strict(&d, &ed25519_dalek::Signature::from_slice(&s.raw)?)?;
    Ok(())
}
type Certificate = sequoia_public_bundle::v5::Certificate;
/// Shared public policy prevents the browser and native authorization path
/// from disagreeing about v5 signatures, expiry, flags or component keys.
fn certificate(b: &[u8]) -> Result<Certificate> {
    sequoia_public_bundle::v5::certificate(b, time())
}
pub(crate) fn is_certificate(b: &[u8]) -> bool {
    unarmor(b)
        .ok()
        .and_then(|v| packets(&v).ok())
        .and_then(|p| p.first().map(|p| p.tag == 6 && p.body.first() == Some(&5)))
        .unwrap_or(false)
}
pub(crate) fn inspect(b: &[u8]) -> Result<Value> {
    let c = certificate(b)?;
    Ok(
        json!({"certificate":B64.encode(&c.raw),"fingerprint":hex(&fpr(&c.primary)),"version":5,"algorithms":["EdDSA (Ed25519)","LibrePGP ML-KEM-768 + X25519"],"emails":c.emails,"hybridContact":true,"encryptionSupported":true,"pqSigning":false,"pqEncryption":true,"certificateHash":format!("{:x}",Sha256::digest(&c.raw)),"supported":true,"signingFingerprint":hex(&fpr(&c.primary)),"recipientKey":hex(&fpr(&c.recipient)),"profile":"level3-v5-hybrid","signingAlgorithm":"Ed25519 (classical)","encryptionAlgorithm":"ML-KEM-768 + X25519 (LibrePGP)"}),
    )
}
pub(crate) fn inspect_identity(b64: &str) -> Result<Value> {
    ensure!(b64.len() <= 349528, "Certificate bound");
    inspect(&B64.decode(b64)?)
}
fn sign_body(
    data: &[u8],
    kind: u8,
    fp: &[u8],
    extra: &[u8],
    secret: &[u8],
    metadata: Option<&[u8]>,
) -> Result<Vec<u8>> {
    use ed25519_dalek::Signer;
    let hashed = cat(&[
        &sub(2, &n(time() as u64, 4)),
        &sub(33, &cat(&[&[5], fp])),
        extra,
    ]);
    let header = cat(&[&[5, kind, 22, 10], &n(hashed.len() as u64, 2), &hashed]);
    let d = Sha512::digest(cat(&[
        data,
        &header,
        metadata.unwrap_or(&[]),
        &[5, 255],
        &n(header.len() as u64, 8),
    ]));
    let key = ed25519_dalek::SigningKey::from_bytes(secret.try_into()?);
    let sig = key.sign(&d).to_bytes();
    let u = sub(16, &fp[..8]);
    Ok(cat(&[
        &header,
        &n(u.len() as u64, 2),
        &u,
        &d[..2],
        &mpi(&sig[..32]),
        &mpi(&sig[32..]),
    ]))
}
pub(crate) fn generate(email: &str) -> Result<(Vec<u8>, Value)> {
    use ml_kem::kem::KeyExport;
    ensure!(
        email.len() <= 254 && !email.chars().any(char::is_control) && email.contains('@'),
        "Mailbox"
    );
    let ed = Zeroizing::new(random::<32>()?);
    let x = Zeroizing::new(random::<32>()?);
    let ml = Zeroizing::new(random::<64>()?);
    let ep = ed25519_dalek::SigningKey::from_bytes(&ed)
        .verifying_key()
        .to_bytes();
    let xp = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*x)).to_bytes();
    let mp = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed((&ml[..]).try_into()?)
        .encapsulation_key()
        .to_bytes();
    let key_body = |alg, mat: &[u8]| {
        cat(&[
            &[5],
            &n(time() as u64, 4),
            &[alg],
            &n(mat.len() as u64, 4),
            mat,
        ])
    };
    let primary = key_body(22, &cat(&[ED_OID, &mpi(&cat(&[&[64], &ep]))]));
    let recipient = key_body(
        8,
        &cat(&[X_OID, &mpi(&cat(&[&[64], &xp])), &n(1184, 4), &mp]),
    );
    let fp = fpr(&primary);
    let prefs = cat(&[
        &sub(27, &[3]),
        &sub(11, &[9]),
        &sub(21, &[10, 9, 8]),
        &sub(22, &[0]),
        &sub(30, &[1]),
    ]);
    let uid = email.as_bytes();
    let uid_sig = sign_body(
        &cat(&[&key_hash(&primary), &[0xb4], &n(uid.len() as u64, 4), uid]),
        19,
        &fp,
        &prefs,
        &ed[..],
        None,
    )?;
    let binding = sign_body(
        &cat(&[&key_hash(&primary), &key_hash(&recipient)]),
        24,
        &fp,
        &sub(27, &[12]),
        &ed[..],
        None,
    )?;
    let public = cat(&[
        &frame(6, &primary),
        &frame(13, uid),
        &frame(2, &uid_sig),
        &frame(14, &recipient),
        &frame(2, &binding),
    ]);
    let secret = json!({"ed25519":B64.encode(&ed[..]),"mlkem768":B64.encode(&ml[..]),"x25519":B64.encode(&x[..])});
    validate_secret(&public, &secret)?;
    Ok((public, secret))
}
pub(crate) fn validate_secret(public: &[u8], secret: &Value) -> Result<()> {
    use ml_kem::kem::KeyExport;
    exact(secret, &["ed25519", "mlkem768", "x25519"])?;
    let c = certificate(public)?;
    let ed = Zeroizing::new(dec(secret, "ed25519", 32)?);
    let ml = Zeroizing::new(dec(secret, "mlkem768", 64)?);
    let x = Zeroizing::new(dec(secret, "x25519", 32)?);
    ensure!(
        ed.len() == 32 && ml.len() == 64 && x.len() == 32,
        "Seed sizes"
    );
    let ep = ed25519_dalek::SigningKey::from_bytes(ed.as_slice().try_into()?)
        .verifying_key()
        .to_bytes();
    let xp = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
        <[u8; 32]>::try_from(x.as_slice())?,
    ))
    .to_bytes();
    let mp = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(ml.as_slice().try_into()?)
        .encapsulation_key()
        .to_bytes();
    ensure!(
        c.ed == ep && c.x == xp && c.ml.as_slice() == mp.as_slice(),
        "Private/public key mismatch"
    );
    Ok(())
}
pub(crate) fn sign(public: &[u8], secret: &Value, r: &Value) -> Result<Value> {
    use ed25519_dalek::Signer;
    validate_secret(public, secret)?;
    exact(
        r,
        &[
            "requestId",
            "signingFingerprint",
            "hashAlgorithm",
            "digest",
            "inlineDigest",
        ],
    )?;
    let c = certificate(public)?;
    ensure!(
        bind(txt(r, "requestId")?)
            && txt(r, "signingFingerprint")? == hex(&fpr(&c.primary))
            && r["hashAlgorithm"] == 10,
        "Signing binding"
    );
    let d = dec(r, "digest", 64)?;
    ensure!(d.len() == 64, "Digest size");
    let seed = Zeroizing::new(dec(secret, "ed25519", 32)?);
    let sig = ed25519_dalek::SigningKey::from_bytes(seed.as_slice().try_into()?)
        .sign(&d)
        .to_bytes();
    let mut v = r.clone();
    v["ed25519"] = json!(B64.encode(sig));
    v["mldsa65"] = json!("");
    let inline = dec(r, "inlineDigest", 64)?;
    ensure!(inline.len() == 64, "Inline digest size");
    v["inlineEd25519"] = json!(B64.encode(
        ed25519_dalek::SigningKey::from_bytes(seed.as_slice().try_into()?)
            .sign(&inline)
            .to_bytes()
    ));
    Ok(v)
}
pub(crate) fn decapsulate(public: &[u8], secret: &Value, r: &Value) -> Result<Value> {
    use ml_kem::kem::Decapsulate;
    validate_secret(public, secret)?;
    exact(
        r,
        &[
            "requestId",
            "cipherHash",
            "recipientKey",
            "mlkemCiphertext",
            "x25519Ephemeral",
        ],
    )?;
    let c = certificate(public)?;
    ensure!(
        bind(txt(r, "requestId")?)
            && txt(r, "recipientKey")? == hex(&fpr(&c.recipient))
            && txt(r, "cipherHash")?.len() == 64,
        "Decryption binding"
    );
    let ct = dec(r, "mlkemCiphertext", 1088)?;
    let ep = dec(r, "x25519Ephemeral", 32)?;
    ensure!(ct.len() == 1088 && ep.len() == 32, "Component sizes");
    let seed = Zeroizing::new(dec(secret, "mlkem768", 64)?);
    let m = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed.as_slice().try_into()?);
    let ct = <&[u8; 1088]>::try_from(ct.as_slice())?;
    let share = Zeroizing::new(m.decapsulate(ct.into()).to_vec());
    let xseed = Zeroizing::new(dec(secret, "x25519", 32)?);
    let x = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(xseed.as_slice())?);
    let ep = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ep.as_slice())?);
    let ec = x.diffie_hellman(&ep);
    ensure!(ec.was_contributory(), "Noncontributory X25519");
    let mut v = r.clone();
    v["mlkemSecret"] = json!(B64.encode(&*share));
    v["x25519Secret"] = json!(B64.encode(ec.as_bytes()));
    Ok(v)
}

/// A document signature has different hash input from a certification. V5 also
/// authenticates literal packet metadata. Detached signatures use six zero
/// octets; inline signatures use the exact literal format/name/time. We never
/// try alternate transcripts after a failure.
pub(crate) fn verify_detached(v: &Value) -> Result<Value> {
    let payload = dec(v, "payload", LIMIT)?;
    let sig = unarmor(&dec(v, "signature", 65536)?)?;
    let p = packets(&sig)?;
    ensure!(p.len() == 1 && p[0].tag == 2, "One detached signature");
    let s = signature(&p[0].body)?;
    ensure!(s.kind == 0, "Binary document signature required");
    let metadata = if v.get("literalMetadata").is_some() {
        let m = dec(v, "literalMetadata", 261)?;
        ensure!(
            m.len() >= 6 && m.len() == 6 + m[1] as usize,
            "Literal metadata bound"
        );
        m
    } else {
        vec![0; 6]
    };
    let certificates = v["certificates"]
        .as_array()
        .context("Certificates required")?;
    ensure!(certificates.len() <= 32, "Certificate count");
    let mut candidate = None;
    for encoded in certificates {
        let Some(raw) = encoded.as_str() else {
            continue;
        };
        if raw.len() > 349528 {
            continue;
        }
        let Ok(bytes) = B64.decode(raw) else { continue };
        let Ok(c) = certificate(&bytes) else { continue };
        if s.policy.issuer.as_deref() == Some(fpr(&c.primary).as_slice()) {
            candidate = Some(c);
            break;
        }
    }
    let result = if let Some(c) = candidate {
        if verify_sig(
            &s,
            &payload,
            Some(&metadata),
            &c.ed,
            &fpr(&c.primary),
            c.created,
        )
        .is_ok()
        {
            json!({"status":"valid","fingerprint":hex(&fpr(&c.primary)),"signingFingerprint":hex(&fpr(&c.primary)),"algorithm":"Ed25519 (LibrePGP v5, classical)","pqSigning":false,"certificate":B64.encode(c.raw),"emails":c.emails})
        } else {
            json!({"status":"invalid","fingerprint":hex(&fpr(&c.primary)),"signingFingerprint":hex(&fpr(&c.primary)),"algorithm":"Ed25519 (LibrePGP v5, classical)","candidateOnly":true})
        }
    } else {
        json!({"status":"unknown-key"})
    };
    Ok(json!({"signatures":[result]}))
}
fn signed_payload(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut data = bytes.to_vec();
    for depth in 0..=3 {
        let p = packets(&data)?;
        if p.len() == 1 && p[0].tag == 8 {
            ensure!(depth < 3 && !p[0].body.is_empty(), "Compression bound");
            let mut out = Vec::new();
            match p[0].body[0] {
                0 => out.extend_from_slice(&p[0].body[1..]),
                1 => {
                    flate2::read::DeflateDecoder::new(&p[0].body[1..])
                        .take((LIMIT + 1) as u64)
                        .read_to_end(&mut out)?;
                }
                2 => {
                    flate2::read::ZlibDecoder::new(&p[0].body[1..])
                        .take((LIMIT + 1) as u64)
                        .read_to_end(&mut out)?;
                }
                _ => bail!("Compression"),
            };
            ensure!(out.len() <= LIMIT, "Expansion limit");
            data = out;
            continue;
        }
        ensure!(
            p.len() == 3 && p.iter().map(|v| v.tag).collect::<Vec<_>>() == vec![4, 11, 2],
            "One signed literal required"
        );
        let s = signature(&p[2].body)?;
        ensure!(s.kind == 0, "Document kind");
        let issuer = s.policy.issuer.as_ref().context("Issuer required")?;
        ensure!(
            p[0].body == cat(&[&[3, s.kind, s.hash, 22], &issuer[..8], &[1]]),
            "One-pass binding"
        );
        let mut r = Reader::new(&p[1].body);
        ensure!([98, 116, 117].contains(&r.byte()?), "Literal format");
        let name = r.byte()? as usize;
        r.take(name + 4)?;
        let metadata = p[1].body[..r.at].to_vec();
        return Ok((r.rest()?.to_vec(), frame(2, &p[2].body), metadata));
    }
    bail!("Compression nesting")
}
struct PendingSign {
    started: f64,
    request: Value,
    cert: Vec<u8>,
    payload: Vec<u8>,
    header: Vec<u8>,
    inline_meta: Vec<u8>,
}
struct PendingDecap {
    started: f64,
    request: Value,
    cert: Vec<u8>,
    cipher: Vec<u8>,
}
thread_local! {static SIGN:RefCell<Option<PendingSign>>=const{RefCell::new(None)};static DECAP:RefCell<Option<PendingDecap>>=const{RefCell::new(None)};}
pub(crate) fn has_signing() -> bool {
    SIGN.with(|s| s.borrow().is_some())
}
pub(crate) fn has_decryption() -> bool {
    DECAP.with(|s| s.borrow().is_some())
}
pub(crate) fn cancel_signing() {
    SIGN.with(|s| {
        s.borrow_mut().take();
    });
}
pub(crate) fn cancel_decryption() {
    DECAP.with(|s| {
        s.borrow_mut().take();
    });
}
pub(crate) fn prepare_signing(v: &Value) -> Result<Value> {
    ensure!(!has_signing(), "Signature pending");
    let raw = dec(v, "senderCertificate", 65536)?;
    let c = certificate(&raw)?;
    ensure!(
        bind(txt(v, "requestId")?)
            && c.emails
                .iter()
                .any(|s| s == txt(v, "senderEmail").unwrap_or("")),
        "Sender binding"
    );
    let payload = dec(v, "payload", LIMIT - 8192)?;
    ensure!(!payload.is_empty(), "Empty payload");
    let fp = fpr(&c.primary);
    let hashed = cat(&[&sub(2, &n(time() as u64, 4)), &sub(33, &cat(&[&[5], &fp]))]);
    let header = cat(&[&[5, 0, 22, 10], &n(hashed.len() as u64, 2), &hashed]);
    let trailer = cat(&[&[5, 255], &n(header.len() as u64, 8)]);
    let inline_meta = vec![98, 0, 0, 0, 0, 0];
    let d = Sha512::digest(cat(&[&payload, &header, &[0; 6], &trailer]));
    let inline = Sha512::digest(cat(&[&payload, &header, &inline_meta, &trailer]));
    let request = json!({"requestId":v["requestId"],"signingFingerprint":hex(&fp),"hashAlgorithm":10,"digest":B64.encode(d),"inlineDigest":B64.encode(inline)});
    SIGN.with(|s| {
        *s.borrow_mut() = Some(PendingSign {
            started: now_ms(),
            request: request.clone(),
            cert: c.raw,
            payload,
            header,
            inline_meta,
        })
    });
    Ok(request)
}
pub(crate) fn finalize_signing(v: &Value) -> Result<Value> {
    let p = SIGN
        .with(|s| s.borrow_mut().take())
        .context("No pending v5 signature")?;
    ensure!(
        now_ms() >= p.started && now_ms() - p.started <= 360000.0,
        "Signature expired"
    );
    exact(
        v,
        &[
            "requestId",
            "signingFingerprint",
            "hashAlgorithm",
            "digest",
            "inlineDigest",
            "ed25519",
            "mldsa65",
            "inlineEd25519",
        ],
    )?;
    for k in [
        "requestId",
        "signingFingerprint",
        "hashAlgorithm",
        "digest",
        "inlineDigest",
    ] {
        ensure!(v[k] == p.request[k], "Signature response binding")
    }
    ensure!(v["mldsa65"] == "", "Classical signature shape");
    let c = certificate(&p.cert)?;
    let make = |signature_name, digest_name| -> Result<Vec<u8>> {
        let raw = dec(v, signature_name, 64)?;
        let d = dec(v, digest_name, 64)?;
        ensure!(raw.len() == 64 && d.len() == 64, "Signature size");
        let key = ed25519_dalek::VerifyingKey::from_bytes(c.ed.as_slice().try_into()?)?;
        key.verify_strict(&d, &ed25519_dalek::Signature::from_slice(&raw)?)?;
        Ok(frame(
            2,
            &cat(&[
                &p.header,
                &[0, 0],
                &d[..2],
                &mpi(&raw[..32]),
                &mpi(&raw[32..]),
            ]),
        ))
    };
    let detached = make("ed25519", "digest")?;
    let inline = make("inlineEd25519", "inlineDigest")?;
    let fp = fpr(&c.primary);
    let signed = cat(&[
        &frame(4, &cat(&[&[3, 0, 10, 22], &fp[..8], &[1]])),
        &frame(11, &cat(&[&p.inline_meta, &p.payload])),
        &inline,
    ]);
    let (recovered, sig, metadata) = signed_payload(&signed)?;
    ensure!(recovered == p.payload, "Final signed payload");
    let verify = verify_detached(
        &json!({"payload":B64.encode(&p.payload),"signature":B64.encode(sig),"literalMetadata":B64.encode(metadata),"certificates":[B64.encode(&c.raw)]}),
    )?;
    ensure!(
        verify["signatures"][0]["status"] == "valid",
        "Final signature check"
    );
    Ok(
        json!({"requestId":p.request["requestId"],"signed":B64.encode(signed),"signature":B64.encode(detached),"payload":B64.encode(p.payload),"senderCertificate":B64.encode(c.raw)}),
    )
}

/// SP800-185 encodings for KMAC256. The fixed LibrePGP key and customization
/// are interoperability constants, not passwords. Their spelling/order must
/// not be substituted with RFC 9980's SHA3 multi-key combiner.
fn left_encode(v: u64) -> Vec<u8> {
    let b = n(v, 8);
    let first = b.iter().position(|x| *x != 0).unwrap_or(7);
    cat(&[&[(8 - first) as u8], &b[first..]])
}
fn right_encode(v: u64) -> Vec<u8> {
    let b = left_encode(v);
    cat(&[&b[1..], &b[..1]])
}
fn encode_string(b: &[u8]) -> Vec<u8> {
    cat(&[&left_encode((b.len() * 8) as u64), b])
}
fn combine(
    ec: &[u8],
    point: &[u8],
    recipient: &[u8],
    pq: &[u8],
    ct: &[u8],
    fp: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    ensure!(
        ec.len() == 32
            && ec.iter().any(|b| *b != 0)
            && point.len() == 32
            && recipient.len() == 32
            && pq.len() == 32
            && ct.len() == 1088
            && fp.len() == 32,
        "Combiner bounds"
    );
    let h = sha3::Sha3_256::digest(cat(&[ec, point, recipient]));
    let input = Zeroizing::new(cat(&[&n(1, 4), &h, point, pq, ct, &[9], fp]));
    let mut mac =
        sha3::CShake256::from_core(sha3::CShake256Core::new_with_function_name(b"KMAC", b"KDF"));
    let mut keyed = cat(&[
        &left_encode(136),
        &encode_string(b"OpenPGPCompositeKeyDerivationFunction"),
    ]);
    keyed.resize((keyed.len() + 135) / 136 * 136, 0);
    Update::update(&mut mac, &keyed);
    Update::update(&mut mac, &input);
    Update::update(&mut mac, &right_encode(256));
    let mut out = Zeroizing::new(vec![0; 32]);
    XofReader::read(&mut mac.finalize_xof(), &mut out);
    Ok(out)
}
/// OpenPGP SEIPDv1 uses CFB without the obsolete resynchronization step. The
/// MDC authenticates the random prefix, payload and D3 14 marker before any
/// plaintext is released to MIME or signature verification.
fn cfb(data: &[u8], key: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let aes = aes::Aes256::new_from_slice(key).map_err(|_| anyhow::anyhow!("AES key size"))?;
    let mut feedback = [0u8; 16];
    let mut out = Vec::with_capacity(data.len());
    for block in data.chunks(16) {
        let mut mask = feedback.into();
        aes.encrypt_block(&mut mask);
        let transformed: Vec<u8> = block.iter().zip(mask.iter()).map(|(x, y)| x ^ y).collect();
        if block.len() == 16 {
            feedback.copy_from_slice(if encrypt { &transformed } else { block });
        }
        out.extend(transformed);
    }
    Ok(out)
}
fn seal_payload(signed: &[u8], session: &[u8]) -> Result<Vec<u8>> {
    let prefix = random::<16>()?;
    let mut clear = Zeroizing::new(cat(&[&prefix, &prefix[14..], signed, &[0xd3, 0x14]]));
    let mdc = sha1::Sha1::digest(&*clear);
    clear.extend_from_slice(&mdc);
    Ok(frame(18, &cat(&[&[1], &cfb(&clear, session, true)?])))
}
fn open_payload(packet: &Packet, session: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if packet.tag == 18 {
        ensure!(
            packet.body.first() == Some(&1) && packet.body.len() > 41,
            "SEIPD version/length"
        );
        let mut clear = Zeroizing::new(cfb(&packet.body[1..], session, false)?);
        let len = clear.len();
        ensure!(
            clear[14..16] == clear[16..18] && clear[len - 22..len - 20] == [0xd3, 0x14],
            "SEIPD prefix/MDC marker"
        );
        let expected = sha1::Sha1::digest(&clear[..len - 20]);
        let mismatch = expected
            .iter()
            .zip(&clear[len - 20..])
            .fold(0u8, |x, (a, b)| x | (a ^ b));
        ensure!(mismatch == 0, "SEIPD authentication failed");
        let out = Zeroizing::new(clear[18..len - 22].to_vec());
        clear.fill(0);
        return Ok(out);
    }
    // LibrePGP/GnuPG also emits tag-20 OCB. Chunk and final tags independently
    // authenticate order, chunk number and total plaintext length.
    ensure!(
        packet.tag == 20
            && packet.body.len() >= 35
            && packet.body[..3] == [1, 9, 2]
            && packet.body[3] <= 16,
        "Bounded AES256 OCB packet"
    );
    use aead::{AeadInPlace, KeyInit};
    type Ocb = ocb3::Ocb3<aes::Aes256, aead::consts::U15>;
    let cipher = Ocb::new_from_slice(session).map_err(|_| anyhow::anyhow!("OCB key"))?;
    let exponent = packet.body[3];
    let chunk = 1usize << (exponent + 6);
    let iv = &packet.body[4..19];
    let data = &packet.body[19..];
    ensure!(data.len() >= 16, "OCB final tag");
    let mut at = 0;
    let mut index = 0u64;
    let mut out = Zeroizing::new(Vec::new());
    while data.len() - at > 16 {
        // A non-final record needs its own tag plus the stream's final tag.
        // Check before subtracting: malformed 17..31-byte tails previously
        // underflowed usize instead of returning an authentication error.
        let remaining = data.len() - at;
        ensure!(remaining >= 32, "OCB chunk length");
        let count = (remaining - 32).min(chunk);
        let mut block = Zeroizing::new(data[at..at + count].to_vec());
        let mut nonce = iv.to_vec();
        for (i, b) in index.to_be_bytes().iter().enumerate() {
            nonce[7 + i] ^= *b
        }
        let aad = cat(&[&[0xd4, 1, 9, 2, exponent], &n(index, 8)]);
        cipher
            .decrypt_in_place_detached(
                nonce.as_slice().into(),
                &aad,
                &mut block,
                data[at + count..at + count + 16].into(),
            )
            .map_err(|_| anyhow::anyhow!("OCB chunk authentication"))?;
        ensure!(out.len() + block.len() <= LIMIT, "OCB output bound");
        out.extend_from_slice(&block);
        block.fill(0);
        at += count + 16;
        index += 1;
    }
    let mut nonce = iv.to_vec();
    for (i, b) in index.to_be_bytes().iter().enumerate() {
        nonce[7 + i] ^= *b
    }
    let aad = cat(&[
        &[0xd4, 1, 9, 2, exponent],
        &n(index, 8),
        &n(out.len() as u64, 8),
    ]);
    ensure!(data.len() - at == 16, "OCB final tag length");
    cipher
        .decrypt_in_place_detached(nonce.as_slice().into(), &aad, &mut [], data[at..].into())
        .map_err(|_| anyhow::anyhow!("OCB final authentication"))?;
    Ok(out)
}
fn sos(point: &[u8]) -> Vec<u8> {
    let bits = point.len() * 8
        - point
            .first()
            .filter(|b| **b != 0)
            .map(|b| b.leading_zeros() as usize)
            .unwrap_or(0);
    cat(&[&n(bits as u64, 2), point])
}
struct Envelope {
    point: Vec<u8>,
    ct: Vec<u8>,
    wrapped: Vec<u8>,
    payload: Packet,
}
fn envelope(cipher: &[u8], cert: &Certificate) -> Result<Envelope> {
    let p = packets(&unarmor(cipher)?)?;
    ensure!(
        p.len() == 2 && p[0].tag == 1 && [18, 20].contains(&p[1].tag),
        "One hybrid envelope"
    );
    let mut r = Reader::new(&p[0].body);
    ensure!(
        r.byte()? == 3 && r.take(8)? == &fpr(&cert.recipient)[..8] && r.byte()? == 8,
        "V5 recipient mismatch"
    );
    let bits = r.number(2)?;
    let point = r.take(32)?.to_vec();
    ensure!(
        sos(&point)[..2] == n(bits, 2) && point.iter().any(|b| *b != 0),
        "X25519 SOS"
    );
    ensure!(r.number(4)? == 1088, "MLKEM ciphertext length");
    let ct = r.take(1088)?.to_vec();
    ensure!(
        r.byte()? == 9 && r.byte()? == 40 && r.left() == 40,
        "AES256 wrapped key"
    );
    Ok(Envelope {
        point,
        ct,
        wrapped: r.take(40)?.to_vec(),
        payload: p[1].clone(),
    })
}
pub(crate) fn encrypt_signed(v: &Value) -> Result<Value> {
    let peer = certificate(&dec(v, "recipientCertificate", 65536)?)?;
    ensure!(
        txt(v, "recipientFingerprint")? == hex(&fpr(&peer.primary))
            && peer
                .emails
                .iter()
                .any(|e| e == txt(v, "recipientEmail").unwrap_or("")),
        "Recipient identity"
    );
    let signed = dec(v, "signed", LIMIT)?;
    let (payload, sig, meta) = signed_payload(&signed)?;
    ensure!(payload == dec(v, "payload", LIMIT)?, "Signed payload");
    let checked = verify_detached(
        &json!({"payload":B64.encode(&payload),"signature":B64.encode(sig),"literalMetadata":B64.encode(meta),"certificates":[v["senderCertificate"].clone()]}),
    )?;
    ensure!(
        checked["signatures"][0]["status"] == "valid",
        "Valid v5 signature required"
    );
    let seed = Zeroizing::new(random::<32>()?);
    let x = x25519_dalek::StaticSecret::from(*seed);
    let point = x25519_dalek::PublicKey::from(&x).to_bytes();
    let ec = x.diffie_hellman(&x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(
        peer.x.as_slice(),
    )?));
    ensure!(ec.was_contributory(), "Noncontributory recipient");
    let m = Zeroizing::new(random::<32>()?);
    let public = <&[u8; 1184]>::try_from(peer.ml.as_slice())?;
    let ml = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new(public.into())
        .map_err(|_| anyhow::anyhow!("KEM public key"))?;
    let (ct, pq) = ml.encapsulate_deterministic((&m[..]).try_into()?);
    let kek = combine(
        ec.as_bytes(),
        &point,
        &peer.x,
        &pq,
        &ct,
        &fpr(&peer.recipient),
    )?;
    let session = Zeroizing::new(random::<32>()?);
    let protected: pgp::crypto::mem::Protected = kek.as_slice().into();
    let wrapped = pgp::crypto::ecdh::aes_key_wrap(
        pgp::types::SymmetricAlgorithm::AES256,
        &protected,
        &pgp::crypto::mem::Protected::from(&session[..]),
    )?;
    let pkesk = frame(
        1,
        &cat(&[
            &[3],
            &fpr(&peer.recipient)[..8],
            &[8],
            &sos(&point),
            &n(ct.len() as u64, 4),
            &ct,
            &[9, wrapped.len() as u8],
            &wrapped,
        ]),
    );
    let cipher = cat(&[&pkesk, &seal_payload(&signed, &session[..])?]);
    ensure!(cipher.len() <= LIMIT, "Ciphertext bound");
    Ok(json!({"cipher":B64.encode(cipher)}))
}
pub(crate) fn prepare_decryption(v: &Value) -> Result<Value> {
    ensure!(!has_decryption(), "Decryption pending");
    exact(
        v,
        &[
            "requestId",
            "cipher",
            "recipientCertificate",
            "recipientKey",
            "purpose",
        ],
    )?;
    ensure!(
        bind(txt(v, "requestId")?) && v["purpose"] == "message",
        "V5 message only"
    );
    let raw = dec(v, "recipientCertificate", 65536)?;
    let c = certificate(&raw)?;
    ensure!(
        txt(v, "recipientKey")? == hex(&fpr(&c.recipient)),
        "Selected recipient"
    );
    let cipher = dec(v, "cipher", LIMIT)?;
    let e = envelope(&cipher, &c)?;
    let request = json!({"requestId":v["requestId"],"cipherHash":format!("{:x}",Sha256::digest(&cipher)),"recipientKey":v["recipientKey"],"mlkemCiphertext":B64.encode(e.ct),"x25519Ephemeral":B64.encode(e.point)});
    DECAP.with(|s| {
        *s.borrow_mut() = Some(PendingDecap {
            started: now_ms(),
            request: request.clone(),
            cert: c.raw,
            cipher,
        })
    });
    Ok(request)
}
pub(crate) fn finalize_decryption(v: &Value) -> Result<Value> {
    let p = DECAP
        .with(|s| s.borrow_mut().take())
        .context("No pending v5 decryption")?;
    ensure!(
        now_ms() >= p.started && now_ms() - p.started <= 360000.0,
        "Decryption expired"
    );
    exact(
        v,
        &[
            "requestId",
            "cipherHash",
            "recipientKey",
            "mlkemCiphertext",
            "x25519Ephemeral",
            "mlkemSecret",
            "x25519Secret",
        ],
    )?;
    for k in [
        "requestId",
        "cipherHash",
        "recipientKey",
        "mlkemCiphertext",
        "x25519Ephemeral",
    ] {
        ensure!(v[k] == p.request[k], "Component response binding")
    }
    let c = certificate(&p.cert)?;
    let e = envelope(&p.cipher, &c)?;
    let ml = Zeroizing::new(dec(v, "mlkemSecret", 32)?);
    let ec = Zeroizing::new(dec(v, "x25519Secret", 32)?);
    let kek = combine(&ec, &e.point, &c.x, &ml, &e.ct, &fpr(&c.recipient))?;
    let protected: pgp::crypto::mem::Protected = kek.as_slice().into();
    let session = pgp::crypto::ecdh::aes_key_unwrap(
        pgp::types::SymmetricAlgorithm::AES256,
        &protected,
        &e.wrapped,
    )?;
    ensure!(session.len() == 32, "AES256 session");
    let plain = open_payload(&e.payload, &session)?;
    let (raw, sig, metadata) = signed_payload(&plain)?;
    Ok(
        json!({"raw":B64.encode(raw),"signature":B64.encode(sig),"literalMetadata":B64.encode(metadata),"encrypted":true,"requestId":p.request["requestId"],"cipherHash":p.request["cipherHash"],"recipientKey":p.request["recipientKey"]}),
    )
}
pub(crate) fn match_recipients(v: &Value) -> Result<Value> {
    exact(v, &["cipher", "candidates"])?;
    let cipher = dec(v, "cipher", LIMIT)?;
    let candidates = v["candidates"].as_array().context("Candidates")?;
    ensure!(candidates.len() <= 16, "Candidate bound");
    let mut matches = Vec::new();
    let mut recipient = Value::Null;
    let mut ids = std::collections::BTreeSet::new();
    for item in candidates {
        exact(item, &["id", "certificate"])?;
        let id = txt(item, "id")?;
        ensure!(
            !id.is_empty()
                && id.len() <= 256
                && !id.chars().any(char::is_control)
                && ids.insert(id),
            "Candidate id"
        );
        let raw = dec(item, "certificate", 65536)?;
        if !is_certificate(&raw) {
            continue;
        }
        let c = certificate(&raw)?;
        if envelope(&cipher, &c).is_err() {
            continue;
        }
        let info = inspect(&raw)?;
        recipient = info["recipientKey"].clone();
        matches.push(json!({"id":id,"fingerprint":info["fingerprint"],"certificateHash":info["certificateHash"],"signingFingerprint":info["signingFingerprint"],"recipientKey":info["recipientKey"],"emails":info["emails"]}));
    }
    Ok(
        json!({"cipherHash":format!("{:x}",Sha256::digest(&cipher)),"recipientKey":recipient,"matches":matches}),
    )
}

/// Public signed-packet validation used before choosing a recipient transport.
/// The full current self-certified mailbox policy is checked by certificate().
pub(crate) fn verify_signed(signed: &[u8], cert: &[u8], payload: &[u8]) -> Result<()> {
    let (clear, sig, metadata) = signed_payload(signed)?;
    ensure!(clear == payload, "Signed data mismatch");
    let result = verify_detached(
        &json!({"payload":B64.encode(payload),"signature":B64.encode(sig),"literalMetadata":B64.encode(metadata),"certificates":[B64.encode(cert)]}),
    )?;
    ensure!(
        result["signatures"][0]["status"] == "valid",
        "V5 signature invalid"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn armor_requires_one_matching_complete_block() {
        let raw = b"public packet fixture";
        let armored = format!("-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: synthetic\n\n{}\n-----END PGP PUBLIC KEY BLOCK-----\n", B64.encode(raw));
        assert_eq!(unarmor(armored.as_bytes()).unwrap(), raw);
        assert!(unarmor(
            armored
                .replace("END PGP PUBLIC KEY BLOCK", "END PGP MESSAGE")
                .as_bytes()
        )
        .is_err());
        assert!(unarmor(format!("{armored}unrelated data").as_bytes()).is_err());
        assert!(unarmor(format!("{armored}{armored}").as_bytes()).is_err());
        assert!(unarmor(armored.replace("-----END", "=AAAA\n-----END").as_bytes()).is_err());
    }

    #[test]
    fn ed25519_opaque_components_preserve_leading_zeroes() {
        // A leading zero is normal random Ed25519 signature output, not an
        // invalid integer. Both GnuPG SOS and conventional MPI writers must
        // round-trip the exact same fixed-width component.
        for leading in 0..=32 {
            let mut component = [0x53; 32];
            component[..leading].fill(0);
            for encoded in [mpi(&component), sos(&component)] {
                let mut reader = Reader::new(&encoded);
                assert_eq!(fixed_mpi(&mut reader, 32).unwrap(), component);
                assert_eq!(reader.left(), 0);
            }
        }
        let invalid = cat(&[&[0, 255], &[0; 32]]);
        assert!(fixed_mpi(&mut Reader::new(&invalid), 32).is_err());
        assert!(fixed_mpi(&mut Reader::new(&[1, 1, 0]), 32).is_err());
    }

    #[test]
    fn critical_subpacket_semantics_and_creation_time_are_enforced() {
        assert!(policy(&sub(0x80 | 20, b"ignored notation")).is_err());
        assert!(policy(&sub(0x80 | 32, b"ignored embedded signature")).is_err());
        assert!(policy(&sub(20, b"noncritical extension")).is_ok());
        assert!(policy(&cat(&[&sub(11, &[9]), &sub(11, &[9])])).is_err());
        // Parsing itself rejects a missing hashed creation time, even for an
        // epoch-zero public key, before considering signature mathematics.
        let hashed = sub(33, &cat(&[&[5], &[0; 32]]));
        let body = cat(&[
            &[5, 0, 22, 10],
            &n(hashed.len() as u64, 2),
            &hashed,
            &[0, 0, 0, 0],
            &mpi(&[1; 32]),
            &mpi(&[2; 32]),
        ]);
        assert!(signature(&body).is_err());
    }

    /// Re-sign mutations with the fixture's legitimate key so rejection proves
    /// policy validation, rather than merely detecting stale signature bytes.
    fn policy_fixture(flags: u8, future_subkey: bool, expired_direct: bool) -> Vec<u8> {
        let (cert, secret) = fixture();
        let mut p = packets(&cert).unwrap();
        let created = time().saturating_sub(120);
        p[0].body[1..5].copy_from_slice(&created.to_be_bytes());
        p[3].body[1..5]
            .copy_from_slice(&(if future_subkey { time() + 120 } else { created }).to_be_bytes());
        let fp = fpr(&p[0].body);
        let seed = dec(&secret, "ed25519", 32).unwrap();
        p[2].body = sign_body(
            &cat(&[
                &key_hash(&p[0].body),
                &[0xb4],
                &n(p[1].body.len() as u64, 4),
                &p[1].body,
            ]),
            19,
            &fp,
            &cat(&[&sub(27, &[3]), &sub(11, &[9])]),
            &seed,
            None,
        )
        .unwrap();
        p[4].body = sign_body(
            &cat(&[&key_hash(&p[0].body), &key_hash(&p[3].body)]),
            24,
            &fp,
            &sub(27, &[flags]),
            &seed,
            None,
        )
        .unwrap();
        let mut out = Vec::new();
        for (i, packet) in p.into_iter().enumerate() {
            out.extend(frame(packet.tag, &packet.body));
            if i == 0 && expired_direct {
                let direct = sign_body(
                    &key_hash(&packet.body),
                    0x1f,
                    &fp,
                    &sub(9, &1u32.to_be_bytes()),
                    &seed,
                    None,
                )
                .unwrap();
                out.extend(frame(2, &direct));
            }
        }
        out
    }

    #[test]
    fn certificate_checks_direct_expiry_binding_time_and_transport_flag() {
        assert!(certificate(&policy_fixture(12, false, false)).is_ok());
        assert!(certificate(&policy_fixture(8, false, false)).is_err());
        assert!(certificate(&policy_fixture(12, true, false)).is_err());
        assert!(certificate(&policy_fixture(12, false, true)).is_err());
    }

    #[test]
    fn ocb_records_authenticate_and_truncated_tails_fail_without_panicking() {
        use aead::{AeadInPlace, KeyInit};
        type Ocb = ocb3::Ocb3<aes::Aes256, aead::consts::U15>;
        let key = [0x41; 32];
        let iv = [0x51; 15];
        let cipher = Ocb::new_from_slice(&key).unwrap();
        for size in [0, 1, 63, 64, 65, 137, 70000] {
            let plain = vec![0x61; size];
            let mut body = cat(&[&[1, 9, 2, 0], &iv]);
            let mut index = 0u64;
            for part in plain.chunks(64) {
                let mut block = part.to_vec();
                let mut nonce = iv;
                for (i, b) in index.to_be_bytes().iter().enumerate() {
                    nonce[7 + i] ^= *b;
                }
                let aad = cat(&[&[0xd4, 1, 9, 2, 0], &n(index, 8)]);
                let tag = cipher
                    .encrypt_in_place_detached((&nonce).into(), &aad, &mut block)
                    .unwrap();
                body.extend(block);
                body.extend_from_slice(&tag);
                index += 1;
            }
            let mut nonce = iv;
            for (i, b) in index.to_be_bytes().iter().enumerate() {
                nonce[7 + i] ^= *b;
            }
            let aad = cat(&[&[0xd4, 1, 9, 2, 0], &n(index, 8), &n(size as u64, 8)]);
            let tag = cipher
                .encrypt_in_place_detached((&nonce).into(), &aad, &mut [])
                .unwrap();
            body.extend_from_slice(&tag);
            let packet = Packet { tag: 20, body };
            assert_eq!(&*open_payload(&packet, &key).unwrap(), &plain);
            let mut bad = packet.clone();
            let last = bad.body.len() - 1;
            bad.body[last] ^= 1;
            assert!(open_payload(&bad, &key).is_err());
        }
        for tail in 17..32 {
            let packet = Packet {
                tag: 20,
                body: cat(&[&[1, 9, 2, 0], &iv, &vec![0; tail]]),
            };
            assert!(open_payload(&packet, &key).is_err());
        }
    }

    /// The fixture directory contains only disposable software keys. Import
    /// independent GnuPG messages rather than inferring interoperability from
    /// the self-roundtrip above; exercise MDC and OCB returns when provided.
    #[test]
    fn optional_gnupg_v5_return_verifies_and_decrypts() -> Result<()> {
        let Ok(directory) = std::env::var("IWA_V5_IMPORT_FIXTURE_DIR") else {
            return Ok(());
        };
        let root = std::path::Path::new(&directory);
        let cert = std::fs::read(root.join("public.pgp"))?;
        let secret: Value =
            serde_json::from_slice(&std::fs::read(root.join("seeds-test-only.json"))?)?;
        let expected = std::fs::read(root.join("payload.bin"))?;
        let info = inspect(&cert)?;
        for name in ["gpg-return.pgp", "gpg-return-ocb.pgp"] {
            let path = root.join(name);
            if name.contains("ocb") && !path.exists() {
                continue;
            }
            let cipher = std::fs::read(path)?;
            cancel_decryption();
            let request = prepare_decryption(
                &json!({"requestId":"B".repeat(64),"cipher":B64.encode(cipher),"recipientCertificate":B64.encode(&cert),"recipientKey":info["recipientKey"],"purpose":"message"}),
            )?;
            let response = decapsulate(&cert, &secret, &request)?;
            let opened =
                finalize_decryption(&response).with_context(|| format!("Opening {name}"))?;
            ensure!(
                dec(&opened, "raw", LIMIT)? == expected,
                "GnuPG plaintext differs"
            );
            let verified = verify_detached(
                &json!({"payload":opened["raw"],"signature":opened["signature"],"literalMetadata":opened["literalMetadata"],"certificates":[B64.encode(&cert)]}),
            )?;
            ensure!(
                verified["signatures"][0]["status"] == "valid",
                "GnuPG signature invalid"
            );
        }
        Ok(())
    }
    /// Exercise real fresh seeds. Neither this module nor its tests have a card,
    /// native bridge, account-token or credential-store dependency.
    fn fixture() -> (Vec<u8>, Value) {
        generate("fixture@example.invalid").unwrap()
    }
    fn signed(cert: &[u8], secret: &Value, payload: &[u8]) -> Value {
        cancel_signing();
        let request=prepare_signing(&json!({"senderCertificate":B64.encode(cert),"senderEmail":"fixture@example.invalid","payload":B64.encode(payload),"requestId":"A".repeat(64)})).unwrap();
        let response = sign(cert, secret, &request).unwrap();
        finalize_signing(&response).unwrap()
    }
    #[test]
    fn genuine_v5_generation_and_private_binding() {
        let (cert, secret) = fixture();
        let info = inspect(&cert).unwrap();
        assert_eq!(info["version"], 5);
        assert_eq!(info["pqSigning"], false);
        assert_eq!(info["pqEncryption"], true);
        let mut bad = secret.clone();
        bad["ed25519"] = json!(B64.encode([0; 32]));
        assert!(validate_secret(&cert, &bad).is_err());
        let mut tampered = cert.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 1;
        assert!(inspect(&tampered).is_err());
    }
    #[test]
    fn detached_and_inline_signatures_use_distinct_metadata() {
        let (cert, secret) = fixture();
        let value = signed(&cert, &secret, b"Synthetic v5\r\n");
        let request = json!({"payload":value["payload"],"signature":value["signature"],"certificates":[B64.encode(&cert)]});
        assert_eq!(
            verify_detached(&request).unwrap()["signatures"][0]["status"],
            "valid"
        );
        let mut wrong = request.clone();
        wrong["literalMetadata"] = json!(B64.encode([98, 0, 0, 0, 0, 0]));
        assert_eq!(
            verify_detached(&wrong).unwrap()["signatures"][0]["status"],
            "invalid"
        );
        verify_signed(
            &B64.decode(value["signed"].as_str().unwrap()).unwrap(),
            &cert,
            b"Synthetic v5\r\n",
        )
        .unwrap();
        assert!(finalize_signing(&json!({})).is_err());
    }
    #[test]
    fn hybrid_message_roundtrip_and_authentication() {
        let (cert, secret) = fixture();
        let info = inspect(&cert).unwrap();
        let value = signed(&cert, &secret, b"Hybrid protected v5\r\n");
        let sealed=encrypt_signed(&json!({"recipientCertificate":B64.encode(&cert),"recipientFingerprint":info["fingerprint"],"recipientEmail":"fixture@example.invalid","senderCertificate":B64.encode(&cert),"signed":value["signed"],"payload":value["payload"]})).unwrap();
        let input = json!({"requestId":"B".repeat(64),"cipher":sealed["cipher"],"recipientCertificate":B64.encode(&cert),"recipientKey":info["recipientKey"],"purpose":"message"});
        cancel_decryption();
        let request = prepare_decryption(&input).unwrap();
        let reply = decapsulate(&cert, &secret, &request).unwrap();
        let plain = finalize_decryption(&reply).unwrap();
        assert_eq!(plain["raw"], value["payload"]);
        assert_eq!(verify_detached(&json!({"payload":plain["raw"],"signature":plain["signature"],"literalMetadata":plain["literalMetadata"],"certificates":[B64.encode(&cert)]})).unwrap()["signatures"][0]["status"],"valid");
        let mut bad = reply.clone();
        bad["mlkemSecret"] = json!(B64.encode([0; 32]));
        prepare_decryption(&input).unwrap();
        assert!(finalize_decryption(&bad).is_err());
        assert!(!has_decryption());
        let mut cipher = B64.decode(sealed["cipher"].as_str().unwrap()).unwrap();
        let n = cipher.len();
        cipher[n - 1] ^= 1;
        let mut corrupted = input.clone();
        corrupted["cipher"] = json!(B64.encode(cipher));
        let request = prepare_decryption(&corrupted).unwrap();
        let reply = decapsulate(&cert, &secret, &request).unwrap();
        assert!(finalize_decryption(&reply).is_err());
    }
    #[test]
    fn packet_lengths_and_public_only_fail_closed() {
        assert!(packets(&[0xcb, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        let (cert, _) = fixture();
        let mut secret = cert.clone();
        secret[0] = 0xc5;
        assert!(inspect(&secret).is_err());
        let mut doubled = cert.clone();
        doubled.extend(&cert);
        assert!(inspect(&doubled).is_err());
    }
    /// This opt-in software-only fixture export is never installed. Its plaintext
    /// test-only secret packet enables independent GnuPG to decrypt the identical
    /// random recipient key, rather than mistaking a self-roundtrip for interop.
    #[test]
    fn export_disposable_v5_fixture() -> Result<()> {
        let Ok(directory) = std::env::var("IWA_V5_FIXTURE_DIR") else {
            return Ok(());
        };
        let root = std::path::Path::new(&directory);
        ensure!(!root.exists(), "Fresh fixture directory required");
        std::fs::create_dir(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        }
        let (cert, secret) = fixture();
        let c = certificate(&cert)?;
        let mut tsk = Vec::new();
        for p in packets(&cert)? {
            if p.tag == 6 || p.tag == 14 {
                let material = if p.tag == 6 {
                    sos(&dec(&secret, "ed25519", 32)?)
                } else {
                    let mut x = dec(&secret, "x25519", 32)?;
                    x[0] &= 248;
                    x[31] &= 127;
                    x[31] |= 64;
                    x.reverse();
                    let seed = dec(&secret, "mlkem768", 64)?;
                    cat(&[&mpi(&x), &n(seed.len() as u64, 4), &seed])
                };
                let sum = material.iter().fold(0u16, |s, b| s.wrapping_add(*b as u16));
                tsk.extend(frame(
                    if p.tag == 6 { 5 } else { 7 },
                    &cat(&[
                        &p.body,
                        &[0, 0],
                        &n(material.len() as u64, 4),
                        &material,
                        &n(sum as u64, 2),
                    ]),
                ));
            } else {
                tsk.extend(frame(p.tag, &p.body));
            }
        }
        let payload = b"Synthetic IWA LibrePGP interoperability\r\n";
        let message = signed(&cert, &secret, payload);
        let encrypted = encrypt_signed(
            &json!({"recipientCertificate":B64.encode(&cert),"recipientFingerprint":hex(&fpr(&c.primary)),"recipientEmail":"fixture@example.invalid","senderCertificate":B64.encode(&cert),"signed":message["signed"],"payload":message["payload"]}),
        )?;
        for (name, data) in [
            ("public.pgp", cert),
            ("secret-test-only.pgp", tsk),
            ("payload.bin", payload.to_vec()),
            ("signature.pgp", B64.decode(txt(&message, "signature")?)?),
            ("signed.pgp", B64.decode(txt(&message, "signed")?)?),
            ("encrypted.pgp", B64.decode(txt(&encrypted, "cipher")?)?),
            ("seeds-test-only.json", serde_json::to_vec(&secret)?),
        ] {
            std::fs::write(root.join(name), data)?;
        }
        Ok(())
    }
}

/// Discriminators choose a parser only. They do not authenticate a message or
/// allow a malformed v5 packet to fall back to another protocol version.
pub(crate) fn is_signature(b: &[u8]) -> bool {
    unarmor(b)
        .ok()
        .and_then(|v| packets(&v).ok())
        .and_then(|p| p.first().map(|p| p.tag == 2 && p.body.first() == Some(&5)))
        .unwrap_or(false)
}
pub(crate) fn is_message(b: &[u8]) -> bool {
    unarmor(b)
        .ok()
        .and_then(|v| packets(&v).ok())
        .and_then(|p| {
            p.first()
                .map(|p| p.tag == 1 && p.body.first() == Some(&3) && p.body.get(9) == Some(&8))
        })
        .unwrap_or(false)
}
