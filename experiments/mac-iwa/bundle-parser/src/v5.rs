//! Bounded, public-only LibrePGP v5 certificate validation shared by the
//! browser and native hardware authorization. No private-key, device or file
//! API is available here. The caller supplies the current time explicitly so
//! the exact policy is usable in wasm32 without a host clock dependency.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sequoia_openpgp as pgp;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
const LIMIT: usize = 262144;
const ED_OID: &[u8] = &[9, 0x2b, 6, 1, 4, 1, 0xda, 0x47, 0x0f, 1];
const X_OID: &[u8] = &[3, 0x2b, 0x65, 0x6e];
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
    now: u32,
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
            && s.policy.created <= now.saturating_add(300),
        "Signature identity/time"
    );
    if let Some(ttl) = s.policy.expires {
        ensure!(
            ttl == 0 || u64::from(s.policy.created) + u64::from(ttl) > u64::from(now),
            "Expired signature"
        )
    }
    let d = digest(s, data, metadata)?;
    ensure!(d[..2] == s.prefix, "Digest prefix");
    let key = ed25519_dalek::VerifyingKey::from_bytes(ed.try_into()?)?;
    key.verify_strict(&d, &ed25519_dalek::Signature::from_slice(&s.raw)?)?;
    Ok(())
}
pub struct Certificate {
    pub raw: Vec<u8>,
    pub primary: Vec<u8>,
    pub recipient: Vec<u8>,
    pub ed: Vec<u8>,
    pub x: Vec<u8>,
    pub ml: Vec<u8>,
    pub emails: Vec<String>,
    pub created: u32,
}
fn key(b: &[u8], algorithm: u8, now: u32) -> Result<(u32, Vec<u8>)> {
    let mut r = Reader::new(b);
    ensure!(r.byte()? == 5, "V5 key required");
    let created = r.number(4)? as u32;
    ensure!(
        created <= now.saturating_add(300) && r.byte()? == algorithm,
        "Key time/algorithm"
    );
    let size = r.number(4)? as usize;
    ensure!(size == r.left(), "Key material length");
    Ok((created, r.rest()?.to_vec()))
}
pub fn certificate(b: &[u8], now: u32) -> Result<Certificate> {
    let raw = unarmor(b)?;
    let p = packets(&raw)?;
    ensure!(p.len() >= 5 && p[0].tag == 6, "Primary required");
    let primary = p[0].body.clone();
    let (created, material) = key(&primary, 22, now)?;
    let mut r = Reader::new(&material);
    ensure!(r.take(ED_OID.len())? == ED_OID, "Ed OID");
    let mut ed = read_mpi(&mut r, 263)?;
    if ed.len() == 33 {
        ensure!(ed[0] == 64, "Ed prefix");
        ed.remove(0);
    }
    ensure!(ed.len() == 32 && r.left() == 0, "Ed key size");
    let fp = fpr(&primary);
    let mut emails = Vec::new();
    let mut recipient = None;
    let mut x = Vec::new();
    let mut ml = Vec::new();
    let mut i = 1;
    while i < p.len() {
        match p[i].tag {
            2 => {
                let s = signature(&p[i].body)?;
                ensure!(s.kind == 0x1f, "Unsupported or revoked direct signature");
                verify_sig(now, &s, &key_hash(&primary), None, &ed, &fp, created)?;
                // The narrow compatibility profile accepts no conflicting
                // expiry override: every supplied direct/UID statement must
                // still authorize the current primary key.
                if let Some(ttl) = s.policy.key_expires {
                    ensure!(
                        ttl == 0 || u64::from(created) + u64::from(ttl) > u64::from(now),
                        "Expired primary"
                    );
                }
                i += 1;
            }
            13 => {
                ensure!(i + 1 < p.len() && p[i + 1].tag == 2, "UID binding required");
                let uid = &p[i].body;
                ensure!(uid.len() <= 1024, "UID size");
                let s = signature(&p[i + 1].body)?;
                ensure!(
                    (0x10..=0x13).contains(&s.kind) && s.policy.flags & 3 == 3 && s.policy.aes,
                    "Signing/AES policy required"
                );
                verify_sig(
                    now, &s,
                    &cat(&[&key_hash(&primary), &[0xb4], &n(uid.len() as u64, 4), uid]),
                    None,
                    &ed,
                    &fp,
                    created,
                )?;
                if let Some(ttl) = s.policy.key_expires {
                    ensure!(
                        ttl == 0 || u64::from(created) + u64::from(ttl) > u64::from(now),
                        "Expired primary"
                    )
                }
                let id = pgp::packet::UserID::from(uid.clone());
                if let Some(email) = id.email_normalized()? {
                    emails.push(email);
                }
                i += 2;
            }
            14 => {
                ensure!(
                    recipient.is_none() && i + 1 < p.len() && p[i + 1].tag == 2,
                    "One bound encryption key"
                );
                let (body_created, material) = key(&p[i].body, 8, now)?;
                let mut r = Reader::new(&material);
                ensure!(r.take(X_OID.len())? == X_OID, "X OID");
                let ec = read_mpi(&mut r, 263)?;
                ensure!(
                    ec.len() == 33 && ec[0] == 64 && r.number(4)? == 1184,
                    "KEM key size"
                );
                x = ec[1..].to_vec();
                ml = r.take(1184)?.to_vec();
                ensure!(r.left() == 0, "KEM trailing data");
                let s = signature(&p[i + 1].body)?;
                ensure!(
                    s.kind == 24 && s.policy.flags & 4 != 0,
                    "Encryption binding flags"
                );
                verify_sig(
                    now, &s,
                    &cat(&[&key_hash(&primary), &key_hash(&p[i].body)]),
                    None,
                    &ed,
                    &fp,
                    created.max(body_created),
                )?;
                if let Some(ttl) = s.policy.key_expires {
                    ensure!(
                        ttl == 0 || u64::from(body_created) + u64::from(ttl) > u64::from(now),
                        "Expired encryption key"
                    )
                };
                recipient = Some(p[i].body.clone());
                i += 2;
            }
            _ => bail!("Unsupported/secret/revoked certificate packet"),
        }
    }
    emails.sort();
    emails.dedup();
    ensure!(
        !emails.is_empty() && emails.len() <= 5,
        "Certified mailbox required"
    );
    Ok(Certificate {
        raw,
        primary,
        recipient: recipient.context("Encryption key required")?,
        ed,
        x,
        ml,
        emails,
        created,
    })
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

/// Inspect a fully self-certified v5 view. Components deliberately have no
/// slots: native must match them to roles in its freshly read signed bundle,
/// never accept a caller-provided slot or derive authority from this JSON.
pub fn inspect(b: &[u8], now: u32) -> Result<Value> {
 let c=certificate(b,now)?;
 let spki=|op,raw:&[u8]| -> Result<String> {Ok(B64.encode(super::public_spki(op,raw)?))};
 Ok(json!({"certificate":B64.encode(&c.raw),"certificateHash":format!("{:x}",Sha256::digest(&c.raw)),
 "fingerprint":hex(&fpr(&c.primary)),"version":5,"profile":"level3-v5-hybrid",
 "emails":c.emails,"signingFingerprint":hex(&fpr(&c.primary)),"recipientKey":hex(&fpr(&c.recipient)),
 "components":[
 {"role":"signing-classical","algorithm":"Ed25519","publicKey":spki(super::Operation::Ed25519,&c.ed)?},
 {"role":"decryption-pq","algorithm":"ML-KEM-768","publicKey":spki(super::Operation::MlKem768,&c.ml)?},
 {"role":"decryption-classical","algorithm":"X25519","publicKey":spki(super::Operation::X25519,&c.x)?}]}))
}
fn hex(b:&[u8])->String {b.iter().map(|v|format!("{v:02X}")).collect()}
