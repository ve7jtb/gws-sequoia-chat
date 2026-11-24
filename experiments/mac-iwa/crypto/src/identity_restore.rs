//! Public-only identity discovery. The signed bundle decoder and live-key
//! binding checks are shared with the Sequoia PIV adapter; this module only
//! translates its authenticated result into bounded browser inventory data.
//! Neither entry point has a PIN, private-operation backend or card-write API.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sequoia_pqmail_piv::restore::{self, Card, ObjectReader};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

const MAX: usize = 65_536;
const PRIMARY_BANK: u32 = 0x5f5000;
const SECONDARY_BANK: u32 = 0x5f5100;

/// An imported file substitutes only object bytes. Serial and every public key
/// are still read from the configured physical card, so the file cannot claim
/// live-key proof merely by containing a matching serial number or manifest.
struct FileCard<'a, C: Card> { live: &'a mut C, objects: BTreeMap<u32, Vec<u8>> }
impl<C: Card> Card for FileCard<'_, C> {
    fn serial(&mut self) -> Result<u32> { self.live.serial() }
    fn public_key(&mut self, slot: u8) -> Result<Option<Vec<u8>>> { self.live.public_key(slot) }
    fn object(&mut self, tag: u32) -> Result<Option<Vec<u8>>> { Ok(self.objects.get(&tag).cloned()) }
}

/// Record the exact public objects consulted by the shared decoder. A final
/// reread closes the window in which an external application could replace a
/// bank while we assemble it. No recovery write or automatic retry is allowed.
struct StableCard<'a, C: Card> { live: &'a mut C, observed: BTreeMap<u32, Option<Vec<u8>>> }
impl<C: Card> Card for StableCard<'_, C> {
    fn serial(&mut self) -> Result<u32> { self.live.serial() }
    fn public_key(&mut self, slot: u8) -> Result<Option<Vec<u8>>> { self.live.public_key(slot) }
    fn object(&mut self, tag: u32) -> Result<Option<Vec<u8>>> {
        let value = self.live.object(tag)?;
        if let Some(previous) = self.observed.insert(tag, value.clone()) {
            ensure!(previous == value, "Public bundle changed while reading");
        }
        Ok(value)
    }
}
impl<C: Card> StableCard<'_, C> {
    fn check(&mut self) -> Result<()> {
        for (tag, expected) in &self.observed {
            ensure!(self.live.object(*tag)? == *expected, "Public bundle changed while reading");
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Wrap an immutable, bounded file in the same chunk framing consumed by the
/// existing decoder. Generation zero is reserved for file imports in our UI:
/// the synthetic generation one here has no freshness/anti-rollback meaning.
fn file_objects(bytes: &[u8]) -> Result<BTreeMap<u32, Vec<u8>>> {
    ensure!(!bytes.is_empty() && bytes.len() <= MAX, "Certificate bundle size limit");
    ensure!(bytes.starts_with(b"PQMZIP01"), "A current compressed public bundle is required");
    let generation = 1u64;
    let mut index = b"PQMIDX01".to_vec();
    index.extend(generation.to_be_bytes());
    index.extend((bytes.len() as u32).to_be_bytes());
    index.extend(Sha256::digest(bytes));
    let mut result = BTreeMap::from([(PRIMARY_BANK, index)]);
    for (i, chunk) in bytes.chunks(2048).enumerate() {
        let mut encoded = b"PQMCHK01".to_vec();
        encoded.extend(generation.to_be_bytes());
        encoded.extend((i as u32).to_be_bytes());
        encoded.extend(chunk);
        result.insert(PRIMARY_BANK + 1 + i as u32, encoded);
    }
    Ok(result)
}

/// Serialize only public certificates and fixed, verified role mappings. The
/// temporary directory contains no keys or credentials and is automatically
/// removed. Using Restored::save avoids copying its private parsing internals
/// or manufacturing unverified accessors in the shared adapter crate.
fn snapshot(restored: restore::Restored, source: &str) -> Result<Value> {
    let review = restored.review();
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("verified-public");
    restored.save(&directory)?;
    let stored = fs::read(directory.join("certificate-bundle.pqmzip"))?;
    let mut certificates = Vec::new();
    for (name, label) in [("openpgp-v6.asc", "OpenPGP v6"),
                          ("openpgp-v4-hybrid.asc", "OpenPGP v4 hybrid"),
                          ("openpgp-v4-classical.asc", "OpenPGP v4 classical")] {
        let path = directory.join(name);
        if path.exists() {
            let raw = fs::read(path)?;
            ensure!(raw.len() <= 131_072, "Certificate size limit");
            certificates.push(json!({"kind":"openpgp","label":label,"certificate":B64.encode(raw)}));
        }
    }
    let hashes = review["publicKeySha256"].as_object().context("Missing verified key map")?;
    let mut slots = Vec::new();
    // These names describe the exact profile accepted by the shared decoder.
    // Imported input cannot choose a backend, arbitrary slot or path.
    for (slot, role, algorithm) in [
        ("9c", "OpenPGP signing", "ML-DSA-65"), ("84", "OpenPGP signing", "Ed25519"),
        ("9d", "OpenPGP decryption", "ML-KEM-768"), ("85", "OpenPGP decryption", "X25519"),
        ("86", "OpenPGP certification", "ML-DSA-65"), ("87", "OpenPGP certification", "Ed25519"),
        ("88", "Classical signing", "Ed25519"), ("89", "Classical decryption", "X25519"),
        ("83", "S/MIME signing", "ECDSA P-384"), ("82", "S/MIME decryption", "ECDH P-384"),
    ] {
        if let Some(digest) = hashes.get(slot) {
            slots.push(json!({"role":role,"slot":slot,"algorithm":algorithm,"publicKeySha256":digest}));
        }
    }
    let mut warnings: Vec<String> = serde_json::from_value(review["warnings"].clone())?;
    if source == "file" {
        // The synthetic file transport intentionally has no second bank. This
        // says nothing about any other object on the actual card.
        warnings.retain(|w| w != &format!("Bank {SECONDARY_BANK:06x} is absent or incomplete"));
        warnings.push("File freshness is not established; live public keys match the configured YubiKey.".into());
    }
    Ok(json!({"format":"sequoia-iwa-identity-preview","version":1,"source":source,
        "serial":restored.serial().to_string(),"bundleHash":hex(&Sha256::digest(stored)),
        "generation":if source=="file" {0} else {review["generation"].as_u64().context("Missing generation")?},
        "certificates":certificates,"slots":slots,"bundleSignatureVerified":true,
        "liveKeysMatched":true,"warnings":warnings}))
}

/// The Python host supplies the fixed object-helper executable and a validated
/// numeric serial, either from its enrollment or a selected-identity request.
/// Serial selection is not authority: restore verifies the signed bundle and
/// every live component. The helper sees only public serial/key/get requests
/// and is reaped by ObjectReader; no caller can supply paths or arbitrary slots.
pub fn preview(request: &Value) -> Result<Value> {
    let serial = request["serial"].as_str().context("Serial required")?.parse::<u32>()?;
    let helper = Path::new(request["objectHelper"].as_str().context("Object helper required")?);
    let file = request.get("bundle").map(|v| -> Result<Vec<u8>> {
        let text = v.as_str().context("Encoded bundle required")?;
        ensure!(text.len() <= 87_384, "Encoded bundle size limit");
        let raw = B64.decode(text)?;
        ensure!(B64.encode(&raw) == text, "Noncanonical bundle encoding");
        // Validate framing before opening a physical connection.
        file_objects(&raw)?;
        Ok(raw)
    }).transpose()?;
    let mut live = ObjectReader::connect(helper, serial)?;
    if let Some(bytes) = file {
        let mut card = FileCard { live: &mut live, objects: file_objects(&bytes)? };
        return snapshot(restore::restore(&mut card, serial)?, "file");
    }
    let mut card = StableCard { live: &mut live, observed: BTreeMap::new() };
    let mut restored = restore::restore(&mut card, serial)?;
    card.check()?;
    ensure!(card.serial()? == serial, "Device changed during public restore");
    // Suppress only a positively absent historical bank. An existing malformed
    // or incomplete manifest must keep its recovery warning in the review.
    if card.observed.get(&SECONDARY_BANK) == Some(&None) {
        restored.warnings.retain(|w| w != &format!("Bank {SECONDARY_BANK:06x} is absent or incomplete"));
    }
    snapshot(restored, "yubikey")
}

#[cfg(test)]
mod tests {
    use super::*;
    /// File object framing is tested without a card. Oversized/old envelopes
    /// are rejected before any public read, PIN request or private operation.
    #[test]
    fn file_framing_is_bounded_and_exact() -> Result<()> {
        let mut bytes = b"PQMZIP01".to_vec(); bytes.extend(vec![7; 4096]);
        let objects = file_objects(&bytes)?;
        assert_eq!(objects.len(), 4);
        let index = &objects[&PRIMARY_BANK];
        assert_eq!(index.len(), 52);
        assert_eq!(&index[20..], Sha256::digest(&bytes).as_slice());
        let joined: Vec<u8> = objects.iter().filter(|(tag, _)| **tag > PRIMARY_BANK)
            .flat_map(|(_, chunk)| chunk[20..].to_vec()).collect();
        assert_eq!(joined, bytes);
        assert!(file_objects(b"PQMAILS1").is_err());
        assert!(file_objects(&vec![0; MAX + 1]).is_err());
        Ok(())
    }
    /// Public-only cross-implementation fixture from the shared adapter. The
    /// synthetic card has no private-operation method; every component must
    /// match before the browser can be told that the bundle is authenticated.
    struct FixtureCard { keys: BTreeMap<u8, Vec<u8>> }
    impl Card for FixtureCard {
        fn serial(&mut self) -> Result<u32> { Ok(123456) }
        fn public_key(&mut self, slot: u8) -> Result<Option<Vec<u8>>> { Ok(self.keys.get(&slot).cloned()) }
        fn object(&mut self, _: u32) -> Result<Option<Vec<u8>>> { unreachable!("FileCard supplies public bytes") }
    }
    fn fixture() -> Result<(FixtureCard, Vec<u8>)> {
        let data: Value = serde_json::from_str(include_str!("../tests/data/restore-level3.json"))?;
        let keys = data["keys"].as_object().unwrap().iter().map(|(slot, value)|
            Ok((u8::from_str_radix(slot,16)?,B64.decode(value.as_str().unwrap())?)))
            .collect::<Result<BTreeMap<_,_>>>()?;
        Ok((FixtureCard { keys }, B64.decode(data["hybrid"].as_str().unwrap())?))
    }
    #[test]
    fn file_restore_checks_signature_and_every_live_component() -> Result<()> {
        let (mut live, bytes) = fixture()?;
        let mut card = FileCard { live: &mut live, objects: file_objects(&bytes)? };
        let result = snapshot(restore::restore(&mut card,123456)?, "file")?;
        assert_eq!(result["source"],"file"); assert_eq!(result["generation"],0);
        assert_eq!(result["certificates"].as_array().unwrap().len(),3);
        assert_eq!(result["slots"].as_array().unwrap().len(),10);
        assert_eq!(result["bundleSignatureVerified"],true);
        assert_eq!(result["liveKeysMatched"],true);
        assert_eq!(result["bundleHash"],hex(&Sha256::digest(&bytes)));
        for slot in live.keys.keys().copied().collect::<Vec<_>>() {
            let (mut bad, _) = fixture()?;
            bad.keys.get_mut(&slot).unwrap()[20] ^= 1;
            let mut card = FileCard { live:&mut bad, objects:file_objects(&bytes)? };
            assert!(restore::restore(&mut card,123456).is_err(),"slot {slot:02x}");
        }
        let mut altered = bytes; let last = altered.len()-1; altered[last] ^= 1;
        let mut card = FileCard { live:&mut live, objects:file_objects(&altered)? };
        assert!(restore::restore(&mut card,123456).is_err());
        Ok(())
    }
    struct ChangingCard { calls: usize }
    impl Card for ChangingCard {
        fn serial(&mut self) -> Result<u32> { Ok(123) }
        fn public_key(&mut self, _: u8) -> Result<Option<Vec<u8>>> { unreachable!("object-only test") }
        fn object(&mut self, _: u32) -> Result<Option<Vec<u8>>> { self.calls+=1; Ok(Some(vec![self.calls as u8])) }
    }
    #[test]
    fn changed_bundle_cannot_keep_live_proof() -> Result<()> {
        let mut live = ChangingCard { calls: 0 };
        let mut card = StableCard { live: &mut live, observed: BTreeMap::new() };
        card.object(PRIMARY_BANK)?;
        assert!(card.check().is_err());
        Ok(())
    }
}
