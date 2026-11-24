//! Independent native authorization using the shared public bundle parser.
//!
//! WASM inventory previews are never accepted as proof here. Native code reads
//! the currently committed card bank, invokes the same bounded parser itself,
//! and matches every authenticated public component against the physical card.
//! Only after stable serial/object/key rereads may it report live-key evidence.
//! This path has no PIN, private-operation or card-write interface.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sequoia_pqmail_piv::restore::{Card, ObjectReader};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

const MAX: usize = 65_536;

/// The fixed native transport reads current single-bank framing. Its checksum
/// is not authentication; `verify` below validates the signed public contents.
/// File bytes are used only by the internal regression facility, never a
/// browser-selected private-operation request or recovery-bank fallback.
fn authorize(card: &mut impl Card, serial: u32, file: Option<&[u8]>) -> Result<Value> {
    ensure!(serial > 0 && serial <= i32::MAX as u32 && card.serial()? == serial,
        "Wrong YubiKey serial");
    let mut observed = BTreeMap::new();
    let (generation, stored) = match file {
        Some(bytes) => {
            ensure!(!bytes.is_empty() && bytes.len() <= MAX, "Certificate bundle size limit");
            (0, bytes.to_vec())
        }
        None => crate::public_snapshot::bundle(card, &mut observed)?,
    };
    // There is one public decoder for both targets. This is a NEW verification
    // of bytes read inside native authority, not a reused browser result or
    // trusted liveKeysMatched flag. The shared result cannot manufacture one.
    let verified = sequoia_public_bundle::verify(&stored)?;
    ensure!(verified.serial() == serial, "Signed bundle belongs to another YubiKey");
    for (slot, expected) in verified.public_keys() {
        ensure!(card.public_key(*slot)?.as_ref() == Some(expected),
            "Live public key differs from signed bundle in slot {slot:02x}");
    }
    // Re-read the exact object frames and ALL authenticated components. This
    // detects external card changes during the operation; a file's matching
    // serial alone cannot establish that its keys exist on the selected card.
    for (tag, expected) in observed {
        ensure!(card.object(tag)?.as_ref() == Some(&expected), "Public bundle changed while reading");
    }
    for (slot, expected) in verified.public_keys() {
        ensure!(card.public_key(*slot)?.as_ref() == Some(expected),
            "Live public key changed in slot {slot:02x}");
    }
    ensure!(card.serial()? == serial, "Device changed during public restore");

    let mut result = verified.preview()?;
    result["source"] = if file.is_some() { "file" } else { "yubikey" }.into();
    result["generation"] = generation.into();
    result["liveKeysMatched"] = true.into();
    let warnings = result["warnings"].as_array_mut().context("Missing public warnings")?;
    warnings.retain(|warning| warning.as_str() !=
        Some("File freshness is not established; live public keys have not been checked."));
    if file.is_some() {
        warnings.push("File freshness is not established; live public keys match the configured YubiKey.".into());
    }
    Ok(result)
}

/// Only the installed Python helper chooses this executable and object reader.
/// The serial must be canonical and the request must have exactly these public
/// fields. The optional file form remains an internal test interface; native
/// message authorization always omits it and reads the current physical bank.
pub fn preview(request: &Value) -> Result<Value> {
    let fields = request.as_object().context("Public restore request required")?;
    let has_file = fields.contains_key("bundle");
    ensure!(fields.len() == if has_file { 4 } else { 3 } &&
        ["op", "serial", "objectHelper"].iter().all(|field| fields.contains_key(*field)) &&
        request["op"] == "identity-restore", "Invalid native restore fields");
    let text = request["serial"].as_str().context("Serial required")?;
    let serial = text.parse::<u32>()?;
    ensure!(serial > 0 && serial <= i32::MAX as u32 && serial.to_string() == text, "Invalid serial");
    let helper = Path::new(request["objectHelper"].as_str().context("Object helper required")?);
    let file = request.get("bundle").map(|value| -> Result<Vec<u8>> {
        let text = value.as_str().context("Encoded bundle required")?;
        ensure!(text.len() <= 87_384, "Encoded bundle size limit");
        let bytes = B64.decode(text)?;
        ensure!(B64.encode(&bytes) == text, "Noncanonical bundle encoding");
        // Reject invalid imported data before even opening a public connection.
        // authorize repeats verification after connecting; no cached approval
        // from this preflight can grant a private operation.
        sequoia_public_bundle::verify(&bytes)?;
        Ok(bytes)
    }).transpose()?;
    let mut card = ObjectReader::connect(helper, serial)?;
    authorize(&mut card, serial, file.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    /// A synthetic public-only card: it has no signing, PIN, policy or write
    /// method. Mutation switches simulate races without accessing hardware.
    struct FixtureCard {
        keys: BTreeMap<u8, Vec<u8>>, objects: BTreeMap<u32, Vec<u8>>,
        key_reads: BTreeMap<u8, usize>, object_reads: BTreeMap<u32, usize>,
        serial_reads: usize, change_key: bool, change_object: bool, change_serial: bool,
    }
    impl Card for FixtureCard {
        fn serial(&mut self) -> Result<u32> {
            self.serial_reads += 1;
            Ok(if self.change_serial && self.serial_reads > 1 { 654321 } else { 123456 })
        }
        fn public_key(&mut self, slot: u8) -> Result<Option<Vec<u8>>> {
            let count = self.key_reads.entry(slot).or_default(); *count += 1;
            let mut value = self.keys.get(&slot).cloned();
            if self.change_key && *count > 1 { value = Some(vec![0]); }
            Ok(value)
        }
        fn object(&mut self, tag: u32) -> Result<Option<Vec<u8>>> {
            let count = self.object_reads.entry(tag).or_default(); *count += 1;
            let mut value = self.objects.get(&tag).cloned();
            if self.change_object && *count > 1 { value = Some(vec![0]); }
            Ok(value)
        }
    }
    fn fixture() -> Result<(FixtureCard, Vec<u8>)> {
        let data: Value = serde_json::from_str(include_str!("../tests/data/restore-level3.json"))?;
        let keys = data["keys"].as_object().unwrap().iter().map(|(slot, value)|
            Ok((u8::from_str_radix(slot,16)?,B64.decode(value.as_str().unwrap())?)))
            .collect::<Result<BTreeMap<_,_>>>()?;
        let bytes = B64.decode(data["hybrid"].as_str().unwrap())?;
        let mut index = b"PQMIDX01".to_vec(); index.extend(17u64.to_be_bytes());
        index.extend((bytes.len() as u32).to_be_bytes()); index.extend(Sha256::digest(&bytes));
        let mut objects = BTreeMap::from([(0x5f5000, index)]);
        for (i, chunk) in bytes.chunks(2048).enumerate() {
            let mut frame = b"PQMCHK01".to_vec(); frame.extend(17u64.to_be_bytes());
            frame.extend((i as u32).to_be_bytes()); frame.extend(chunk);
            objects.insert(0x5f5001+i as u32, frame);
        }
        Ok((FixtureCard {keys,objects,key_reads:BTreeMap::new(),object_reads:BTreeMap::new(),
            serial_reads:0,change_key:false,change_object:false,change_serial:false}, bytes))
    }
    #[test]
    fn shared_parser_and_native_authority_return_identical_public_material() -> Result<()> {
        let (mut card, bytes) = fixture()?;
        let browser: Value = serde_json::from_str(&sequoia_public_bundle::inspect(
            &json!({"bundle":B64.encode(&bytes)}).to_string())?)?;
        let on_key = authorize(&mut card, 123456, None)?;
        let (mut card, _) = fixture()?;
        let file = authorize(&mut card, 123456, Some(&bytes))?;
        for field in ["serial", "bundleHash", "certificates", "slots", "bundleSignatureVerified"] {
            assert_eq!(browser[field], on_key[field], "{field}");
            assert_eq!(browser[field], file[field], "{field}");
        }
        assert_eq!(browser["liveKeysMatched"], false);
        assert_eq!(on_key["liveKeysMatched"], true); assert_eq!(on_key["generation"], 17);
        assert_eq!(file["liveKeysMatched"], true); assert_eq!(file["generation"], 0);
        assert_eq!(on_key["certificates"].as_array().unwrap().len(), 3);
        assert_eq!(on_key["slots"].as_array().unwrap().len(), 10);
        assert!(card.object_reads.is_empty(), "File verification must not read unrelated objects");
        assert!(card.key_reads.values().all(|reads| *reads == 2));
        Ok(())
    }
    #[test]
    fn every_component_and_missing_key_is_checked_before_live_evidence() -> Result<()> {
        let (card, bytes) = fixture()?;
        for slot in card.keys.keys() {
            for missing in [false, true] {
                let (mut bad, _) = fixture()?;
                if missing { bad.keys.remove(slot); } else { bad.keys.get_mut(slot).unwrap()[20] ^= 1; }
                assert!(authorize(&mut bad, 123456, Some(&bytes)).is_err(), "slot {slot:02x}");
            }
        }
        Ok(())
    }
    #[test]
    fn invalid_signature_never_receives_live_key_evidence() -> Result<()> {
        let (mut card, mut bytes) = fixture()?;
        let last = bytes.len()-1; bytes[last] ^= 1;
        assert!(authorize(&mut card, 123456, Some(&bytes)).is_err());
        assert!(card.key_reads.is_empty(), "Signature must verify before public-key matching");
        Ok(())
    }
    #[test]
    fn object_key_or_serial_changes_fail_closed() -> Result<()> {
        for case in 0..3 {
            let (mut card, _) = fixture()?;
            match case { 0 => card.change_key=true, 1 => card.change_object=true, _ => card.change_serial=true }
            assert!(authorize(&mut card, 123456, None).is_err(), "case {case}");
        }
        Ok(())
    }
    #[test]
    fn browser_authority_fields_cannot_bypass_native_reads() {
        for field in ["liveKeysMatched", "bundleSignatureVerified", "slots", "certificate", "pin"] {
            let mut request = json!({"op":"identity-restore","serial":"123456","objectHelper":"/nonexistent"});
            request[field] = true.into();
            assert!(preview(&request).unwrap_err().to_string().contains("fields"));
        }
    }
}
