//! Bounded, read-only transport for browser-owned public-bundle inspection.
//!
//! This module knows only the current PIV object framing and fixed public slot
//! namespace. It never decompresses a bundle, parses certificates, verifies a
//! signature, or declares an identity usable. WASM owns those public checks;
//! identity_restore still independently authenticates the complete live bundle
//! before a selected identity can authorize a private operation.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sequoia_pqmail_piv::restore::{Card, ObjectReader};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

const MAX_BUNDLE: usize = 65_536;
const MAX_PUBLIC_KEY: usize = 8_192;
const PRIMARY_BANK: u32 = 0x5f5000;
const MAX_GENERATION: u64 = 9_007_199_254_740_991; // Exact in browser JSON numbers.
const SLOTS: [u8; 24] = [
    0x9a, 0x9c, 0x9d, 0x9e, 0x82, 0x83, 0x84, 0x85,
    0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
    0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
];

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Read only the committed primary bank and its declared bounded chunks. The
/// manifest digest is a transport-integrity check, not a signed-bundle claim.
/// We deliberately do not inspect historical/recovery banks or fall back from
/// malformed current data: deciding which authenticated identity to use is not
/// a responsibility of this raw UI transport.
pub(crate) fn bundle(card: &mut impl Card, observed: &mut BTreeMap<u32, Vec<u8>>) -> Result<(u64, Vec<u8>)> {
    let manifest = card.object(PRIMARY_BANK)?.context("Current public bundle absent")?;
    ensure!(manifest.len() == 52 && manifest.starts_with(b"PQMIDX01"), "Invalid public bundle index");
    let generation = u64::from_be_bytes(manifest[8..16].try_into()?);
    let size = u32::from_be_bytes(manifest[16..20].try_into()?) as usize;
    ensure!((1..=MAX_GENERATION).contains(&generation) && (1..=MAX_BUNDLE).contains(&size), "Public bundle index limits");
    let digest = manifest[20..].to_vec();
    observed.insert(PRIMARY_BANK, manifest);
    let mut bytes = Vec::with_capacity(size);
    for i in 0..size.div_ceil(2048) {
        // The fixed base and MAX_BUNDLE bound make all possible selectors fall
        // in 0x5f5001..=0x5f5020; no browser field can name an object or slot.
        let tag = PRIMARY_BANK + 1 + i as u32;
        let chunk = card.object(tag)?.context("Incomplete current public bundle")?;
        ensure!(chunk.len() == 20 + 2048.min(size - i * 2048) && chunk.starts_with(b"PQMCHK01"), "Invalid public bundle chunk");
        ensure!(u64::from_be_bytes(chunk[8..16].try_into()?) == generation &&
            u32::from_be_bytes(chunk[16..20].try_into()?) == i as u32, "Stale public bundle chunk");
        bytes.extend_from_slice(&chunk[20..]);
        observed.insert(tag, chunk);
    }
    ensure!(Sha256::digest(&bytes).as_slice() == digest, "Public bundle transport digest mismatch");
    // Only identify the supported container. Its compressed content and all
    // authenticity checks remain opaque to this read-only native endpoint.
    ensure!(bytes.starts_with(b"PQMZIP01"), "Current compressed public bundle required");
    Ok((generation, bytes))
}

fn read(card: &mut impl Card, expected_serial: u32, include_bundle: bool) -> Result<Value> {
    ensure!(expected_serial > 0 && expected_serial <= i32::MAX as u32 &&
        card.serial()? == expected_serial, "Wrong YubiKey serial");
    let mut observed = BTreeMap::new();
    let stored = if include_bundle { Some(bundle(card, &mut observed)?) } else { None };
    let mut keys = BTreeMap::new();
    let mut slots = Vec::with_capacity(SLOTS.len());
    for slot in SLOTS {
        let key = card.public_key(slot)?;
        if let Some(bytes) = &key {
            ensure!(!bytes.is_empty() && bytes.len() <= MAX_PUBLIC_KEY, "Public key size limit");
        }
        slots.push(json!({"slot":format!("{slot:02x}"),
            "publicKeySha256":key.as_ref().map(|bytes|hex(&Sha256::digest(bytes)))}));
        keys.insert(slot, key);
    }
    // One operation lock excludes other IWA operations. Re-read the exact
    // objects and all 24 public slot states as well, detecting external writes
    // or device substitution during the snapshot rather than mixing sources.
    // None is an explicit absent slot; transport failures always abort.
    for (tag, bytes) in observed {
        ensure!(card.object(tag)?.as_ref() == Some(&bytes), "Public bundle changed while reading");
    }
    for (slot, bytes) in keys {
        ensure!(card.public_key(slot)? == bytes, "Public keys changed while reading");
    }
    ensure!(card.serial()? == expected_serial, "Device changed during public snapshot");
    let mut value = json!({"format":"sequoia-iwa-public-snapshot","version":1,
        "serial":expected_serial.to_string(),"slots":slots,"warnings":[]});
    if let Some((generation, bytes)) = stored {
        value["bundle"] = B64.encode(bytes).into();
        value["generation"] = generation.into();
    }
    // No verification/trust/selection flags are emitted by a transport read.
    Ok(value)
}

pub fn snapshot(request: &Value) -> Result<Value> {
    let fields = request.as_object().context("Public snapshot request required")?;
    ensure!(fields.len() == 3 && ["op", "serial", "objectHelper"].iter().all(|field| fields.contains_key(*field)), "Invalid public snapshot fields");
    let include_bundle = match request["op"].as_str() {
        Some("identity-bundle-read") => true,
        Some("identity-key-snapshot") => false,
        _ => anyhow::bail!("Unknown public snapshot operation"),
    };
    let text = request["serial"].as_str().context("Serial required")?;
    let serial = text.parse::<u32>()?;
    ensure!(serial > 0 && serial <= i32::MAX as u32 && serial.to_string() == text, "Invalid serial");
    let helper = Path::new(request["objectHelper"].as_str().context("Object helper required")?);
    let mut card = ObjectReader::connect(helper, serial)?;
    read(&mut card, serial, include_bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct PublicCard {
        serials: Vec<u32>, keys: BTreeMap<u8, Vec<u8>>, objects: BTreeMap<u32, Vec<u8>>,
        object_reads: Vec<u32>, key_reads: Vec<u8>, change_object: bool, change_key: bool,
    }
    impl Card for PublicCard {
        fn serial(&mut self) -> Result<u32> { Ok(self.serials.remove(0)) }
        fn public_key(&mut self, slot: u8) -> Result<Option<Vec<u8>>> {
            ensure!(SLOTS.contains(&slot), "Unexpected public slot");
            let mut value = self.keys.get(&slot).cloned();
            if self.change_key && self.key_reads.contains(&slot) { value = Some(vec![9]); }
            self.key_reads.push(slot); Ok(value)
        }
        fn object(&mut self, tag: u32) -> Result<Option<Vec<u8>>> {
            ensure!((PRIMARY_BANK..=PRIMARY_BANK+32).contains(&tag), "Unexpected public object");
            let mut value = self.objects.get(&tag).cloned();
            if self.change_object && self.object_reads.contains(&tag) { value = Some(vec![9]); }
            self.object_reads.push(tag); Ok(value)
        }
    }
    fn fixture(bytes: &[u8]) -> PublicCard {
        let mut manifest = b"PQMIDX01".to_vec(); manifest.extend(17u64.to_be_bytes());
        manifest.extend((bytes.len() as u32).to_be_bytes()); manifest.extend(Sha256::digest(bytes));
        let mut objects = BTreeMap::from([(PRIMARY_BANK,manifest)]);
        for (i, chunk) in bytes.chunks(2048).enumerate() {
            let mut frame = b"PQMCHK01".to_vec(); frame.extend(17u64.to_be_bytes());
            frame.extend((i as u32).to_be_bytes()); frame.extend(chunk);
            objects.insert(PRIMARY_BANK+1+i as u32,frame);
        }
        PublicCard {serials:vec![123456,123456],keys:BTreeMap::from([(0x9c,vec![1,2,3])]),objects,
            object_reads:vec![],key_reads:vec![],change_object:false,change_key:false}
    }
    #[test]
    fn transports_opaque_bounded_bundle_and_all_public_slot_hashes() -> Result<()> {
        // Deliberately not a valid signed/compressed bundle: transport must not
        // silently regain the certificate/authentication policy owned by WASM.
        let mut bytes = b"PQMZIP01opaque browser input".to_vec(); bytes.extend(vec![3;4096]);
        let mut card = fixture(&bytes); let value = read(&mut card,123456,true)?;
        assert_eq!(value["bundle"],B64.encode(&bytes)); assert_eq!(value["generation"],17);
        assert_eq!(value["serial"],"123456"); assert_eq!(value["slots"].as_array().unwrap().len(),24);
        assert_eq!(value["slots"][1]["publicKeySha256"],hex(&Sha256::digest([1,2,3])));
        assert!(value["slots"][0]["publicKeySha256"].is_null());
        assert!(value.get("bundleSignatureVerified").is_none()); assert!(value.get("liveKeysMatched").is_none());
        assert_eq!(card.key_reads.len(),48); assert_eq!(card.object_reads.len(),8);
        Ok(())
    }
    #[test]
    fn key_snapshot_never_reads_bundle_objects() -> Result<()> {
        let mut card=fixture(b"not a bundle"); let value=read(&mut card,123456,false)?;
        assert!(card.object_reads.is_empty()); assert_eq!(card.key_reads.len(),48);
        assert!(value.get("bundle").is_none()); assert!(value.get("generation").is_none()); Ok(())
    }
    #[test]
    fn incomplete_stale_oversized_or_corrupt_transport_fails_closed() {
        for case in 0..8 {
            let mut card=fixture(b"PQMZIP01opaque");
            match case {
                0 => {card.objects.remove(&PRIMARY_BANK);},
                1 => {card.objects.remove(&(PRIMARY_BANK+1));},
                2 => {card.objects.get_mut(&PRIMARY_BANK).unwrap()[16..20].copy_from_slice(&65_537u32.to_be_bytes());},
                3 => {card.objects.get_mut(&PRIMARY_BANK).unwrap()[8..16].copy_from_slice(&(MAX_GENERATION+1).to_be_bytes());},
                4 => {card.objects.get_mut(&(PRIMARY_BANK+1)).unwrap()[15]^=1;},
                5 => {card.objects.get_mut(&(PRIMARY_BANK+1)).unwrap().push(1);},
                6 => {card.objects.get_mut(&PRIMARY_BANK).unwrap()[20]^=1;},
                _ => {card.objects.get_mut(&PRIMARY_BANK).unwrap().push(1);},
            }
            assert!(read(&mut card,123456,true).is_err(),"case {case}");
            assert!(card.key_reads.is_empty(),"Malformed framing must fail before slot reads");
        }
    }
    #[test]
    fn changed_objects_keys_or_serial_cannot_claim_a_stable_snapshot() {
        for case in 0..4 {
            let mut card=fixture(b"PQMZIP01opaque");
            match case {0=>card.change_object=true,1=>card.change_key=true,
                2=>card.serials[1]=999,_=>card.serials[0]=999}
            assert!(read(&mut card,123456,true).is_err(),"case {case}");
        }
    }
    #[test]
    fn empty_and_oversized_public_key_reads_are_rejected() {
        for bytes in [vec![],vec![1;MAX_PUBLIC_KEY+1]] {
            let mut card=fixture(b"PQMZIP01opaque"); card.keys.insert(0x9c,bytes);
            assert!(read(&mut card,123456,false).is_err());
        }
    }
    #[test]
    fn caller_cannot_select_object_slot_path_or_private_operation() {
        for extra in ["slot","tag","bundle","pin","config"] {
            let mut request=json!({"op":"identity-bundle-read","serial":"123456","objectHelper":"/nonexistent"});
            request[extra]="forbidden".into();
            assert!(snapshot(&request).unwrap_err().to_string().contains("fields"));
        }
    }
}
