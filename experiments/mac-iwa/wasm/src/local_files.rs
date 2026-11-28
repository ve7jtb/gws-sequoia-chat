//! Dedicated ML-KEM-1024 and X448 keys for the local file store.
use super::*;
use cx448::x448;
use ml_kem::{
    kem::{Decapsulate, KeyExport},
    DecapsulationKey, EncapsulationKey, MlKem1024, TryKeyInit,
};
use zeroize::Zeroizing;

const KEM_LEN: usize = 1568;
const X448_LEN: usize = 56;
type MlSecret = DecapsulationKey<MlKem1024>;

fn key_parts(seed: &[u8]) -> Result<(MlSecret, Zeroizing<x448::Secret>)> {
    ensure!(seed.len() == 64 + X448_LEN, "Invalid file-store seed");
    let ml = MlSecret::from_seed(seed[..64].try_into()?);
    let x = Zeroizing::new(x448::Secret::from(<[u8; X448_LEN]>::try_from(&seed[64..])?));
    Ok((ml, x))
}

fn shared_x448(secret: &x448::Secret, peer: &[u8]) -> Result<Zeroizing<x448::SharedSecret>> {
    let peer = x448::PublicKey::from_bytes(peer.try_into()?).context("Invalid X448 public key")?;
    Ok(Zeroizing::new(
        secret
            .as_diffie_hellman(&peer)
            .context("Noncontributory X448 key")?,
    ))
}

#[wasm_bindgen]
pub fn local_file_public(seed: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let seed = Zeroizing::new(seed);
    let (ml, x) = key_parts(&seed).map_err(local_error)?;
    let mut public = ml.encapsulation_key().to_bytes().to_vec();
    public.extend_from_slice(x448::PublicKey::from(&*x).as_bytes());
    Ok(public)
}

// Return the ciphertext and ephemeral point, followed by the two shared
// secrets. The one-shot file worker uses those secrets only for HKDF and AES.
#[wasm_bindgen]
pub fn local_file_encapsulate(public: &[u8]) -> Result<Vec<u8>, JsValue> {
    let run = || -> Result<Vec<u8>> {
        ensure!(
            public.len() == KEM_LEN + X448_LEN,
            "Invalid file-store public key"
        );
        let ek = EncapsulationKey::<MlKem1024>::new_from_slice(&public[..KEM_LEN])
            .map_err(|_| anyhow::anyhow!("Invalid ML-KEM-1024 public key"))?;
        let mut random = Zeroizing::new([0; 32 + X448_LEN]);
        getrandom::fill(&mut *random).map_err(|_| anyhow::anyhow!("Randomness unavailable"))?;
        let x = Zeroizing::new(x448::Secret::from(<[u8; X448_LEN]>::try_from(
            &random[32..],
        )?));
        let shared = shared_x448(&x, &public[KEM_LEN..])?;
        let (cipher, mut ml) = ek.encapsulate_deterministic(random[..32].try_into()?);
        let mut out = Vec::with_capacity(KEM_LEN + X448_LEN + 32 + X448_LEN);
        out.extend_from_slice(cipher.as_slice());
        out.extend_from_slice(x448::PublicKey::from(&*x).as_bytes());
        out.extend_from_slice(ml.as_slice());
        out.extend_from_slice(shared.as_bytes());
        ml.as_mut_slice().fill(0);
        Ok(out)
    };
    run().map_err(local_error)
}

#[wasm_bindgen]
pub fn local_file_decapsulate(seed: Vec<u8>, capsule: &[u8]) -> Result<Vec<u8>, JsValue> {
    let seed = Zeroizing::new(seed);
    let run = || -> Result<Vec<u8>> {
        ensure!(
            capsule.len() == KEM_LEN + X448_LEN,
            "Invalid file-store capsule"
        );
        let (ml, x) = key_parts(&seed)?;
        let shared = shared_x448(&x, &capsule[KEM_LEN..])?;
        let ct: &[u8; KEM_LEN] = capsule[..KEM_LEN].try_into()?;
        let mut ml = ml.decapsulate(ct.into());
        let mut out = Vec::with_capacity(32 + X448_LEN);
        out.extend_from_slice(ml.as_slice());
        out.extend_from_slice(shared.as_bytes());
        ml.as_mut_slice().fill(0);
        Ok(out)
    };
    run().map_err(local_error)
}

fn local_error(_: anyhow::Error) -> JsValue {
    JsValue::from_str("Local file hybrid cryptography failed")
}
