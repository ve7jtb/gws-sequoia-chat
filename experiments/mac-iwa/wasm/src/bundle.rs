//! Browser binding for the shared, target-independent public bundle parser.
//! There is deliberately no second parser or native fallback here. Every
//! successful result still says liveKeysMatched=false; hardware evidence is
//! collected separately and never becomes native private-operation authority.
use wasm_bindgen::prelude::*;

/// This exact parser is also called independently by native authorization on
/// freshly read card bytes. Return a fixed error instead of reflecting hostile
/// certificate bytes, parser diagnostics or caller-supplied text into the UI.
#[wasm_bindgen]
pub fn inspect_bundle(input: &str) -> Result<String, JsValue> {
    sequoia_public_bundle::inspect(input)
        .map_err(|_| JsValue::from_str("Public bundle inspection rejected"))
}
