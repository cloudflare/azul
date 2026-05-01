// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! wasm-bindgen wrapper for the `tlog_tiles` crate.
//!
//! Exposes checkpoint parsing and Merkle proof verification to JS/TS consumers.
//! See <https://c2sp.org/tlog-tiles> and <https://c2sp.org/tlog-checkpoint>.

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// A parsed checkpoint text (origin + tree size + root hash + optional extensions).
///
/// This is the text portion of a signed checkpoint, without the signature block.
/// Parse with `CheckpointText.fromBytes()`.
#[wasm_bindgen]
pub struct CheckpointText {
    inner: tlog_tiles::CheckpointText,
}

#[wasm_bindgen]
impl CheckpointText {
    /// Parse checkpoint text from its wire format.
    ///
    /// Input is the text portion of a signed note (everything before the
    /// blank line separator), ending with a newline.
    ///
    /// # Errors
    ///
    /// Returns a JS error string if the input is not a valid checkpoint text.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(data: &[u8]) -> Result<CheckpointText, JsValue> {
        tlog_tiles::CheckpointText::from_bytes(data)
            .map(|c| CheckpointText { inner: c })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// The log's origin string (first line of the checkpoint).
    #[must_use]
    pub fn origin(&self) -> String {
        self.inner.origin().to_string()
    }

    /// Number of entries in the log (tree size).
    #[must_use]
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    /// The Merkle tree root hash (32 bytes, SHA-256).
    #[must_use]
    #[wasm_bindgen(js_name = "rootHash")]
    pub fn root_hash(&self) -> Vec<u8> {
        self.inner.hash().0.to_vec()
    }

    /// Extension lines (may be empty). Each line is terminated by newline.
    #[must_use]
    pub fn extension(&self) -> String {
        self.inner.extension().to_string()
    }

    /// Serialize back to the wire format.
    #[must_use]
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

/// Verify a Merkle consistency proof between two tree heads.
///
/// This implements RFC 9162 Section 2.1.4.2 consistency proof verification,
/// confirming that the tree of `new_size` with `new_root` is an append-only
/// extension of the tree of `old_size` with `old_root`.
///
/// `proof_hashes` is a flat `Uint8Array` of concatenated 32-byte SHA-256 hashes.
/// For example, a proof with 3 nodes is 96 bytes (3 x 32).
///
/// Throws on verification failure. Returns nothing on success.
///
/// # Errors
///
/// Returns a JS error string if the proof is invalid or the input sizes are wrong.
///
/// # Panics
///
/// Panics if a 32-byte chunk-to-array conversion fails, which cannot happen
/// since `proof_hashes.len()` is verified to be a multiple of 32 beforehand.
#[wasm_bindgen(js_name = "verifyConsistencyProof")]
pub fn verify_consistency_proof(
    proof_hashes: &[u8],
    old_size: u64,
    old_root: &[u8],
    new_size: u64,
    new_root: &[u8],
) -> Result<(), JsValue> {
    if old_root.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "old root hash must be 32 bytes, got {}",
            old_root.len()
        )));
    }
    if new_root.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "new root hash must be 32 bytes, got {}",
            new_root.len()
        )));
    }
    if !proof_hashes.len().is_multiple_of(32) {
        return Err(JsValue::from_str(&format!(
            "proof_hashes length must be a multiple of 32, got {}",
            proof_hashes.len()
        )));
    }

    let proof: Vec<tlog_core::Hash> = proof_hashes
        .chunks_exact(32)
        .map(|chunk| tlog_core::Hash(chunk.try_into().unwrap()))
        .collect();

    // Underlying API: (proof, n=new_size, root_hash=new_root, m=old_size, m_hash=old_root)
    tlog_core::verify_consistency_proof(
        &proof,
        new_size,
        tlog_core::Hash(new_root.try_into().unwrap()),
        old_size,
        tlog_core::Hash(old_root.try_into().unwrap()),
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}
