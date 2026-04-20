// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! wasm-bindgen wrapper for the `signed_note` crate.
//!
//! Exposes the C2SP signed-note API to JavaScript/TypeScript consumers.
//! See <https://c2sp.org/signed-note> for the protocol specification.

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// A parsed signed note (text + signatures).
///
/// Notes are the outer envelope for transparency log checkpoints.
/// Parse with `Note.fromBytes()`, verify with `note.verify()`.
#[wasm_bindgen]
pub struct Note {
    inner: signed_note::Note,
}

#[wasm_bindgen]
impl Note {
    /// Parse a signed note from its wire format.
    ///
    /// The input must be a valid signed note: UTF-8 text ending in newline,
    /// followed by a blank line, followed by one or more signature lines.
    ///
    /// # Errors
    ///
    /// Returns a JS error string if the input is not a valid signed note.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(data: &[u8]) -> Result<Note, JsValue> {
        signed_note::Note::from_bytes(data)
            .map(|n| Note { inner: n })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Verify the note's signatures against a set of known verifiers.
    ///
    /// Returns a `VerifyResult` with counts of verified and unverified signatures.
    ///
    /// # Errors
    ///
    /// Returns a JS error string if a known verifier rejects its signature
    /// (invalid signature), or if no signatures could be verified at all.
    pub fn verify(&self, verifiers: &VerifierList) -> Result<VerifyResult, JsValue> {
        let (verified, unverified) = self
            .inner
            .verify(verifiers.built_inner()?)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(VerifyResult {
            verified_count: verified.len(),
            unverified_count: unverified.len(),
        })
    }

    /// The note's text as raw bytes (everything before the signature block).
    #[must_use]
    pub fn text(&self) -> Vec<u8> {
        self.inner.text().to_vec()
    }

    /// The note's text as a string (convenience for JS consumers).
    ///
    /// Note text is always valid UTF-8 per the spec, so this is a lossless conversion.
    ///
    /// # Panics
    ///
    /// Panics if the note text is not valid UTF-8, which is guaranteed not to
    /// happen by the signed-note spec and is enforced at parse time.
    #[must_use]
    #[wasm_bindgen(js_name = "textString")]
    pub fn text_string(&self) -> String {
        String::from_utf8(self.inner.text().to_vec())
            .expect("note text is guaranteed UTF-8 by the signed-note spec")
    }

    /// Serialize the note back to its wire format.
    #[must_use]
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

#[wasm_bindgen]
pub struct VerifyResult {
    pub verified_count: usize,
    /// Signatures from unknown verifiers. Not an error, just ignored.
    pub unverified_count: usize,
}

/// Ed25519 signature verifier, constructed from an encoded verifier key (vkey).
///
/// A vkey string has the format: `<name>+<hex_key_id>+<base64_key_data>`
/// where `key_data` is `0x01 || ed25519_public_key`.
#[wasm_bindgen]
pub struct Ed25519NoteVerifier {
    inner: signed_note::Ed25519NoteVerifier,
}

#[wasm_bindgen]
impl Ed25519NoteVerifier {
    /// Example vkey: `"transparency.dev/google-ct+af032437+ATj4kNR6..."`
    ///
    /// # Errors
    ///
    /// Returns a JS error string if the encoded vkey is malformed.
    #[wasm_bindgen(constructor)]
    pub fn new(encoded_vkey: &str) -> Result<Ed25519NoteVerifier, JsValue> {
        signed_note::Ed25519NoteVerifier::new_from_encoded_key(encoded_vkey)
            .map(|v| Ed25519NoteVerifier { inner: v })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// A collection of known verifiers for signature verification.
///
/// Build one at startup from your trusted vkey strings, then call `.build()`
/// to finalize. Pass the built list to `Note.verify()` for each incoming checkpoint.
#[wasm_bindgen]
pub struct VerifierList {
    // Accumulate verifiers here until build() is called, since VerifierList::new()
    // takes ownership and we need to add them one at a time from JS.
    pending: Option<Vec<Box<dyn signed_note::NoteVerifier>>>,
    inner: Option<signed_note::VerifierList>,
}

impl Default for VerifierList {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierList {
    fn built_inner(&self) -> Result<&signed_note::VerifierList, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("must call build() before verify()"))
    }
}

#[wasm_bindgen]
impl VerifierList {
    #[must_use]
    #[wasm_bindgen(constructor)]
    pub fn new() -> VerifierList {
        VerifierList {
            pending: Some(Vec::new()),
            inner: None,
        }
    }

    /// Add an Ed25519 verifier to the list. Call this for each trusted vkey.
    ///
    /// Must be called before `.build()`. Consumes the verifier.
    ///
    /// # Errors
    ///
    /// Returns a JS error string if `build()` has already been called.
    #[wasm_bindgen(js_name = "addEd25519")]
    pub fn add_ed25519(&mut self, v: Ed25519NoteVerifier) -> Result<(), JsValue> {
        let pending = self
            .pending
            .as_mut()
            .ok_or_else(|| JsValue::from_str("cannot add verifiers after build()"))?;
        pending.push(Box::new(v.inner));
        Ok(())
    }

    /// Must be called after adding all verifiers and before `Note.verify()`.
    ///
    /// # Errors
    ///
    /// Returns a JS error string if `build()` has already been called.
    pub fn build(&mut self) -> Result<(), JsValue> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| JsValue::from_str("build() already called"))?;
        self.inner = Some(signed_note::VerifierList::new(pending));
        Ok(())
    }
}

/// Compute the key ID for a given server name and encoded public key.
///
/// Key ID = SHA-256(name + "\n" + `key_data`)[:4], as recommended by
/// <https://c2sp.org/signed-note#signatures>.
///
/// # Errors
///
/// Returns a JS error string if `name` is not a valid signed-note key name.
#[wasm_bindgen(js_name = "computeKeyId")]
pub fn compute_key_id(name: &str, signature_type: &[u8], pubkey: &[u8]) -> Result<u32, JsValue> {
    let key_name = signed_note::KeyName::new(name.to_string())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(signed_note::compute_key_id(
        &key_name,
        signature_type,
        pubkey,
    ))
}

/// Returns a vkey string: `<name>+<hex_key_id>+<base64(0x01 || pubkey)>`
///
/// # Errors
///
/// Returns a JS error string if `name` is not a valid signed-note key name,
/// or if `public_key` is not a valid 32-byte Ed25519 public key.
///
/// # Panics
///
/// Panics if the 32-byte slice-to-array conversion fails, which cannot happen
/// when `public_key.len() == 32` (checked before calling into dalek).
#[wasm_bindgen(js_name = "newEncodedEd25519VerifierKey")]
pub fn new_encoded_ed25519_verifier_key(name: &str, public_key: &[u8]) -> Result<String, JsValue> {
    if public_key.len() != 32 {
        return Err(JsValue::from_str("Ed25519 public key must be 32 bytes"));
    }
    let key_name = signed_note::KeyName::new(name.to_string())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key.try_into().unwrap())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(signed_note::new_encoded_ed25519_verifier_key(
        &key_name,
        &verifying_key,
    ))
}
