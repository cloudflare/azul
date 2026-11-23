// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! key-service-backed Ed25519 and ML-DSA-44 cosigners. Key handles never contain private material.
//! key service RPC is intentionally isolated here: the public C2SP crates remain
//! independent of the Workers runtime.

// mod rotation;

use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey as _};
use ml_dsa::{MlDsa44, VerifyingKey as MlDsaVerifyingKey};
use signed_note::{self, SignatureType, compute_key_id};
use worker::{Env, js_sys, wasm_bindgen, wasm_bindgen_futures::JsFuture};

use serde::Deserialize;
use std::{marker::PhantomData, num::NonZeroU32, rc::Rc};
use wasm_bindgen::{JsCast as _, JsValue};

#[wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    type JsKeyring;
    #[wasm_bindgen(method, catch, js_name = create)]
    fn create_key(
        this: &JsKeyring,
        name: &str,
        algorithm: &str,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = versions)]
    fn versions(this: &JsKeyring, name: &str) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = get)]
    fn get_version(
        this: &JsKeyring,
        name: &str,
        opts: &JsValue,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = exportKey)]
    fn export_key(
        this: &JsKeyring,
        format: &str,
        key: &JsValue,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = sign)]
    fn sign(
        this: &JsKeyring,
        algorithm: &JsValue,
        key: &JsValue,
        data: &js_sys::Uint8Array,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = encrypt)]
    fn encrypt(
        this: &JsKeyring,
        algorithm: &JsValue,
        key: &JsValue,
        data: &js_sys::Uint8Array,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = decrypt)]
    fn decrypt(
        this: &JsKeyring,
        algorithm: &JsValue,
        key: &JsValue,
        data: &js_sys::Uint8Array,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = get)]
    fn get_default(this: &JsKeyring, name: &str) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = details)]
    fn details(this: &JsKeyring, key: &JsValue) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = newVersion)]
    fn new_version(
        this: &JsKeyring,
        name: &str,
        opts: &JsValue,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = setDefaultVersion)]
    fn set_default_version(
        this: &JsKeyring,
        name: &str,
        version: u32,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = updateVersion)]
    fn update_version(
        this: &JsKeyring,
        name: &str,
        version: u32,
        patch: &JsValue,
    ) -> Result<js_sys::Promise, JsValue>;
}

#[derive(Debug)]
pub enum KeyServiceError {
    KeyServiceNotEnabled,
    KeyNotFound,
    InvalidArgument(String),
    Internal(String),
    Runtime(worker::Error),
}

impl From<worker::Error> for KeyServiceError {
    fn from(value: worker::Error) -> Self {
        Self::Runtime(value)
    }
}

impl std::fmt::Display for KeyServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyServiceError::KeyServiceNotEnabled => write!(f, "key service is not enabled"),
            KeyServiceError::KeyNotFound => write!(f, "key not found in key service"),
            KeyServiceError::InvalidArgument(msg) => {
                write!(f, "invalid argument to key service: {msg}")
            }
            KeyServiceError::Internal(msg) => {
                write!(f, "internal key service error: {msg}")
            }
            KeyServiceError::Runtime(msg) => write!(f, "key service runtime error: {msg}"),
        }
    }
}
impl std::error::Error for KeyServiceError {}

fn rpc_error(operation: &str, error: &JsValue) -> worker::Error {
    worker::Error::from(format!("key service {operation}: {error:?}"))
}

async fn call(
    operation: &str,
    promise: Result<js_sys::Promise, JsValue>,
) -> Result<JsValue, worker::Error> {
    JsFuture::from(promise.map_err(|e| rpc_error(operation, &e))?)
        .await
        .map_err(|e| rpc_error(operation, &e))
}

fn property(object: &JsValue, name: &str) -> Result<JsValue, worker::Error> {
    js_sys::Reflect::get(object, &JsValue::from_str(name)).map_err(|e| rpc_error(name, &e))
}

// Consume the returned JS value as part of converting it to a validated array.
#[allow(clippy::needless_pass_by_value)]
fn as_array(object: JsValue) -> Result<js_sys::Array, worker::Error> {
    if !js_sys::Array::is_array(&object) {
        return Err(worker::Error::from("key service returned invalid versions"));
    }
    Ok(js_sys::Array::from(&object))
}

macro_rules! js {
    // Peel off Rust fields until the receiver is a parenthesized expression.
    ($receiver:ident.$field:ident.$($rest:tt)+) => {
        js!(($receiver.$field).$($rest)+)
    };
    // Forward a method call on a simple receiver to the expression form.
    ($receiver:ident.$method:ident($($arg:expr),* $(,)?)) => {
        js!(($receiver).$method($($arg),*))
    };
    // Forward a property read on a simple receiver.
    ($receiver:ident.$field:ident) => {
        js!(($receiver).$field)
    };
    // Forward a property write on a simple receiver.
    ($receiver:ident.$field:ident = $value:expr) => {
        js!(($receiver).$field = $value)
    };
    // Continue peeling Rust fields from a parenthesized receiver.
    (($receiver:expr).$field:ident.$($rest:tt)+) => {
        js!((($receiver).$field).$($rest)+)
    };
    // Await a JS method's promise and translate its errors.
    (($receiver:expr).$method:ident($($arg:expr),* $(,)?)) => {
        call(stringify!($method), ($receiver).$method($($arg),*)).await?
    };
    // Read a JS property and translate reflection errors.
    (($receiver:expr).$field:ident) => {
        property(&($receiver), stringify!($field))?
    };
    // Write a JS property and translate reflection errors.
    (($receiver:expr).$field:ident = $value:expr) => {
        js_sys::Reflect::set(&($receiver), &JsValue::from_str(stringify!($field)), &$value)
            .map_err(|error| rpc_error(stringify!($field), &error))?;
    };
}

#[derive(Clone)]
pub struct Keyring {
    js: Rc<JsKeyring>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct VersionNumber(NonZeroU32);

impl std::fmt::Display for VersionNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq<NonZeroU32> for VersionNumber {
    fn eq(&self, other: &NonZeroU32) -> bool {
        self.0.eq(other)
    }
}

impl VersionNumber {
    #[must_use]
    pub fn get(self) -> u32 {
        self.0.get()
    }
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl Keyring {
    #[must_use]
    pub fn new(env: &Env) -> Option<Self> {
        let env_js = env.as_ref();
        let binding = (|| Ok::<_, worker::Error>(js!(env_js.KEY_SERVICE)))().ok()?;
        if binding.is_undefined() || binding.is_null() {
            return None;
        }
        Some(Self {
            js: Rc::new(binding.unchecked_into()),
        })
    }

    /// Create a logical key using the specified key service algorithm.
    ///
    /// # Errors
    /// Returns an error if the key service cannot create the key.
    pub async fn create_key(&self, name: &str, algorithm: &str) -> Result<(), KeyServiceError> {
        js!(self.js.create_key(name, algorithm));
        Ok(())
    }

    /// Read the current default version of a logical key.
    ///
    /// # Errors
    /// Returns an error if the key service fails or returns an invalid version.
    pub async fn current_default(&self, name: &str) -> Result<VersionNumber, KeyServiceError> {
        let pair = js!(self.js.get_default(name));
        let details = js!(self.js.details(&pair));
        version_number(&js!(details.version))
    }

    /// Create a new version with the requested usages and extractability.
    ///
    /// # Errors
    /// Returns an error if the key service fails or returns an invalid version.
    pub async fn new_version(
        &self,
        name: &str,
        usage: KeyUsage,
        extractable: bool,
    ) -> Result<VersionNumber, KeyServiceError> {
        // Set usages atomically with creation: no inert or verify-only version.
        let opts = js_sys::Object::new();
        js!(opts.usages = usage.as_js());
        js!(opts.extractable = if extractable {
            JsValue::TRUE
        } else {
            JsValue::FALSE
        });
        version_number(&js!(self.js.new_version(name, &opts)))
    }

    /// Set a version as the logical key's default.
    ///
    /// # Errors
    /// Returns an error if the key service cannot promote the version.
    pub async fn promote(&self, name: &str, version: VersionNumber) -> Result<(), KeyServiceError> {
        js!(self.js.set_default_version(name, version.get()));
        Ok(())
    }

    /// Replace the allowed usages for a key version.
    ///
    /// # Errors
    /// Returns an error if the key service cannot update the version.
    pub async fn change_usages(
        &self,
        name: &str,
        version: VersionNumber,
        usage: KeyUsage,
    ) -> Result<(), KeyServiceError> {
        let patch = js_sys::Object::new();
        js!(patch.usages = usage.as_js());
        // Preserve public-key export for verification of existing signatures.
        js!(self.js.update_version(name, version.get(), &patch));
        Ok(())
    }

    /// Discover sign-enabled versions, excluding explicitly retired (verify-only)
    /// versions.
    ///
    /// Malformed versions and key service failures are errors, not a reason to use local keys.
    ///
    /// # Errors
    /// Returns an error if discovery, public-key export, or validation fails.
    pub async fn load_singing_keys(
        &self,
        key_name: &str,
        identity: &str,
    ) -> Result<Vec<KeyServiceSigner>, KeyServiceError> {
        let versions = self.versions::<key_kind::Signing>(key_name).await?;
        let name = signed_note::KeyName::new(identity.to_owned()).map_err(|e| {
            KeyServiceError::InvalidArgument(format!("invalid key service identity name: {e:?}"))
        })?;
        let mut signers = Vec::new();
        for version in versions
            .into_iter()
            .filter(|version| version.usage == KeyUsage::SingingVerify)
        {
            let handle = version_handle(&self.js, key_name, version.number).await?;
            let public = js!(handle.publicKey);
            if public.is_undefined() {
                return Err(KeyServiceError::InvalidArgument(
                    "key service signing key is not an asymmetric key pair".into(),
                ));
            }
            if js!(handle.privateKey).is_undefined() {
                return Err(KeyServiceError::Internal(
                    "key service signing key has no private handle".into(),
                ));
            }
            let der = js_sys::Uint8Array::new(&js!(self.js.export_key("spki", &public))).to_vec();
            let (algorithm, key_id) = parse_public_key(&der, &name)?;
            signers.push(KeyServiceSigner {
                keyring: self.clone(),
                version,
                handle,
                public_key_der: der,
                name: name.clone(),
                key_id,
                algorithm,
            });
        }
        Ok(signers)
    }

    /// Sign a message with a key service signing version.
    ///
    /// # Errors
    /// Returns an error if the private handle is unavailable or signing fails.
    pub async fn sign(
        &self,
        signer: &KeyServiceSigner,
        message: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        Ok(js_sys::Uint8Array::new(&js!(self.js.sign(
            &signing_algorithm(&signer.algorithm),
            &js!(signer.handle.privateKey),
            &js_sys::Uint8Array::from(message)
        )))
        .to_vec())
    }

    /// Encrypt a payload using a ticket-key version.
    ///
    /// # Errors
    /// Returns an error if the key service cannot encrypt the payload.
    pub async fn encrypt(
        &self,
        algorithm: EncryptAlgorithm<'_>,
        key: &VersionState<key_kind::Ticket>,
        payload: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        Ok(js_sys::Uint8Array::new(&js!(self.js.encrypt(
            &algorithm.to_js()?,
            &version_handle(&self.js, &key.name, key.number).await?,
            &js_sys::Uint8Array::from(payload),
        )))
        .to_vec())
    }

    /// Decrypt a payload using a ticket-key version.
    ///
    /// # Errors
    /// Returns an error if the key service cannot decrypt the payload.
    pub async fn decrypt(
        &self,
        algorithm: EncryptAlgorithm<'_>,
        key: &VersionState<key_kind::Ticket>,
        payload: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        Ok(js_sys::Uint8Array::new(&js!(self.js.decrypt(
            &algorithm.to_js()?,
            &version_handle(&self.js, &key.name, key.number).await?,
            &js_sys::Uint8Array::from(payload),
        )))
        .to_vec())
    }

    /// Read and validate the versions of a logical key according to its kind.
    ///
    /// # Errors
    /// Returns an error if the key is missing, the key service fails, or a version is invalid.
    pub async fn versions<Kind: KeyKind>(
        &self,
        key_name: &str,
    ) -> Result<Vec<VersionState<Kind>>, KeyServiceError> {
        let promise = match self.js.versions(key_name) {
            Ok(promise) => promise,
            Err(error) if is_missing_key(&error) => {
                return Err(KeyServiceError::KeyNotFound);
            }
            Err(error) => return Err(rpc_error("versions", &error).into()),
        };
        match JsFuture::from(promise).await {
            Ok(versions) => Ok(version_states(key_name, &as_array(versions)?)?),
            Err(error) if is_missing_key(&error) => Err(KeyServiceError::KeyNotFound),
            Err(error) => Err(rpc_error("versions", &error).into()),
        }
    }
}

pub struct EncryptAlgorithm<'s> {
    pub name: &'s str,
    pub iv: &'s [u8],
    pub aad: &'s [u8],
    pub tag_len: u8,
}

impl EncryptAlgorithm<'_> {
    fn to_js(&self) -> Result<JsValue, worker::Error> {
        let algorithm = js_sys::Object::new();
        js!(algorithm.name = JsValue::from_str(self.name));
        js!(algorithm.iv = js_sys::Uint8Array::from(self.iv));
        js!(algorithm.additionalData = js_sys::Uint8Array::from(self.aad));
        js!(algorithm.tagLength = JsValue::from_f64(f64::from(self.tag_len)));
        Ok(algorithm.into())
    }
}

fn version_number(value: &JsValue) -> Result<VersionNumber, KeyServiceError> {
    let number = value
        .as_f64()
        .filter(|n| n.is_finite() && n.fract() == 0.0 && *n > 0.0 && *n <= f64::from(u32::MAX))
        .ok_or_else(|| {
            KeyServiceError::Internal("key service returned an invalid version".into())
        })?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    NonZeroU32::new(number as u32)
        .map(VersionNumber)
        .ok_or_else(|| KeyServiceError::Internal("key service returned an invalid version".into()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUsage {
    SingingVerify,
    Verify,
    EncryptDecrypt,
    Decrypt,
    /// A ticket-key version with no usages.
    Retired,
}

impl KeyUsage {
    #[must_use]
    pub fn decrypt(self) -> bool {
        matches!(self, KeyUsage::Decrypt | KeyUsage::EncryptDecrypt)
    }

    fn as_js(self) -> js_sys::Array {
        match self {
            KeyUsage::SingingVerify => {
                js_sys::Array::of2(&JsValue::from_str("sign"), &JsValue::from_str("verify"))
            }
            KeyUsage::Verify => js_sys::Array::of1(&JsValue::from_str("verify")),
            KeyUsage::EncryptDecrypt => {
                js_sys::Array::of2(&JsValue::from_str("encrypt"), &JsValue::from_str("decrypt"))
            }
            KeyUsage::Decrypt => js_sys::Array::of1(&JsValue::from_str("decrypt")),
            KeyUsage::Retired => js_sys::Array::new(),
        }
    }
}

pub mod key_kind {
    use super::KeyUsage;

    pub struct Signing();

    impl KeyKind for Signing {
        fn usages(usages: &[String]) -> Option<KeyUsage> {
            let sign = usages.iter().any(|usage| usage == "sign");
            let verify = usages.iter().any(|usage| usage == "verify");
            match (usages.len(), sign, verify) {
                (2, true, true) => Some(KeyUsage::SingingVerify),
                (1, false, true) => Some(KeyUsage::Verify),
                _ => None,
            }
        }
    }
    pub struct Ticket();
    impl KeyKind for Ticket {
        fn usages(usages: &[String]) -> Option<KeyUsage> {
            let encrypt = usages.iter().any(|usage| usage == "encrypt");
            let decrypt = usages.iter().any(|usage| usage == "decrypt");
            match (usages.len(), encrypt, decrypt) {
                (2, true, true) => Some(KeyUsage::EncryptDecrypt),
                (1, false, true) => Some(KeyUsage::Decrypt),
                (0, false, false) => Some(KeyUsage::Retired),
                _ => None,
            }
        }
    }

    pub trait KeyKind {
        fn usages(usages: &[String]) -> Option<KeyUsage>;
    }
}
pub use key_kind::KeyKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionState<Kind> {
    pub name: Rc<str>,
    pub number: VersionNumber,
    pub usage: KeyUsage,
    _kind: PhantomData<Kind>,
}

impl<Kind: KeyKind> VersionState<Kind> {
    /// Construct a version state from the key service's usage strings.
    ///
    /// # Errors
    /// Returns an error if the usages are invalid for this key kind.
    pub fn new(
        name: Rc<str>,
        number: VersionNumber,
        usages: &[String],
    ) -> Result<Self, KeyServiceError> {
        let usage = Kind::usages(usages).ok_or_else(|| {
            KeyServiceError::Internal(format!(
                "key service key {name} version {number} has invalid usages for its role: {usages:?}"
            ))
        })?;
        Ok(Self {
            name,
            number,
            usage,
            _kind: PhantomData,
        })
    }
}

fn version_states<Kind: KeyKind>(
    name: &str,
    versions: &js_sys::Array,
) -> Result<Vec<VersionState<Kind>>, KeyServiceError> {
    let mut states = Vec::with_capacity(versions.length() as usize);
    let name: Rc<str> = name.into();
    for version in versions.iter() {
        let number = version_number(&js!(version.version))?;
        let usages = as_array(js!(version.usages))?
            .iter()
            .map(|usage| {
                usage.as_string().ok_or_else(|| {
                    KeyServiceError::Internal("key usage was not a string or utf8".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        states.push(VersionState::new(Rc::clone(&name), number, &usages)?);
    }
    states.sort_by_key(|s| s.number);
    Ok(states)
}

async fn version_handle(
    keyring: &JsKeyring,
    key_name: &str,
    version: VersionNumber,
) -> Result<JsValue, worker::Error> {
    let opts = js_sys::Object::new();
    js!(opts.version = JsValue::from_f64(f64::from(version.0.get())));
    Ok(js!(keyring.get_version(key_name, &opts)))
}

pub struct KeyServiceSigner {
    pub keyring: Keyring,
    pub version: VersionState<key_kind::Signing>,
    pub handle: JsValue,
    pub public_key_der: Vec<u8>,
    pub name: signed_note::KeyName,
    pub key_id: u32,
    pub algorithm: KeyServiceAlgorithm,
}

pub enum KeyServiceAlgorithm {
    Ed25519,
    MlDsa44(MlDsaVerifyingKey<MlDsa44>),
}

fn parse_public_key(
    der: &[u8],
    name: &signed_note::KeyName,
) -> Result<(KeyServiceAlgorithm, u32), KeyServiceError> {
    if let Ok(key) = VerifyingKey::from_public_key_der(der) {
        return Ok((
            KeyServiceAlgorithm::Ed25519,
            compute_key_id(name, &[SignatureType::CosignatureV1 as u8], &key.to_bytes()),
        ));
    }
    let key = MlDsaVerifyingKey::<MlDsa44>::from_public_key_der(der).map_err(|e| {
        KeyServiceError::InvalidArgument(format!(
            "key service public key is neither Ed25519 nor ML-DSA-44: {e}"
        ))
    })?;
    let id = compute_key_id(
        name,
        &[SignatureType::MlDsa44 as u8],
        key.encode().as_slice(),
    );
    Ok((KeyServiceAlgorithm::MlDsa44(key), id))
}

fn signing_algorithm(algorithm: &KeyServiceAlgorithm) -> JsValue {
    match algorithm {
        KeyServiceAlgorithm::Ed25519 => JsValue::from_str("Ed25519"),
        // key service signs ML-DSA-44 with an empty context and rejects a `context`
        // property, even when its value is an empty Uint8Array.
        KeyServiceAlgorithm::MlDsa44(_) => JsValue::from_str("ML-DSA-44"),
    }
}

fn is_missing_key(error: &JsValue) -> bool {
    js_sys::Reflect::get(error, &JsValue::from_str("message"))
        .ok()
        .and_then(|value| value.as_string())
        .or_else(|| error.as_string())
        .as_deref()
        .is_some_and(missing_key_message)
}

fn missing_key_message(message: &str) -> bool {
    message.contains("key not found:")
}

#[cfg(test)]
mod tests {
    use super::{KeyUsage, VersionState, call, key_kind, missing_key_message, property, rpc_error};

    use crate::key_service::VersionNumber;
    use std::{num::NonZeroU32, rc::Rc};
    use worker::{js_sys, wasm_bindgen::JsValue};

    #[test]
    fn js_accepts_expression_receivers() {
        // Compile the expansions without executing JS operations on the native test runner.
        async fn check(signer: &super::KeyServiceSigner) -> Result<(), worker::Error> {
            struct Wrapper<'a> {
                signer: &'a super::KeyServiceSigner,
            }
            let wrapper = Wrapper { signer };
            let _ = js!(signer.keyring.js.get_default("key"));
            let _ = js!(wrapper.signer.handle.privateKey);
            let _ = js!((signer.handle.clone()).privateKey);
            js!(wrapper.signer.handle.version = JsValue::TRUE);
            js!((worker::js_sys::Object::new()).version = JsValue::TRUE);
            Ok(())
        }
        let _ = check;
    }

    fn n(x: u32) -> VersionNumber {
        VersionNumber(NonZeroU32::new(x).unwrap())
    }

    #[test]
    fn missing_key_message_recognizes_any_logical_key() {
        assert!(missing_key_message("key not found: witness"));
        assert!(missing_key_message("key not found: other"));
        assert!(!missing_key_message("keyring not found"));
        assert!(!missing_key_message("key service unavailable"));
    }

    #[test]
    fn version_usages_follow_their_key_role() {
        fn state<Kind: super::KeyKind>(
            usages: &[&str],
        ) -> Result<VersionState<Kind>, super::KeyServiceError> {
            VersionState::<Kind>::new(
                Rc::from("test-key"),
                n(1),
                &usages
                    .iter()
                    .map(|usage| (*usage).to_owned())
                    .collect::<Vec<_>>(),
            )
        }
        assert_eq!(
            state::<key_kind::Signing>(&["sign", "verify"])
                .unwrap()
                .usage,
            KeyUsage::SingingVerify
        );
        assert_eq!(
            state::<key_kind::Signing>(&["verify", "sign"])
                .unwrap()
                .usage,
            KeyUsage::SingingVerify
        );
        assert_eq!(
            state::<key_kind::Signing>(&["verify"]).unwrap().usage,
            KeyUsage::Verify
        );
        assert_eq!(
            state::<key_kind::Ticket>(&["encrypt", "decrypt"])
                .unwrap()
                .usage,
            KeyUsage::EncryptDecrypt
        );
        assert_eq!(
            state::<key_kind::Ticket>(&["decrypt", "encrypt"])
                .unwrap()
                .usage,
            KeyUsage::EncryptDecrypt
        );
        assert_eq!(
            state::<key_kind::Ticket>(&["decrypt"]).unwrap().usage,
            KeyUsage::Decrypt
        );
        assert_eq!(
            state::<key_kind::Ticket>(&[]).unwrap().usage,
            KeyUsage::Retired
        );
        for usages in [
            vec![],
            vec!["sign"],
            vec!["encrypt"],
            vec!["decrypt"],
            vec!["sign", "encrypt"],
            vec!["sign", "verify", "encrypt"],
            vec!["verify", "verify"],
            vec!["sign", "verify", "verify"],
            vec!["verify", "other"],
        ] {
            assert!(state::<key_kind::Signing>(&usages).is_err(), "{usages:?}");
        }
        for usages in [
            vec!["sign"],
            vec!["verify"],
            vec!["encrypt"],
            vec!["sign", "verify"],
            vec!["encrypt", "encrypt"],
            vec!["decrypt", "decrypt"],
            vec!["encrypt", "decrypt", "decrypt"],
            vec!["decrypt", "other"],
        ] {
            assert!(state::<key_kind::Ticket>(&usages).is_err(), "{usages:?}");
        }
    }
}
