// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! key-service-backed Ed25519 and ML-DSA-44 cosigners. Key handles never contain private material.
//! key service RPC is intentionally isolated here: the public C2SP crates remain
//! independent of the Workers runtime.

mod rotation;

use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey as _};
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature, MlDsa44, VerifyingKey as MlDsaVerifyingKey,
};
use signed_note::{self, NoteSignature, NoteVerifier, SignatureType, compute_key_id};
use tlog_checkpoint::{CheckpointText, UnixTimestampMillis};
use tlog_core::{EMPTY_HASH, Hash, Subtree};
use tlog_cosignature::{
    SubtreeV1NoteVerifier,
    subtree_v1::{build_cosigned_message, checkpoint_cosignature},
};
use worker::{Env, js_sys, wasm_bindgen, wasm_bindgen_futures::JsFuture};

use std::num::NonZeroU32;
use wasm_bindgen::{JsCast as _, JsValue};

#[wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    type Keyring;
    #[wasm_bindgen(method, catch, js_name = create)]
    fn create_key(this: &Keyring, name: &str, algorithm: &str) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = versions)]
    fn versions(this: &Keyring, name: &str) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = get)]
    fn get_version(this: &Keyring, name: &str, opts: &JsValue) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = exportKey)]
    fn export_key(this: &Keyring, format: &str, key: &JsValue) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = sign)]
    fn sign(
        this: &Keyring,
        algorithm: &JsValue,
        key: &JsValue,
        data: &js_sys::Uint8Array,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = encrypt)]
    fn encrypt(
        this: &Keyring,
        algorithm: &JsValue,
        key: &JsValue,
        data: &js_sys::Uint8Array,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = decrypt)]
    fn decrypt(
        this: &Keyring,
        algorithm: &JsValue,
        key: &JsValue,
        data: &js_sys::Uint8Array,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = get)]
    fn get_default(this: &Keyring, name: &str) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = details)]
    fn details(this: &Keyring, key: &JsValue) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = newVersion)]
    fn new_version(this: &Keyring, name: &str, opts: &JsValue) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = setDefaultVersion)]
    fn set_default_version(
        this: &Keyring,
        name: &str,
        version: u32,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = updateVersion)]
    fn update_version(
        this: &Keyring,
        name: &str,
        version: u32,
        patch: &JsValue,
    ) -> Result<js_sys::Promise, JsValue>;
}

#[derive(Debug)]
pub(crate) enum KeyServiceError {
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
    ($receiver:ident.$field:tt.$method:ident($($arg:expr),* $(,)?)) => {
        call(stringify!($method), $receiver.$field.$method($($arg),*))
    };
    ($receiver:ident.$method:ident($($arg:expr),* $(,)?)) => {
        call(stringify!($method), $receiver.$method($($arg),*)).await?
    };
    ($receiver:ident.$field:ident) => {
        property(&$receiver, stringify!($field))?
    };
    ($receiver:ident.$field:ident = $value:expr) => {
        js_sys::Reflect::set(&$receiver, &JsValue::from_str(stringify!($field)), &$value)
            .map_err(|error| rpc_error(stringify!($field), &error))?;
    };
}

fn keyring(env: &Env) -> Result<Keyring, KeyServiceError> {
    let env_js = env.as_ref();
    let binding = js!(env_js.KEY_SERVICE);
    if binding.is_undefined() || binding.is_null() {
        return Err(KeyServiceError::KeyServiceNotEnabled);
    }
    Ok(binding.unchecked_into())
}

fn version_number(value: &JsValue) -> Result<NonZeroU32, KeyServiceError> {
    let number = value
        .as_f64()
        .filter(|n| n.is_finite() && n.fract() == 0.0 && *n > 0.0 && *n <= f64::from(u32::MAX))
        .ok_or_else(|| {
            KeyServiceError::Internal("key service returned an invalid version".into())
        })?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    NonZeroU32::new(number as u32)
        .ok_or_else(|| KeyServiceError::Internal("key service returned an invalid version".into()))
}

// The header separates AES-GCM tickets from the unversioned local format and
// authenticates the version used to decrypt each ticket.
const TICKET_PREFIX: &[u8; 16] = b"azul-ticket-v1\0\0";
const TICKET_NONCE_LEN: usize = 12;
const TICKET_TAG_LEN: usize = 16;
const TICKET_HEADER_LEN: usize = TICKET_PREFIX.len() + 4;

pub(crate) fn is_service_ticket(ticket: &[u8]) -> bool {
    ticket.starts_with(TICKET_PREFIX)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigningKeyName {
    Mirror,
    Witness,
}

impl SigningKeyName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mirror => "MIRROR_SIGNING_KEY",
            Self::Witness => "WITNESS_SIGNING_KEY",
        }
    }
}

impl std::fmt::Display for SigningKeyName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyName {
    Ticket,
    SigningKey(SigningKeyName),
}

impl KeyName {
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyName::Ticket => "MIRROR_TICKET_KEY",
            KeyName::SigningKey(signing_key_name) => signing_key_name.as_str(),
        }
    }
}

impl From<SigningKeyName> for KeyName {
    fn from(value: SigningKeyName) -> Self {
        Self::SigningKey(value)
    }
}

impl std::fmt::Display for KeyName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
    EncryptDecrypt,
    Decrypt,
    /// Any version without decrypt permission, including an inert version.
    Retired,
}

fn ticket_state(
    mut usages: impl Iterator<Item = Result<String, KeyServiceError>>,
) -> Result<State, KeyServiceError> {
    let (encrypting, decrypting) =
        usages.try_fold((false, false), |(encrypting, decrypting), usage| {
            let usage = usage?;
            Ok::<_, KeyServiceError>((
                encrypting || usage == "encrypt",
                decrypting || usage == "decrypt",
            ))
        })?;
    Ok(match (encrypting, decrypting) {
        (true, true) => State::EncryptDecrypt,
        (false, true) => State::Decrypt,
        _ => State::Retired,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TicketVersionState {
    number: NonZeroU32,
    state: State,
}

impl TicketVersionState {
    const fn new(number: NonZeroU32, state: State) -> Self {
        Self { number, state }
    }
}

fn ticket_version_states(
    versions: &js_sys::Array,
) -> Result<Vec<TicketVersionState>, KeyServiceError> {
    let mut states = Vec::with_capacity(versions.length() as usize);
    for version in versions.iter() {
        let number = version_number(&js!(version.version))?;
        let state = ticket_state(as_array(js!(version.usages))?.iter().map(|value| {
            value.as_string().ok_or_else(|| {
                KeyServiceError::Internal("ticket key usage was not a string or utf8".into())
            })
        }))?;
        states.push(TicketVersionState::new(number, state));
    }
    sort_ticket_versions(states)
}

fn sort_ticket_versions(
    mut states: Vec<TicketVersionState>,
) -> Result<Vec<TicketVersionState>, KeyServiceError> {
    states.sort_unstable_by_key(|state| state.number);
    if !states
        .last()
        .is_some_and(|version| version.state == State::EncryptDecrypt)
    {
        return Err(KeyServiceError::Internal(
            "key service ticket key has no usable newest version".into(),
        ));
    }
    Ok(states)
}

fn ticket_parts(ticket: &[u8]) -> Result<(NonZeroU32, &[u8], &[u8]), KeyServiceError> {
    if !is_service_ticket(ticket)
        || ticket.len() < TICKET_HEADER_LEN + TICKET_NONCE_LEN + TICKET_TAG_LEN
    {
        return Err(KeyServiceError::InvalidArgument(
            "invalid key service ticket".into(),
        ));
    }
    const VERSION_RANGE: std::ops::Range<usize> = {
        assert!(
            TICKET_HEADER_LEN - TICKET_PREFIX.len() == std::mem::size_of::<u32>(),
            "Version range is not the size of a u32"
        );
        TICKET_PREFIX.len()..TICKET_HEADER_LEN
    };
    let version = u32::from_be_bytes(
        ticket[VERSION_RANGE]
            .try_into()
            .expect("this never panics due to the static assertion"),
    );
    Ok((
        NonZeroU32::new(version)
            .ok_or_else(|| KeyServiceError::Internal("invalid ticket version".to_string()))?,
        &ticket[TICKET_HEADER_LEN..TICKET_HEADER_LEN + TICKET_NONCE_LEN],
        &ticket[TICKET_HEADER_LEN + TICKET_NONCE_LEN..],
    ))
}

fn ticket_algorithm(nonce: &[u8], aad: &[u8]) -> Result<JsValue, worker::Error> {
    let algorithm = js_sys::Object::new();
    js!(algorithm.name = JsValue::from_str("AES-GCM"));
    js!(algorithm.iv = js_sys::Uint8Array::from(nonce));
    js!(algorithm.additionalData = js_sys::Uint8Array::from(aad));
    js!(algorithm.tagLength = JsValue::from_f64(128.0));
    Ok(algorithm.into())
}

fn ticket_aad(header: &[u8], origin: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + origin.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(origin);
    aad
}

/// Issue a versioned ticket using the current symmetric key-service version.
/// The version and origin are authenticated as associated data.
pub(crate) async fn seal_ticket(
    env: &Env,
    payload: &[u8],
    origin: &[u8],
) -> Result<Vec<u8>, KeyServiceError> {
    let ring = keyring(env)?;
    let versions = ring.ticket_versions().await?;
    let latest = versions
        .last()
        .ok_or_else(|| KeyServiceError::Internal("ticket key has no versions".into()))?;
    let key = version_handle(&ring, const { KeyName::Ticket.as_str() }, latest.number).await?;
    if !as_array(js!(key.usages))?
        .iter()
        .any(|value| value.as_string().as_deref() == Some("decrypt"))
    {
        return Err(KeyServiceError::Internal(
            "tried to encrypt with a ticket key that can't decrypt".into(),
        ));
    }
    let mut header = Vec::from(TICKET_PREFIX.as_slice());
    header.extend_from_slice(&latest.number.get().to_be_bytes());
    let mut nonce = [0u8; TICKET_NONCE_LEN];
    getrandom_03::fill(&mut nonce)
        .map_err(|error| worker::Error::from(format!("ticket nonce: {error}")))?;
    let aad = ticket_aad(&header, origin);
    let algorithm = ticket_algorithm(&nonce, &aad)?;
    let ciphertext = js_sys::Uint8Array::new(&js!(ring.encrypt(
        &algorithm,
        &key,
        &js_sys::Uint8Array::from(payload)
    )))
    .to_vec();
    let mut ticket = header;
    ticket.extend_from_slice(&nonce);
    ticket.extend_from_slice(&ciphertext);
    Ok(ticket)
}

/// Only versioned tickets are opened here. Never use the current default to
/// open: tickets must survive a key-service default-version change.
pub(crate) async fn open_ticket(
    env: &Env,
    ticket: &[u8],
    origin: &[u8],
) -> Result<Vec<u8>, KeyServiceError> {
    // this must not be moved down as it checks if the key service is available before checking if
    // the ticket is valid
    let ring = keyring(env)?;
    let (version, nonce, ciphertext) = ticket_parts(ticket)?;
    let header = &ticket[..TICKET_HEADER_LEN];
    if !ring
        .ticket_versions()
        .await?
        .iter()
        .any(|state| state.number == version && state.state != State::Retired)
    {
        return Err(KeyServiceError::KeyNotFound);
    }
    let key = version_handle(&ring, const { KeyName::Ticket.as_str() }, version).await?;
    let algorithm = ticket_algorithm(nonce, &ticket_aad(header, origin))?;
    Ok(js_sys::Uint8Array::new(&js!(ring.decrypt(
        &algorithm,
        &key,
        &js_sys::Uint8Array::from(ciphertext)
    )))
    .to_vec())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VersionState {
    number: NonZeroU32,
    signing: bool,
}

impl VersionState {
    fn new(
        name: SigningKeyName,
        number: NonZeroU32,
        usages: &[String],
    ) -> Result<Self, KeyServiceError> {
        let signing = usages.iter().any(|usage| usage == "sign");
        let verifying = usages.iter().any(|usage| usage == "verify");
        // Only an explicitly verify-only version represents retirement. Empty
        // or unexpected usages are not silently interpreted as retired keys.
        if !signing && !verifying {
            return Err(KeyServiceError::Internal(format!(
                "key service key {name} version {number} must allow signing or be verify-only"
            )));
        }
        Ok(Self { number, signing })
    }
}

fn version_states(
    name: SigningKeyName,
    versions: &js_sys::Array,
) -> Result<Vec<VersionState>, KeyServiceError> {
    let mut states = Vec::with_capacity(versions.length() as usize);
    for version in versions.iter() {
        let number = version_number(&js!(version.version))?;
        let usages = as_array(js!(version.usages))?
            .iter()
            .map(|usage| {
                usage.as_string().ok_or_else(|| {
                    KeyServiceError::Internal("singing key usage was not a string or utf8".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        states.push(VersionState::new(name, number, &usages)?);
    }
    states.sort_by_key(|s| s.number);
    if !states.iter().any(|state| state.signing) {
        return Err(KeyServiceError::Internal(format!(
            "key service key {name} has no signing versions"
        )));
    }
    Ok(states)
}

/// Rust-facing rotation operations; all key service JavaScript interop stays here.
impl Keyring {
    pub(super) async fn get_ticket_default(&self) -> Result<JsValue, worker::Error> {
        Ok(js!(self.get_default(const { KeyName::Ticket.as_str() })))
    }

    pub(super) async fn current_ticket_default(&self) -> Result<NonZeroU32, KeyServiceError> {
        let key = self.get_ticket_default().await?;
        let details = js!(self.details(&key));
        version_number(&js!(details.version))
    }

    async fn ticket_versions(&self) -> Result<Vec<TicketVersionState>, KeyServiceError> {
        let promise = match self.versions(const { KeyName::Ticket.as_str() }) {
            Ok(promise) => promise,
            Err(error) if is_missing_key(&error) => {
                return Err(KeyServiceError::KeyNotFound);
            }
            Err(error) => return Err(rpc_error("versions", &error).into()),
        };
        match JsFuture::from(promise).await {
            Ok(versions) => Ok(ticket_version_states(&as_array(versions)?)?),
            Err(error) if is_missing_key(&error) => Err(KeyServiceError::KeyNotFound),
            Err(error) => Err(rpc_error("versions", &error).into()),
        }
    }

    pub(super) async fn create_ticket_key(&self) -> Result<(), worker::Error> {
        js!(self.create_key(const { KeyName::Ticket.as_str() }, "AES_256_GCM"));
        Ok(())
    }

    pub(super) async fn new_ticket_version(&self) -> Result<NonZeroU32, KeyServiceError> {
        let opts = js_sys::Object::new();
        let usages =
            js_sys::Array::of2(&JsValue::from_str("encrypt"), &JsValue::from_str("decrypt"));
        js!(opts.usages = usages);
        js!(opts.extractable = JsValue::FALSE);
        version_number(&js!(
            self.new_version(const { KeyName::Ticket.as_str() }, &opts)
        ))
    }

    pub(super) async fn retire_ticket_version(
        &self,
        version: NonZeroU32,
    ) -> Result<(), worker::Error> {
        let patch = js_sys::Object::new();
        // The key-service API has no delete-version operation. An inert
        // version cannot encrypt or decrypt new or existing tickets.
        let usages = js_sys::Array::new();
        js!(patch.usages = usages);
        js!(self.update_version(const { KeyName::Ticket.as_str() }, version.get(), &patch));
        Ok(())
    }
    pub(super) async fn current_default(
        &self,
        name: SigningKeyName,
    ) -> Result<NonZeroU32, KeyServiceError> {
        let pair = js!(self.get_default(name.as_str()));
        if js!(pair.privateKey).is_undefined() {
            return Err(KeyServiceError::InvalidArgument(
                "expected an asymmetric key service signing key".into(),
            ));
        }
        let details = js!(self.details(&pair));
        version_number(&js!(details.version))
    }

    /// Only an absent logical key is treated as uninitialized. All other
    /// key-service failures remain errors so operator requests can be retried.
    pub(super) async fn signing_key_exists(
        &self,
        name: SigningKeyName,
    ) -> Result<bool, KeyServiceError> {
        let promise = match self.versions(name.as_str()) {
            Ok(promise) => promise,
            Err(error) if is_missing_key(&error) => return Ok(false),
            Err(error) => return Err(rpc_error("versions", &error).into()),
        };
        match JsFuture::from(promise).await {
            Ok(_) => Ok(true),
            Err(error) if is_missing_key(&error) => Ok(false),
            Err(error) => Err(rpc_error("versions", &error).into()),
        }
    }

    pub(super) async fn create_signing_key(
        &self,
        name: SigningKeyName,
        algorithm: &str,
    ) -> Result<(), worker::Error> {
        js!(self.create_key(name.as_str(), algorithm));
        Ok(())
    }

    pub(super) async fn key_versions(
        &self,
        name: SigningKeyName,
    ) -> Result<Vec<VersionState>, KeyServiceError> {
        version_states(name, &as_array(js!(self.versions(name.as_str())))?)
    }

    pub(super) async fn new_signing_version(
        &self,
        name: SigningKeyName,
    ) -> Result<NonZeroU32, KeyServiceError> {
        // Set usages atomically with creation: no inert or verify-only version.
        let opts = js_sys::Object::new();
        let usages = js_sys::Array::of2(&JsValue::from_str("sign"), &JsValue::from_str("verify"));
        js!(opts.usages = usages);
        js!(opts.extractable = JsValue::TRUE);
        version_number(&js!(self.new_version(name.as_str(), &opts)))
    }

    pub(super) async fn promote(
        &self,
        name: impl Into<KeyName>,
        version: NonZeroU32,
    ) -> Result<(), worker::Error> {
        js!(self.set_default_version(name.into().as_str(), version.get()));
        Ok(())
    }

    pub(super) async fn retire(
        &self,
        name: SigningKeyName,
        version: NonZeroU32,
    ) -> Result<(), worker::Error> {
        let patch = js_sys::Object::new();
        let usages = js_sys::Array::of1(&JsValue::from_str("verify"));
        js!(patch.usages = usages);
        // Preserve public-key export for verification of existing signatures.
        js!(self.update_version(name.as_str(), version.get(), &patch));
        Ok(())
    }
}

async fn version_handle(
    keyring: &Keyring,
    key_name: &str,
    version: NonZeroU32,
) -> Result<JsValue, worker::Error> {
    let opts = js_sys::Object::new();
    js!(opts.version = JsValue::from_f64(f64::from(version.get())));
    Ok(js!(keyring.get_version(key_name, &opts)))
}

pub(crate) struct KeyServiceSigner {
    pub(crate) key_name: SigningKeyName,
    pub(crate) version: NonZeroU32,
    pub(crate) public_key_der: Vec<u8>,
    pub(crate) name: signed_note::KeyName,
    pub(crate) key_id: u32,
    algorithm: KeyServiceAlgorithm,
}

enum KeyServiceAlgorithm {
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

fn cosignature(
    name: &signed_note::KeyName,
    key_id: u32,
    seconds: u64,
    signature: &[u8],
) -> Result<NoteSignature, KeyServiceError> {
    if signature.len() != 64 {
        return Err(KeyServiceError::InvalidArgument(
            "key service returned an invalid Ed25519 signature length".to_string(),
        ));
    }
    let mut payload = seconds.to_be_bytes().to_vec();
    payload.extend_from_slice(signature);
    Ok(NoteSignature::new(name.clone(), key_id, payload))
}

/// Discover sign-enabled versions, excluding explicitly retired (verify-only)
/// versions. malformed versions and all other key service failures (except KeyServiceNotEnabled)
/// are errors, not a reason to use local keys.
pub(crate) async fn load(
    env: &Env,
    key_name: SigningKeyName,
    identity: &str,
) -> Result<Vec<KeyServiceSigner>, KeyServiceError> {
    let ring = keyring(env)?;
    let versions_promise = match ring.versions(key_name.as_str()) {
        Ok(promise) => promise,
        Err(error) if is_missing_key(&error) => return Err(KeyServiceError::KeyNotFound),
        Err(error) => return Err(rpc_error("versions", &error).into()),
    };
    let versions = match JsFuture::from(versions_promise).await {
        Ok(versions) => version_states(key_name, &as_array(versions)?)?,
        Err(error) if is_missing_key(&error) => return Err(KeyServiceError::KeyNotFound),
        Err(error) => return Err(rpc_error("versions", &error).into()),
    };
    let name = signed_note::KeyName::new(identity.to_owned()).map_err(|e| {
        KeyServiceError::InvalidArgument(format!("invalid key service identity name: {e:?}"))
    })?;
    let mut signers = Vec::new();
    for version in versions.into_iter().filter(|version| version.signing) {
        let version_num = version.number;
        let pair = version_handle(&ring, key_name.as_str(), version_num).await?;
        let public = js!(pair.publicKey);
        if public.is_undefined() {
            return Err(KeyServiceError::InvalidArgument(
                "key service signing key is not an asymmetric key pair".into(),
            ));
        }
        let der = js_sys::Uint8Array::new(&js!(ring.export_key("spki", &public))).to_vec();
        let (algorithm, key_id) = parse_public_key(&der, &name)?;
        signers.push(KeyServiceSigner {
            key_name,
            version: version_num,
            public_key_der: der,
            name: name.clone(),
            key_id,
            algorithm,
        });
    }
    Ok(signers)
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

impl KeyServiceSigner {
    pub(crate) fn algorithm(&self) -> &'static str {
        match self.algorithm {
            KeyServiceAlgorithm::Ed25519 => "cosignature/v1",
            KeyServiceAlgorithm::MlDsa44(_) => "subtree/v1",
        }
    }

    pub(crate) fn subtree_verifier(&self) -> Option<Box<dyn NoteVerifier>> {
        match &self.algorithm {
            KeyServiceAlgorithm::Ed25519 => None,
            KeyServiceAlgorithm::MlDsa44(key) => Some(Box::new(SubtreeV1NoteVerifier::new(
                self.name.clone(),
                key.clone(),
            ))),
        }
    }

    pub(crate) fn supports_sign_subtree(&self) -> bool {
        matches!(self.algorithm, KeyServiceAlgorithm::MlDsa44(_))
    }

    async fn sign_raw(&self, env: &Env, message: &[u8]) -> Result<Vec<u8>, KeyServiceError> {
        let ring = keyring(env)?;
        let pair = version_handle(&ring, self.key_name.as_str(), self.version).await?;
        let private = js!(pair.privateKey);
        if private.is_undefined() {
            return Err(KeyServiceError::Internal(
                "key service signing key has no private handle".into(),
            ));
        }
        let bytes = js_sys::Uint8Array::from(message);
        Ok(js_sys::Uint8Array::new(&js!(ring.sign(
            &signing_algorithm(&self.algorithm),
            &private,
            &bytes
        )))
        .to_vec())
    }

    pub(crate) async fn sign_subtree(
        &self,
        env: &Env,
        origin: &str,
        subtree: &Subtree,
        hash: &Hash,
    ) -> Result<NoteSignature, KeyServiceError> {
        if !matches!(self.algorithm, KeyServiceAlgorithm::MlDsa44(_)) {
            return Err(KeyServiceError::InvalidArgument(
                "key service key does not support sign-subtree".to_string(),
            ));
        }
        let message =
            build_cosigned_message(&self.name, 0, origin, subtree.lo(), subtree.hi(), hash);
        let signature = self.sign_raw(env, &message).await?;
        ml_dsa_cosignature(&self.name, self.key_id, None, &signature)
    }

    pub(crate) async fn sign(
        &self,
        env: &Env,
        timestamp: UnixTimestampMillis,
        checkpoint: &CheckpointText,
    ) -> Result<NoteSignature, KeyServiceError> {
        let seconds = timestamp / 1000;
        match self.algorithm {
            KeyServiceAlgorithm::Ed25519 => {
                let mut message = format!("cosignature/v1\ntime {seconds}\n").into_bytes();
                message.extend(checkpoint.to_bytes());
                let signature = self.sign_raw(env, &message).await?;
                Ok(cosignature(&self.name, self.key_id, seconds, &signature)?)
            }
            KeyServiceAlgorithm::MlDsa44(_) => {
                if checkpoint.size() == 0 && checkpoint.hash() != &EMPTY_HASH {
                    return Err(KeyServiceError::InvalidArgument(
                        "invalid empty checkpoint hash".to_string(),
                    ));
                }
                let message = build_cosigned_message(
                    &self.name,
                    seconds,
                    checkpoint.origin(),
                    0,
                    checkpoint.size(),
                    checkpoint.hash(),
                );
                let signature = self.sign_raw(env, &message).await?;
                Ok(ml_dsa_cosignature(
                    &self.name,
                    self.key_id,
                    Some(seconds),
                    &signature,
                )?)
            }
        }
    }
}

fn check_ml_dsa_signature(signature: &[u8]) -> Result<(), KeyServiceError> {
    if signature.len() != core::mem::size_of::<MlDsaEncodedSignature<MlDsa44>>() {
        return Err(KeyServiceError::InvalidArgument(
            "key service returned an invalid ML-DSA-44 signature length".to_string(),
        ));
    }
    Ok(())
}

fn ml_dsa_cosignature(
    name: &signed_note::KeyName,
    key_id: u32,
    seconds: Option<u64>,
    signature: &[u8],
) -> Result<NoteSignature, KeyServiceError> {
    check_ml_dsa_signature(signature)?;
    let payload = seconds.map_or_else(
        || signature.to_vec(),
        |seconds| checkpoint_cosignature(seconds, signature),
    );
    Ok(NoteSignature::new(name.clone(), key_id, payload))
}

#[cfg(test)]
mod tests {
    use super::{
        KeyServiceAlgorithm, KeyServiceSigner, State, TICKET_NONCE_LEN, TICKET_PREFIX,
        TICKET_TAG_LEN, TicketVersionState, VersionState, cosignature, is_service_ticket,
        missing_key_message, ml_dsa_cosignature, parse_public_key, sort_ticket_versions,
        ticket_aad, ticket_parts, ticket_state,
    };

    use crate::key_service::SigningKeyName;
    use ed25519_dalek::SigningKey;
    use ml_dsa::{ExpandedSigningKey, MlDsa44};
    use pkcs8::EncodePublicKey as _;
    use std::num::NonZeroU32;
    use tlog_checkpoint::{CheckpointSigner as _, CheckpointText};
    use tlog_core::{Hash, Subtree};
    use tlog_cosignature::{
        CosignatureV1CheckpointSigner, SubtreeV1CheckpointSigner, SubtreeV1NoteVerifier,
        subtree_v1::build_cosigned_message,
    };

    fn n(x: u32) -> NonZeroU32 {
        NonZeroU32::new(x).unwrap()
    }

    #[test]
    fn ticket_state_tracks_encrypt_and_decrypt_usages() {
        let state = |usages: &[&str]| {
            ticket_state(usages.iter().map(|usage| Ok((*usage).to_owned()))).unwrap()
        };
        assert_eq!(state(&["encrypt", "decrypt"]), State::EncryptDecrypt);
        assert_eq!(state(&["decrypt"]), State::Decrypt);
        assert_eq!(state(&["encrypt"]), State::Retired);
        assert_eq!(state(&[]), State::Retired);
        assert_eq!(state(&["sign"]), State::Retired);
        assert_eq!(state(&["decrypt", "decrypt"]), State::Decrypt);
    }

    #[test]
    fn ticket_versions_are_sorted_without_deduplication() {
        let active = |number| TicketVersionState::new(number, State::EncryptDecrypt);
        let states = sort_ticket_versions(vec![active(n(3)), active(n(1)), active(n(2))]).unwrap();
        assert_eq!(
            states.iter().map(|state| state.number).collect::<Vec<_>>(),
            [n(1), n(2), n(3)]
        );
        let duplicates =
            sort_ticket_versions(vec![active(n(2)), active(n(1)), active(n(2))]).unwrap();
        assert_eq!(
            duplicates
                .iter()
                .map(|state| state.number)
                .collect::<Vec<_>>(),
            [n(1), n(2), n(2)]
        );
    }

    #[test]
    fn ticket_format_distinguishes_local_and_service_tickets() {
        let local = tlog_mirror::TicketSealer::new(&[42; 32]);
        let old_ticket = local.seal(b"signed note", b"example/log");
        assert!(!is_service_ticket(&old_ticket));
        assert_eq!(
            local.open(&old_ticket, b"example/log").unwrap(),
            b"signed note"
        );
        assert!(local.open(&old_ticket, b"other/log").is_err());

        let mut new_ticket = TICKET_PREFIX.to_vec();
        new_ticket.extend_from_slice(&7u32.to_be_bytes());
        new_ticket.extend_from_slice(&[0; TICKET_NONCE_LEN]);
        new_ticket.extend_from_slice(&[0; TICKET_TAG_LEN]);
        assert!(is_service_ticket(&new_ticket));
        let (version, nonce, ciphertext) = ticket_parts(&new_ticket).unwrap();
        assert_eq!(version, n(7));
        assert_eq!(nonce.len(), TICKET_NONCE_LEN);
        assert_eq!(ciphertext.len(), TICKET_TAG_LEN);
        assert_ne!(
            ticket_aad(&new_ticket[..20], b"example/log"),
            ticket_aad(&new_ticket[..20], b"other/log")
        );
        assert_ne!(
            ticket_aad(&new_ticket[..20], b"example/log"),
            ticket_aad(&new_ticket[..20], b"example/log2")
        );
        let mut other_header = new_ticket[..20].to_vec();
        other_header[19] ^= 1;
        assert_ne!(
            ticket_aad(&new_ticket[..20], b"example/log"),
            ticket_aad(&other_header, b"example/log")
        );
        assert!(ticket_parts(&new_ticket[..new_ticket.len() - 1]).is_err());
        new_ticket[TICKET_PREFIX.len()..20].fill(0);
        assert!(ticket_parts(&new_ticket).is_err());
        new_ticket[0] ^= 1;
        assert!(!is_service_ticket(&new_ticket));
    }

    #[test]
    fn key_service_signature_matches_local_cosignature_wire_format() {
        use ed25519_dalek::Signer as _;

        let key = SigningKey::from_bytes(&[7; 32]);
        let name = signed_note::KeyName::new("mirror.example".to_owned()).unwrap();
        let local = CosignatureV1CheckpointSigner::new(name.clone(), key.clone());
        let checkpoint = CheckpointText::from_bytes(
            b"example.com/log\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
        )
        .unwrap();
        let timestamp = 1_234_567_u64;
        let seconds = timestamp / 1000;
        let mut message = format!("cosignature/v1\ntime {seconds}\n").into_bytes();
        message.extend(checkpoint.to_bytes());
        let signature = key.sign(&message);
        let remote = cosignature(&name, local.key_id(), seconds, &signature.to_bytes()).unwrap();
        assert_eq!(remote, local.sign(timestamp, &checkpoint).unwrap());
        assert!(cosignature(&name, local.key_id(), seconds, &[0; 63]).is_err());
    }

    #[test]
    fn missing_key_message_recognizes_any_logical_key() {
        assert!(missing_key_message("key not found: witness"));
        assert!(missing_key_message("key not found: other"));
        assert!(!missing_key_message("keyring not found"));
        assert!(!missing_key_message("key service unavailable"));
    }

    #[test]
    fn verify_only_versions_are_retired() {
        let state = |usages: &[&str]| {
            VersionState::new(
                SigningKeyName::Mirror,
                n(1),
                &usages
                    .iter()
                    .map(|usage| (*usage).to_owned())
                    .collect::<Vec<_>>(),
            )
        };
        assert!(state(&["sign", "verify"]).unwrap().signing);
        assert!(!state(&["verify"]).unwrap().signing);
        assert!(state(&["sign"]).unwrap().signing);
        assert!(state(&[]).is_err());
        assert!(state(&["encrypt"]).is_err());
    }

    #[test]
    fn key_service_ml_dsa_checkpoint_and_subtree_match_local_signer() {
        let name = signed_note::KeyName::new("mirror.example".to_owned()).unwrap();
        let key = ExpandedSigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from([7; 32]));
        let der = key.verifying_key().to_public_key_der().unwrap();
        let (algorithm, key_id) = parse_public_key(der.as_bytes(), &name).unwrap();
        assert!(matches!(algorithm, KeyServiceAlgorithm::MlDsa44(_)));
        let key_service = KeyServiceSigner {
            key_name: SigningKeyName::Mirror,
            version: n(1),
            public_key_der: der.as_bytes().to_vec(),
            name: name.clone(),
            key_id,
            algorithm,
        };
        assert_eq!(key_service.algorithm(), "subtree/v1");
        assert!(key_service.supports_sign_subtree());
        let local = SubtreeV1CheckpointSigner::new(name.clone(), key.clone());
        assert_eq!(key_id, local.key_id());

        let checkpoint = CheckpointText::from_bytes(
            b"example.com/log\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
        )
        .unwrap();
        let seconds = 1234_u64;
        let message = build_cosigned_message(
            &name,
            seconds,
            checkpoint.origin(),
            0,
            checkpoint.size(),
            checkpoint.hash(),
        );
        // The Rust signer and key service use the same empty ML-DSA context.
        let signature = key.sign_deterministic(&message, b"").unwrap();
        let remote =
            ml_dsa_cosignature(&name, key_id, Some(seconds), signature.encode().as_slice())
                .unwrap();
        assert_eq!(remote, local.sign(seconds * 1000, &checkpoint).unwrap());
        assert!(
            key_service
                .subtree_verifier()
                .unwrap()
                .verify(&checkpoint.to_bytes(), remote.signature())
        );

        let subtree = Subtree::new(8, 16).unwrap();
        let hash = Hash([0x42; 32]);
        let message = build_cosigned_message(
            &name,
            0,
            checkpoint.origin(),
            subtree.lo(),
            subtree.hi(),
            &hash,
        );
        let signature = key.sign_deterministic(&message, b"").unwrap();
        let remote =
            ml_dsa_cosignature(&name, key_id, None, signature.encode().as_slice()).unwrap();
        assert_eq!(
            remote,
            local.sign_subtree(checkpoint.origin(), &subtree, &hash)
        );
        assert!(
            SubtreeV1NoteVerifier::new(name.clone(), key.verifying_key()).verify_subtree(
                checkpoint.origin(),
                &subtree,
                &hash,
                remote.signature()
            )
        );
        assert!(ml_dsa_cosignature(&name, key_id, None, &[0; 63]).is_err());
    }
}
