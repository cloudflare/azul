// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! key-service-backed Ed25519 and ML-DSA-44 cosigners. Key handles never contain private material.
//! key service RPC is intentionally isolated here: the public C2SP crates remain
//! independent of the Workers runtime.

use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey as _};
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature, MlDsa44, VerifyingKey as MlDsaVerifyingKey,
};
use signed_note::{KeyName, NoteSignature, NoteVerifier, SignatureType, compute_key_id};
use tlog_checkpoint::{CheckpointText, UnixTimestampMillis};
use tlog_core::{EMPTY_HASH, Hash, Subtree};
use tlog_cosignature::{
    SubtreeV1NoteVerifier,
    subtree_v1::{build_cosigned_message, checkpoint_cosignature},
};
use worker::{Env, Error, Result, js_sys, wasm_bindgen, wasm_bindgen_futures::JsFuture};

use wasm_bindgen::{JsCast as _, JsValue};

#[path = "key_service_rotation.rs"]
mod rotation;

#[wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    type Keyring;
    #[wasm_bindgen(method, catch, js_name = versions)]
    fn versions(this: &Keyring, name: &str) -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = get)]
    fn get_version(
        this: &Keyring,
        name: &str,
        opts: &JsValue,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = exportKey)]
    fn export_key(
        this: &Keyring,
        format: &str,
        key: &JsValue,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = sign)]
    fn sign(
        this: &Keyring,
        algorithm: &JsValue,
        key: &JsValue,
        data: &js_sys::Uint8Array,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = get)]
    fn get_default(this: &Keyring, name: &str) -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = details)]
    fn details(this: &Keyring, key: &JsValue) -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = newVersion)]
    fn new_version(
        this: &Keyring,
        name: &str,
        opts: &JsValue,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = setDefaultVersion)]
    fn set_default_version(
        this: &Keyring,
        name: &str,
        version: u32,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = updateVersion)]
    fn update_version(
        this: &Keyring,
        name: &str,
        version: u32,
        patch: &JsValue,
    ) -> std::result::Result<js_sys::Promise, JsValue>;
}

fn rpc_error(operation: &str, error: &JsValue) -> Error {
    Error::from(format!("key service {operation}: {error:?}"))
}

async fn call(
    operation: &str,
    promise: std::result::Result<js_sys::Promise, JsValue>,
) -> Result<JsValue> {
    JsFuture::from(promise.map_err(|e| rpc_error(operation, &e))?)
        .await
        .map_err(|e| rpc_error(operation, &e))
}

fn property(object: &JsValue, name: &str) -> Result<JsValue> {
    js_sys::Reflect::get(object, &JsValue::from_str(name)).map_err(|e| rpc_error(name, &e))
}

// Consume the returned JS value as part of converting it to a validated array.
#[allow(clippy::needless_pass_by_value)]
fn as_array(object: JsValue) -> Result<js_sys::Array, Error> {
    if !js_sys::Array::is_array(&object) {
        return Err(Error::from("key service returned invalid versions"));
    }
    Ok(js_sys::Array::from(&object))
}

macro_rules! js {
    ($receiver:ident.$field:tt.$method:ident($($arg:expr),* $(,)?)) => {
        call(stringify!($method), $receiver.$field.$method($($arg),*))
    };
    ($receiver:ident.$method:ident($($arg:expr),* $(,)?)) => {
        call(stringify!($method), $receiver.$method($($arg),*))
    };
    ($receiver:ident.$field:ident) => {
        property(&$receiver, stringify!($field))?
    };
    ($receiver:ident.$field:ident = $value:expr) => {
        js_sys::Reflect::set(&$receiver, &JsValue::from_str(stringify!($field)), &$value)
            .map_err(|error| rpc_error(stringify!($field), &error))?;
    };
}

fn keyring(env: &Env) -> Result<Keyring> {
    let env_js = env.as_ref();
    let binding = js!(env_js.KEY_SERVICE);
    if binding.is_undefined() || binding.is_null() {
        return Err(Error::from(
            "key service binding is required for key service signing",
        ));
    }
    Ok(binding.unchecked_into())
}

fn version_number(value: &JsValue) -> Result<u32> {
    let number = value
        .as_f64()
        .filter(|n| n.is_finite() && n.fract() == 0.0 && *n > 0.0 && *n <= f64::from(u32::MAX))
        .ok_or_else(|| Error::from("key service returned an invalid version"))?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(number as u32)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VersionState {
    number: u32,
    signing: bool,
}

impl VersionState {
    fn new(name: &str, number: u32, usages: &[String], extractable: bool) -> Result<Self> {
        if !extractable {
            return Err(Error::from(format!(
                "key service key {name} version {number} must have an exportable public key"
            )));
        }
        let signing = usages.iter().any(|usage| usage == "sign");
        // Only an explicitly verify-only version represents retirement. Empty
        // or unexpected usages are not silently interpreted as retired keys.
        if !signing && usages != ["verify"] {
            return Err(Error::from(format!(
                "key service key {name} version {number} must allow signing or be verify-only"
            )));
        }
        Ok(Self { number, signing })
    }
}

fn version_states(name: &str, versions: &js_sys::Array) -> Result<Vec<VersionState>> {
    let mut states = Vec::with_capacity(versions.length() as usize);
    for version in versions.iter() {
        let number = version_number(&js!(version.version))?;
        let usages = as_array(js!(version.usages))?
            .iter()
            .map(|usage| {
                usage.as_string().ok_or_else(|| {
                    Error::from(format!(
                        "key service key {name} version {number} has invalid usages"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let extractable = js!(version.extractable).as_bool() == Some(true);
        if states
            .last()
            .is_some_and(|previous: &VersionState| previous.number >= number)
        {
            return Err(Error::from(format!(
                "key service key {name} versions are not strictly increasing"
            )));
        }
        states.push(VersionState::new(name, number, &usages, extractable)?);
    }
    if !states.iter().any(|state| state.signing) {
        return Err(Error::from(format!(
            "key service key {name} has no signing versions"
        )));
    }
    Ok(states)
}

/// Rust-facing rotation operations; all key service JavaScript interop stays here.
impl Keyring {
    pub(super) async fn current_default(&self, name: &str) -> Result<u32> {
        let pair = js!(self.get_default(name)).await?;
        if js!(pair.privateKey).is_undefined() {
            return Err(Error::from(
                "expected an asymmetric key service signing key",
            ));
        }
        let details = js!(self.details(&pair)).await?;
        version_number(&js!(details.version))
    }

    pub(super) async fn key_versions(&self, name: &str) -> Result<Vec<VersionState>> {
        version_states(name, &as_array(js!(self.versions(name)).await?)?)
    }

    pub(super) async fn new_signing_version(&self, name: &str) -> Result<u32> {
        // Set usages atomically with creation: no inert or verify-only version.
        let opts = js_sys::Object::new();
        let usages = js_sys::Array::of2(&JsValue::from_str("sign"), &JsValue::from_str("verify"));
        js!(opts.usages = usages);
        js!(opts.extractable = JsValue::TRUE);
        version_number(&js!(self.new_version(name, &opts)).await?)
    }

    pub(super) async fn promote(&self, name: &str, version: u32) -> Result<()> {
        js!(self.set_default_version(name, version)).await?;
        Ok(())
    }

    pub(super) async fn retire(&self, name: &str, version: u32) -> Result<()> {
        let patch = js_sys::Object::new();
        let usages = js_sys::Array::of1(&JsValue::from_str("verify"));
        js!(patch.usages = usages);
        // Preserve public-key export for verification of existing signatures.
        js!(self.update_version(name, version, &patch)).await?;
        Ok(())
    }
}

async fn version_handle(keyring: &Keyring, name: &str, version: u32) -> Result<JsValue> {
    let opts = js_sys::Object::new();
    js!(opts.version = JsValue::from_f64(f64::from(version)));
    js!(keyring.get_version(name, &opts)).await
}

pub(crate) struct KeyServiceSigner {
    pub(crate) key_name: String,
    pub(crate) version: u32,
    pub(crate) public_key_der: Vec<u8>,
    pub(crate) name: KeyName,
    pub(crate) key_id: u32,
    algorithm: KeyServiceAlgorithm,
}

enum KeyServiceAlgorithm {
    Ed25519,
    MlDsa44(MlDsaVerifyingKey<MlDsa44>),
}

fn parse_public_key(der: &[u8], name: &KeyName) -> Result<(KeyServiceAlgorithm, u32)> {
    if let Ok(key) = VerifyingKey::from_public_key_der(der) {
        return Ok((
            KeyServiceAlgorithm::Ed25519,
            compute_key_id(name, &[SignatureType::CosignatureV1 as u8], &key.to_bytes()),
        ));
    }
    let key = MlDsaVerifyingKey::<MlDsa44>::from_public_key_der(der).map_err(|e| {
        Error::from(format!(
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
    name: &KeyName,
    key_id: u32,
    seconds: u64,
    signature: &[u8],
) -> Result<NoteSignature> {
    if signature.len() != 64 {
        return Err(Error::from(
            "key service returned an invalid Ed25519 signature length",
        ));
    }
    let mut payload = seconds.to_be_bytes().to_vec();
    payload.extend_from_slice(signature);
    Ok(NoteSignature::new(name.clone(), key_id, payload))
}

/// Discover sign-enabled versions, excluding explicitly retired (verify-only)
/// versions. `None` means the logical key does not exist; malformed versions
/// and all other key service failures are errors, not a reason to use local keys.
/// Do not cache key service versions across requests.
pub(crate) async fn load(
    env: &Env,
    key_name: &str,
    identity: &str,
) -> Result<Option<Vec<KeyServiceSigner>>> {
    let ring = keyring(env)?;
    let versions_promise = match ring.versions(key_name) {
        Ok(promise) => promise,
        Err(error) if is_missing_key(&error, key_name) => return Ok(None),
        Err(error) => return Err(rpc_error("versions", &error)),
    };
    let versions = match JsFuture::from(versions_promise).await {
        Ok(versions) => version_states(key_name, &as_array(versions)?)?,
        Err(error) if is_missing_key(&error, key_name) => return Ok(None),
        Err(error) => return Err(rpc_error("versions", &error)),
    };
    let name = KeyName::new(identity.to_owned())
        .map_err(|e| Error::from(format!("invalid key service identity name: {e:?}")))?;
    let mut signers = Vec::new();
    for version in versions.into_iter().filter(|version| version.signing) {
        let version_num = version.number;
        let pair = version_handle(&ring, key_name, version_num).await?;
        let public = js!(pair.publicKey);
        if public.is_undefined() {
            return Err(Error::from(
                "key service signing key is not an asymmetric key pair",
            ));
        }
        let der = js_sys::Uint8Array::new(&js!(ring.export_key("spki", &public)).await?).to_vec();
        let (algorithm, key_id) = parse_public_key(&der, &name)?;
        signers.push(KeyServiceSigner {
            key_name: key_name.to_owned(),
            version: version_num,
            public_key_der: der,
            name: name.clone(),
            key_id,
            algorithm,
        });
    }
    Ok(Some(signers))
}

fn is_missing_key(error: &JsValue, key_name: &str) -> bool {
    let message = js_sys::Reflect::get(error, &JsValue::from_str("message"))
        .ok()
        .and_then(|value| value.as_string())
        .or_else(|| error.as_string());
    message
        .as_deref()
        .is_some_and(|message| missing_key_message(message, key_name))
}

fn missing_key_message(message: &str, key_name: &str) -> bool {
    message == format!("key not found: {key_name}")
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

    async fn sign_raw(&self, env: &Env, message: &[u8]) -> Result<Vec<u8>> {
        let ring = keyring(env)?;
        let pair = version_handle(&ring, &self.key_name, self.version).await?;
        let private = js!(pair.privateKey);
        if private.is_undefined() {
            return Err(Error::from("key service signing key has no private handle"));
        }
        let bytes = js_sys::Uint8Array::from(message);
        Ok(js_sys::Uint8Array::new(
            &js!(ring.sign(&signing_algorithm(&self.algorithm), &private, &bytes)).await?,
        )
        .to_vec())
    }

    pub(crate) async fn sign_subtree(
        &self,
        env: &Env,
        origin: &str,
        subtree: &Subtree,
        hash: &Hash,
    ) -> Result<NoteSignature> {
        if !matches!(self.algorithm, KeyServiceAlgorithm::MlDsa44(_)) {
            return Err(Error::from("key service key does not support sign-subtree"));
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
    ) -> Result<NoteSignature> {
        let seconds = timestamp / 1000;
        match self.algorithm {
            KeyServiceAlgorithm::Ed25519 => {
                let mut message = format!("cosignature/v1\ntime {seconds}\n").into_bytes();
                message.extend(checkpoint.to_bytes());
                let signature = self.sign_raw(env, &message).await?;
                cosignature(&self.name, self.key_id, seconds, &signature)
            }
            KeyServiceAlgorithm::MlDsa44(_) => {
                if checkpoint.size() == 0 && checkpoint.hash() != &EMPTY_HASH {
                    return Err(Error::from("invalid empty checkpoint hash"));
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
                ml_dsa_cosignature(&self.name, self.key_id, Some(seconds), &signature)
            }
        }
    }
}

fn check_ml_dsa_signature(signature: &[u8]) -> Result<()> {
    if signature.len() != core::mem::size_of::<MlDsaEncodedSignature<MlDsa44>>() {
        return Err(Error::from(
            "key service returned an invalid ML-DSA-44 signature length",
        ));
    }
    Ok(())
}

fn ml_dsa_cosignature(
    name: &KeyName,
    key_id: u32,
    seconds: Option<u64>,
    signature: &[u8],
) -> Result<NoteSignature> {
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
        KeyServiceAlgorithm, KeyServiceSigner, VersionState, cosignature, missing_key_message,
        ml_dsa_cosignature, parse_public_key,
    };
    use ed25519_dalek::SigningKey;
    use ml_dsa::{ExpandedSigningKey, MlDsa44};
    use pkcs8::EncodePublicKey as _;
    use signed_note::KeyName;
    use tlog_checkpoint::{CheckpointSigner as _, CheckpointText};
    use tlog_core::{Hash, Subtree};
    use tlog_cosignature::{
        CosignatureV1CheckpointSigner, SubtreeV1CheckpointSigner, SubtreeV1NoteVerifier,
        subtree_v1::build_cosigned_message,
    };

    #[test]
    fn key_service_signature_matches_local_cosignature_wire_format() {
        use ed25519_dalek::Signer as _;

        let key = SigningKey::from_bytes(&[7; 32]);
        let name = KeyName::new("mirror.example".to_owned()).unwrap();
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
    fn only_missing_logical_key_enables_local_fallback() {
        assert!(missing_key_message("key not found: witness", "witness"));
        assert!(!missing_key_message("key not found: other", "witness"));
        assert!(!missing_key_message("keyring not found", "witness"));
        assert!(!missing_key_message("key service unavailable", "witness"));
    }

    #[test]
    fn only_exportable_verify_only_versions_are_retired() {
        let state = |usages: &[&str], extractable| {
            VersionState::new(
                "mirror",
                1,
                &usages
                    .iter()
                    .map(|usage| (*usage).to_owned())
                    .collect::<Vec<_>>(),
                extractable,
            )
        };
        assert!(state(&["sign", "verify"], true).unwrap().signing);
        assert!(!state(&["verify"], true).unwrap().signing);
        assert!(state(&["verify"], false).is_err());
        assert!(state(&["sign"], false).is_err());
        assert!(state(&[], true).is_err());
        assert!(state(&["encrypt"], true).is_err());
    }

    #[test]
    fn key_service_ml_dsa_checkpoint_and_subtree_match_local_signer() {
        let name = KeyName::new("mirror.example".to_owned()).unwrap();
        let key = ExpandedSigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from([7; 32]));
        let der = key.verifying_key().to_public_key_der().unwrap();
        let (algorithm, key_id) = parse_public_key(der.as_bytes(), &name).unwrap();
        assert!(matches!(algorithm, KeyServiceAlgorithm::MlDsa44(_)));
        let key_service = KeyServiceSigner {
            key_name: "test".to_owned(),
            version: 1,
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
