//! Typed boundary for the key-service JavaScript binding.
//! RPC types follow the binding's TypeScript declarations.
//! `CryptoKey` objects retain their JavaScript identity across deserialization.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use wasm_bindgen::{JsCast as _, JsValue};
use worker::{Env, js_sys, wasm_bindgen, wasm_bindgen_futures::JsFuture};

use super::{KeyServiceError, VersionNumber};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum CryptoKeyType {
    Public,
    Private,
    Secret,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CryptoKeyUsage {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
}

#[derive(Deserialize)]
struct CloudflareCryptoKeyFields {
    #[serde(rename = "type")]
    key_type: CryptoKeyType,
    extractable: bool,
    algorithm: serde_json::Value,
    usages: Vec<CryptoKeyUsage>,
}

#[allow(dead_code)] // Preserve all declared key metadata even when callers only need the handle.
#[derive(Clone)]
pub(super) struct CloudflareCryptoKey {
    pub r#type: CryptoKeyType,
    pub extractable: bool,
    pub algorithm: serde_json::Value,
    pub usages: Vec<CryptoKeyUsage>,
    js: JsValue,
}

impl<'de> Deserialize<'de> for CloudflareCryptoKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value: JsValue = serde_wasm_bindgen::preserve::deserialize(deserializer)?;
        if value.is_null() || value.is_undefined() {
            return Err(serde::de::Error::custom("key handle is null or undefined"));
        }
        let fields: CloudflareCryptoKeyFields =
            serde_wasm_bindgen::from_value(value.clone()).map_err(serde::de::Error::custom)?;
        Ok(Self {
            r#type: fields.key_type,
            extractable: fields.extractable,
            algorithm: fields.algorithm,
            usages: fields.usages,
            js: value,
        })
    }
}

impl CloudflareCryptoKey {
    fn as_js(&self) -> &JsValue {
        &self.js
    }
}

// `Keyring.get` and `create` return this union. Keep the original pair object
// because `Keyring.details` accepts the pair itself, not just its keys.
pub(super) enum KeyReference {
    Key(CloudflareCryptoKey),
    Pair {
        pair: CloudflareCryptoKeyPair,
        raw: JsValue,
    },
}

#[derive(Deserialize)]
struct CryptoKeyTypeProbe {
    #[serde(rename = "type")]
    key_type: Option<CryptoKeyType>,
}

impl<'de> Deserialize<'de> for KeyReference {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: JsValue = serde_wasm_bindgen::preserve::deserialize(deserializer)?;
        let probe: CryptoKeyTypeProbe =
            serde_wasm_bindgen::from_value(raw.clone()).map_err(serde::de::Error::custom)?;
        if probe.key_type.is_some() {
            let key = serde_wasm_bindgen::from_value(raw).map_err(serde::de::Error::custom)?;
            Ok(Self::Key(key))
        } else {
            let pair =
                serde_wasm_bindgen::from_value(raw.clone()).map_err(serde::de::Error::custom)?;
            Ok(Self::Pair { pair, raw })
        }
    }
}

impl KeyReference {
    fn as_js(&self) -> &JsValue {
        match self {
            Self::Key(key) => key.as_js(),
            Self::Pair { raw, .. } => raw,
        }
    }

    pub(super) fn into_key(self) -> Result<CloudflareCryptoKey, KeyServiceError> {
        match self {
            Self::Key(key) => Ok(key),
            Self::Pair { .. } => Err(KeyServiceError::Internal(
                "key service ticket key is an asymmetric key pair".into(),
            )),
        }
    }

    pub(super) fn into_pair(self) -> Result<CloudflareCryptoKeyPair, KeyServiceError> {
        match self {
            Self::Pair { pair, .. } => Ok(pair),
            Self::Key(_) => Err(KeyServiceError::InvalidArgument(
                "key service signing key is not an asymmetric key pair".into(),
            )),
        }
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct KeyringBinding(#[serde(with = "serde_wasm_bindgen::preserve")] JsValue);

impl KeyringBinding {
    fn as_js(&self) -> &JsValue {
        &self.0
    }
}

#[derive(Deserialize)]
struct KeyServiceEnv {
    #[serde(rename = "KEY_SERVICE")]
    key_service: Option<KeyringBinding>,
}

#[derive(Deserialize)]
struct RpcError {
    message: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CloudflareCryptoKeyPair {
    pub public_key: CloudflareCryptoKey,
    pub private_key: CloudflareCryptoKey,
}

#[derive(Deserialize)]
pub(super) struct KeyDetails {
    pub version: VersionNumber,
}

// Only the fields needed to construct a validated, public `KeyVersion`.
#[derive(Deserialize)]
pub(super) struct KeyVersionResponse {
    pub version: VersionNumber,
    pub usages: Vec<CryptoKeyUsage>,
}

#[derive(Serialize)]
pub(super) struct GetKeyOptions {
    pub version: VersionNumber,
}

#[derive(Serialize)]
pub(super) struct KeyVersionPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usages: Option<&'static [&'static str]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extractable: Option<bool>,
}

#[allow(dead_code)] // The byte-export overload supports formats we do not yet request.
pub(super) enum ExportKeyFormat {
    Spki,
    Raw,
    RawPublic,
}

impl ExportKeyFormat {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Spki => "spki",
            Self::Raw => "raw",
            Self::RawPublic => "raw-public",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptAlgorithm<'s> {
    pub name: &'s str,
    #[serde(with = "serde_bytes")]
    pub iv: &'s [u8],
    #[serde(with = "serde_bytes")]
    pub additional_data: &'s [u8],
    pub tag_length: u8,
}

#[wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    type JsKeyring;
    #[wasm_bindgen(method, catch, js_name = create)]
    fn create(this: &JsKeyring, name: &str, algorithm: &str) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = versions)]
    fn versions(this: &JsKeyring, name: &str) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = get)]
    fn get(this: &JsKeyring, name: &str, opts: &JsValue) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = exportKey)]
    fn export_key(
        this: &JsKeyring,
        format: &str,
        key: &JsValue,
    ) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(method, catch, js_name = sign)]
    fn sign(
        this: &JsKeyring,
        algorithm: &str,
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

fn rpc_error(operation: &str, error: &JsValue) -> worker::Error {
    worker::Error::from(format!("key service {operation}: {error:?}"))
}

async fn call(
    operation: &str,
    promise: Result<js_sys::Promise, JsValue>,
) -> Result<JsValue, worker::Error> {
    JsFuture::from(promise.map_err(|error| rpc_error(operation, &error))?)
        .await
        .map_err(|error| rpc_error(operation, &error))
}

fn decode<T: DeserializeOwned>(value: JsValue, description: &str) -> Result<T, KeyServiceError> {
    serde_wasm_bindgen::from_value(value).map_err(|error| {
        KeyServiceError::Internal(format!(
            "key service returned invalid {description}: {error}"
        ))
    })
}

async fn call_typed<T: DeserializeOwned>(
    operation: &str,
    promise: Result<js_sys::Promise, JsValue>,
    description: &str,
) -> Result<T, KeyServiceError> {
    decode(call(operation, promise).await?, description)
}

fn encode<T: Serialize>(value: &T) -> Result<JsValue, worker::Error> {
    serde_wasm_bindgen::to_value(value).map_err(Into::into)
}

fn is_missing_key(error: &JsValue) -> bool {
    serde_wasm_bindgen::from_value::<RpcError>(error.clone())
        .ok()
        .and_then(|error| error.message)
        .or_else(|| error.as_string())
        .as_deref()
        .is_some_and(missing_key_message)
}

fn missing_key_message(message: &str) -> bool {
    message.contains("key not found:")
}

pub(super) struct KeyServiceRpc {
    js: JsKeyring,
}

impl KeyServiceRpc {
    pub(super) fn new(env: &Env) -> Option<Self> {
        let env_js: &JsValue = env.as_ref();
        let binding = serde_wasm_bindgen::from_value::<KeyServiceEnv>(env_js.clone())
            .ok()?
            .key_service?;
        Some(Self {
            js: binding.as_js().clone().unchecked_into(),
        })
    }

    pub(super) async fn create(
        &self,
        name: &str,
        algorithm: &str,
    ) -> Result<KeyReference, KeyServiceError> {
        call_typed("create", self.js.create(name, algorithm), "key").await
    }

    pub(super) async fn get(
        &self,
        name: &str,
        options: Option<&GetKeyOptions>,
    ) -> Result<KeyReference, KeyServiceError> {
        let options = options
            .map(encode)
            .transpose()?
            .unwrap_or(JsValue::UNDEFINED);
        call_typed("get", self.js.get(name, &options), "key").await
    }

    pub(super) async fn details(&self, key: &KeyReference) -> Result<KeyDetails, KeyServiceError> {
        call_typed("details", self.js.details(key.as_js()), "key details").await
    }

    pub(super) async fn new_version(
        &self,
        name: &str,
        options: &KeyVersionPatch,
    ) -> Result<VersionNumber, KeyServiceError> {
        let options = encode(options)?;
        call_typed(
            "new_version",
            self.js.new_version(name, &options),
            "version number",
        )
        .await
    }

    pub(super) async fn set_default_version(
        &self,
        name: &str,
        version: VersionNumber,
    ) -> Result<(), KeyServiceError> {
        call(
            "set_default_version",
            self.js.set_default_version(name, version.get()),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn update_version(
        &self,
        name: &str,
        version: VersionNumber,
        patch: &KeyVersionPatch,
    ) -> Result<(), KeyServiceError> {
        let patch = encode(patch)?;
        call(
            "update_version",
            self.js.update_version(name, version.get(), &patch),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn export_key(
        &self,
        format: ExportKeyFormat,
        key: &CloudflareCryptoKey,
    ) -> Result<Vec<u8>, KeyServiceError> {
        let value = call(
            "export_key",
            self.js.export_key(format.as_str(), key.as_js()),
        )
        .await?;
        Ok(js_sys::Uint8Array::new(&value).to_vec())
    }

    pub(super) async fn sign(
        &self,
        algorithm: &str,
        key: &CloudflareCryptoKey,
        message: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        let value = call(
            "sign",
            self.js
                .sign(algorithm, key.as_js(), &js_sys::Uint8Array::from(message)),
        )
        .await?;
        Ok(js_sys::Uint8Array::new(&value).to_vec())
    }

    pub(super) async fn encrypt(
        &self,
        algorithm: &EncryptAlgorithm<'_>,
        key: &CloudflareCryptoKey,
        payload: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        let algorithm = encode(algorithm)?;
        let value = call(
            "encrypt",
            self.js
                .encrypt(&algorithm, key.as_js(), &js_sys::Uint8Array::from(payload)),
        )
        .await?;
        Ok(js_sys::Uint8Array::new(&value).to_vec())
    }

    pub(super) async fn decrypt(
        &self,
        algorithm: &EncryptAlgorithm<'_>,
        key: &CloudflareCryptoKey,
        payload: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        let algorithm = encode(algorithm)?;
        let value = call(
            "decrypt",
            self.js
                .decrypt(&algorithm, key.as_js(), &js_sys::Uint8Array::from(payload)),
        )
        .await?;
        Ok(js_sys::Uint8Array::new(&value).to_vec())
    }

    pub(super) async fn versions(
        &self,
        name: &str,
    ) -> Result<Vec<KeyVersionResponse>, KeyServiceError> {
        // Both synchronous throws and rejected promises can mean the key is absent.
        let promise = match self.js.versions(name) {
            Ok(promise) => promise,
            Err(error) if is_missing_key(&error) => return Err(KeyServiceError::KeyNotFound),
            Err(error) => return Err(rpc_error("versions", &error).into()),
        };
        match JsFuture::from(promise).await {
            Ok(versions) => decode(versions, "versions"),
            Err(error) if is_missing_key(&error) => Err(KeyServiceError::KeyNotFound),
            Err(error) => Err(rpc_error("versions", &error).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CloudflareCryptoKeyFields, CloudflareCryptoKeyPair, CryptoKeyType, CryptoKeyTypeProbe,
        CryptoKeyUsage, ExportKeyFormat, missing_key_message,
    };

    #[test]
    fn crypto_key_metadata_matches_binding_interface() {
        let key: CloudflareCryptoKeyFields = serde_json::from_str(
            r#"{"type":"public","extractable":true,"algorithm":{"name":"Ed25519"},"usages":["verify"]}"#,
        )
        .unwrap();
        assert!(matches!(key.key_type, CryptoKeyType::Public));
        assert!(key.extractable);
        assert_eq!(key.algorithm["name"], "Ed25519");
        assert!(matches!(key.usages.as_slice(), [CryptoKeyUsage::Verify]));
        assert!(
            serde_json::from_str::<CloudflareCryptoKeyFields>(
                r#"{"type":"public","extractable":false,"algorithm":{"name":"Ed25519"},"usages":["wrapKey"]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn signing_key_pair_requires_both_handles() {
        assert!(serde_json::from_str::<CloudflareCryptoKeyPair>("{}").is_err());
    }

    #[test]
    fn get_result_distinguishes_key_and_pair_shapes() {
        let key: CryptoKeyTypeProbe = serde_json::from_str(r#"{"type":"secret"}"#).unwrap();
        assert!(key.key_type.is_some());
        let pair: CryptoKeyTypeProbe =
            serde_json::from_str(r#"{"publicKey":{},"privateKey":{}}"#).unwrap();
        assert!(pair.key_type.is_none());
        assert!(serde_json::from_str::<CryptoKeyTypeProbe>(r#"{"type":"other"}"#).is_err());
    }

    #[test]
    fn export_formats_match_key_service() {
        assert_eq!(ExportKeyFormat::Spki.as_str(), "spki");
        assert_eq!(ExportKeyFormat::Raw.as_str(), "raw");
        assert_eq!(ExportKeyFormat::RawPublic.as_str(), "raw-public");
    }

    #[test]
    fn missing_key_message_recognizes_any_logical_key() {
        assert!(missing_key_message("key not found: witness"));
        assert!(missing_key_message("key not found: other"));
        assert!(!missing_key_message("keyring not found"));
        assert!(!missing_key_message("key service unavailable"));
    }
}
