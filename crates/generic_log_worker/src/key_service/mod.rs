// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! key-service-backed Ed25519 and ML-DSA-44 cosigners. Key handles never contain private material.
//! key service RPC is intentionally isolated here: the public C2SP crates remain
//! independent of the Workers runtime.

// mod rotation;
mod rpc;

use rpc::{
    CloudflareCryptoKeyPair, ExportKeyFormat, GetKeyOptions, KeyServiceRpc, KeyVersionPatch,
    KeyVersionResponse,
};
pub use rpc::{CryptoKeyUsage, EncryptAlgorithm};

use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey as _};
use ml_dsa::{MlDsa44, VerifyingKey as MlDsaVerifyingKey};
use signed_note::{self, SignatureType, compute_key_id};
use worker::Env;

use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, num::NonZeroU32, rc::Rc};

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

#[derive(Clone)]
pub struct Keyring {
    rpc: Rc<KeyServiceRpc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
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
        Some(Self {
            rpc: Rc::new(KeyServiceRpc::new(env)?),
        })
    }

    /// Create a logical key using the specified key service algorithm.
    ///
    /// # Errors
    /// Returns an error if the key service cannot create the key.
    pub async fn create_key(&self, name: &str, algorithm: &str) -> Result<(), KeyServiceError> {
        self.rpc.create(name, algorithm).await?;
        Ok(())
    }

    /// Read the current default version of a logical key.
    ///
    /// # Errors
    /// Returns an error if the key service fails or returns an invalid version.
    pub async fn current_default(&self, name: &str) -> Result<VersionNumber, KeyServiceError> {
        let key = self.rpc.get(name, None).await?;
        Ok(self.rpc.details(&key).await?.version)
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
        self.rpc
            .new_version(
                name,
                &KeyVersionPatch {
                    usages: Some(usage.as_strings()),
                    extractable: Some(extractable),
                },
            )
            .await
    }

    /// Set a version as the logical key's default.
    ///
    /// # Errors
    /// Returns an error if the key service cannot promote the version.
    pub async fn promote(&self, name: &str, version: VersionNumber) -> Result<(), KeyServiceError> {
        self.rpc.set_default_version(name, version).await
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
        // Preserve public-key export for verification of existing signatures.
        self.rpc
            .update_version(
                name,
                version,
                &KeyVersionPatch {
                    usages: Some(usage.as_strings()),
                    extractable: None,
                },
            )
            .await
    }

    /// Discover sign-enabled versions, excluding explicitly retired (verify-only)
    /// versions.
    ///
    /// Malformed versions and key service failures are errors, not a reason to use local keys.
    ///
    /// # Errors
    /// Returns an error if discovery, public-key export, or validation fails.
    pub async fn load_signing_keys(
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
            .filter(|version| version.usage == KeyUsage::SigningVerify)
        {
            let pair = self
                .rpc
                .get(
                    key_name,
                    Some(&GetKeyOptions {
                        version: version.number,
                    }),
                )
                .await?
                .into_pair()?;
            let der = self
                .rpc
                .export_key(ExportKeyFormat::Spki, &pair.public_key)
                .await?;
            let (algorithm, key_id) = parse_public_key(&der, &name)?;
            signers.push(KeyServiceSigner {
                keyring: self.clone(),
                version,
                handle: pair,
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
    /// Returns an error if signing fails.
    pub async fn sign(
        &self,
        signer: &KeyServiceSigner,
        message: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        self.rpc
            .sign(
                signing_algorithm(&signer.algorithm),
                &signer.handle.private_key,
                message,
            )
            .await
    }

    /// Encrypt a payload using a ticket-key version.
    ///
    /// # Errors
    /// Returns an error if the key service cannot encrypt the payload.
    pub async fn encrypt(
        &self,
        algorithm: EncryptAlgorithm<'_>,
        key: &KeyVersion<key_kind::Ticket>,
        payload: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        let handle = self
            .rpc
            .get(
                &key.name,
                Some(&GetKeyOptions {
                    version: key.number,
                }),
            )
            .await?
            .into_key()?;
        self.rpc.encrypt(&algorithm, &handle, payload).await
    }

    /// Decrypt a payload using a ticket-key version.
    ///
    /// # Errors
    /// Returns an error if the key service cannot decrypt the payload.
    pub async fn decrypt(
        &self,
        algorithm: EncryptAlgorithm<'_>,
        key: &KeyVersion<key_kind::Ticket>,
        payload: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        let handle = self
            .rpc
            .get(
                &key.name,
                Some(&GetKeyOptions {
                    version: key.number,
                }),
            )
            .await?
            .into_key()?;
        self.rpc.decrypt(&algorithm, &handle, payload).await
    }

    /// Read and validate the versions of a logical key according to its kind.
    ///
    /// # Errors
    /// Returns an error if the key is missing, the key service fails, or a version is invalid.
    pub async fn versions<Kind: KeyKind>(
        &self,
        key_name: &str,
    ) -> Result<Vec<KeyVersion<Kind>>, KeyServiceError> {
        version_states(key_name, self.rpc.versions(key_name).await?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUsage {
    SigningVerify,
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

    fn as_strings(self) -> &'static [&'static str] {
        match self {
            KeyUsage::SigningVerify => &["sign", "verify"],
            KeyUsage::Verify => &["verify"],
            KeyUsage::EncryptDecrypt => &["encrypt", "decrypt"],
            KeyUsage::Decrypt => &["decrypt"],
            KeyUsage::Retired => &[],
        }
    }
}

pub mod key_kind {
    use super::KeyUsage;
    use crate::key_service::CryptoKeyUsage;

    pub struct Signing();

    impl KeyKind for Signing {
        const IS_SIGNING: bool = true;
    }
    pub struct Ticket();
    impl KeyKind for Ticket {
        const IS_SIGNING: bool = false;
    }

    pub trait KeyKind {
        const IS_SIGNING: bool;
    }

    pub(super) fn usages<K: KeyKind>(usages: &[CryptoKeyUsage]) -> Option<KeyUsage> {
        if K::IS_SIGNING {
            let sign = usages.contains(&CryptoKeyUsage::Sign);
            let verify = usages.contains(&CryptoKeyUsage::Verify);
            match (usages.len(), sign, verify) {
                (2, true, true) => Some(KeyUsage::SigningVerify),
                (1, false, true) => Some(KeyUsage::Verify),
                _ => None,
            }
        } else {
            let encrypt = usages.contains(&CryptoKeyUsage::Encrypt);
            let decrypt = usages.contains(&CryptoKeyUsage::Decrypt);
            match (usages.len(), encrypt, decrypt) {
                (2, true, true) => Some(KeyUsage::EncryptDecrypt),
                (1, false, true) => Some(KeyUsage::Decrypt),
                (0, false, false) => Some(KeyUsage::Retired),
                _ => None,
            }
        }
    }
}

pub use key_kind::KeyKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyVersion<Kind> {
    pub name: Rc<str>,
    pub number: VersionNumber,
    pub usage: KeyUsage,
    _kind: PhantomData<Kind>,
}

impl<Kind: KeyKind> KeyVersion<Kind> {
    /// Construct a version state from the key service's usage strings.
    ///
    /// # Errors
    /// Returns an error if the usages are invalid for this key kind.
    pub fn new(
        name: Rc<str>,
        number: VersionNumber,
        usages: &[CryptoKeyUsage],
    ) -> Result<Self, KeyServiceError> {
        let usage = key_kind::usages::<Kind>(usages).ok_or_else(|| {
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
    versions: Vec<KeyVersionResponse>,
) -> Result<Vec<KeyVersion<Kind>>, KeyServiceError> {
    let mut states = Vec::with_capacity(versions.len());
    let name: Rc<str> = name.into();
    for version in versions {
        states.push(KeyVersion::new(
            Rc::clone(&name),
            version.version,
            &version.usages,
        )?);
    }
    states.sort_by_key(|s| s.number);
    Ok(states)
}

pub struct KeyServiceSigner {
    pub keyring: Keyring,
    pub version: KeyVersion<key_kind::Signing>,
    handle: CloudflareCryptoKeyPair,
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

fn signing_algorithm(algorithm: &KeyServiceAlgorithm) -> &'static str {
    match algorithm {
        KeyServiceAlgorithm::Ed25519 => "Ed25519",
        // key service signs ML-DSA-44 with an empty context and rejects a `context`
        // property, even when its value is an empty Uint8Array.
        KeyServiceAlgorithm::MlDsa44(_) => "ML-DSA-44",
    }
}

#[cfg(test)]
mod tests {
    use super::{EncryptAlgorithm, KeyUsage, KeyVersion, key_kind};

    use crate::key_service::rpc::{GetKeyOptions, KeyVersionPatch, KeyVersionResponse};
    use crate::key_service::{CryptoKeyUsage, VersionNumber};
    use std::{num::NonZeroU32, rc::Rc};

    fn n(x: u32) -> VersionNumber {
        VersionNumber(NonZeroU32::new(x).unwrap())
    }

    #[test]
    fn rpc_records_preserve_key_service_field_names_and_version_validation() {
        assert_eq!(
            serde_json::to_value(KeyVersionPatch {
                usages: Some(KeyUsage::SigningVerify.as_strings()),
                extractable: Some(false),
            })
            .unwrap(),
            serde_json::json!({"usages": ["sign", "verify"], "extractable": false})
        );
        assert_eq!(
            serde_json::to_value(KeyVersionPatch {
                usages: Some(KeyUsage::Retired.as_strings()),
                extractable: None,
            })
            .unwrap(),
            serde_json::json!({"usages": []})
        );
        assert_eq!(
            serde_json::to_value(GetKeyOptions { version: n(3) }).unwrap(),
            serde_json::json!({"version": 3})
        );
        assert_eq!(
            serde_json::to_value(EncryptAlgorithm {
                name: "AES-GCM",
                iv: &[1, 2],
                additional_data: &[3],
                tag_length: 128,
            })
            .unwrap(),
            serde_json::json!({
                "name": "AES-GCM", "iv": [1, 2], "additionalData": [3], "tagLength": 128
            })
        );
        let record: KeyVersionResponse =
            serde_json::from_value(serde_json::json!({"version": 3, "usages": ["decrypt"]}))
                .unwrap();
        assert_eq!(record.version, n(3));
        assert!(
            serde_json::from_value::<KeyVersionResponse>(
                serde_json::json!({"version": 0, "usages": ["decrypt"]})
            )
            .is_err()
        );
    }

    #[test]
    fn version_usages_follow_their_key_role() {
        use CryptoKeyUsage::{Decrypt, Encrypt, Sign, Verify};

        fn state<Kind: super::KeyKind>(
            usages: &[CryptoKeyUsage],
        ) -> Result<KeyVersion<Kind>, super::KeyServiceError> {
            KeyVersion::<Kind>::new(Rc::from("test-key"), n(1), usages)
        }
        assert_eq!(
            state::<key_kind::Signing>(&[Sign, Verify]).unwrap().usage,
            KeyUsage::SigningVerify
        );
        assert_eq!(
            state::<key_kind::Signing>(&[Verify, Sign]).unwrap().usage,
            KeyUsage::SigningVerify
        );
        assert_eq!(
            state::<key_kind::Signing>(&[Verify]).unwrap().usage,
            KeyUsage::Verify
        );
        assert_eq!(
            state::<key_kind::Ticket>(&[Encrypt, Decrypt])
                .unwrap()
                .usage,
            KeyUsage::EncryptDecrypt
        );
        assert_eq!(
            state::<key_kind::Ticket>(&[Decrypt, Encrypt])
                .unwrap()
                .usage,
            KeyUsage::EncryptDecrypt
        );
        assert_eq!(
            state::<key_kind::Ticket>(&[Decrypt]).unwrap().usage,
            KeyUsage::Decrypt
        );
        assert_eq!(
            state::<key_kind::Ticket>(&[]).unwrap().usage,
            KeyUsage::Retired
        );
        for usages in [
            vec![],
            vec![Sign],
            vec![Encrypt],
            vec![Decrypt],
            vec![Sign, Encrypt],
            vec![Sign, Verify, Encrypt],
            vec![Verify, Verify],
            vec![Sign, Verify, Verify],
        ] {
            assert!(state::<key_kind::Signing>(&usages).is_err(), "{usages:?}");
        }
        for usages in [
            vec![Sign],
            vec![Verify],
            vec![Encrypt],
            vec![Sign, Verify],
            vec![Encrypt, Encrypt],
            vec![Decrypt, Decrypt],
            vec![Encrypt, Decrypt, Decrypt],
        ] {
            assert!(state::<key_kind::Ticket>(&usages).is_err(), "{usages:?}");
        }
        assert!(
            serde_json::from_value::<KeyVersionResponse>(
                serde_json::json!({"version": 1, "usages": ["verify", "other"]})
            )
            .is_err()
        );
    }
}
