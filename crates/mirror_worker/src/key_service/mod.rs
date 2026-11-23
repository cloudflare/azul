// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! key-service-backed Ed25519 and ML-DSA-44 cosigners. Key handles never contain private material.
//! key service RPC is intentionally isolated here: the public C2SP crates remain
//! independent of the Workers runtime.

mod rotation;

use ml_dsa::{EncodedSignature as MlDsaEncodedSignature, MlDsa44};
use signed_note::{self, NoteSignature, NoteVerifier};
use tlog_checkpoint::{CheckpointText, UnixTimestampMillis};
use tlog_core::{EMPTY_HASH, Hash, Subtree};
use tlog_cosignature::{
    SubtreeV1NoteVerifier,
    subtree_v1::{build_cosigned_message, checkpoint_cosignature},
};
use worker::Env;

use generic_log_worker::key_service::{
    EncryptAlgorithm, KeyServiceAlgorithm, VersionNumber, key_kind,
};
use std::num::NonZeroU32;

pub use generic_log_worker::key_service::{
    KeyServiceError, KeyServiceSigner, KeyUsage, KeyVersion,
};
use serde::Deserialize;

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

#[derive(Clone, Copy, Deserialize, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    #[serde(rename = "ED25519")]
    Ed25519,
    #[serde(rename = "ML_DSA_44")]
    MlDsa44,
}

impl KeyAlgorithm {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ED25519",
            Self::MlDsa44 => "ML_DSA_44",
        }
    }
}

#[derive(Clone)]
pub struct Keyring {
    keyring: generic_log_worker::key_service::Keyring,
}

impl Keyring {
    pub fn new(env: &Env) -> Option<Self> {
        generic_log_worker::key_service::Keyring::new(env).map(|keyring| Self { keyring })
    }

    pub async fn signing_versions(
        &self,
        key_name: SigningKeyName,
    ) -> Result<Vec<KeyVersion<key_kind::Signing>>, KeyServiceError> {
        self.keyring.versions(key_name.as_str()).await
    }

    pub async fn ticket_versions(
        &self,
    ) -> Result<Vec<KeyVersion<key_kind::Ticket>>, KeyServiceError> {
        self.keyring.versions(KeyName::Ticket.as_str()).await
    }

    pub async fn create_signing_key(
        &self,
        key_name: SigningKeyName,
        algorithm: KeyAlgorithm,
    ) -> Result<(), KeyServiceError> {
        self.keyring
            .create_key(key_name.as_str(), algorithm.as_str())
            .await
    }

    pub async fn create_ticket_key(&self) -> Result<(), KeyServiceError> {
        self.keyring
            .create_key(const { KeyName::Ticket.as_str() }, "AES_256_GCM")
            .await
    }

    pub async fn current_default(
        &self,
        key_name: impl Into<KeyName>,
    ) -> Result<VersionNumber, KeyServiceError> {
        self.keyring.current_default(key_name.into().as_str()).await
    }

    pub async fn new_default_version(
        &self,
        key_name: impl Into<KeyName>,
        usage: KeyUsage,
        extractable: bool,
    ) -> Result<VersionNumber, KeyServiceError> {
        let key_name = key_name.into();
        let v = self
            .keyring
            .new_version(key_name.as_str(), usage, extractable)
            .await?;
        self.promote(key_name, v).await?;
        Ok(v)
    }

    pub async fn promote(
        &self,
        key_name: impl Into<KeyName>,
        version: VersionNumber,
    ) -> Result<(), KeyServiceError> {
        self.keyring
            .promote(key_name.into().as_str(), version)
            .await?;
        Ok(())
    }

    pub async fn retire(
        &self,
        key_name: impl Into<KeyName>,
        version: VersionNumber,
    ) -> Result<(), KeyServiceError> {
        match key_name.into() {
            KeyName::Ticket => {
                self.keyring
                    .change_usages(
                        const { KeyName::Ticket.as_str() },
                        version,
                        KeyUsage::Retired,
                    )
                    .await?;
            }
            KeyName::SigningKey(k) => {
                self.keyring
                    .change_usages(k.as_str(), version, KeyUsage::Verify)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn load_signing_keys(
        &self,
        key_name: SigningKeyName,
        identity: &str,
    ) -> Result<Vec<KeyServiceSigner>, KeyServiceError> {
        self.keyring
            .load_signing_keys(key_name.as_str(), identity)
            .await
    }

    // /// Issue a versioned ticket using the current symmetric key-service version.
    // /// The version and origin are authenticated as associated data.
    pub async fn seal_ticket(
        &self,
        payload: &[u8],
        origin: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        let versions = self
            .keyring
            .versions(const { KeyName::Ticket.as_str() })
            .await?;
        let latest = versions
            .last()
            .ok_or_else(|| KeyServiceError::Internal("ticket key has no versions".into()))?;
        // let key = version_handle(&ring, const { KeyName::Ticket.as_str() }, latest.number).await?;
        if !latest.usage.decrypt() {
            return Err(KeyServiceError::Internal(
                "tried to encrypt with a ticket key that can't decrypt".into(),
            ));
        }
        let mut header = Vec::from(TICKET_PREFIX.as_slice());
        header.extend_from_slice(&latest.number.get().to_be_bytes());
        let mut nonce = [0u8; TICKET_NONCE_LEN];
        getrandom_03::fill(&mut nonce)
            .map_err(|error| worker::Error::from(format!("ticket nonce: {error}")))?;
        let ciphertext = self
            .keyring
            .encrypt(
                ticket_algorithm(&nonce, &ticket_aad(&header, origin)),
                latest,
                payload,
            )
            .await?;
        let mut ticket = header;
        ticket.extend_from_slice(&nonce);
        ticket.extend_from_slice(&ciphertext);
        Ok(ticket)
    }

    /// Only versioned tickets are opened here. Never use the current default to
    /// open: tickets must survive a key-service default-version change.
    pub(crate) async fn open_ticket(
        self,
        ticket: &[u8],
        origin: &[u8],
    ) -> Result<Vec<u8>, KeyServiceError> {
        // this must not be moved down as it checks if the key service is available before checking if
        // the ticket is valid
        let (version, nonce, ciphertext) = ticket_parts(ticket)?;
        let header = &ticket[..TICKET_HEADER_LEN];
        match self
            .ticket_versions()
            .await?
            .iter()
            .find(|s| s.usage != KeyUsage::Retired && s.number == version)
        {
            Some(version) => Ok(self
                .keyring
                .decrypt(
                    ticket_algorithm(nonce, &ticket_aad(header, origin)),
                    version,
                    ciphertext,
                )
                .await?),
            None => Err(KeyServiceError::KeyNotFound),
        }
    }

    pub(crate) async fn sign_subtree(
        &self,
        origin: &str,
        subtree: &Subtree,
        hash: &Hash,
        signer: &KeyServiceSigner,
    ) -> Result<NoteSignature, KeyServiceError> {
        if !matches!(signer.algorithm, KeyServiceAlgorithm::MlDsa44(_)) {
            return Err(KeyServiceError::InvalidArgument(
                "key service key does not support sign-subtree".to_string(),
            ));
        }
        let message =
            build_cosigned_message(&signer.name, 0, origin, subtree.lo(), subtree.hi(), hash);
        let signature = self.keyring.sign(signer, &message).await?;
        ml_dsa_cosignature(&signer.name, signer.key_id, None, &signature)
    }

    pub(crate) async fn sign(
        &self,
        timestamp: UnixTimestampMillis,
        checkpoint: &CheckpointText,
        signer: &KeyServiceSigner,
    ) -> Result<NoteSignature, KeyServiceError> {
        let seconds = timestamp / 1000;
        match signer.algorithm {
            KeyServiceAlgorithm::Ed25519 => {
                let mut message = format!("cosignature/v1\ntime {seconds}\n").into_bytes();
                message.extend(checkpoint.to_bytes());
                let signature = self.keyring.sign(signer, &message).await?;
                Ok(cosignature(
                    &signer.name,
                    signer.key_id,
                    seconds,
                    &signature,
                )?)
            }
            KeyServiceAlgorithm::MlDsa44(_) => {
                if checkpoint.size() == 0 && checkpoint.hash() != &EMPTY_HASH {
                    return Err(KeyServiceError::InvalidArgument(
                        "invalid empty checkpoint hash".to_string(),
                    ));
                }
                let message = build_cosigned_message(
                    &signer.name,
                    seconds,
                    checkpoint.origin(),
                    0,
                    checkpoint.size(),
                    checkpoint.hash(),
                );
                let signature = self.keyring.sign(signer, &message).await?;
                Ok(ml_dsa_cosignature(
                    &signer.name,
                    signer.key_id,
                    Some(seconds),
                    &signature,
                )?)
            }
        }
    }
}

fn ticket_algorithm<'s>(nonce: &'s [u8], aad: &'s [u8]) -> EncryptAlgorithm<'s> {
    EncryptAlgorithm {
        name: "AES-GCM",
        iv: nonce,
        additional_data: aad,
        tag_length: 128,
    }
}

pub trait KeyServiceSignerExt {
    fn algorithm(&self) -> &'static str;

    fn subtree_verifier(&self) -> Option<Box<dyn NoteVerifier>>;

    fn supports_sign_subtree(&self) -> bool;
}

impl KeyServiceSignerExt for KeyServiceSigner {
    fn algorithm(&self) -> &'static str {
        match self.algorithm {
            KeyServiceAlgorithm::Ed25519 => "cosignature/v1",
            KeyServiceAlgorithm::MlDsa44(_) => "subtree/v1",
        }
    }

    fn subtree_verifier(&self) -> Option<Box<dyn NoteVerifier>> {
        match &self.algorithm {
            KeyServiceAlgorithm::Ed25519 => None,
            KeyServiceAlgorithm::MlDsa44(key) => Some(Box::new(SubtreeV1NoteVerifier::new(
                self.name.clone(),
                key.clone(),
            ))),
        }
    }

    fn supports_sign_subtree(&self) -> bool {
        matches!(self.algorithm, KeyServiceAlgorithm::MlDsa44(_))
    }
}

fn ticket_parts(ticket: &[u8]) -> Result<(NonZeroU32, &[u8], &[u8]), KeyServiceError> {
    const VERSION_RANGE: std::ops::Range<usize> = {
        assert!(
            TICKET_HEADER_LEN - TICKET_PREFIX.len() == std::mem::size_of::<u32>(),
            "Version range is not the size of a u32"
        );
        TICKET_PREFIX.len()..TICKET_HEADER_LEN
    };
    if !is_service_ticket(ticket)
        || ticket.len() < TICKET_HEADER_LEN + TICKET_NONCE_LEN + TICKET_TAG_LEN
    {
        return Err(KeyServiceError::InvalidArgument(
            "invalid key service ticket".into(),
        ));
    }
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

fn ticket_aad(header: &[u8], origin: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + origin.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(origin);
    aad
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

fn ml_dsa_cosignature(
    name: &signed_note::KeyName,
    key_id: u32,
    seconds: Option<u64>,
    signature: &[u8],
) -> Result<NoteSignature, KeyServiceError> {
    if signature.len() != core::mem::size_of::<MlDsaEncodedSignature<MlDsa44>>() {
        return Err(KeyServiceError::InvalidArgument(
            "key service returned an invalid ML-DSA-44 signature length".to_string(),
        ));
    }
    let payload = seconds.map_or_else(
        || signature.to_vec(),
        |seconds| checkpoint_cosignature(seconds, signature),
    );
    Ok(NoteSignature::new(name.clone(), key_id, payload))
}

#[cfg(test)]
mod tests {
    use super::{
        TICKET_NONCE_LEN, TICKET_PREFIX, TICKET_TAG_LEN, cosignature, is_service_ticket,
        ml_dsa_cosignature, ticket_aad, ticket_parts,
    };

    use ed25519_dalek::SigningKey;
    use ml_dsa::{ExpandedSigningKey, MlDsa44};
    use signed_note::NoteVerifier as _;
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
    fn key_service_ml_dsa_checkpoint_and_subtree_match_local_signer() {
        let name = signed_note::KeyName::new("mirror.example".to_owned()).unwrap();
        let key = ExpandedSigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from([7; 32]));
        let local = SubtreeV1CheckpointSigner::new(name.clone(), key.clone());
        let key_id = local.key_id();

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
            SubtreeV1NoteVerifier::new(name.clone(), key.verifying_key())
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
