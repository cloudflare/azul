// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Per-shard, non-rotating key service keys. Never retain JS key handles across requests.

use ed25519_dalek::pkcs8::DecodePublicKey as _;
use generic_log_worker::{
    CheckpointSource,
    key_service::{
        KeyServiceAlgorithm, KeyServiceError, KeyServiceSigner, KeyUsage, Keyring, P256Key,
        key_kind,
    },
};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier as _};
use signed_note::{Ed25519NoteVerifier, NoteSignature, NoteVerifier, VerifierList};
use static_ct_api::{
    AddChainResponse, Extensions, RFC6962NoteVerifier, StaticCTLogEntry,
    serialize_sth_signature_input,
};
use tlog_checkpoint::{CheckpointText, UnixTimestampMillis};
use worker::{Env, Error, Result};

use crate::load_origin;

pub(crate) enum ShardSigningKey {
    Local(&'static SigningKey),
    Service { ring: Keyring, key: P256Key },
}

impl ShardSigningKey {
    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        match self {
            Self::Local(key) => key.verifying_key(),
            Self::Service { key, .. } => &key.verifying_key,
        }
    }

    pub(crate) async fn sign_sct(&self, entry: &StaticCTLogEntry) -> Result<AddChainResponse> {
        match self {
            Self::Local(key) => static_ct_api::signed_certificate_timestamp(key, entry)
                .map_err(|e| Error::from(e.to_string())),
            Self::Service { ring, key } => signed_certificate_timestamp(ring, key, entry).await,
        }
    }
}

pub(crate) async fn load_shard_signing_key(env: &Env, shard: &str) -> Result<ShardSigningKey> {
    match Keyring::new(env) {
        Some(ring) => {
            let key = signing_key(&ring, shard).await?;
            Ok(ShardSigningKey::Service { ring, key })
        }
        None => Ok(ShardSigningKey::Local(crate::load_signing_key(env, shard)?)),
    }
}

fn signing_name(shard: &str) -> String {
    format!("SIGNING_KEY_{shard}")
}

fn witness_name(shard: &str) -> String {
    format!("WITNESS_KEY_{shard}")
}

async fn create_if_missing(ring: &Keyring, name: &str, algorithm: &str) -> Result<()> {
    match ring.versions::<key_kind::Signing>(name).await {
        Ok(_) => Ok(()),
        Err(KeyServiceError::KeyNotFound) => {
            // A concurrent first access may have created the same logical key.
            if let Err(error) = ring.create_key(name, algorithm).await {
                ring.versions::<key_kind::Signing>(name)
                    .await
                    .map_err(|_| Error::from(error.to_string()))?;
            }
            Ok(())
        }
        Err(error) => Err(Error::from(error.to_string())),
    }
}

pub(crate) async fn signing_key(ring: &Keyring, shard: &str) -> Result<P256Key> {
    let name = signing_name(shard);
    create_if_missing(ring, &name, "ECDSA_P256_SHA256").await?;
    // CT signing keys are not rotated: reject unexpected additional versions.
    let versions = ring
        .versions::<key_kind::Signing>(&name)
        .await
        .map_err(|e| Error::from(e.to_string()))?;
    if versions.len() != 1 || versions[0].usage != KeyUsage::SigningVerify {
        return Err(Error::from(format!(
            "{name} must have exactly one sign-enabled version"
        )));
    }
    ring.load_p256_key(&name, versions[0].number)
        .await
        .map_err(|e| Error::from(e.to_string()))
}

async fn witness_key(ring: &Keyring, shard: &str) -> Result<KeyServiceSigner> {
    let name = witness_name(shard);
    create_if_missing(ring, &name, "ED25519").await?;
    let versions = ring
        .versions::<key_kind::Signing>(&name)
        .await
        .map_err(|e| Error::from(e.to_string()))?;
    if versions.len() != 1 || versions[0].usage != KeyUsage::SigningVerify {
        return Err(Error::from(format!(
            "{name} must have exactly one sign-enabled version"
        )));
    }
    let mut signers = ring
        .load_signing_keys(&name, load_origin(shard).as_str())
        .await
        .map_err(|e| Error::from(e.to_string()))?;
    let signer = signers
        .pop()
        .ok_or_else(|| Error::from(format!("{name} is not sign-enabled")))?;
    if !matches!(signer.algorithm, KeyServiceAlgorithm::Ed25519) {
        return Err(Error::from(format!("{name} is not an Ed25519 key")));
    }
    Ok(signer)
}

fn encode_signature(raw: &[u8]) -> Result<Vec<u8>> {
    let sig = Signature::try_from(raw).map_err(|e| {
        Error::from(format!(
            "key service returned an invalid P-256 signature: {e}"
        ))
    })?;
    Ok(static_ct_api::encode_digitally_signed(&sig))
}

pub(crate) async fn signed_certificate_timestamp(
    ring: &Keyring,
    key: &P256Key,
    entry: &StaticCTLogEntry,
) -> Result<AddChainResponse> {
    let mut message = vec![0, 0]; // RFC 6962 v1 certificate_timestamp
    message.extend(
        entry
            .marshal_timestamped_entry()
            .map_err(|e| Error::from(e.to_string()))?,
    );
    let raw = ring
        .sign_p256(key, &message)
        .await
        .map_err(|e| Error::from(e.to_string()))?;
    let signature = Signature::try_from(raw.as_slice()).map_err(|e| {
        Error::from(format!(
            "key service returned an invalid P-256 signature: {e}"
        ))
    })?;
    key.verifying_key
        .verify(&message, &signature)
        .map_err(|e| {
            Error::from(format!(
                "key service signature does not match shard key: {e}"
            ))
        })?;
    Ok(AddChainResponse {
        sct_version: 0,
        id: static_ct_api::log_id_from_key(&key.verifying_key)
            .map_err(|e| Error::from(e.to_string()))?
            .to_vec(),
        timestamp: entry.timestamp,
        extensions: Extensions {
            leaf_index: entry.leaf_index,
        }
        .to_bytes(),
        signature: encode_signature(&raw)?,
    })
}

pub(crate) struct ShardCheckpointSigner {
    ring: Keyring,
    shard: String,
}

impl ShardCheckpointSigner {
    pub(crate) fn new(ring: Keyring, shard: &str) -> Self {
        Self {
            ring,
            shard: shard.to_owned(),
        }
    }

    async fn sign_tree_head(
        &self,
        timestamp: UnixTimestampMillis,
        checkpoint: &CheckpointText,
    ) -> std::result::Result<NoteSignature, String> {
        // RFC 6962-type signatures do not sign extension lines.
        if !checkpoint.extension().is_empty() {
            return Err("static CT checkpoints cannot have extensions".into());
        }

        let signing = signing_key(&self.ring, &self.shard)
            .await
            .map_err(|e| e.to_string())?;

        // Produce the bytestring that will be signed
        let tree_head_bytes =
            serialize_sth_signature_input(timestamp, checkpoint.size(), checkpoint.hash());

        // Sign the string
        let raw = self
            .ring
            .sign_p256(&signing, &tree_head_bytes)
            .await
            .map_err(|e| e.to_string())?;
        let tree_head_sig = encode_signature(&raw).map_err(|e| e.to_string())?;

        // Now format the final signature
        let mut note_sig = Vec::new();
        note_sig.extend_from_slice(&timestamp.to_be_bytes());
        note_sig.extend(&tree_head_sig);

        let origin = load_origin(&self.shard);
        let log_id =
            static_ct_api::log_id_from_key(&signing.verifying_key).map_err(|e| e.to_string())?;
        let key_id = signed_note::compute_key_id(
            &origin,
            &[signed_note::SignatureType::RFC6962TreeHead as u8],
            &log_id,
        );
        Ok(NoteSignature::new(origin, key_id, note_sig))
    }

    async fn sign_witness(
        &self,
        checkpoint: &CheckpointText,
    ) -> std::result::Result<NoteSignature, String> {
        let witness = witness_key(&self.ring, &self.shard)
            .await
            .map_err(|e| e.to_string())?;
        let witness_signature = self
            .ring
            .sign(&witness, &checkpoint.to_bytes())
            .await
            .map_err(|e| e.to_string())?;
        // The generic key service signer uses the cosignature/v1 key ID for Ed25519;
        // static CT's witness uses the signed-note Ed25519 (0x01) key ID.
        let witness_public =
            ed25519_dalek::VerifyingKey::from_public_key_der(&witness.public_key_der)
                .map_err(|e| e.to_string())?;
        let verifier = Ed25519NoteVerifier::new(witness.name.clone(), witness_public);
        Ok(NoteSignature::new(
            witness.name,
            verifier.key_id(),
            witness_signature,
        ))
    }
}

pub(crate) async fn load_shard_verifiers(
    ring: &Keyring,
    shard: &str,
) -> std::result::Result<VerifierList, String> {
    let signing = signing_key(ring, shard).await.map_err(|e| e.to_string())?;
    let witness = witness_key(ring, shard).await.map_err(|e| e.to_string())?;
    let witness_key = ed25519_dalek::VerifyingKey::from_public_key_der(&witness.public_key_der)
        .map_err(|e| e.to_string())?;
    let log = RFC6962NoteVerifier::new(load_origin(shard), &signing.verifying_key)
        .map_err(|e| format!("{e:?}"))?;
    Ok(VerifierList::new(vec![
        Box::new(log),
        Box::new(Ed25519NoteVerifier::new(witness.name, witness_key)),
    ]))
}

impl CheckpointSource for ShardCheckpointSigner {
    async fn sign(
        &self,
        timestamp: UnixTimestampMillis,
        checkpoint: &CheckpointText,
    ) -> std::result::Result<Vec<NoteSignature>, String> {
        Ok(vec![
            self.sign_tree_head(timestamp, checkpoint).await?,
            self.sign_witness(checkpoint).await?,
        ])
    }

    async fn verifiers(&self) -> std::result::Result<VerifierList, String> {
        load_shard_verifiers(&self.ring, &self.shard).await
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_signature, signing_name, witness_name};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
    use signed_note::{Ed25519NoteVerifier, Note, NoteSignature, NoteVerifier, VerifierList};
    use static_ct_api::{RFC6962NoteVerifier, serialize_sth_signature_input};
    use tlog_checkpoint::{CheckpointText, open_checkpoint};

    #[test]
    fn shard_keys_have_distinct_names() {
        assert_eq!(signing_name("dev2026h2a"), "SIGNING_KEY_dev2026h2a");
        assert_eq!(witness_name("dev2026h2a"), "WITNESS_KEY_dev2026h2a");
        assert_ne!(signing_name("a"), signing_name("b"));
    }

    #[test]
    fn p1363_signature_is_encoded_for_tls() {
        let raw = Signature::try_from([1_u8; 64].as_slice())
            .unwrap()
            .to_bytes();
        let encoded = encode_signature(raw.as_slice()).unwrap();
        assert_eq!(&encoded[..2], &[4, 3]);
        assert_eq!(
            encoded.len() - 4,
            u16::from_be_bytes([encoded[2], encoded[3]]) as usize
        );
        assert_eq!(Signature::from_der(&encoded[4..]).unwrap().to_bytes(), raw);
    }

    #[test]
    fn key_service_checkpoint_signatures_verify_as_static_ct() {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let witness = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let origin = crate::load_origin("dev2026h2a");
        let checkpoint =
            CheckpointText::new(origin.as_str(), 0, tlog_core::EMPTY_HASH, &[]).unwrap();
        let log_verifier = RFC6962NoteVerifier::new(origin.clone(), key.verifying_key()).unwrap();
        let log_id = static_ct_api::log_id_from_key(key.verifying_key()).unwrap();
        assert_eq!(
            signed_note::compute_key_id(
                &origin,
                &[signed_note::SignatureType::RFC6962TreeHead as u8],
                &log_id,
            ),
            log_verifier.key_id()
        );
        let witness_verifier = Ed25519NoteVerifier::new(origin.clone(), witness.verifying_key());
        let timestamp = 42;
        let message =
            serialize_sth_signature_input(timestamp, checkpoint.size(), checkpoint.hash());
        let raw: Signature = key.sign(&message);
        let mut tree_head = timestamp.to_be_bytes().to_vec();
        tree_head.extend(encode_signature(raw.to_bytes().as_slice()).unwrap());
        assert_eq!(&tree_head[8..], static_ct_api::sign(&key, &message));
        let witness_signature = ed25519_dalek::Signer::sign(&witness, &checkpoint.to_bytes());
        let note = Note::new(
            &checkpoint.to_bytes(),
            &[
                NoteSignature::new(origin.clone(), log_verifier.key_id(), tree_head),
                NoteSignature::new(
                    origin.clone(),
                    witness_verifier.key_id(),
                    witness_signature.to_vec(),
                ),
            ],
        )
        .unwrap();
        let verifiers = VerifierList::new(vec![Box::new(log_verifier), Box::new(witness_verifier)]);
        open_checkpoint(origin.as_str(), &verifiers, timestamp, &note.to_bytes()).unwrap();
    }
}
