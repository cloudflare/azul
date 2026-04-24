// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! MTC cosigner types for signing and verifying checkpoints and subtrees.
//!
//! # Overview
//!
//! A CA maintains a single key pair ([`MtcSigningKey`] / [`MtcVerifyingKey`]) used to sign
//! both tlog checkpoints and MTC subtrees. The two uses share the same binary signing format
//! (the `mtc-subtree/v1` layout from
//! [`tlog_subtree_signature::serialize_subtree_signature_input`]) but are distinguished by
//! different key IDs in the signed-note layer:
//!
//! - **Checkpoint signatures** (`start = 0`): published at the `/checkpoint` endpoint and
//!   consumed by tlog witnesses and mirrors. The signed-note key ID is derived from the
//!   `mtc-checkpoint/v1` context string. See [`MtcCheckpointNoteVerifier`].
//!
//! - **Subtree signatures** (`start ≥ 0`): embedded in the `signatureValue` of standalone
//!   MTC certificates (§6.2). The signed-note key ID is derived from the `mtc-subtree/v1`
//!   context string. For certificate verification, [`ParsedMtcProof::verify_cosignature`]
//!   verifies the raw signature bytes directly, bypassing the note layer. For the
//!   `sign-subtree` HTTP endpoint (Appendix C.2), use
//!   [`MtcSubtreeNoteVerifier`][crate::MtcSubtreeNoteVerifier], which lives in the
//!   [`sign_subtree`][crate::sign_subtree] module alongside the request/response
//!   parsers.
//!
//! # Types
//!
//! - [`MtcCosigner`]: holds a key pair and implements [`CheckpointSigner`] for the tlog
//!   machinery. Also exposes [`MtcCosigner::sign_subtree`] for producing certificate
//!   cosignatures.
//!
//! - [`MtcCheckpointNoteVerifier`]: [`NoteVerifier`] for checkpoint-scoped signatures.
//!   Used with [`open_checkpoint`][tlog_tiles::open_checkpoint] to verify the `/checkpoint`
//!   endpoint.
//!
//! - [`ParsedMtcProof`]: parses and verifies the `MTCProof` from a certificate's
//!   `signatureValue`.
//!
//! The binary signing format and the algorithm-agnostic [`RawSigner`] / [`RawVerifier`]
//! traits live in the [`tlog_subtree_signature`] crate. [`MtcSigningKey`] /
//! [`MtcVerifyingKey`] implement those traits so MTC keys can be plugged into that
//! crate's [`sign_subtree`][tlog_subtree_signature::sign_subtree] and
//! [`SubtreeNoteVerifier`][tlog_subtree_signature::SubtreeNoteVerifier] helpers.
//!
//! # Algorithm support
//!
//! Both Ed25519 and ML-DSA-44 are supported.
//!
//! ML-DSA-44 uses the `RustCrypto` `ml-dsa` crate. When draft-03 aligns with the
//! `subtree/v1` unified signature format from <https://github.com/C2SP/C2SP/pull/237>,
//! the binary signing format (and the key ID algorithm bytes) will need to be
//! updated in `tlog_subtree_signature`.
//!
//! [`RawSigner`]: tlog_subtree_signature::RawSigner
//! [`RawVerifier`]: tlog_subtree_signature::RawVerifier

use byteorder::{BigEndian, ReadBytesExt};
use ed25519_dalek::pkcs8::EncodePublicKey as Ed25519EncodePublicKey;
use ed25519_dalek::{
    ed25519::signature::{self, Signer as Ed25519SignerTrait},
    SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use ml_dsa::{
    signature::Verifier as MlDsaVerifier, EncodedSignature as MlDsaEncodedSignature,
    ExpandedSigningKey as MlDsaExpandedSigningKey, MlDsa44, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey,
};
use pkcs8::EncodePublicKey as PkcsEncodePublicKey;
use signed_note::{KeyName, NoteError, NoteSignature, NoteVerifier};
use std::collections::HashMap;
use tlog_subtree_signature::{
    serialize_subtree_signature_input, sign_subtree as sign_subtree_raw, RawSigner, RawVerifier,
};
use tlog_tiles::{CheckpointSigner, CheckpointText, Hash, LeafIndex, UnixTimestamp};

use crate::{RelativeOid, ID_RDNA_TRUSTANCHOR_ID};

pub type TrustAnchorID = RelativeOid;

// ---------------------------------------------------------------------------
// Multi-algorithm key types
// ---------------------------------------------------------------------------

/// A signing key for MTC checkpoint and subtree cosignatures.
// ML-DSA signing key is ~2.5× the size of Ed25519's; the enum is always used
// behind indirection (via `MtcCosigner`) so the size difference is not a
// hot-path concern.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum MtcSigningKey {
    Ed25519(Ed25519SigningKey),
    MlDsa44(MlDsaExpandedSigningKey<MlDsa44>),
}

/// A verifying key for MTC checkpoint and subtree cosignatures.
// ML-DSA verifying key is much larger than Ed25519's; see note on MtcSigningKey.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum MtcVerifyingKey {
    Ed25519(Ed25519VerifyingKey),
    MlDsa44(MlDsaVerifyingKey<MlDsa44>),
}

impl RawSigner for MtcSigningKey {
    /// Sign `msg`, returning the algorithm's raw signature bytes.
    ///
    /// Not currently fallible for either variant, but future algorithms
    /// (e.g. randomized schemes requiring entropy) may be.
    fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        Ok(match self {
            Self::Ed25519(sk) => sk.sign(msg).to_bytes().to_vec(),
            Self::MlDsa44(sk) => sk.sign(msg).encode().as_slice().to_vec(),
        })
    }
}

impl RawVerifier for MtcVerifyingKey {
    fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        match self {
            Self::Ed25519(vk) => {
                let Ok(sig_arr) = sig_bytes.try_into() else {
                    return false;
                };
                let sig = ed25519_dalek::Signature::from_bytes(sig_arr);
                Ed25519Verifier::verify(vk, msg, &sig).is_ok()
            }
            Self::MlDsa44(vk) => MlDsaEncodedSignature::<MlDsa44>::try_from(sig_bytes)
                .ok()
                .and_then(|enc| MlDsaSignature::<MlDsa44>::decode(&enc))
                .is_some_and(|sig| MlDsaVerifier::verify(vk, msg, &sig).is_ok()),
        }
    }
}

impl MtcVerifyingKey {
    /// Return the DER-encoded `SubjectPublicKeyInfo` for this key. This includes the algorithm
    /// prefix to allow for distinguishing between key types.
    ///
    /// # Panics
    ///
    /// Panics if PKCS#8 encoding fails, which should never happen for a valid key.
    #[must_use]
    pub fn to_public_key_der(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(vk) => Ed25519EncodePublicKey::to_public_key_der(vk)
                .expect("Ed25519 SPKI encoding failed")
                .to_vec(),
            Self::MlDsa44(vk) => PkcsEncodePublicKey::to_public_key_der(vk)
                .expect("ML-DSA-44 SPKI encoding failed")
                .to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// MtcCosigner
// ---------------------------------------------------------------------------

pub struct MtcCosigner {
    v: MtcCheckpointNoteVerifier,
    k: MtcSigningKey,
}

impl MtcCosigner {
    /// Return a checkpoint cosigner from an `MtcSigningKey` and `MtcVerifyingKey`.
    #[must_use]
    pub fn new_checkpoint(
        cosigner_id: TrustAnchorID,
        log_id: TrustAnchorID,
        sk: MtcSigningKey,
        vk: MtcVerifyingKey,
    ) -> Self {
        Self {
            v: MtcCheckpointNoteVerifier::new(cosigner_id, log_id, vk),
            k: sk,
        }
    }

    /// Compute a subtree cosignature as defined in
    /// <https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-02.html#name-signature-format>.
    ///
    /// Delegates the binary-format construction and signing to
    /// [`tlog_subtree_signature::sign_subtree`].
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails. Future algorithm variants may be
    /// fallible; use this method when the error can be propagated.
    pub fn sign_subtree(
        &self,
        start: LeafIndex,
        end: LeafIndex,
        root_hash: &Hash,
    ) -> Result<Vec<u8>, signature::Error> {
        sign_subtree_raw(
            &self.k,
            self.v.cosigner_id.as_bytes(),
            self.v.log_id.as_bytes(),
            start,
            end,
            root_hash,
        )
    }

    /// Return the log ID.
    #[must_use]
    pub fn log_id(&self) -> &TrustAnchorID {
        &self.v.log_id
    }

    /// Return the cosigner ID.
    #[must_use]
    pub fn cosigner_id(&self) -> &TrustAnchorID {
        &self.v.cosigner_id
    }

    /// Return the DER-encoded `SubjectPublicKeyInfo` of the verifying key.
    /// This allows clients pulling the get from the /metadata endpoint to determine the algorithm.
    #[must_use]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.v.verifying_key.to_public_key_der()
    }
}

/// Support signing tlog-checkpoints. For checkpoints, the subtree start index is always 0.
impl CheckpointSigner for MtcCosigner {
    fn name(&self) -> &KeyName {
        self.v.name()
    }

    fn key_id(&self) -> u32 {
        self.v.key_id()
    }

    fn sign(
        &self,
        _timestamp_unix_millis: UnixTimestamp,
        checkpoint: &tlog_tiles::CheckpointText,
    ) -> Result<NoteSignature, NoteError> {
        let sig = self.sign_subtree(0, checkpoint.size(), checkpoint.hash())?;
        Ok(NoteSignature::new(self.name().clone(), self.key_id(), sig))
    }

    fn verifier(&self) -> Box<dyn NoteVerifier> {
        Box::new(self.v.clone())
    }
}

// ---------------------------------------------------------------------------
// MtcCheckpointNoteVerifier
// ---------------------------------------------------------------------------

/// Verifier for MTC checkpoint cosignatures (subtrees with `start = 0`).
///
/// Used with the tlog signed-note machinery to verify the `/checkpoint` endpoint
/// and `open_checkpoint` calls. The key ID is derived from the `mtc-checkpoint/v1`
/// context string, distinct from subtree cosignatures.
///
/// See <https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-02.html#appendix-C.1>.
#[derive(Clone)]
pub struct MtcCheckpointNoteVerifier {
    cosigner_id: TrustAnchorID,
    log_id: TrustAnchorID,
    name: KeyName,
    id: u32,
    verifying_key: MtcVerifyingKey,
}

impl MtcCheckpointNoteVerifier {
    /// Construct a new checkpoint note verifier.
    ///
    /// # Panics
    ///
    /// Will panic if the trust anchor ID cannot be parsed as a valid key name
    /// according to <https://c2sp.org/signed-note#format>.
    #[must_use]
    pub fn new(
        cosigner_id: TrustAnchorID,
        log_id: TrustAnchorID,
        verifying_key: MtcVerifyingKey,
    ) -> Self {
        let name = KeyName::new(format!("oid/{ID_RDNA_TRUSTANCHOR_ID}.{log_id}")).unwrap();
        let id = signed_note::compute_key_id(&name, b"\xffmtc-checkpoint/v1", &[]);
        Self {
            cosigner_id,
            log_id,
            name,
            id,
            verifying_key,
        }
    }
}

impl NoteVerifier for MtcCheckpointNoteVerifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    /// Verify a checkpoint cosignature. The `msg` is the raw checkpoint note body;
    /// it is parsed to extract the tree size and root hash, which are then used to
    /// reconstruct the `MTCSubtreeSignatureInput` with `start = 0`.
    fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        let Ok(checkpoint) = CheckpointText::from_bytes(msg) else {
            return false;
        };

        let msg = serialize_subtree_signature_input(
            self.cosigner_id.as_bytes(),
            self.log_id.as_bytes(),
            0,
            checkpoint.size(),
            checkpoint.hash(),
        );

        RawVerifier::verify(&self.verifying_key, &msg, sig_bytes)
    }

    fn extract_timestamp_millis(&self, _sig: &[u8]) -> Result<Option<u64>, NoteError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Proof parsing and verification
// ---------------------------------------------------------------------------

/// A decoded `MTCProof` extracted from a certificate's `signatureValue`.
///
/// See draft-ietf-plants-merkle-tree-certs §6.1.
#[derive(Debug)]
pub struct ParsedMtcProof {
    /// Start of the covering subtree interval (inclusive).
    pub start: u64,
    /// End of the covering subtree interval (exclusive).
    pub end: u64,
    /// Merkle inclusion proof hashes.
    pub inclusion_proof: Vec<Hash>,
    /// Cosignatures keyed by `cosigner_id`.
    pub signatures: HashMap<TrustAnchorID, Vec<u8>>,
}

impl ParsedMtcProof {
    /// Parse an `MTCProof` from the raw `signatureValue` bytes of an MTC certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are malformed.
    ///
    /// # Panics
    ///
    /// Panics if a 32-byte hash slice cannot be converted to a fixed-size array,
    /// which cannot happen since `chunks_exact(32)` guarantees the length.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, crate::MtcError> {
        let start = bytes.read_u64::<BigEndian>()?;
        let end = bytes.read_u64::<BigEndian>()?;

        // inclusion_proof: uint16-prefixed list of 32-byte hashes
        let proof_len = bytes.read_u16::<BigEndian>()? as usize;
        if bytes.len() < proof_len {
            return Err(crate::MtcError::Dynamic("truncated inclusion proof".into()));
        }
        let (proof_bytes, rest) = bytes.split_at(proof_len);
        bytes = rest;
        let inclusion_proof = proof_bytes
            .chunks_exact(32)
            .map(|c| Hash(c.try_into().unwrap()))
            .collect();

        // signatures: uint16-prefixed list of MtcSignature
        let sigs_len = bytes.read_u16::<BigEndian>()? as usize;
        if bytes.len() < sigs_len {
            return Err(crate::MtcError::Dynamic("truncated signatures".into()));
        }
        let mut sig_bytes = &bytes[..sigs_len];
        let mut signatures = HashMap::new();
        while !sig_bytes.is_empty() {
            let id_len = sig_bytes.read_u8()? as usize;
            if sig_bytes.len() < id_len {
                return Err(crate::MtcError::Dynamic("truncated cosigner_id".into()));
            }
            let id_raw = &sig_bytes[..id_len];
            sig_bytes = &sig_bytes[id_len..];
            let cosigner_id = TrustAnchorID::from_ber_bytes(id_raw)
                .map_err(|e| crate::MtcError::Dynamic(format!("invalid cosigner_id: {e}")))?;

            let signature_len = sig_bytes.read_u16::<BigEndian>()? as usize;
            if sig_bytes.len() < signature_len {
                return Err(crate::MtcError::Dynamic("truncated signature".into()));
            }
            let sig = sig_bytes[..signature_len].to_vec();
            sig_bytes = &sig_bytes[signature_len..];
            signatures.insert(cosigner_id, sig);
        }

        Ok(Self {
            start,
            end,
            inclusion_proof,
            signatures,
        })
    }

    /// Verify that one of the proof's cosignatures is valid for the given
    /// subtree hash, cosigner verifying key, cosigner ID, and log ID.
    ///
    /// This verifies the raw `MTCSubtreeSignatureInput` bytes directly, bypassing
    /// the signed-note layer. For verifying subtree notes from the `sign-subtree`
    /// endpoint, use [`MtcSubtreeNoteVerifier`] instead.
    ///
    /// # Errors
    ///
    /// Returns an error if no matching cosignature is found or verification fails.
    pub fn verify_cosignature(
        &self,
        subtree_hash: &Hash,
        verifying_key: &MtcVerifyingKey,
        cosigner_id: &TrustAnchorID,
        log_id: &TrustAnchorID,
    ) -> Result<(), crate::MtcError> {
        let sig_bytes = self.signatures.get(cosigner_id).ok_or_else(|| {
            crate::MtcError::Dynamic(format!("no signature found for cosigner_id {cosigner_id}"))
        })?;
        let msg = serialize_subtree_signature_input(
            cosigner_id.as_bytes(),
            log_id.as_bytes(),
            self.start,
            self.end,
            subtree_hash,
        );
        if RawVerifier::verify(verifying_key, &msg, sig_bytes) {
            Ok(())
        } else {
            Err(crate::MtcError::Dynamic(
                "cosignature verification failed".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {

    use tlog_tiles::{open_checkpoint, record_hash, TreeWithTimestamp};

    use super::*;
    use signed_note::VerifierList;
    use std::str::FromStr;

    #[test]
    fn test_cosignature_v1_sign_verify() {
        let origin = "example.com/origin";
        let timestamp = 100;
        let tree_size = 4;

        // Make a tree head and sign it
        let tree = TreeWithTimestamp::new(tree_size, record_hash(b"hello world"), timestamp);
        let signer = {
            let sk = Ed25519SigningKey::generate(&mut rand::rng());
            let vk = sk.verifying_key();
            MtcCosigner::new_checkpoint(
                TrustAnchorID::from_str("1.2.3").unwrap(),
                TrustAnchorID::from_str("4.5.6").unwrap(),
                MtcSigningKey::Ed25519(sk),
                MtcVerifyingKey::Ed25519(vk),
            )
        };
        let checkpoint = tree
            .sign(origin, &[], &[&signer], &mut rand::rng())
            .unwrap();

        // Now verify the signed checkpoint
        let verifier = signer.verifier();
        open_checkpoint(
            origin,
            &VerifierList::new(vec![verifier]),
            timestamp,
            &checkpoint,
        )
        .unwrap();
    }
}
