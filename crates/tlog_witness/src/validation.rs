// Copyright (c) 2025-2026 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

use signed_note::{Note, NoteError, VerifierList};
use tlog_checkpoint::{CheckpointText, MalformedCheckpointTextError};
use tlog_core::{
    EMPTY_HASH, Hash, Subtree, verify_consistency_proof, verify_subtree_consistency_proof,
};

use crate::{
    AddCheckpointRequest, SignSubtreeRequest, TlogWitnessError, parse_add_checkpoint_request,
    parse_sign_subtree_request,
};

/// An `add-checkpoint` request after wire, checkpoint, and range validation.
#[derive(Debug)]
pub struct ValidatedAddCheckpointRequest {
    old_size: u64,
    consistency_proof: Vec<Hash>,
    checkpoint: Note,
    checkpoint_text: CheckpointText,
}

impl ValidatedAddCheckpointRequest {
    #[must_use]
    pub fn into_parts(self) -> (u64, Vec<Hash>, Note, CheckpointText) {
        (
            self.old_size,
            self.consistency_proof,
            self.checkpoint,
            self.checkpoint_text,
        )
    }
}

/// Validate the transport-neutral parts of an `add-checkpoint` request.
///
/// # Errors
///
/// Returns a domain error for malformed wire data, malformed checkpoint text,
/// or an old size greater than the submitted checkpoint size.
pub fn validate_add_checkpoint_request(
    body: &[u8],
) -> Result<ValidatedAddCheckpointRequest, AddCheckpointValidationError> {
    let AddCheckpointRequest {
        old_size,
        consistency_proof,
        checkpoint,
    } = parse_add_checkpoint_request(body).map_err(AddCheckpointValidationError::Request)?;
    let checkpoint_text = CheckpointText::from_bytes(checkpoint.text())
        .map_err(AddCheckpointValidationError::Checkpoint)?;
    if old_size > checkpoint_text.size() {
        return Err(AddCheckpointValidationError::OldSizeAfterCheckpoint {
            old_size,
            checkpoint_size: checkpoint_text.size(),
        });
    }
    Ok(ValidatedAddCheckpointRequest {
        old_size,
        consistency_proof,
        checkpoint,
        checkpoint_text,
    })
}

/// Domain errors from transport-neutral `add-checkpoint` validation.
#[derive(Debug, thiserror::Error)]
pub enum AddCheckpointValidationError {
    #[error("{0}")]
    Request(TlogWitnessError),
    #[error("{0}")]
    Checkpoint(MalformedCheckpointTextError),
    #[error("old_size {old_size} > checkpoint size {checkpoint_size}")]
    OldSizeAfterCheckpoint { old_size: u64, checkpoint_size: u64 },
}

/// Errors from checking a checkpoint against a caller-supplied trust set.
#[derive(Debug, thiserror::Error)]
pub enum TrustedSignatureError {
    #[error("no valid signatures from trusted keys: {0:?}")]
    NoValidSignature(NoteError),
    #[error("unexpected verifier error: {0:?}")]
    VerifierInvariant(NoteError),
}

/// Require at least one valid checkpoint signature from `verifiers`.
///
/// # Errors
///
/// Signature absence and invalid signatures are client-domain failures.
/// Other verifier errors indicate an invalid verifier configuration or an
/// invariant violation.
pub fn verify_trusted_checkpoint_signature(
    checkpoint: &Note,
    verifiers: &VerifierList,
) -> Result<(), TrustedSignatureError> {
    checkpoint
        .verify(verifiers)
        .map(|_| ())
        .map_err(|error| match error {
            NoteError::UnverifiedNote | NoteError::InvalidSignature { .. } => {
                TrustedSignatureError::NoValidSignature(error)
            }
            _ => TrustedSignatureError::VerifierInvariant(error),
        })
}

/// A `sign-subtree` request after wire, checkpoint, and range validation.
#[derive(Debug)]
pub struct ValidatedSignSubtreeRequest {
    subtree_hash: Hash,
    subtree_cosignatures: Vec<signed_note::NoteSignature>,
    consistency_proof: Vec<Hash>,
    checkpoint: Note,
    checkpoint_text: CheckpointText,
    subtree: Subtree,
}

impl ValidatedSignSubtreeRequest {
    #[must_use]
    pub const fn subtree_hash(&self) -> &Hash {
        &self.subtree_hash
    }

    #[must_use]
    pub fn subtree_cosignatures(&self) -> &[signed_note::NoteSignature] {
        &self.subtree_cosignatures
    }

    #[must_use]
    pub fn consistency_proof(&self) -> &[Hash] {
        &self.consistency_proof
    }

    #[must_use]
    pub const fn checkpoint(&self) -> &Note {
        &self.checkpoint
    }

    #[must_use]
    pub const fn checkpoint_text(&self) -> &CheckpointText {
        &self.checkpoint_text
    }

    #[must_use]
    pub const fn subtree(&self) -> &Subtree {
        &self.subtree
    }
}

/// Domain errors from transport-neutral `sign-subtree` validation.
#[derive(Debug, thiserror::Error)]
pub enum SignSubtreeValidationError {
    #[error("{0}")]
    Request(TlogWitnessError),
    #[error("{0}")]
    Checkpoint(MalformedCheckpointTextError),
    #[error("subtree end {subtree_end} > checkpoint size {checkpoint_size}")]
    SubtreeAfterCheckpoint {
        subtree_end: u64,
        checkpoint_size: u64,
    },
    #[error("invalid subtree: {0:?}")]
    InvalidSubtree(tlog_core::TlogError),
    #[error("subtree consistency proof failed")]
    ConsistencyProofFailed,
}

/// Validate the transport-neutral structural parts of a `sign-subtree` request.
///
/// # Errors
///
/// Returns a domain error for malformed wire data or checkpoint text, and for
/// a range that is invalid or extends past the checkpoint.
pub fn validate_sign_subtree_request(
    body: &[u8],
) -> Result<ValidatedSignSubtreeRequest, SignSubtreeValidationError> {
    let SignSubtreeRequest {
        subtree_start,
        subtree_end,
        subtree_hash,
        subtree_cosignatures,
        consistency_proof,
        checkpoint,
    } = parse_sign_subtree_request(body).map_err(SignSubtreeValidationError::Request)?;
    let checkpoint_text = CheckpointText::from_bytes(checkpoint.text())
        .map_err(SignSubtreeValidationError::Checkpoint)?;
    if subtree_end > checkpoint_text.size() {
        return Err(SignSubtreeValidationError::SubtreeAfterCheckpoint {
            subtree_end,
            checkpoint_size: checkpoint_text.size(),
        });
    }
    let subtree = Subtree::new(subtree_start, subtree_end)
        .map_err(SignSubtreeValidationError::InvalidSubtree)?;
    Ok(ValidatedSignSubtreeRequest {
        subtree_hash,
        subtree_cosignatures,
        consistency_proof,
        checkpoint,
        checkpoint_text,
        subtree,
    })
}

/// Verify a validated subtree against its reference checkpoint.
///
/// # Errors
///
/// Returns [`SignSubtreeValidationError::ConsistencyProofFailed`] if the proof
/// does not authenticate the subtree.
pub fn validate_sign_subtree_proof(
    request: &ValidatedSignSubtreeRequest,
) -> Result<(), SignSubtreeValidationError> {
    verify_subtree_consistency_proof(
        &request.consistency_proof,
        request.checkpoint_text.size(),
        *request.checkpoint_text.hash(),
        &request.subtree,
        request.subtree_hash,
    )
    .map_err(|_| SignSubtreeValidationError::ConsistencyProofFailed)
}

/// The size and root hash relevant to an atomic checkpoint transition.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CheckpointState {
    pub size: u64,
    pub hash: Hash,
}

/// Why an empty consistency proof is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofRequirement {
    Initial,
    SameSize,
}

/// Domain errors from validating an atomic checkpoint state transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointTransitionError {
    #[error("stored size does not match old size")]
    OldSizeMismatch,
    #[error("stored hash does not match checkpoint hash at the same size")]
    HashMismatch,
    #[error("a size-zero checkpoint must use the empty-tree hash")]
    InvalidEmptyTreeHash,
    #[error("consistency proof must be empty")]
    ProofMustBeEmpty(ProofRequirement),
    #[error("consistency proof failed")]
    ConsistencyProofFailed,
}

/// Validate a checkpoint transition against persisted state.
///
/// # Errors
///
/// Returns a domain error for stale state, same-size hash disagreement,
/// forbidden proof data, or a failed consistency proof.
pub fn validate_checkpoint_transition(
    current: Option<CheckpointState>,
    old_size: u64,
    new: CheckpointState,
    proof: &[Hash],
) -> Result<(), CheckpointTransitionError> {
    if new.size == 0 && new.hash != EMPTY_HASH {
        return Err(CheckpointTransitionError::InvalidEmptyTreeHash);
    }
    let Some(current) = current else {
        if old_size != 0 {
            return Err(CheckpointTransitionError::OldSizeMismatch);
        }
        if !proof.is_empty() {
            return Err(CheckpointTransitionError::ProofMustBeEmpty(
                ProofRequirement::Initial,
            ));
        }
        return Ok(());
    };
    if current.size != old_size {
        return Err(CheckpointTransitionError::OldSizeMismatch);
    }
    if old_size == new.size {
        if current.hash != new.hash {
            return Err(CheckpointTransitionError::HashMismatch);
        }
        if !proof.is_empty() {
            return Err(CheckpointTransitionError::ProofMustBeEmpty(
                ProofRequirement::SameSize,
            ));
        }
        return Ok(());
    }
    if old_size == 0 {
        if !proof.is_empty() {
            return Err(CheckpointTransitionError::ProofMustBeEmpty(
                ProofRequirement::Initial,
            ));
        }
        return Ok(());
    }
    verify_consistency_proof(proof, new.size, new.hash, old_size, current.hash)
        .map_err(|_| CheckpointTransitionError::ConsistencyProofFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use signed_note::{KeyName, NoteSignature};
    use tlog_core::{EMPTY_HASH, node_hash, record_hash};

    #[test]
    #[allow(clippy::too_many_lines)]
    fn checkpoint_transition_table() {
        let a = record_hash(b"a");
        let b = record_hash(b"b");
        let two = node_hash(a, b);
        let cases = [
            (
                "empty accepts the protocol zero root",
                None,
                0,
                CheckpointState {
                    size: 0,
                    hash: EMPTY_HASH,
                },
                vec![],
                Ok(()),
            ),
            (
                "empty rejects nonzero old",
                None,
                1,
                CheckpointState { size: 1, hash: a },
                vec![],
                Err(CheckpointTransitionError::OldSizeMismatch),
            ),
            (
                "empty rejects a non-empty root",
                None,
                0,
                CheckpointState { size: 0, hash: a },
                vec![],
                Err(CheckpointTransitionError::InvalidEmptyTreeHash),
            ),
            (
                "empty rejects proof",
                None,
                0,
                CheckpointState { size: 1, hash: a },
                vec![b],
                Err(CheckpointTransitionError::ProofMustBeEmpty(
                    ProofRequirement::Initial,
                )),
            ),
            (
                "stale old",
                Some(CheckpointState { size: 1, hash: a }),
                0,
                CheckpointState { size: 1, hash: a },
                vec![],
                Err(CheckpointTransitionError::OldSizeMismatch),
            ),
            (
                "same size and hash",
                Some(CheckpointState { size: 1, hash: a }),
                1,
                CheckpointState { size: 1, hash: a },
                vec![],
                Ok(()),
            ),
            (
                "same size different hash",
                Some(CheckpointState { size: 1, hash: a }),
                1,
                CheckpointState { size: 1, hash: b },
                vec![],
                Err(CheckpointTransitionError::HashMismatch),
            ),
            (
                "same size rejects proof",
                Some(CheckpointState { size: 1, hash: a }),
                1,
                CheckpointState { size: 1, hash: a },
                vec![b],
                Err(CheckpointTransitionError::ProofMustBeEmpty(
                    ProofRequirement::SameSize,
                )),
            ),
            (
                "persisted zero advances without proof",
                Some(CheckpointState {
                    size: 0,
                    hash: EMPTY_HASH,
                }),
                0,
                CheckpointState { size: 1, hash: a },
                vec![],
                Ok(()),
            ),
            (
                "persisted zero accepts the same empty checkpoint",
                Some(CheckpointState {
                    size: 0,
                    hash: EMPTY_HASH,
                }),
                0,
                CheckpointState {
                    size: 0,
                    hash: EMPTY_HASH,
                },
                vec![],
                Ok(()),
            ),
            (
                "persisted zero rejects a non-empty root",
                Some(CheckpointState {
                    size: 0,
                    hash: EMPTY_HASH,
                }),
                0,
                CheckpointState { size: 0, hash: a },
                vec![],
                Err(CheckpointTransitionError::InvalidEmptyTreeHash),
            ),
            (
                "persisted zero rejects proof",
                Some(CheckpointState {
                    size: 0,
                    hash: EMPTY_HASH,
                }),
                0,
                CheckpointState { size: 1, hash: a },
                vec![b],
                Err(CheckpointTransitionError::ProofMustBeEmpty(
                    ProofRequirement::Initial,
                )),
            ),
            (
                "valid growth",
                Some(CheckpointState { size: 1, hash: a }),
                1,
                CheckpointState { size: 2, hash: two },
                vec![b],
                Ok(()),
            ),
            (
                "invalid growth proof",
                Some(CheckpointState { size: 1, hash: a }),
                1,
                CheckpointState { size: 2, hash: two },
                vec![],
                Err(CheckpointTransitionError::ConsistencyProofFailed),
            ),
        ];
        for (name, current, old_size, new, proof, expected) in cases {
            assert_eq!(
                validate_checkpoint_transition(current, old_size, new, &proof),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn validated_subtree_retains_cosignatures() {
        let checkpoint = Note::new(
            format!(
                "log.example\n1\n{}\n",
                base64::engine::general_purpose::STANDARD.encode(record_hash(b"entry").0)
            )
            .as_bytes(),
            &[],
        )
        .unwrap();
        let cosignature = NoteSignature::new(
            KeyName::new("witness.example".to_owned()).unwrap(),
            7,
            vec![9; 64],
        );
        let body = crate::serialize_sign_subtree_request(
            0,
            1,
            &record_hash(b"entry"),
            std::slice::from_ref(&cosignature),
            &[],
            &checkpoint,
        )
        .unwrap();
        let validated = validate_sign_subtree_request(&body).unwrap();
        assert_eq!(validated.subtree_cosignatures().len(), 1);
        assert_eq!(validated.subtree_cosignatures()[0].id(), 7);
    }
}
