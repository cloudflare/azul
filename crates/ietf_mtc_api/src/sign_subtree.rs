// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! MTC-flavored re-exports of the generic `sign-subtree` cosigner protocol.
//!
//! The wire format is specified in draft-ietf-plants-merkle-tree-certs-02
//! Appendix C.2 and is expected to migrate into a standalone C2SP spec
//! (provisionally `c2sp.org/tlog-subtree-signature`). The transport-layer
//! parsers/serializers live in the [`tlog_subtree_signature`] crate, which
//! this module re-exports for source compatibility; this module adds the
//! MTC-specific [`MtcSubtreeNoteVerifier`] that bakes in the MTC
//! `oid/{id_rdna_trustanchor_id}.{log_id}` key name format and the
//! `mtc-subtree/v1` key-ID context string.
//!
//! # What this module provides
//!
//! - Re-exports of [`SignSubtreeRequest`], [`SubtreeNoteBody`],
//!   [`parse_sign_subtree_request`], [`serialize_sign_subtree_response`],
//!   [`serialize_subtree_note_body`], [`serialize_sign_subtree_request`],
//!   [`parse_sign_subtree_response`], and [`MAX_CONSISTENCY_PROOF_HASHES`]
//!   from [`tlog_subtree_signature`].
//! - [`MtcSubtreeNoteVerifier`]: a [`NoteVerifier`] for MTC subtree
//!   cosignatures. Relocated from [`crate::cosigner`] because it is only
//!   meaningful in the context of the `sign-subtree` flow.
//!
//! The semantic-validation and cosigning logic (checking the checkpoint
//! signature against the cosigner's own key, verifying the consistency proof,
//! producing a cosignature via [`crate::MtcCosigner::sign_subtree`], etc.) is
//! *not* in this module — that belongs in the worker, where keys, log state,
//! and policy decisions live.

pub use tlog_subtree_signature::{
    parse_sign_subtree_request, parse_sign_subtree_response, serialize_sign_subtree_request,
    serialize_sign_subtree_response, serialize_subtree_note_body, SignSubtreeRequest,
    SubtreeNoteBody, MAX_CONSISTENCY_PROOF_HASHES,
};

use signed_note::{KeyName, NoteError, NoteVerifier};
use tlog_subtree_signature::SubtreeNoteVerifier;

use crate::{MtcVerifyingKey, TrustAnchorID, ID_RDNA_TRUSTANCHOR_ID};

// ---------------------------------------------------------------------------
// MtcSubtreeNoteVerifier
// ---------------------------------------------------------------------------

/// Verifier for MTC subtree cosignatures in signed-note format (Appendix C.1/C.2).
///
/// Used when verifying signatures attached to the incoming subtree note at the
/// `sign-subtree` endpoint. The key name is
/// `oid/{id_rdna_trustanchor_id}.{log_id}` and the key ID is derived from the
/// `mtc-subtree/v1` context string, distinct from checkpoint cosignatures.
///
/// Internally this wraps a generic
/// [`SubtreeNoteVerifier<MtcVerifyingKey>`][SubtreeNoteVerifier] with the
/// MTC-specific naming baked in.
///
/// Certificates embed raw signature bytes directly (not signed-note lines); use
/// [`crate::ParsedMtcProof::verify_cosignature`] for those.
///
/// See <https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-02.html#appendix-C.1>.
#[derive(Clone)]
pub struct MtcSubtreeNoteVerifier {
    inner: SubtreeNoteVerifier<MtcVerifyingKey>,
}

impl MtcSubtreeNoteVerifier {
    /// Construct a new subtree note verifier.
    ///
    /// # Panics
    ///
    /// Will panic if the trust anchor ID cannot be formatted as a valid key
    /// name per <https://c2sp.org/signed-note#format>.
    #[must_use]
    pub fn new(
        cosigner_id: &TrustAnchorID,
        log_id: &TrustAnchorID,
        verifying_key: MtcVerifyingKey,
    ) -> Self {
        let name = KeyName::new(format!("oid/{ID_RDNA_TRUSTANCHOR_ID}.{log_id}")).unwrap();
        let id = signed_note::compute_key_id(&name, b"\xffmtc-subtree/v1", &[]);
        let inner = SubtreeNoteVerifier::new(
            name,
            id,
            cosigner_id.as_bytes().to_vec(),
            log_id.as_bytes().to_vec(),
            verifying_key,
        );
        Self { inner }
    }
}

impl NoteVerifier for MtcSubtreeNoteVerifier {
    fn name(&self) -> &KeyName {
        self.inner.name()
    }

    fn key_id(&self) -> u32 {
        self.inner.key_id()
    }

    fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        self.inner.verify(msg, sig_bytes)
    }

    fn extract_timestamp_millis(&self, sig: &[u8]) -> Result<Option<u64>, NoteError> {
        self.inner.extract_timestamp_millis(sig)
    }
}
