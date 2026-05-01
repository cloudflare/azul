// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! An implementation of the [c2sp.org/tlog-witness][spec] protocol.
//!
//! This crate provides wire-format parsers and serializers for the synchronous
//! HTTP witness protocol used by transparency logs to obtain cosignatures.
//! It is transport-agnostic and has no dependency on any particular HTTP
//! runtime — deployers plug it into their server of choice and supply their
//! own policy for verifying the log's checkpoint signature, persisting the
//! latest cosigned state, and producing cosignatures.
//!
//! # What's in scope
//!
//! - [`parse_add_checkpoint_request`] / [`serialize_add_checkpoint_request`]
//!   and the corresponding response helpers: wire-format parsers and
//!   serializers for the [`POST /add-checkpoint`][add] endpoint, in both
//!   directions (log → witness and witness → log).
//! - [`MAX_CONSISTENCY_PROOF_LINES`]: the spec-mandated upper bound of 63
//!   consistency-proof lines per request.
//! - [`CONTENT_TYPE_TLOG_SIZE`]: the `text/x.tlog.size` media type used for
//!   `409 Conflict` response bodies.
//!
//! # What's out of scope
//!
//! - Checkpoint-signature verification: the caller is expected to maintain a
//!   set of trusted log public keys and use its own [`signed_note`]-based
//!   verifier. The parsers here return the checkpoint [`Note`] with its
//!   signatures still attached so the caller can inspect them.
//! - Cosignature production: producing a `cosignature/v1` signature is
//!   handled by [`tlog_cosignature::CosignatureV1CheckpointSigner`] (or any
//!   other [`tlog_tiles::CheckpointSigner`] impl).
//! - Consistency-proof verification: use
//!   [`tlog_core::verify_consistency_proof`] directly.
//! - Persistent state for the "latest cosigned checkpoint per origin" check
//!   that [`add-checkpoint`][add] mandates — that is a deployment concern,
//!   not a wire-format concern.
//!
//! [spec]: https://c2sp.org/tlog-witness
//! [add]: https://c2sp.org/tlog-witness#add-checkpoint
//! [`Note`]: signed_note::Note
//! [`tlog_cosignature::CosignatureV1CheckpointSigner`]: https://docs.rs/tlog_cosignature/latest/tlog_cosignature/cosignature_v1/struct.CosignatureV1CheckpointSigner.html

mod add_checkpoint;

pub use add_checkpoint::{
    parse_add_checkpoint_request, parse_add_checkpoint_response, serialize_add_checkpoint_request,
    serialize_add_checkpoint_response, AddCheckpointRequest, TlogWitnessError,
    CONTENT_TYPE_TLOG_SIZE, MAX_CONSISTENCY_PROOF_LINES,
};
