// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! An implementation of [c2sp.org/tlog-cosignature][spec].
//!
//! A *cosignature* is a statement by a cosigner that it verified the
//! consistency of a [checkpoint][]. Log clients combine cosignatures from
//! multiple cosigners to prevent split-view attacks before trusting an
//! inclusion proof.
//!
//! This crate provides signers and verifiers for the cosignature formats
//! specified by the C2SP document:
//!
//! - [`cosignature_v1`]: the legacy Ed25519 timestamped checkpoint
//!   cosignature (signed-note algorithm byte `0x04`). Locked to
//!   start = 0; signs the checkpoint note body verbatim.
//! - [`subtree_v1`]: an ML-DSA-44 cosignature over an arbitrary subtree
//!   (signed-note algorithm byte `0x06`). The checkpoint case
//!   (`start = 0`, `end = size`) is interchangeable with `cosignature/v1`
//!   semantically; non-zero `start` cosignatures are used by tlog-witness'
//!   `sign-subtree` API and by Merkle Tree certificates.
//!
//! HTTP transports for requesting cosignatures are out of scope; see
//! [`tlog_witness`] for parsers/serializers of the
//! [c2sp.org/tlog-witness](https://c2sp.org/tlog-witness) protocol.
//!
//! [spec]: https://c2sp.org/tlog-cosignature
//! [checkpoint]: https://c2sp.org/tlog-checkpoint
//! [`tlog_witness`]: https://docs.rs/tlog_witness

pub mod cosignature_v1;
pub mod subtree_v1;

pub use cosignature_v1::{CosignatureV1CheckpointSigner, CosignatureV1NoteVerifier};
pub use subtree_v1::{SubtreeV1CheckpointSigner, SubtreeV1NoteVerifier};
