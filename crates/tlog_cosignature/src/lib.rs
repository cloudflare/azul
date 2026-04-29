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
//! specified by the C2SP document. Today only the Ed25519 `cosignature/v1`
//! format is implemented (in the [`cosignature_v1`] module); the
//! ML-DSA-44 `subtree/v1` format will be added in a follow-up alongside
//! support for signing arbitrary subtrees.
//!
//! HTTP transports for requesting cosignatures are out of scope; see
//! [`tlog_witness`] for parsers/serializers of the
//! [c2sp.org/tlog-witness](https://c2sp.org/tlog-witness) protocol.
//!
//! [spec]: https://c2sp.org/tlog-cosignature
//! [checkpoint]: https://c2sp.org/tlog-checkpoint
//! [`tlog_witness`]: https://docs.rs/tlog_witness

pub mod cosignature_v1;

pub use cosignature_v1::{CosignatureV1CheckpointSigner, CosignatureV1NoteVerifier};
