// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! An implementation of [c2sp.org/tlog-mirror](https://c2sp.org/tlog-mirror).
//!
//! This crate provides the wire-format pieces needed to build a tlog
//! mirror, deliberately scoped to spec-level concerns:
//!
//! * [`wire::AddEntriesRequestHeader`] and [`wire::EntryPackage`] for the
//!   `add-entries` request body.
//! * [`wire::MirrorInfo`] for the `text/x.tlog.mirror-info` 409 Conflict
//!   response body.
//! * [`TicketMacer`] for the default opaque-ticket authentication
//!   scheme (HMAC-SHA-256 truncated to 128 bits over the
//!   signed-checkpoint bytes). The construction is deterministic;
//!   confidentiality is not required because pending checkpoints are
//!   public.
//!
//! The mirror's `add-checkpoint` endpoint handles requests identically
//! to a witness's `add-checkpoint` (per spec) but writes to a *pending*
//! checkpoint slot rather than the witness's monotonic checkpoint state.
//! The wire format is reused via the `tlog_witness` crate; the request
//! handler is not currently shared and lives in each worker's frontend.
//!
//! Storage, retention, and pruning policy are out of scope for this
//! crate.
//!
//! See the spec for a full description of the mirror protocol.

// TODO: factor the witness `add-checkpoint` request handler currently
// living in `crates/witness_worker/src/frontend_worker.rs` into a
// reusable helper (likely in `tlog_witness` or a new `tlog_witness_io`
// crate) so that mirrors and witnesses share the implementation, not
// just the wire format. Tracked alongside #230.

pub mod ticket;
pub mod wire;

mod error;

pub use error::{ParseError, TicketError};
pub use ticket::{TicketMacer, TAG_LEN};
pub use wire::{
    package_ranges, AddEntriesRequestHeader, EntryPackage, MirrorInfo, PackageRanges,
    MAX_HASHES_PER_PROOF, MIRROR_INFO_CONTENT_TYPE, PACKAGE_ALIGNMENT,
};
