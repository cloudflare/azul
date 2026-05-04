// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! An implementation of [c2sp.org/tlog-mirror](https://c2sp.org/tlog-mirror).
//!
//! Wire-format pieces for building a tlog mirror, scoped to spec-level
//! concerns:
//!
//! * [`wire::AddEntriesRequestHeader`] and [`wire::EntryPackage`] for the
//!   `add-entries` request body.
//! * [`wire::MirrorInfo`] for the `text/x.tlog.mirror-info` 409 Conflict
//!   response body.
//! * [`TicketSealer`] for the default opaque-ticket scheme.
//!
//! A mirror's `add-checkpoint` endpoint is expected to reuse the witness
//! wire format via the `tlog_witness` crate. Storage, retention, and
//! pruning policy are out of scope.

pub mod ticket;
pub mod wire;

mod error;

pub use error::{ParseError, TicketError};
pub use ticket::{TAG_LEN, TicketSealer};
pub use wire::{
    AddEntriesRequestHeader, EntryPackage, MAX_HASHES_PER_PROOF, MIRROR_INFO_CONTENT_TYPE,
    MirrorInfo, PACKAGE_ALIGNMENT, PackageRanges, package_ranges,
};
