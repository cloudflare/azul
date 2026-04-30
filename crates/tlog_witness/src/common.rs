// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Shared types and helpers used by both the [`add_checkpoint`] and
//! [`sign_subtree`] wire formats.
//!
//! Both endpoints share a common error enum and a common base64-encoded
//! consistency-proof line shape (32-byte hash per line, capped at
//! [`MAX_CONSISTENCY_PROOF_LINES`] per the spec).
//!
//! [`add_checkpoint`]: crate::add_checkpoint
//! [`sign_subtree`]: crate::sign_subtree

use base64::prelude::*;
use tlog_tiles::{Hash, HASH_SIZE};

/// Maximum number of consistency-proof lines a client may send in either
/// the `add-checkpoint` or `sign-subtree` request, per
/// [c2sp.org/tlog-witness][spec].
///
/// A Merkle consistency proof over a log with at most `2^64` entries has
/// at most 63 hashes.
///
/// [spec]: https://c2sp.org/tlog-witness
pub const MAX_CONSISTENCY_PROOF_LINES: usize = 63;

/// Content type used for `add-checkpoint`'s `409 Conflict` response
/// body, which carries the latest known tree size as ASCII decimal.
pub const CONTENT_TYPE_TLOG_SIZE: &str = "text/x.tlog.size";

/// Errors produced by this crate's parsers and serializers.
#[derive(Debug, thiserror::Error)]
pub enum TlogWitnessError {
    /// The request body failed high-level structural checks (missing
    /// blank line, malformed `old` or `subtree` line, too many
    /// proof/cosignature lines, etc.).
    #[error("malformed request: {0}")]
    MalformedRequest(String),

    /// The response body was malformed.
    #[error("malformed response: {0}")]
    MalformedResponse(String),

    /// An embedded signed note (checkpoint or signature line) failed to
    /// parse.
    #[error("signed note: {0:?}")]
    Note(signed_note::NoteError),
}

/// Parse a single base64-encoded consistency-proof line into a
/// 32-byte [`Hash`]. Used by both endpoint parsers.
pub(crate) fn parse_proof_line(line: &str) -> Result<Hash, TlogWitnessError> {
    let decoded = BASE64_STANDARD
        .decode(line)
        .map_err(|e| TlogWitnessError::MalformedRequest(format!("base64 proof line: {e}")))?;
    let arr: [u8; HASH_SIZE] = decoded.try_into().map_err(|v: Vec<u8>| {
        TlogWitnessError::MalformedRequest(format!(
            "consistency proof hash is {} bytes, want {HASH_SIZE}",
            v.len()
        ))
    })?;
    Ok(Hash(arr))
}
