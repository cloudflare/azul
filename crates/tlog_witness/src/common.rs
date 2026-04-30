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

/// Upper bound on the size of an `add-checkpoint` or `sign-subtree`
/// request body the parsers are willing to inspect.
///
/// The parsers reject anything above this cap up front so that a
/// malicious or misconfigured client cannot make the parser
/// base64-decode arbitrarily large blobs even though the spec-mandated
/// line *counts* are bounded. The cap covers the worst-case
/// well-formed `sign-subtree` request: a 1 MiB embedded checkpoint
/// (per [`signed_note::MAX_NOTE_SIZE`]) plus a header consisting of
/// the range/hash lines, up to 8 ML-DSA-44 cosignature lines (~3.3
/// KiB each on the wire after base64), and up to 63 base64 proof
/// hashes (~44 bytes each). 64 KiB of header headroom comfortably
/// covers that.
///
/// Worker-level deployments may apply an even tighter cap before
/// calling the parser; this constant is the minimum every caller
/// must enforce.
///
/// [`signed_note::MAX_NOTE_SIZE`]: https://docs.rs/signed_note/latest/signed_note/constant.MAX_NOTE_SIZE.html
pub const MAX_REQUEST_BODY_SIZE: usize = 1_024 * 1_024 + 64 * 1_024;

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

/// Parse an ASCII decimal `u64` per the spec's tree-size encoding rules:
/// digits 0-9 only, no leading zeros except for the value zero itself,
/// and no leading `+` (which Rust's [`u64::from_str`] would otherwise
/// accept). `what` is interpolated into the error message.
///
/// Used for the `old` size in `add-checkpoint` and the subtree start /
/// end in `sign-subtree`.
pub(crate) fn parse_tree_size_decimal(text: &str, what: &str) -> Result<u64, TlogWitnessError> {
    if text.is_empty() {
        return Err(TlogWitnessError::MalformedRequest(format!("empty {what}")));
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(TlogWitnessError::MalformedRequest(format!(
            "{what} has leading zeros"
        )));
    }
    // `u64::from_str` accepts a leading `+` and (in some configurations)
    // could accept underscores or non-ASCII digits the spec forbids; be
    // strict about what we accept here.
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TlogWitnessError::MalformedRequest(format!(
            "{what} must consist of ASCII digits only"
        )));
    }
    text.parse::<u64>()
        .map_err(|e| TlogWitnessError::MalformedRequest(format!("parsing {what}: {e}")))
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
