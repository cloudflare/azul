// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Error types for `tlog_mirror`.

use thiserror::Error;

/// Errors returned when parsing tlog-mirror wire-format messages.
#[derive(Debug, Error)]
pub enum ParseError {
    /// An IO error occurred while reading from the input stream.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// The `log_origin_size` u16 prefix advertised more bytes than were
    /// available in the input.
    #[error("log_origin truncated: advertised {advertised} bytes")]
    LogOriginTruncated {
        /// Size advertised by the wire `log_origin_size` u16.
        advertised: u16,
    },

    /// The `log_origin` bytes were not valid UTF-8.
    #[error("log_origin is not valid UTF-8")]
    LogOriginNotUtf8,

    /// `upload_start` was greater than `upload_end`.
    #[error("upload_start ({start}) > upload_end ({end})")]
    UploadRangeInverted {
        /// `upload_start` from the wire.
        start: u64,
        /// `upload_end` from the wire.
        end: u64,
    },

    /// `num_hashes` for a subtree consistency proof exceeded the spec's
    /// maximum of 63.
    #[error("num_hashes {0} exceeds spec maximum of 63")]
    TooManyHashes(u8),

    /// The `text/x.tlog.mirror-info` body did not have exactly three
    /// newline-terminated lines.
    #[error("mirror-info body is malformed: {0}")]
    MalformedMirrorInfo(&'static str),

    /// A decimal field in the `text/x.tlog.mirror-info` body could not be
    /// parsed as a `u64`.
    #[error("mirror-info decimal field {field} could not be parsed: {value:?}")]
    InvalidDecimal {
        /// Field name (`tree_size` or `next_entry`).
        field: &'static str,
        /// Verbatim bytes from the wire.
        value: String,
    },

    /// The base64-encoded ticket in a `text/x.tlog.mirror-info` body could
    /// not be decoded.
    #[error("mirror-info ticket is not valid base64")]
    InvalidTicketBase64,
}

/// Errors returned by [`TicketMacer`](crate::TicketMacer).
#[derive(Debug, Error)]
pub enum TicketError {
    /// The sealed ticket was shorter than the HMAC tag length
    /// ([`TAG_LEN`](crate::TAG_LEN), 16 bytes), so it cannot possibly be
    /// a valid ticket.
    #[error("sealed ticket too short: {0} bytes, need at least 16")]
    TooShort(usize),

    /// HMAC tag verification failed: either the tag or the payload has
    /// been tampered with, or the ticket was authenticated with a
    /// different key.
    #[error("ticket authentication failed")]
    AuthenticationFailed,
}
