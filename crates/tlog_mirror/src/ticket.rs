// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Default ticket authentication scheme for tlog-mirror operators.
//!
//! The c2sp.org/tlog-mirror spec leaves the ticket payload opaque and
//! requires only that the mirror authenticate any data it derives from
//! a ticket. Pending checkpoints are public data (operators publish them
//! at `<monitoring prefix>/<encoded origin>/checkpoint`), so the ticket
//! has no confidentiality requirement; authentication is sufficient.
//!
//! [`TicketMacer`] uses HMAC-SHA-256 truncated to 128 bits as the
//! authentication tag. The ticket layout is:
//!
//! ```text
//! ticket = tag (16 bytes) || plaintext
//! ```
//!
//! where `tag = HMAC-SHA-256(key, plaintext)[..16]`. A 128-bit tag
//! provides 2^128 forgery resistance, matching AES-GCM tag strength and
//! common practice in TLS and `IPsec`. Truncation of HMAC-SHA-256 to 128
//! bits is endorsed by NIST SP 800-107 (which permits truncation down to
//! 32 bits and recommends 64+ for general use, 96+ for high-security
//! contexts) and used by widely-deployed protocols including
//! `HMAC-SHA256-128` TLS cipher suites and `IPsec` ESP
//! `AUTH_HMAC_SHA2_256_128`.
//!
//! The construction is **deterministic**: identical plaintexts produce
//! identical tickets. This is appropriate because pending-checkpoint
//! bytes are public, so linkability across retries reveals no information
//! that the mirror does not already publish.
//!
//! Mirror operators who want a different payload type, AAD binding, or
//! confidentiality (e.g. AEAD over a structured plaintext) MAY ignore
//! this module and roll their own; the wire format treats the ticket as
//! opaque bytes.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::error::TicketError;

/// Length of the HMAC-SHA-256 authentication tag, in bytes. The full
/// SHA-256 output is 32 bytes; we truncate to the leftmost 16 bytes.
pub const TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA-256-128-based ticket authenticator.
///
/// Holds an immutable HMAC instance preinitialized with the operator's
/// secret key. Sealing a ticket allocates a `Vec<u8>` containing
/// `tag_16 || plaintext`. Opening a ticket constant-time-verifies the
/// 128-bit tag and returns a slice of the original plaintext, or a
/// [`TicketError`] on tamper or short input.
#[derive(Clone)]
pub struct TicketMacer {
    /// HMAC instance with the key already mixed in. Cloning is cheap
    /// (clones the precomputed inner/outer SHA-256 state) and avoids
    /// the per-seal HMAC key-derivation cost.
    mac: HmacSha256,
}

impl TicketMacer {
    /// Construct a new authenticator from a 32-byte symmetric key.
    ///
    /// The key length is not security-critical for HMAC — any byte string
    /// will work — but a 32-byte key matches SHA-256's output size and is
    /// recommended by RFC 2104.
    ///
    /// # Panics
    /// Cannot panic in practice. `Hmac::new_from_slice` only fails on
    /// implementations with key-size constraints; HMAC accepts keys of
    /// any length.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
        Self { mac }
    }

    /// Authenticate a payload, returning `tag_16 || plaintext`.
    #[must_use]
    pub fn seal(&self, payload: &[u8]) -> Vec<u8> {
        let mut mac = self.mac.clone();
        mac.update(payload);
        let full_tag = mac.finalize().into_bytes();
        let mut out = Vec::with_capacity(TAG_LEN + payload.len());
        out.extend_from_slice(&full_tag[..TAG_LEN]);
        out.extend_from_slice(payload);
        out
    }

    /// Open an authenticated ticket, returning a slice of the original
    /// plaintext. The returned slice borrows from `sealed`.
    ///
    /// # Errors
    /// Returns [`TicketError::TooShort`] if `sealed` is shorter than
    /// [`TAG_LEN`] (and so cannot contain a valid tag), or
    /// [`TicketError::AuthenticationFailed`] if the tag does not validate
    /// (tamper, wrong key, etc.). Tag comparison is constant-time.
    pub fn open<'a>(&self, sealed: &'a [u8]) -> Result<&'a [u8], TicketError> {
        if sealed.len() < TAG_LEN {
            return Err(TicketError::TooShort(sealed.len()));
        }
        let (tag, payload) = sealed.split_at(TAG_LEN);
        let mut mac = self.mac.clone();
        mac.update(payload);
        // `verify_truncated_left` does the constant-time compare against
        // the left-truncated full tag, which is exactly our scheme.
        mac.verify_truncated_left(tag)
            .map_err(|_| TicketError::AuthenticationFailed)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn macer() -> TicketMacer {
        TicketMacer::new(&[0x42; 32])
    }

    #[test]
    fn seal_open_roundtrip() {
        let m = macer();
        let payload = b"signed-checkpoint-bytes-here";
        let sealed = m.seal(payload);
        // Layout: 16-byte tag || plaintext.
        assert_eq!(sealed.len(), TAG_LEN + payload.len());
        let opened = m.open(&sealed).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn seal_is_deterministic() {
        let m = macer();
        let payload = b"same plaintext";
        let a = m.seal(payload);
        let b = m.seal(payload);
        // Identical plaintexts produce identical tickets. This is the
        // intended behaviour: pending-checkpoint bytes are public, and
        // determinism makes the ticket a content-addressable handle on
        // the pending checkpoint.
        assert_eq!(a, b);
    }

    #[test]
    fn open_rejects_short_input() {
        let m = macer();
        let err = m.open(b"short").unwrap_err();
        assert!(matches!(err, TicketError::TooShort(5)));
    }

    #[test]
    fn open_rejects_empty_input() {
        let m = macer();
        let err = m.open(b"").unwrap_err();
        assert!(matches!(err, TicketError::TooShort(0)));
    }

    #[test]
    fn open_rejects_tampered_payload() {
        let m = macer();
        let mut sealed = m.seal(b"hello");
        // Flip a bit in the payload (past the tag).
        sealed[TAG_LEN] ^= 0x01;
        let err = m.open(&sealed).unwrap_err();
        assert!(matches!(err, TicketError::AuthenticationFailed));
    }

    #[test]
    fn open_rejects_tampered_tag() {
        let m = macer();
        let mut sealed = m.seal(b"hello");
        // Flip a bit in the tag.
        sealed[0] ^= 0x01;
        let err = m.open(&sealed).unwrap_err();
        assert!(matches!(err, TicketError::AuthenticationFailed));
    }

    #[test]
    fn open_rejects_wrong_key() {
        let a = macer();
        let b = TicketMacer::new(&[0x07; 32]);
        let sealed = a.seal(b"hello");
        let err = b.open(&sealed).unwrap_err();
        assert!(matches!(err, TicketError::AuthenticationFailed));
    }

    #[test]
    fn seal_open_roundtrip_empty_payload() {
        let m = macer();
        let sealed = m.seal(b"");
        // 16-byte tag, no payload.
        assert_eq!(sealed.len(), TAG_LEN);
        assert_eq!(m.open(&sealed).unwrap(), b"");
    }

    #[test]
    fn open_returns_payload_borrow() {
        // Sanity-check that `open` returns a slice into the input buffer
        // rather than allocating. This is the documented behaviour and
        // matches our "data is public, just authenticate" stance.
        let m = macer();
        let sealed = m.seal(b"world");
        let opened = m.open(&sealed).unwrap();
        // The returned slice should point inside `sealed`.
        let sealed_range = sealed.as_ptr_range();
        let opened_ptr = opened.as_ptr();
        assert!(sealed_range.start <= opened_ptr && opened_ptr < sealed_range.end);
    }
}
