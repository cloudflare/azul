// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Default ticket authentication for tlog-mirror operators.
//!
//! The spec treats the ticket as opaque and only requires the mirror to
//! authenticate data derived from it; pending checkpoints are public, so
//! confidentiality is not needed. [`TicketSealer`] still encrypts with
//! AES-256-GCM-SIV to enforce that opacity, so clients cannot depend on
//! the ticket's internal format.
//!
//! Sealing is deterministic (fixed nonce): identical `(payload, aad)`
//! inputs yield identical tickets, which is safe because AES-GCM-SIV is
//! nonce-misuse resistant. `aad` is authenticated but not encrypted;
//! callers pass the log origin to bind a ticket to its log.

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::error::TicketError;

/// Length of the AES-GCM-SIV authentication tag, in bytes.
pub const TAG_LEN: usize = 16;

/// Fixed nonce; deterministic sealing is safe under AES-GCM-SIV's
/// nonce-misuse resistance (see module docs).
const NONCE: [u8; 12] = [0u8; 12];

/// AES-256-GCM-SIV ticket sealer, keyed with the operator's secret.
#[derive(Clone)]
pub struct TicketSealer {
    cipher: Aes256GcmSiv,
}

impl TicketSealer {
    /// Construct a new sealer from a 32-byte AES-256 key.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        // 32-byte key: conversion into the cipher key is infallible.
        let cipher = Aes256GcmSiv::new(&(*key).into());
        Self { cipher }
    }

    /// Seal a payload, returning `ciphertext || tag`. `aad` is
    /// authenticated but not encrypted and must match on
    /// [`open`](Self::open).
    ///
    /// # Panics
    /// Only if the input exceeds AES-GCM-SIV's length limit (~64 GiB),
    /// which ticket payloads never approach.
    #[must_use]
    pub fn seal(&self, payload: &[u8], aad: &[u8]) -> Vec<u8> {
        self.cipher
            .encrypt(&Nonce::from(NONCE), Payload { msg: payload, aad })
            .expect("AES-GCM-SIV encryption cannot fail for in-memory ticket payloads")
    }

    /// Open a sealed ticket, returning the decrypted payload. `aad` must
    /// match the value passed to [`seal`](Self::seal).
    ///
    /// # Errors
    /// [`TicketError::TooShort`] if `sealed` cannot contain a tag, or
    /// [`TicketError::AuthenticationFailed`] if the ticket, tag, key, or
    /// `aad` do not match. Verification is constant-time.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, TicketError> {
        if sealed.len() < TAG_LEN {
            return Err(TicketError::TooShort(sealed.len()));
        }
        self.cipher
            .decrypt(&Nonce::from(NONCE), Payload { msg: sealed, aad })
            .map_err(|_| TicketError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AAD: &[u8] = b"example.com/log";

    fn sealer() -> TicketSealer {
        TicketSealer::new(&[0x42; 32])
    }

    #[test]
    fn seal_open_roundtrip() {
        let s = sealer();
        let payload = b"signed-checkpoint-bytes-here";
        let sealed = s.seal(payload, AAD);
        // Ciphertext is the payload length plus the appended tag.
        assert_eq!(sealed.len(), payload.len() + TAG_LEN);
        let opened = s.open(&sealed, AAD).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn seal_is_deterministic() {
        let s = sealer();
        let payload = b"same plaintext";
        // Identical (payload, aad) produce identical tickets: the fixed
        // nonce makes the ticket a content-addressable handle on the
        // pending checkpoint, which is safe under AES-GCM-SIV.
        assert_eq!(s.seal(payload, AAD), s.seal(payload, AAD));
    }

    #[test]
    fn seal_hides_plaintext() {
        let s = sealer();
        let payload = b"pending-checkpoint-plaintext";
        let sealed = s.seal(payload, AAD);
        // The payload must not appear verbatim in the sealed ticket:
        // clients cannot parse the internal format.
        assert!(
            sealed.windows(payload.len()).all(|w| w != payload),
            "plaintext leaked into sealed ticket",
        );
    }

    #[test]
    fn open_rejects_wrong_aad() {
        let s = sealer();
        let sealed = s.seal(b"hello", AAD);
        let err = s.open(&sealed, b"other.com/log").unwrap_err();
        assert!(matches!(err, TicketError::AuthenticationFailed));
    }

    #[test]
    fn open_rejects_short_input() {
        let s = sealer();
        let err = s.open(b"short", AAD).unwrap_err();
        assert!(matches!(err, TicketError::TooShort(5)));
    }

    #[test]
    fn open_rejects_empty_input() {
        let s = sealer();
        let err = s.open(b"", AAD).unwrap_err();
        assert!(matches!(err, TicketError::TooShort(0)));
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let s = sealer();
        let mut sealed = s.seal(b"hello", AAD);
        // Flip a bit in the ciphertext body.
        sealed[0] ^= 0x01;
        let err = s.open(&sealed, AAD).unwrap_err();
        assert!(matches!(err, TicketError::AuthenticationFailed));
    }

    #[test]
    fn open_rejects_tampered_tag() {
        let s = sealer();
        let mut sealed = s.seal(b"hello", AAD);
        // Flip a bit in the appended tag.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let err = s.open(&sealed, AAD).unwrap_err();
        assert!(matches!(err, TicketError::AuthenticationFailed));
    }

    #[test]
    fn open_rejects_wrong_key() {
        let a = sealer();
        let b = TicketSealer::new(&[0x07; 32]);
        let sealed = a.seal(b"hello", AAD);
        let err = b.open(&sealed, AAD).unwrap_err();
        assert!(matches!(err, TicketError::AuthenticationFailed));
    }

    #[test]
    fn seal_open_roundtrip_empty_payload() {
        let s = sealer();
        let sealed = s.seal(b"", AAD);
        // Empty payload: sealed ticket is exactly the tag.
        assert_eq!(sealed.len(), TAG_LEN);
        assert_eq!(s.open(&sealed, AAD).unwrap(), b"");
    }
}
