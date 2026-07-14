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
//! A fresh random 96-bit nonce is generated per [`seal`](TicketSealer::seal)
//! and prepended to the ciphertext, so the sealed ticket is
//! `nonce || ciphertext || tag`. RFC 8452 recommends against fixing
//! the nonce, so we do not: a random nonce keeps the security margin even
//! under a long-lived key without bounding the number of tickets. `aad` is
//! authenticated but not encrypted; callers pass the log origin to bind a
//! ticket to its log.

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngExt;

use crate::error::TicketError;

/// Length of the AES-GCM-SIV authentication tag, in bytes.
pub const TAG_LEN: usize = 16;

/// Length of the AES-GCM-SIV nonce, in bytes. Prepended to every sealed
/// ticket (see module docs).
pub const NONCE_LEN: usize = 12;

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

    /// Seal a payload, returning `nonce || ciphertext || tag` with a fresh
    /// random nonce. `aad` is authenticated but not encrypted and must
    /// match on [`open`](Self::open).
    ///
    /// # Panics
    /// Only if the input exceeds AES-GCM-SIV's length limit (~64 GiB),
    /// which ticket payloads never approach.
    #[must_use]
    pub fn seal(&self, payload: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill(&mut nonce[..]);
        let ciphertext = self
            .cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: payload, aad })
            .expect("AES-GCM-SIV encryption cannot fail for in-memory ticket payloads");
        let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        sealed
    }

    /// Open a sealed ticket (`nonce || ciphertext || tag`), returning the
    /// decrypted payload. `aad` must match the value passed to
    /// [`seal`](Self::seal).
    ///
    /// # Errors
    /// [`TicketError::TooShort`] if `sealed` cannot contain a nonce and
    /// tag, or [`TicketError::AuthenticationFailed`] if the ticket, tag,
    /// key, or `aad` do not match. Verification is constant-time.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, TicketError> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(TicketError::TooShort(sealed.len()));
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_bytes);
        self.cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
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
        // Sealed ticket is the prepended nonce, the payload, and the tag.
        assert_eq!(sealed.len(), NONCE_LEN + payload.len() + TAG_LEN);
        let opened = s.open(&sealed, AAD).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn seal_is_randomized() {
        let s = sealer();
        let payload = b"same plaintext";
        // A fresh random nonce per seal means identical (payload, aad)
        // inputs produce distinct tickets (RFC 8452 §9), yet both open.
        let a = s.seal(payload, AAD);
        let b = s.seal(payload, AAD);
        assert_ne!(a, b);
        assert_eq!(s.open(&a, AAD).unwrap(), payload);
        assert_eq!(s.open(&b, AAD).unwrap(), payload);
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
        // Flip a bit in the ciphertext body (just past the nonce).
        sealed[NONCE_LEN] ^= 0x01;
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
        // Empty payload: sealed ticket is exactly the nonce plus the tag.
        assert_eq!(sealed.len(), NONCE_LEN + TAG_LEN);
        assert_eq!(s.open(&sealed, AAD).unwrap(), b"");
    }
}
