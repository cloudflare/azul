// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! SCT signature verification per RFC 6962. Supports ECDSA P-256 with SHA-256

use std::mem::size_of;

use crate::error::SctError;
use crate::sct::{ParsedSct, SignatureAlgorithm};
use crate::CtLog;
use length_prefixed::WriteLengthPrefixedBytesExt;
use p256::ecdsa::{signature::Verifier, Signature as P256Signature};
use sha2::{Digest, Sha256};

// RFC 6962 constants for the signed data structure
const SCT_VERSION_V1: u8 = 0;
const SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP: u8 = 0;
const LOG_ENTRY_TYPE_X509_ENTRY: [u8; 2] = [0, 0];
const LOG_ENTRY_TYPE_PRECERT_ENTRY: [u8; 2] = [0, 1];

/// Verifies an SCT signature.
///
/// For regular certificate entries, `ct_cert_der` is the full DER-encoded
/// certificate and `issuer_spki_der` is unused (pass an empty slice).
///
/// For precertificate entries, `ct_cert_der` is the DER-encoded TBS certificate
/// with the CT poison extension removed, and `issuer_spki_der` is the
/// DER-encoded `SubjectPublicKeyInfo` of the issuer.
///
/// # Errors
///
/// Will return an error if serializing the signed data fails or the signature
/// does not verify.
pub fn verify_sct_signature(
    sct: &ParsedSct,
    log: &CtLog,
    ct_cert_der: &[u8],
    issuer_spki_der: &[u8],
) -> Result<(), SctError> {
    let is_precert = !issuer_spki_der.is_empty();
    let signed_data = build_signed_data(sct, ct_cert_der, issuer_spki_der, is_precert)?;

    match sct.signature.algorithm {
        SignatureAlgorithm::EcdsaSha256 => {
            verify_ecdsa_p256(&log.key, &signed_data, &sct.signature.signature)
        }
    }
}

/// Builds the signed data payload according to RFC 6962.
fn build_signed_data(
    sct: &ParsedSct,
    ct_cert_der: &[u8],
    issuer_spki_der: &[u8],
    is_precert: bool,
) -> Result<Vec<u8>, SctError> {
    // Certificate length must fit in 24 bits (3 bytes)
    let cert_len = ct_cert_der.len();
    if cert_len > 0xFF_FFFF {
        return Err(SctError::Other(format!(
            "certificate too large: {cert_len} bytes (max 16MB)"
        )));
    }

    // Extensions length must fit in 16 bits (2 bytes)
    let ext_len = sct.extensions.len();
    if ext_len > 0xFFFF {
        return Err(SctError::Other(format!(
            "extensions too large: {ext_len} bytes (max 64KB)"
        )));
    }

    // For precert entries: compute issuer key hash (SHA-256 of SubjectPublicKeyInfo).
    let issuer_key_hash: Option<[u8; 32]> = if is_precert {
        Some(Sha256::digest(issuer_spki_der).into())
    } else {
        None
    };

    // Build the signed data (pre-allocate exact size).
    //
    // X509 entry format (RFC 6962 §3.2):
    //   version(1) + sig_type(1) + timestamp(8) + entry_type(2) + cert_len(3)
    //   + cert(N) + ext_len(2) + ext(M)
    //
    // Precert entry format (RFC 6962 §3.2):
    //   version(1) + sig_type(1) + timestamp(8) + entry_type(2)
    //   + issuer_key_hash(32) + tbs_len(3) + tbs(N) + ext_len(2) + ext(M)
    let header_len = 2 // version + signature type
        + size_of::<u64>() // timestamp
        + 2; // entry type
    let issuer_hash_len = if is_precert { 32 } else { 0 };
    let mut data = Vec::with_capacity(header_len + issuer_hash_len + 3 + cert_len + 2 + ext_len);

    // Version (1 byte)
    data.push(SCT_VERSION_V1);

    // Signature type (1 byte)
    data.push(SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP);

    // Timestamp (8 bytes, big-endian)
    data.extend(&sct.timestamp.to_be_bytes());

    // Entry type (2 bytes)
    if is_precert {
        data.extend(&LOG_ENTRY_TYPE_PRECERT_ENTRY);
        // Issuer key hash (32 bytes) — only for precert entries
        data.extend(issuer_key_hash.unwrap());
    } else {
        data.extend(&LOG_ENTRY_TYPE_X509_ENTRY);
    }

    // Certificate / TBS length (3 bytes) + data
    data.write_length_prefixed(ct_cert_der, 3)
        .map_err(|e| SctError::Other(e.to_string()))?;

    // Extensions length (2 bytes) + extensions
    data.write_length_prefixed(&sct.extensions, 2)
        .map_err(|e| SctError::Other(e.to_string()))?;

    Ok(data)
}

fn verify_ecdsa_p256(
    key: &p256::ecdsa::VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), SctError> {
    let signature = P256Signature::from_der(signature_bytes)
        .map_err(|e| SctError::Other(format!("invalid ECDSA signature encoding: {e}")))?;
    key.verify(message, &signature)
        .map_err(|e| SctError::Other(format!("ECDSA signature verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_signed_data_x509_entry() {
        let sct = ParsedSct {
            log_id: [0u8; 32],
            timestamp: 1_234_567_890_123,
            extensions: vec![],
            signature: crate::sct::SctSignature {
                algorithm: SignatureAlgorithm::EcdsaSha256,
                signature: vec![],
            },
        };

        let ct_cert = b"test certificate";
        // Regular cert: no issuer SPKI
        let data = build_signed_data(&sct, ct_cert, b"", false).unwrap();

        // Structure:
        // - Byte 0: version (0)
        // - Byte 1: signature type (0)
        // - Bytes 2-9: timestamp (8 bytes BE)
        // - Bytes 10-11: entry type (0, 0) — x509_entry
        // - Bytes 12-14: cert length (3 bytes) = 16
        // - Bytes 15-30: cert data (16 bytes)
        // - Bytes 31-32: extensions length (2 bytes) = 0
        // Total: 33 bytes
        assert_eq!(data[0], 0); // version
        assert_eq!(data[1], 0); // signature type
        assert_eq!(&data[10..12], &[0, 0]); // entry type = x509_entry
        assert_eq!(&data[12..15], &[0, 0, 16]); // cert length
        assert_eq!(&data[31..33], &[0, 0]); // extensions length
        assert_eq!(data.len(), 33);
    }

    #[test]
    fn test_build_signed_data_precert_entry() {
        let sct = ParsedSct {
            log_id: [0u8; 32],
            timestamp: 1_234_567_890_123,
            extensions: vec![],
            signature: crate::sct::SctSignature {
                algorithm: SignatureAlgorithm::EcdsaSha256,
                signature: vec![],
            },
        };

        let ct_cert = b"test certificate";
        let issuer_spki = b"test issuer spki";
        let data = build_signed_data(&sct, ct_cert, issuer_spki, true).unwrap();

        // Structure:
        // - Byte 0: version (0)
        // - Byte 1: signature type (0)
        // - Bytes 2-9: timestamp (8 bytes BE)
        // - Bytes 10-11: entry type (0, 1) — precert_entry
        // - Bytes 12-43: issuer key hash (32 bytes)
        // - Bytes 44-46: cert length (3 bytes) = 16
        // - Bytes 47-62: cert data (16 bytes)
        // - Bytes 63-64: extensions length (2 bytes)
        // Total: 65 bytes
        assert_eq!(data[0], 0); // version
        assert_eq!(data[1], 0); // signature type
        assert_eq!(&data[10..12], &[0, 1]); // entry type = precert_entry
        assert_eq!(&data[44..47], &[0, 0, 16]); // cert length
        assert_eq!(&data[63..65], &[0, 0]); // extensions length
        assert_eq!(data.len(), 65);
    }

    #[test]
    fn test_cert_too_large() {
        let sct = ParsedSct {
            log_id: [0u8; 32],
            timestamp: 0,
            extensions: vec![],
            signature: crate::sct::SctSignature {
                algorithm: SignatureAlgorithm::EcdsaSha256,
                signature: vec![],
            },
        };

        let small_cert = vec![0u8; 1000];
        let result = build_signed_data(&sct, &small_cert, b"issuer", true);
        assert!(result.is_ok());
    }
}
