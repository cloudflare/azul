// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! SCT parsing from X.509 certificates.

use crate::error::SctError;
use const_oid::AssociatedOid;
use der::{Decode, Encode};
use x509_cert::ext::pkix::sct::{SignedCertificateTimestamp, SignedCertificateTimestampList};
use x509_cert::Certificate;

/// A parsed SCT from a certificate.
#[derive(Clone, Debug)]
pub struct ParsedSct {
    /// The log ID (32 bytes, SHA-256 hash of the log's public key).
    pub log_id: [u8; 32],
    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp: u64,
    /// SCT extensions (contains leaf index for Static CT API logs)
    pub extensions: Vec<u8>,
    /// The signature over the SCT data.
    pub signature: SctSignature,
}

/// An SCT signature with its algorithm.
#[derive(Clone, Debug)]
pub struct SctSignature {
    /// The signature algorithm.
    pub algorithm: SignatureAlgorithm,
    /// The raw signature bytes.
    pub signature: Vec<u8>,
}

/// Signature algorithms supported by SCTs.
/// Only ECDSA P-256 with SHA-256 is supported
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA with SHA-256.
    EcdsaSha256,
}

/// Extracts SCTs and returns (`scts`, `tbs_cert_without_sct_ext`,
/// `lifetime_days`).
///
/// # Errors
///
/// Will return an error if there is an issue parsing the leaf cert, if the SCT
/// extension is missing or malformed, or if there are issues generating the
/// `TBSCertificate` from the leaf.
pub fn extract_scts_from_cert(leaf_der: &[u8]) -> Result<(Vec<ParsedSct>, Vec<u8>, u64), SctError> {
    let cert = Certificate::from_der(leaf_der).map_err(|e| SctError::Other(e.to_string()))?;
    let lifetime_days = extract_lifetime_days(&cert)?;

    let mut tbs = cert.tbs_certificate;
    let extensions = tbs.extensions.as_mut().ok_or(SctError::NoSctExtension)?;
    let (sct_ext_index, parsed_scts) = find_and_parse_scts(extensions)?;

    // Remove SCT extension to get the "CT certificate" that was signed
    extensions.remove(sct_ext_index);

    let ct_cert_der = tbs
        .to_der()
        .map_err(|e| SctError::Other(format!("failed to re-serialize TBS: {e}")))?;

    Ok((parsed_scts, ct_cert_der, lifetime_days))
}

fn find_and_parse_scts(
    extensions: &[x509_cert::ext::Extension],
) -> Result<(usize, Vec<ParsedSct>), SctError> {
    // Per RFC 6962, all SCTs go in one extension. Reject certs with multiple.
    let sct_extensions: Vec<_> = extensions
        .iter()
        .enumerate()
        .filter(|(_, ext)| ext.extn_id == SignedCertificateTimestampList::OID)
        .collect();

    let (index, sct_ext) = match sct_extensions.as_slice() {
        [] => return Err(SctError::NoSctExtension),
        [(idx, ext)] => (*idx, *ext),
        _ => {
            return Err(SctError::Other(format!(
                "certificate has {} SCT extensions, expected 1",
                sct_extensions.len()
            )))
        }
    };

    let sct_list = SignedCertificateTimestampList::from_der(sct_ext.extn_value.as_bytes())
        .map_err(|e| SctError::Other(format!("failed to parse SCT list DER: {e}")))?;

    let raw_timestamps = sct_list
        .parse_timestamps()
        .map_err(|e| SctError::Other(format!("failed to parse timestamps: {e:?}")))?;

    let mut parsed_scts = Vec::new();
    for raw_ts in raw_timestamps {
        if let Ok(sct) = raw_ts.parse_timestamp() {
            parsed_scts.push(convert_sct(&sct)?);
        }
    }

    Ok((index, parsed_scts))
}

fn convert_sct(sct: &SignedCertificateTimestamp) -> Result<ParsedSct, SctError> {
    let log_id_slice = sct.log_id.key_id.as_ref();
    let log_id: [u8; 32] = log_id_slice.try_into().map_err(|_| {
        SctError::Other(format!(
            "log ID has invalid length: {} (expected 32)",
            log_id_slice.len()
        ))
    })?;

    let algorithm = parse_signature_algorithm(&sct.signature)?;

    Ok(ParsedSct {
        log_id,
        timestamp: sct.timestamp,
        extensions: sct.extensions.clone().into_vec(),
        signature: SctSignature {
            algorithm,
            signature: sct.signature.signature.clone().into_vec(),
        },
    })
}

fn parse_signature_algorithm(
    sig: &x509_cert::ext::pkix::sct::DigitallySigned,
) -> Result<SignatureAlgorithm, SctError> {
    use x509_cert::ext::pkix::sct::{HashAlgorithm, SignatureAlgorithm as X509SigAlg};

    if sig.algorithm.hash != HashAlgorithm::Sha256 {
        return Err(SctError::Other(format!(
            "unsupported hash algorithm: {:?} (only SHA-256 is supported)",
            sig.algorithm.hash
        )));
    }

    match sig.algorithm.signature {
        X509SigAlg::Ecdsa => Ok(SignatureAlgorithm::EcdsaSha256),
        ref other => Err(SctError::Other(format!(
            "unsupported signature algorithm: {other:?} (only ECDSA is supported)",
        ))),
    }
}

fn extract_lifetime_days(cert: &Certificate) -> Result<u64, SctError> {
    let validity = &cert.tbs_certificate.validity;
    let not_before_secs = validity.not_before.to_unix_duration().as_secs();
    let not_after_secs = validity.not_after.to_unix_duration().as_secs();

    if not_after_secs < not_before_secs {
        return Err(SctError::Other(
            "certificate notAfter is before notBefore".to_string(),
        ));
    }

    let lifetime_secs = not_after_secs - not_before_secs;
    let lifetime_days = lifetime_secs / (24 * 60 * 60);

    Ok(lifetime_days)
}
