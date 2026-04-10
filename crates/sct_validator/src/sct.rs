// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! SCT parsing from X.509 certificates.

use crate::error::SctError;
use const_oid::AssociatedOid;
use der::Decode;
use x509_cert::{
    ext::{
        pkix::sct::{SignedCertificateTimestamp, SignedCertificateTimestampList},
        Extension,
    },
    Certificate,
};

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

    let extensions = cert
        .tbs_certificate()
        .extensions()
        .ok_or(SctError::NoSctExtension)?;

    // Single pass: separate the SCT extension from the rest.
    // Per RFC 6962, all SCTs go in one extension — reject certs with multiple.
    let mut sct_ext: Option<&Extension> = None;
    let mut other_extensions: Vec<&Extension> = Vec::with_capacity(extensions.len() - 1);
    for ext in extensions {
        if ext.extn_id == SignedCertificateTimestampList::OID {
            if sct_ext.is_some() {
                return Err(SctError::Other(
                    "certificate has multiple SCT extensions, expected 1".into(),
                ));
            }
            sct_ext = Some(ext);
        } else {
            other_extensions.push(ext);
        }
    }
    let sct_ext = sct_ext.ok_or(SctError::NoSctExtension)?;

    let parsed_scts = parse_sct_extension(sct_ext)?;

    let tbs_der = encode_tbs_without_sct(&cert, &other_extensions)
        .map_err(|e| SctError::Other(format!("failed to re-serialize TBS: {e}")))?;

    Ok((parsed_scts, tbs_der, lifetime_days))
}

/// Rebuild the TBS DER with the SCT extension removed.
///
/// Works by re-encoding each TBS field individually via the public getter API
/// introduced in x509-cert 0.3, then rebuilding the extensions [3] EXPLICIT
/// wrapper without the SCT entry.
fn encode_tbs_without_sct(
    cert: &Certificate,
    other_extensions: &[&Extension],
) -> Result<Vec<u8>, der::Error> {
    use der::{
        asn1::{ContextSpecific, ContextSpecificRef},
        Encode, TagMode, TagNumber,
    };

    let tbs = cert.tbs_certificate();
    let mut tbs_content = Vec::new();

    // version [0] EXPLICIT INTEGER DEFAULT v1 — omit if v1.
    if tbs.version() != x509_cert::certificate::Version::V1 {
        let tagged = ContextSpecific {
            tag_number: TagNumber(0),
            tag_mode: TagMode::Explicit,
            value: tbs.version(),
        };
        tagged.encode_to_vec(&mut tbs_content)?;
    }
    tbs.serial_number().encode_to_vec(&mut tbs_content)?;
    tbs.signature().encode_to_vec(&mut tbs_content)?;
    tbs.issuer().encode_to_vec(&mut tbs_content)?;
    tbs.validity().encode_to_vec(&mut tbs_content)?;
    tbs.subject().encode_to_vec(&mut tbs_content)?;
    tbs.subject_public_key_info()
        .encode_to_vec(&mut tbs_content)?;
    if let Some(uid) = tbs.issuer_unique_id() {
        // issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL
        ContextSpecificRef {
            tag_number: TagNumber(1),
            tag_mode: TagMode::Implicit,
            value: uid,
        }
        .encode_to_vec(&mut tbs_content)?;
    }
    if let Some(uid) = tbs.subject_unique_id() {
        // subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL
        ContextSpecificRef {
            tag_number: TagNumber(2),
            tag_mode: TagMode::Implicit,
            value: uid,
        }
        .encode_to_vec(&mut tbs_content)?;
    }
    if !other_extensions.is_empty() {
        // Encode extensions as SEQUENCE OF Extension.
        let mut exts_items = Vec::new();
        for ext in other_extensions {
            exts_items.extend(ext.to_der()?);
        }
        // Wrap in SEQUENCE (= Extensions type).
        let mut exts_seq = Vec::new();
        der::Header::new(der::Tag::Sequence, der::Length::try_from(exts_items.len())?)
            .encode_to_vec(&mut exts_seq)?;
        exts_seq.extend(exts_items);
        // Wrap in [3] EXPLICIT.
        let exts_any = der::asn1::Any::from_der(&exts_seq)?;
        let tagged = ContextSpecific {
            tag_number: TagNumber(3),
            tag_mode: TagMode::Explicit,
            value: exts_any,
        };
        tagged.encode_to_vec(&mut tbs_content)?;
    }

    // Wrap tbs_content in outer SEQUENCE.
    let mut tbs_der = Vec::new();
    der::Header::new(
        der::Tag::Sequence,
        der::Length::try_from(tbs_content.len())?,
    )
    .encode_to_vec(&mut tbs_der)?;
    tbs_der.extend(tbs_content);
    Ok(tbs_der)
}

fn parse_sct_extension(sct_ext: &Extension) -> Result<Vec<ParsedSct>, SctError> {
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
    Ok(parsed_scts)
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
    let validity = cert.tbs_certificate().validity();
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

#[cfg(test)]
mod tests {
    use super::*;
    use der::{
        asn1::{BitString, ContextSpecific, ContextSpecificRef},
        Decode as _, Encode as _, TagMode, TagNumber,
    };
    use x509_cert::Certificate;

    /// Construct a Certificate DER identical to `cert` but with `issuerUniqueID`
    /// and `subjectUniqueID` injected, to exercise the unique ID encoding paths
    /// in `encode_tbs_without_sct`.
    fn inject_unique_ids(cert: &Certificate) -> Certificate {
        let tbs = cert.tbs_certificate();
        let issuer_uid = BitString::from_bytes(&[0xDE, 0xAD]).unwrap();
        let subject_uid = BitString::from_bytes(&[0xBE, 0xEF]).unwrap();

        let mut content = Vec::new();
        ContextSpecific {
            tag_number: TagNumber(0),
            tag_mode: TagMode::Explicit,
            value: tbs.version(),
        }
        .encode_to_vec(&mut content)
        .unwrap();
        tbs.serial_number().encode_to_vec(&mut content).unwrap();
        tbs.signature().encode_to_vec(&mut content).unwrap();
        tbs.issuer().encode_to_vec(&mut content).unwrap();
        tbs.validity().encode_to_vec(&mut content).unwrap();
        tbs.subject().encode_to_vec(&mut content).unwrap();
        tbs.subject_public_key_info()
            .encode_to_vec(&mut content)
            .unwrap();
        ContextSpecificRef {
            tag_number: TagNumber(1),
            tag_mode: TagMode::Implicit,
            value: &issuer_uid,
        }
        .encode_to_vec(&mut content)
        .unwrap();
        ContextSpecificRef {
            tag_number: TagNumber(2),
            tag_mode: TagMode::Implicit,
            value: &subject_uid,
        }
        .encode_to_vec(&mut content)
        .unwrap();
        if let Some(exts) = tbs.extensions() {
            let mut exts_items = Vec::new();
            for ext in exts {
                exts_items.extend(ext.to_der().unwrap());
            }
            let mut exts_seq = Vec::new();
            der::Header::new(
                der::Tag::Sequence,
                der::Length::try_from(exts_items.len()).unwrap(),
            )
            .encode_to_vec(&mut exts_seq)
            .unwrap();
            exts_seq.extend(exts_items);
            let exts_any = der::asn1::Any::from_der(&exts_seq).unwrap();
            ContextSpecific {
                tag_number: TagNumber(3),
                tag_mode: TagMode::Explicit,
                value: exts_any,
            }
            .encode_to_vec(&mut content)
            .unwrap();
        }
        let mut tbs_der = Vec::new();
        der::Header::new(
            der::Tag::Sequence,
            der::Length::try_from(content.len()).unwrap(),
        )
        .encode_to_vec(&mut tbs_der)
        .unwrap();
        tbs_der.extend(content);

        let mut cert_content = tbs_der;
        cert.signature_algorithm()
            .encode_to_vec(&mut cert_content)
            .unwrap();
        cert.signature().encode_to_vec(&mut cert_content).unwrap();
        let mut cert_der = Vec::new();
        der::Header::new(
            der::Tag::Sequence,
            der::Length::try_from(cert_content.len()).unwrap(),
        )
        .encode_to_vec(&mut cert_der)
        .unwrap();
        cert_der.extend(cert_content);
        Certificate::from_der(&cert_der).unwrap()
    }

    /// Golden-file regression test for `extract_scts_from_cert`.
    ///
    /// The golden file contains the expected TBS DER output after the SCT extension
    /// is removed from `cloudflare.pem`.  Re-generate with:
    ///
    /// ```sh
    /// UPDATE_GOLDEN=1 cargo test -p sct_validator test_tbs_without_sct_golden
    /// ```
    #[test]
    fn test_tbs_without_sct_golden() {
        use der::Encode as _;
        use x509_cert::der::DecodePem as _;

        const GOLDEN: &str = "tests/golden/cloudflare-tbs-without-sct.der";

        let cert = Certificate::load_pem_chain(include_bytes!("../tests/cloudflare.pem"))
            .unwrap()
            .remove(0);
        let cert_der = cert.to_der().unwrap();
        let (_, tbs_der, _) = extract_scts_from_cert(&cert_der).unwrap();

        let golden_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
        if std::env::var("UPDATE_GOLDEN").is_ok() {
            std::fs::write(&golden_path, &tbs_der).expect("failed to write golden file");
            return;
        }
        let expected =
            std::fs::read(&golden_path).expect("golden file missing — run with UPDATE_GOLDEN=1");
        assert_eq!(
            tbs_der, expected,
            "TBS DER mismatch — if intentional, re-run with UPDATE_GOLDEN=1"
        );
    }

    #[test]
    fn test_unique_ids_round_trip() {
        let cert = Certificate::load_pem_chain(include_bytes!("../tests/cloudflare.pem"))
            .unwrap()
            .remove(0);
        let cert_with_uids = inject_unique_ids(&cert);
        let tbs = cert_with_uids.tbs_certificate();

        // Confirm unique IDs parsed correctly from the injected cert.
        assert!(tbs.issuer_unique_id().is_some());
        assert!(tbs.subject_unique_id().is_some());

        // Use extract_scts_from_cert end-to-end so the single-pass logic is exercised.
        let cert_der = cert_with_uids.to_der().unwrap();
        let (_, rebuilt_tbs_der, _) = extract_scts_from_cert(&cert_der).unwrap();
        let rebuilt = x509_cert::certificate::TbsCertificate::from_der(&rebuilt_tbs_der).unwrap();

        // SCT extension must be gone.
        assert!(rebuilt
            .get_extension::<SignedCertificateTimestampList>()
            .unwrap()
            .is_none());

        // Unique IDs must survive with correct IMPLICIT tags.
        assert_eq!(
            rebuilt.issuer_unique_id(),
            tbs.issuer_unique_id(),
            "issuerUniqueID was dropped or corrupted"
        );
        assert_eq!(
            rebuilt.subject_unique_id(),
            tbs.subject_unique_id(),
            "subjectUniqueID was dropped or corrupted"
        );
    }
}
