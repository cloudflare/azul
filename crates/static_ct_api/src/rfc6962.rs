// Ported from "sunlight" (https://github.com/FiloSottile/sunlight)
// Copyright 2023 The Sunlight Authors
// Licensed under ISC License found in the LICENSE file or at https://opensource.org/license/isc-license-txt
//
// Ported from "certificate-transparency-go" (https://github.com/google/certificate-transparency-go)
// Copyright 2016 Google LLC. All Rights Reserved.
// Licensed under Apache-2.0 License found in the LICENSE file or at https://www.apache.org/licenses/LICENSE-2.0
//
// This ports code from the original Go projects "sunlight" and "certificate-transparency-go" and adapts it to Rust idioms.
//
// Modifications and Rust implementation Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Provides functionality for parsing and validating certificates based on the requirements of [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962).
//!
//! This file contains code ported from the original projects [sunlight](https://github.com/FiloSottile/sunlight) and [certificate-transparency-go](https://github.com/google/certificate-transparency-go).
//!
//! References:
//! - [http.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/internal/ctlog/http.go)
//! - [cert_checker.go](https://github.com/google/certificate-transparency-go/blob/74d106d3a25205b16d571354c64147c5f1f7dbc1/trillian/ctfe/cert_checker.go)
//! - [cert_checker_test.go](https://github.com/google/certificate-transparency-go/blob/74d106d3a25205b16d571354c64147c5f1f7dbc1/trillian/ctfe/cert_checker_test.go)

use crate::{PrecertData, StaticCTError, StaticCTPendingLogEntry};
use der::{
    asn1::Null,
    oid::{
        db::rfc5280::ID_KP_SERVER_AUTH,
        db::rfc6962::{CT_PRECERT_POISON, CT_PRECERT_SIGNING_CERT},
        AssociatedOid, ObjectIdentifier,
    },
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use tlog_tiles::UnixTimestamp;
use x509_cert::{
    der::Encode,
    ext::{pkix::ExtendedKeyUsage, Extension},
    impl_newtype, Certificate, TbsCertificate,
};
use x509_util::{validate_chain_lax, CertPool, ValidationOptions};

// Data structures for the [Static CT Submission APIs](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#submission-apis),
// a subset of the APIs from [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962).

/// Add-(pre-)chain request.
#[serde_as]
#[derive(Deserialize)]
pub struct AddChainRequest {
    #[serde_as(as = "Vec<Base64>")]
    pub chain: Vec<Vec<u8>>,
}

/// Add-(pre-)chain response.
#[serde_as]
#[derive(Serialize)]
pub struct AddChainResponse {
    pub sct_version: u8,
    #[serde_as(as = "Base64")]
    pub id: Vec<u8>,
    pub timestamp: UnixTimestamp,
    #[serde_as(as = "Base64")]
    pub extensions: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub signature: Vec<u8>,
}

/// Get-roots response.
#[serde_as]
#[derive(Serialize)]
pub struct GetRootsResponse {
    #[serde_as(as = "Vec<Base64>")]
    pub certificates: Vec<Vec<u8>>,
}

/// Validates a certificate chain according to
/// [RFC6962](https://datatracker.ietf.org/doc/html/rfc6962) and returns a pending log entry and the
/// inferred root, if a root had to be inferred.
///
/// # Errors
///
/// Returns a `ValidationError` if the chain fails to validate.
pub fn partially_validate_chain(
    raw_chain: &[Vec<u8>],
    roots: &CertPool,
    not_after_start: Option<UnixTimestamp>,
    not_after_end: Option<UnixTimestamp>,
    expect_precert: bool,
    require_server_auth_eku: bool,
) -> Result<(StaticCTPendingLogEntry, Option<usize>), StaticCTError> {
    // We will run the basic validator supplied by x509_utils. However, we need some extra checks
    // that are particular to CT, and we need to collect information along the way. So define a hook
    // for the validator that does these checks and returns a pending log entry
    let validator_hook = |leaf: Certificate,
                          chain_certs: Vec<&Certificate>,
                          chain_fingerprints: Vec<[u8; 32]>,
                          found_root_idx: Option<usize>|
     -> Result<(StaticCTPendingLogEntry, Option<usize>), StaticCTError> {
        // Check if the CT poison extension is present. If present, it must be critical.
        let is_leaf_precert = is_precert(&leaf)?;
        if is_leaf_precert != expect_precert {
            return Err(StaticCTError::EndpointMismatch {
                is_precert: is_leaf_precert,
            });
        }

        // Check that Server Auth EKU is present. Chrome's CT policy lists this as one acceptable
        // reason for a CT log to reject a submission: <https://googlechrome.github.io/CertificateTransparency/log_policy.html>.
        if require_server_auth_eku
            && !leaf
                .tbs_certificate()
                .get_extension::<ExtendedKeyUsage>()?
                .is_some_and(|(_, eku)| eku.0.contains(&ID_KP_SERVER_AUTH))
        {
            return Err(StaticCTError::InvalidLeaf);
        }

        // Construct the fields needed for the pending log entry. If the entry
        // is a precertificate, `precert_opt` is populated with the
        // precertificate data.
        let (precert_opt, certificate) = if is_leaf_precert {
            // Reject if the precertificate doesn't have an issuer.
            if chain_certs.is_empty() {
                return Err(StaticCTError::MissingPrecertIssuer);
            }
            // Reject precertificate signing certificates.  As of 2026-03-15,
            // CAs are no longer permitted to use them, and the static-ct-api
            // spec (https://github.com/C2SP/C2SP/pull/218) allows logs to
            // reject any chain that includes one.
            if is_precert_signing_cert(chain_certs[0])? {
                return Err(StaticCTError::PrecertSigningCertNotAccepted);
            }
            let issuer = chain_certs[0];
            (
                Some(PrecertData {
                    issuer_key_hash: Sha256::digest(
                        issuer
                            .tbs_certificate()
                            .subject_public_key_info()
                            .to_der()?,
                    )
                    .into(),
                    pre_certificate: leaf.to_der()?,
                }),
                build_precert_tbs(leaf.tbs_certificate())?,
            )
        } else {
            (None, leaf.to_der()?)
        };

        Ok((
            StaticCTPendingLogEntry {
                certificate,
                precert_opt,
                chain_fingerprints,
            },
            found_root_idx,
        ))
    };

    // Call validation with the hook
    let pending_entry = validate_chain_lax(
        raw_chain,
        roots,
        &ValidationOptions {
            stop_on_first_trusted_cert: false,
            not_after_start,
            not_after_end,
        },
        validator_hook,
    );
    pending_entry.map_err(|e| match e {
        x509_util::HookOrValidationError::Validation(ve) => ve.into(),
        x509_util::HookOrValidationError::Hook(he) => he,
    })
}

/// Precertificate poison extension that can be decoded with [`TbsCertificate::get`].
#[derive(Debug)]
struct CTPrecertPoison(Null);

impl AssociatedOid for CTPrecertPoison {
    const OID: ObjectIdentifier = CT_PRECERT_POISON;
}
impl_newtype!(CTPrecertPoison, Null);

/// Returns whether or not the certificate contains the precertificate poison extension.
fn is_precert(cert: &Certificate) -> Result<bool, StaticCTError> {
    match cert.tbs_certificate().get_extension::<CTPrecertPoison>()? {
        Some((true, _)) => Ok(true),
        Some((false, _)) => Err(StaticCTError::InvalidCTPoison),
        None => Ok(false),
    }
}

/// Returns whether or not the certificate is a precertificate signing certificate.
fn is_precert_signing_cert(cert: &Certificate) -> Result<bool, StaticCTError> {
    match cert.tbs_certificate().get_extension::<ExtendedKeyUsage>()? {
        Some((_, eku)) => {
            for usage in eku.0 {
                if usage == CT_PRECERT_SIGNING_CERT {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        None => Ok(false),
    }
}

/// Builds a Certificate Transparency pre-certificate TBS (RFC 6962 §3.1) from
/// the given `TBSCertificate`, returning the DER-encoded result.
///
/// Removes the CT poison extension (there must be exactly one), preserving the
/// order of other extensions.
///
/// Note: Precertificate Signing Certificates are not supported.  CA/Browser
/// Forum Ballot SC-092 (effective 2026-03-15) sunsetted their use:
/// <https://cabforum.org/2025/09/02/ballot-sc-092-sunset-use-of-precertificate-signing-cas/>
/// Chains containing a Precertificate Signing Certificate are rejected by
/// `partially_validate_chain` before this function is called.
///
/// # Errors
///
/// Returns an error if the certificate is not a valid precertificate.
pub fn build_precert_tbs(tbs: &TbsCertificate) -> Result<Vec<u8>, StaticCTError> {
    let extensions = tbs.extensions().ok_or(StaticCTError::InvalidCTPoison)?;

    // Remove CT poison extension (there must be exactly 1).
    let ct_poison_idx = extensions
        .iter()
        .position(|v| v.extn_id == CT_PRECERT_POISON)
        .ok_or(StaticCTError::InvalidCTPoison)?;

    let filtered: Vec<&Extension> = extensions
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != ct_poison_idx)
        .map(|(_, ext)| ext)
        .collect();

    Ok(x509_util::encode_tbs_with_extensions(tbs, &filtered)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::prelude::*;
    use der::{asn1::OctetString, Decode};
    use x509_cert::ext::Extension;
    use x509_cert::{Certificate, TbsCertificate};

    fn parse_datetime(s: &str) -> UnixTimestamp {
        u64::try_from(DateTime::parse_from_rfc3339(s).unwrap().timestamp_millis()).unwrap()
    }

    macro_rules! test_is_precert {
        ($name:ident, $cert:expr, $want_precert:expr, $want_err:expr) => {
            #[test]
            fn $name() {
                match is_precert($cert) {
                    Ok(b) => {
                        assert!(!$want_err);
                        assert_eq!(b, $want_precert);
                    }
                    Err(_) => assert!($want_err),
                }
            }
        };
    }

    test_is_precert!(
        valid_precert,
        &Certificate::load_pem_chain(include_bytes!("../tests/precert-valid.pem")).unwrap()[0],
        true,
        false
    );

    test_is_precert!(
        valid_cert,
        &Certificate::load_pem_chain(include_bytes!("../tests/ca-cert.pem")).unwrap()[0],
        false,
        false
    );

    test_is_precert!(
        remove_exts_from_precert,
        &wipe_extensions(
            &Certificate::load_pem_chain(include_bytes!("../tests/precert-valid.pem")).unwrap()[0]
        ),
        false,
        false
    );

    test_is_precert!(
        poison_non_critical,
        &make_poison_non_critical(
            &Certificate::load_pem_chain(include_bytes!("../tests/precert-valid.pem")).unwrap()[0]
        ),
        false,
        true
    );

    test_is_precert!(
        poison_non_null,
        &make_poison_non_null(
            &Certificate::load_pem_chain(include_bytes!("../tests/precert-valid.pem")).unwrap()[0]
        ),
        false,
        true
    );

    macro_rules! test_validate_chain {
        ($name:ident; $($root_file:expr),+; $($chain_file:expr),+; $not_after_start:expr; $not_after_end:expr; $expect_precert:expr; $require_server_auth_eku:expr; $want_err:expr; $want_chain_len:expr) => {
            #[test]
            fn $name() {
                let roots = x509_util::build_chain!($($root_file),*);
                let chain = x509_util::build_chain!($($chain_file),*);

                let result = partially_validate_chain(
                        &x509_util::certs_to_bytes(&chain).unwrap(),
                        &CertPool::new(roots).unwrap(),
                        $not_after_start,
                        $not_after_end,
                        $expect_precert,
                        $require_server_auth_eku,
                );
                assert_eq!(result.is_err(), $want_err);

                if let Ok((pending_entry, _found_root_idx)) = result {
                    assert_eq!(pending_entry.chain_fingerprints.len(), $want_chain_len);
                }
            }
        };
    }

    // NOTE(lvalenta): there are more tests in the original Go library that we
    // could import (related to various validation options), but those are
    // probably not relevant given this library's more limited scope.
    // Also https://github.com/google/certificate-transparency-go/blob/74d106d3a25205b16d571354c64147c5f1f7dbc1/x509/x509_test.go.

    macro_rules! test_not_after {
        ($name:ident; $start:expr; $end:expr; $want_err:expr) => {
            test_validate_chain!($name; "../tests/fake-ca-cert.pem"; "../tests/leaf-signed-by-fake-intermediate-cert.pem", "../tests/fake-intermediate-cert.pem"; $start; $end; false; true; $want_err; 2);
        };
    }
    test_not_after!(not_after_no_range; None; None; false);
    test_not_after!(not_after_valid_range; Some(parse_datetime("2018-01-01T00:00:00Z")); Some(parse_datetime("2020-07-01T00:00:00Z")); false);
    test_not_after!(not_after_before_start; Some(parse_datetime("2020-01-01T00:00:00Z")); None; true);
    test_not_after!(not_after_after_end; None; Some(parse_datetime("1999-01-01T00:00:00Z")); true);
    test_validate_chain!(missing_server_auth_eku_not_required; "../tests/fake-root-ca-cert.pem"; "../tests/subleaf.chain"; None; None; false; false; false; 3);
    test_validate_chain!(missing_server_auth_eku_required; "../tests/fake-root-ca-cert.pem"; "../tests/subleaf.chain"; None; None; false; true; true; 0);
    // Precertificate Signing Certificates are now rejected unconditionally.
    test_validate_chain!(preissuer_chain; "../tests/test-roots.pem"; "../tests/preissuer-chain.pem"; None; None; true; true; true; 0);

    test_validate_chain!(intermediate_as_accepted_root; "../tests/fake-intermediate-cert.pem"; "../tests/leaf-signed-by-fake-intermediate-cert.pem"; None; None; false; true; false; 1);

    test_validate_chain!(leaf_as_accepted_root; "../tests/leaf-signed-by-fake-intermediate-cert.pem"; "../tests/leaf-signed-by-fake-intermediate-cert.pem"; None; None; false; true; false; 0);

    test_validate_chain!(valid_chain_inc_root;  "../../static_ct_api/tests/fake-ca-cert.pem"; "../tests/leaf-signed-by-fake-intermediate-cert.pem", "../tests/fake-intermediate-cert.pem", "../tests/fake-ca-cert.pem"; None; None; false; true; false; 2);

    // CT does not allow extra certs at the end of the chain.
    test_validate_chain!(unrelated_cert_after_chain_inc_root;  "../../static_ct_api/tests/fake-ca-cert.pem"; "../tests/leaf-signed-by-fake-intermediate-cert.pem", "../tests/fake-intermediate-cert.pem", "../tests/fake-ca-cert.pem", "../tests/test-cert.pem"; None; None; false; true; true; 0);

    /// Golden-file regression test for `build_precert_tbs`.
    ///
    /// The golden file contains the expected TBS DER output after the CT poison
    /// extension is removed from the precertificate in `preissuer-chain.pem`.
    /// Re-generate with:
    ///
    /// ```sh
    /// UPDATE_GOLDEN=1 cargo test -p static_ct_api test_build_precert_tbs_golden
    /// ```
    #[test]
    fn test_build_precert_tbs_golden() {
        const GOLDEN: &str = "tests/golden/preissuer-precert-tbs.der";

        let precert_chain =
            Certificate::load_pem_chain(include_bytes!("../tests/preissuer-chain.pem")).unwrap();
        let tbs_der = build_precert_tbs(precert_chain[0].tbs_certificate()).unwrap();

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
    fn test_build_precert_tbs() {
        let precert_chain =
            Certificate::load_pem_chain(include_bytes!("../tests/preissuer-chain.pem")).unwrap();
        let precert = precert_chain[0].tbs_certificate();

        let der = build_precert_tbs(precert).unwrap();
        let tbs = TbsCertificate::from_der(&der).unwrap();

        // Ensure CT poison is removed.
        assert!(precert
            .get_extension::<CTPrecertPoison>()
            .unwrap()
            .is_some());
        assert!(tbs.get_extension::<CTPrecertPoison>().unwrap().is_none());
    }

    /// Build a Certificate DER from the given `precert_tbs_der` (which contains a CT
    /// poison extension) by wrapping it with a dummy signature, suitable for passing
    /// to `build_precert_tbs`.  Used to inject synthetic fields (e.g. unique IDs) that
    /// don't appear in committed test fixtures.
    fn make_cert_from_tbs_der(tbs_der: Vec<u8>) -> Certificate {
        use der::{asn1::BitString, Encode};
        use x509_cert::der::Decode;
        // Dummy AlgorithmIdentifier (sha256WithRSAEncryption OID, NULL params) and empty BIT STRING.
        let sig_alg_der: &[u8] = &[
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
            0x00,
        ];
        let sig_bs = BitString::from_bytes(&[]).unwrap();
        let mut cert_content = tbs_der;
        cert_content.extend(sig_alg_der);
        sig_bs.encode_to_vec(&mut cert_content).unwrap();
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

    /// Construct a TBS DER for a precertificate identical to `tbs` but with
    /// `issuerUniqueID` and `subjectUniqueID` injected, for round-trip testing.
    fn inject_unique_ids_into_precert_tbs(tbs: &TbsCertificate) -> Vec<u8> {
        use der::{
            asn1::{BitString, ContextSpecific, ContextSpecificRef},
            Encode, TagMode, TagNumber,
        };
        let issuer_uid = BitString::from_bytes(&[0xDE, 0xAD]).unwrap();
        let subject_uid = BitString::from_bytes(&[0xBE, 0xEF]).unwrap();
        let mut content = Vec::new();
        // [0] EXPLICIT version (V3)
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
        // [1] IMPLICIT issuerUniqueID
        ContextSpecificRef {
            tag_number: TagNumber(1),
            tag_mode: TagMode::Implicit,
            value: &issuer_uid,
        }
        .encode_to_vec(&mut content)
        .unwrap();
        // [2] IMPLICIT subjectUniqueID
        ContextSpecificRef {
            tag_number: TagNumber(2),
            tag_mode: TagMode::Implicit,
            value: &subject_uid,
        }
        .encode_to_vec(&mut content)
        .unwrap();
        // [3] EXPLICIT extensions (copy from original, including CT poison)
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
        tbs_der
    }

    #[test]
    fn test_build_precert_tbs_unique_ids_round_trip() {
        let precert_chain =
            Certificate::load_pem_chain(include_bytes!("../tests/preissuer-chain.pem")).unwrap();
        let precert_tbs = precert_chain[0].tbs_certificate();

        let tbs_der = inject_unique_ids_into_precert_tbs(precert_tbs);
        let cert = make_cert_from_tbs_der(tbs_der);
        let tbs_with_uids = cert.tbs_certificate();

        // Sanity-check that the injected unique IDs are present in the parsed input cert.
        assert!(tbs_with_uids.issuer_unique_id().is_some());
        assert!(tbs_with_uids.subject_unique_id().is_some());

        let rebuilt_der = build_precert_tbs(tbs_with_uids).unwrap();
        let rebuilt = TbsCertificate::from_der(&rebuilt_der).unwrap();

        // CT poison must be stripped.
        assert!(rebuilt
            .get_extension::<CTPrecertPoison>()
            .unwrap()
            .is_none());

        // Unique IDs must survive the reconstruction with correct IMPLICIT tags.
        assert_eq!(
            rebuilt.issuer_unique_id(),
            tbs_with_uids.issuer_unique_id(),
            "issuerUniqueID was dropped or corrupted"
        );
        assert_eq!(
            rebuilt.subject_unique_id(),
            tbs_with_uids.subject_unique_id(),
            "subjectUniqueID was dropped or corrupted"
        );
    }

    /// Rebuild a `Certificate` replacing its TBS extensions with `new_exts`.
    fn rebuild_cert_with_extensions(
        cert: &Certificate,
        new_exts: Option<&[Extension]>,
    ) -> Certificate {
        use der::Encode;
        let exts_refs: Vec<&Extension> = new_exts.unwrap_or_default().iter().collect();
        let tbs_der =
            x509_util::encode_tbs_with_extensions(cert.tbs_certificate(), &exts_refs).unwrap();

        let mut cert_content = Vec::new();
        cert_content.extend(&tbs_der);
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

    fn wipe_extensions(cert: &Certificate) -> Certificate {
        rebuild_cert_with_extensions(cert, None)
    }

    fn make_poison_non_critical(cert: &Certificate) -> Certificate {
        let exts = vec![Extension {
            extn_id: CT_PRECERT_POISON,
            critical: false,
            extn_value: OctetString::new(Null.to_der().unwrap()).unwrap(),
        }];
        rebuild_cert_with_extensions(cert, Some(&exts))
    }

    fn make_poison_non_null(cert: &Certificate) -> Certificate {
        let exts = vec![Extension {
            extn_id: CT_PRECERT_POISON,
            critical: true,
            extn_value: OctetString::new([]).unwrap(),
        }];
        rebuild_cert_with_extensions(cert, Some(&exts))
    }
}
