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
    asn1::{Null, OctetString},
    oid::{
        db::rfc5280::{ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_KP_SERVER_AUTH},
        db::rfc6962::{CT_PRECERT_POISON, CT_PRECERT_SIGNING_CERT},
        AssociatedOid, ObjectIdentifier,
    },
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use tlog_tiles::UnixTimestamp;
use x509_cert::{
    der::{Decode, Encode},
    ext::{
        pkix::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage},
        Extension,
    },
    impl_newtype, Certificate, TbsCertificate,
};
use x509_util::CertPool;
use x509_verify::VerifyingKey;

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

/// Validates a certificate chain and returns a pending log entry.
///
/// # Errors
///
/// Returns a `ValidationError` if the chain fails to validate.
#[allow(clippy::too_many_lines)]
pub fn validate_chain(
    raw_chain: &[Vec<u8>],
    roots: &CertPool,
    not_after_start: Option<UnixTimestamp>,
    not_after_end: Option<UnixTimestamp>,
    expect_precert: bool,
    require_server_auth_eku: bool,
) -> Result<StaticCTPendingLogEntry, StaticCTError> {
    // First make sure the cert is well-formed.
    let mut iter = raw_chain.iter();
    let leaf: Certificate = match iter.next() {
        Some(v) => parse_certificate(v)?,
        None => return Err(StaticCTError::EmptyChain),
    };

    // Check whether the expiry date is within the acceptable range for this log shard.
    let not_after = u64::try_from(
        leaf.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_millis(),
    )
    .map_err(|_| StaticCTError::InvalidLeaf)?;
    if not_after_start.is_some_and(|start| start > not_after)
        || not_after_end.is_some_and(|end| end <= not_after)
    {
        return Err(StaticCTError::InvalidLeaf);
    }

    // Check if the CT poison extension is present. If present, it must be critical.
    let is_precert = is_precert(&leaf)?;
    if is_precert != expect_precert {
        return Err(StaticCTError::EndpointMismatch { is_precert });
    }

    // Check that Server Auth EKU is present. Chrome's CT policy lists this as one acceptable
    // reason for a CT log to reject a submission: <https://googlechrome.github.io/CertificateTransparency/log_policy.html>.
    if require_server_auth_eku
        && !leaf
            .tbs_certificate
            .get::<ExtendedKeyUsage>()?
            .is_some_and(|(_, eku)| eku.0.iter().any(|v| *v == ID_KP_SERVER_AUTH))
    {
        return Err(StaticCTError::InvalidLeaf);
    }

    // We can now do the verification. Use fairly lax options for verification, as
    // CT is intended to observe certifications rather than police them.

    let mut intermediates: Vec<Certificate> = iter
        .map(|v| parse_certificate(v))
        .collect::<Result<_, _>>()?;

    // Walk up the chain, ensuring that each certificate signs the previous one.
    // This simplified chain validation is possible due to the constraints laid out in RFC 6962.
    let mut to_verify = &leaf;
    let mut has_precert_signing_cert = false;
    for (idx, ca) in intermediates.iter().enumerate() {
        if !is_link_valid(to_verify, ca) {
            return Err(StaticCTError::InvalidLinkInChain);
        }
        to_verify = ca;

        // Also check that intermediates have the CA Basic Constraint,
        // but don't enforce for Precertificate Signing Certificates.
        if is_precert && idx == 0 && is_pre_issuer(ca)? {
            has_precert_signing_cert = true;
        }
        if ca
            .tbs_certificate
            .get::<BasicConstraints>()?
            .is_some_and(|(_, bc)| !bc.ca)
        {
            return Err(StaticCTError::IntermediateMissingCABasicConstraint);
        }
    }

    // The last certificate in the chain is either a root certificate
    // or a certificate that chains to a known root certificate.
    let mut found = false;
    let to_verify_issuer = to_verify.tbs_certificate.issuer.to_string();
    for &idx in roots.find_potential_parents(to_verify)? {
        if to_verify == &roots.certs[idx] {
            found = true;
            break;
        }
        if is_link_valid(to_verify, &roots.certs[idx]) {
            intermediates.push(roots.certs[idx].clone());
            found = true;
            break;
        }
    }
    if !found {
        return Err(StaticCTError::NoPathToTrustedRoot { to_verify_issuer });
    }

    // Construct a pending log entry.
    let precert_opt: Option<PrecertData>;
    let certificate: Vec<u8>;
    if is_precert {
        let mut pre_issuer: Option<&TbsCertificate> = None;
        let issuer_key_hash: [u8; 32];
        if has_precert_signing_cert {
            pre_issuer = Some(&intermediates[0].tbs_certificate);
            if intermediates.len() < 2 {
                return Err(StaticCTError::MissingPrecertSigningCertificateIssuer);
            }
            issuer_key_hash = Sha256::digest(
                intermediates[1]
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()?,
            )
            .into();
        } else {
            issuer_key_hash = Sha256::digest(
                intermediates[0]
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()?,
            )
            .into();
        }
        let pre_certificate = leaf.to_der()?;
        precert_opt = Some(PrecertData {
            issuer_key_hash,
            pre_certificate,
        });
        certificate = build_precert_tbs(&leaf.tbs_certificate, pre_issuer)?;
    } else {
        precert_opt = None;
        certificate = leaf.to_der()?;
    }

    let chain_fingerprints = raw_chain[1..]
        .iter()
        .map(|issuer| Sha256::digest(issuer).into())
        .collect();

    Ok(StaticCTPendingLogEntry {
        certificate,
        precert_opt,
        chain_fingerprints,
    })
}

/// Precertificate poison extension that can be decoded with [`TbsCertificate::get`].
#[derive(Debug)]
struct CTPrecertPoison(Null);

impl AssociatedOid for CTPrecertPoison {
    const OID: ObjectIdentifier = CT_PRECERT_POISON;
}
impl_newtype!(CTPrecertPoison, Null);

/// Returns whether or not the given link in the chain is valid.
/// [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962#section-3.1) says:
/// ```text
/// Logs MUST verify that the submitted end-entity certificate or
/// Precertificate has a valid signature chain leading back to a trusted
/// root CA certificate, using the chain of intermediate CA certificates
/// provided by the submitter.
/// ```
fn is_link_valid(child: &Certificate, issuer: &Certificate) -> bool {
    if let Ok(key) = VerifyingKey::try_from(issuer) {
        key.verify_strict(child).is_ok()
    } else {
        false
    }
}

/// Returns whether or not the certificate contains the precertificate poison extension.
fn is_precert(cert: &Certificate) -> Result<bool, StaticCTError> {
    match cert.tbs_certificate.get::<CTPrecertPoison>()? {
        Some((true, _)) => Ok(true),
        Some((false, _)) => Err(StaticCTError::InvalidCTPoison),
        None => Ok(false),
    }
}

/// Returns whether or not the certificate contains the `CertificateTransparency` extended key usage.
fn is_pre_issuer(cert: &Certificate) -> Result<bool, StaticCTError> {
    match cert.tbs_certificate.get::<ExtendedKeyUsage>()? {
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

/// Builds a Certificate Transparency pre-certificate (RFC 6962
/// s3.1) from the given DER-encoded `TBSCertificate`, returning a DER-encoded
/// `TBSCertificate`.
///
/// This function removes the CT poison extension (there must be exactly 1 of
/// these), preserving the order of other extensions.
///
/// If `issuer_opt` is provided, this should be a Precertificate Signing Certificate
/// that was used to sign the precert (indicated by having the special
/// `CertificateTransparency` extended key usage).  In this case, the issuance
/// information of the pre-cert is updated to reflect the next issuer in the
/// chain, i.e. the issuer of this special intermediate:
///   - The precert's `Issuer` is changed to the Issuer of the intermediate
///   - The precert's `AuthorityKeyId` is changed to the `AuthorityKeyId` of the
///     intermediate.
fn build_precert_tbs(
    tbs: &TbsCertificate,
    issuer_opt: Option<&TbsCertificate>,
) -> Result<Vec<u8>, StaticCTError> {
    let mut tbs = tbs.clone();

    let exts = tbs
        .extensions
        .as_mut()
        .ok_or(StaticCTError::InvalidCTPoison)?;

    // Remove CT poison extension.
    let ct_poison_idx = exts
        .iter()
        .position(|v| v.extn_id == CT_PRECERT_POISON)
        .ok_or(StaticCTError::InvalidCTPoison)?;
    exts.remove(ct_poison_idx);

    if let Some(issuer) = issuer_opt {
        // Update the precert's Issuer field.
        tbs.issuer = issuer.issuer.clone();

        // Also need to update the cert's AuthorityKeyID extension
        // to that of the preIssuer.
        let issuer_auth_key_id = match issuer.get::<AuthorityKeyIdentifier>()? {
            Some((_, aki)) => Some(OctetString::new(aki.to_der()?)?),
            None => None,
        };

        let mut key_at: Option<usize> = None;
        for (idx, ext) in exts.iter().enumerate() {
            if ext.extn_id == ID_CE_AUTHORITY_KEY_IDENTIFIER {
                key_at = Some(idx);
            }
        }

        if let Some(idx) = key_at {
            // PreCert has an auth-key-id; replace it with the value from the preIssuer
            if let Some(key_id) = issuer_auth_key_id {
                exts[idx].extn_value = key_id;
            } else {
                exts.remove(idx);
            }
        } else if let Some(key_id) = issuer_auth_key_id {
            // PreCert did not have an auth-key-id, but the preIssuer does, so add it at the end.
            exts.push(Extension {
                extn_id: ID_CE_AUTHORITY_KEY_IDENTIFIER,
                critical: false,
                extn_value: key_id,
            });
        }
    }

    Ok(tbs.to_der()?)
}

// Parse a certificate and verify that it is well-formed.
fn parse_certificate(bytes: &[u8]) -> Result<Certificate, StaticCTError> {
    let cert = Certificate::from_der(bytes)?;
    // Reject mismatched signature algorithms: https://github.com/google/certificate-transparency-go/pull/702.
    if cert.signature_algorithm != cert.tbs_certificate.signature {
        return Err(StaticCTError::MismatchingSigAlg);
    }

    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::prelude::*;
    use x509_verify::x509_cert::Certificate;

    fn parse_datetime(s: &str) -> UnixTimestamp {
        u64::try_from(DateTime::parse_from_rfc3339(s).unwrap().timestamp_millis()).unwrap()
    }

    #[test]
    fn test_mismatched_sig_alg() {
        // Mismatched signature on leaf.
        parse_certificate(include_bytes!("../tests/mismatching-sig-alg.pem")).unwrap_err();
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
        wipe_extensions(
            &mut Certificate::load_pem_chain(include_bytes!("../tests/precert-valid.pem")).unwrap()
                [0]
        ),
        false,
        false
    );

    test_is_precert!(
        poison_non_critical,
        make_poison_non_critical(
            &mut Certificate::load_pem_chain(include_bytes!("../tests/precert-valid.pem")).unwrap()
                [0]
        ),
        false,
        true
    );

    test_is_precert!(
        poison_non_null,
        make_poison_non_null(
            &mut Certificate::load_pem_chain(include_bytes!("../tests/precert-valid.pem")).unwrap()
                [0]
        ),
        false,
        true
    );

    macro_rules! test_validate_chain {
        ($name:ident; $($root_file:expr),+; $($chain_file:expr),+; $not_after_start:expr; $not_after_end:expr; $expect_precert:expr; $require_server_auth_eku:expr; $want_err:expr) => {
            #[test]
            fn $name() {
                let mut roots = Vec::new();
                $(
                    roots.append(&mut Certificate::load_pem_chain(include_bytes!($root_file)).unwrap());
                )*
                let mut chain = Vec::new();
                $(
                    chain.append(&mut Certificate::load_pem_chain(include_bytes!($chain_file)).unwrap());
                )*

                assert_eq!(validate_chain(
                        &x509_util::certs_to_bytes(&chain).unwrap(),
                        &CertPool::new(roots).unwrap(),
                        $not_after_start,
                        $not_after_end,
                        $expect_precert,
                        $require_server_auth_eku,
                    )
                    .is_err(), $want_err);
            }
        };
    }

    macro_rules! test_validate_chain_success {
        ($name:ident, $($chain_file:expr),+) => {
            test_validate_chain!($name; "../tests/fake-ca-cert.pem", "../tests/fake-root-ca-cert.pem", "../tests/ca-cert.pem", "../tests/real-precert-intermediate.pem"; $($chain_file),+; None; None; false; false; false);
        };
    }

    macro_rules! test_validate_chain_fail {
        ($name:ident, $($chain_file:expr),+) => {
            test_validate_chain!($name; "../tests/fake-ca-cert.pem", "../tests/fake-root-ca-cert.pem", "../tests/ca-cert.pem", "../tests/real-precert-intermediate.pem"; $($chain_file),+; None; None; false; false; true);
        };
    }

    test_validate_chain_fail!(
        missing_intermediate_ca,
        "../tests/leaf-signed-by-fake-intermediate-cert.pem"
    );
    test_validate_chain_fail!(
        wrong_cert_order,
        "../tests/fake-intermediate-cert.pem",
        "../tests/leaf-signed-by-fake-intermediate-cert.pem"
    );
    test_validate_chain_fail!(
        unrelated_cert_in_chain,
        "../tests/fake-intermediate-cert.pem",
        "../tests/test-cert.pem"
    );
    test_validate_chain_fail!(
        unrelated_cert_after_chain,
        "../tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../tests/fake-intermediate-cert.pem",
        "../tests/test-cert.pem"
    );
    test_validate_chain_fail!(
        mismatched_sig_alg_on_intermediate,
        "../tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../tests/fake-intermediate-with-mismatching-sig-alg.pem"
    );
    test_validate_chain_success!(
        valid_chain,
        "../tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../tests/fake-intermediate-cert.pem"
    );
    test_validate_chain_success!(
        valid_chain_with_policy_constraints,
        "../tests/leaf-cert.pem",
        "../tests/fake-intermediate-with-policy-constraints-cert.pem"
    );
    test_validate_chain_success!(
        valid_chain_with_policy_constraints_inc_root,
        "../tests/leaf-cert.pem",
        "../tests/fake-intermediate-with-policy-constraints-cert.pem",
        "../tests/fake-root-ca-cert.pem"
    );
    test_validate_chain_success!(
        valid_chain_with_name_constraints,
        "../tests/leaf-cert.pem",
        "../tests/fake-intermediate-with-name-constraints-cert.pem"
    );
    test_validate_chain_success!(
        valid_chain_with_invalid_name_constraints,
        "../tests/leaf-cert.pem",
        "../tests/fake-intermediate-with-invalid-name-constraints-cert.pem"
    );
    test_validate_chain_success!(valid_chain_of_len_4, "../tests/subleaf.chain");
    test_validate_chain_fail!(
        misordered_chain_of_len_4,
        "../tests/subleaf.misordered.chain"
    );
    // NOTE(lvalenta): there are more tests in the original Go library that we
    // could import (related to various validation options), but those are
    // probably not relevant given this library's more limited scope.
    // Also https://github.com/google/certificate-transparency-go/blob/74d106d3a25205b16d571354c64147c5f1f7dbc1/x509/x509_test.go.

    macro_rules! test_not_after {
        ($name:ident; $start:expr; $end:expr; $want_err:expr) => {
            test_validate_chain!($name; "../tests/fake-ca-cert.pem"; "../tests/leaf-signed-by-fake-intermediate-cert.pem", "../tests/fake-intermediate-cert.pem"; $start; $end; false; true; $want_err);
        };
    }
    test_not_after!(not_after_no_range; None; None; false);
    test_not_after!(not_after_valid_range; Some(parse_datetime("2018-01-01T00:00:00Z")); Some(parse_datetime("2020-07-01T00:00:00Z")); false);
    test_not_after!(not_after_before_start; Some(parse_datetime("2020-01-01T00:00:00Z")); None; true);
    test_not_after!(not_after_after_end; None; Some(parse_datetime("1999-01-01T00:00:00Z")); true);
    test_validate_chain!(missing_server_auth_eku_not_required; "../tests/fake-root-ca-cert.pem"; "../tests/subleaf.chain"; None; None; false; false; false);
    test_validate_chain!(missing_server_auth_eku_required; "../tests/fake-root-ca-cert.pem"; "../tests/subleaf.chain"; None; None; false; true; true);
    test_validate_chain!(preissuer_chain; "../tests/test-roots.pem"; "../tests/preissuer-chain.pem"; None; None; true; true; false);

    #[test]
    fn test_build_precert_tbs() {
        let precert_chain =
            Certificate::load_pem_chain(include_bytes!("../tests/preissuer-chain.pem")).unwrap();
        let precert = &precert_chain[0].tbs_certificate;
        let pre_issuer = &precert_chain[1].tbs_certificate;

        let der = build_precert_tbs(precert, Some(pre_issuer)).unwrap();

        let tbs = TbsCertificate::from_der(&der).unwrap();

        // Ensure CT poison is removed.
        assert!(precert.get::<CTPrecertPoison>().unwrap().is_some());
        assert!(tbs.get::<CTPrecertPoison>().unwrap().is_none());

        // Ensure issuer has been updated.
        assert_ne!(precert.issuer, tbs.issuer);
        assert_eq!(tbs.issuer, pre_issuer.issuer);

        // Ensure authority key ID has been updated.
        let old_aki = precert.get::<AuthorityKeyIdentifier>().unwrap().unwrap();
        let aki = tbs.get::<AuthorityKeyIdentifier>().unwrap().unwrap();
        let pre_aki = pre_issuer.get::<AuthorityKeyIdentifier>().unwrap().unwrap();
        assert_ne!(aki, old_aki);
        assert_eq!(aki, pre_aki);
    }

    fn wipe_extensions(cert: &mut Certificate) -> &Certificate {
        cert.tbs_certificate.extensions = None;
        cert
    }

    fn make_poison_non_critical(cert: &mut Certificate) -> &Certificate {
        cert.tbs_certificate.extensions = Some(vec![Extension {
            extn_id: CT_PRECERT_POISON,
            critical: false,
            extn_value: OctetString::new(Null.to_der().unwrap()).unwrap(),
        }]);
        cert
    }

    fn make_poison_non_null(cert: &mut Certificate) -> &Certificate {
        cert.tbs_certificate.extensions = Some(vec![Extension {
            extn_id: CT_PRECERT_POISON,
            critical: true,
            extn_value: OctetString::new([]).unwrap(),
        }]);
        cert
    }
}
