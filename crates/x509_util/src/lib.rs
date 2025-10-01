// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Utilities for X.509 operations.

use der::{Decode, Encode, Error as DerError};
use sha2::{Digest, Sha256};
use std::collections::{hash_map::Entry, HashMap};
use x509_cert::{
    ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier},
    Certificate,
};
use x509_verify::VerifyingKey;

/// Converts a vector of certificates into an array of DER-encoded certificates.
///
/// # Errors
///
/// Returns an error if any of the certificates cannot be DER-encoded.
pub fn certs_to_bytes(certs: &[Certificate]) -> Result<Vec<Vec<u8>>, DerError> {
    certs
        .iter()
        .map(der::Encode::to_der)
        .collect::<Result<_, _>>()
}

/// A `CertPool` is a set of certificates.
#[derive(Default)]
pub struct CertPool {
    // Map from SHA256 fingerprint to index in `certs`.
    by_fingerprint: HashMap<[u8; 32], usize>,
    // Map from subject name to list of indexes of certs with that name.
    by_name: HashMap<String, Vec<usize>>,
    // Map from SKI to list of indexes of certs with that SKI.
    by_subject_key_id: HashMap<Vec<u8>, Vec<usize>>,
    // List of certificates in pool.
    pub certs: Vec<Certificate>,
}

impl CertPool {
    /// Constructs a `CertPool` from the given certificates, weeding out
    /// duplicates.
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues DER-encoding certificate
    /// extensions.
    pub fn new(certs: Vec<Certificate>) -> Result<Self, DerError> {
        let mut pool = Self::default();
        for cert in certs {
            pool.add_cert(cert)?;
        }
        Ok(pool)
    }

    /// Search the certificate pool for potential parents for the provided certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues DER-encoding certificate extensions.
    pub fn find_potential_parents(&self, cert: &Certificate) -> Result<&[usize], DerError> {
        if let Some((_, aki)) = cert.tbs_certificate.get::<AuthorityKeyIdentifier>()? {
            if let Some(indexes) = self.by_subject_key_id.get(&aki.to_der()?) {
                return Ok(indexes);
            }
        }
        if let Some(indexes) = self.by_name.get(&cert.tbs_certificate.issuer.to_string()) {
            return Ok(indexes);
        }
        Ok(&[])
    }

    /// Add a certificate to the certificate pool if it is not already included.
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues DER-encoding the certificate or
    /// parsing its extensions.
    pub fn add_cert(&mut self, cert: Certificate) -> Result<(), DerError> {
        let fingerprint: [u8; 32] = Sha256::digest(cert.to_der()?).into();
        if let Entry::Vacant(e) = self.by_fingerprint.entry(fingerprint) {
            let idx = self.certs.len();
            e.insert(idx);
            self.by_name
                .entry(cert.tbs_certificate.subject.to_string())
                .or_default()
                .push(idx);
            if let Some((_, ski)) = cert.tbs_certificate.get::<SubjectKeyIdentifier>()? {
                self.by_subject_key_id
                    .entry(ski.to_der()?)
                    .or_default()
                    .push(idx);
            }
            self.certs.push(cert);
        }

        Ok(())
    }

    /// Add certs to the pool from a byte slice assumed to contain PEM encoded
    /// data. Skips over non certificate blocks in the data.
    ///
    /// # Errors
    ///
    /// Returns an error if there are DER encoding issues.
    pub fn append_certs_from_pem(&mut self, input: &[u8]) -> Result<(), DerError> {
        // Until next x509-cert release, load_pem_chain doesn't support an empty
        // input: https://github.com/RustCrypto/formats/pull/1965
        if !input.is_empty() {
            for cert in Certificate::load_pem_chain(input)? {
                self.add_cert(cert)?;
            }
        }
        Ok(())
    }

    /// Check if the pool includes a certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues DER-encoding the certificate.
    pub fn includes(&self, cert: &Certificate) -> Result<bool, DerError> {
        Ok(self
            .by_fingerprint
            .contains_key::<[u8; 32]>(&Sha256::digest(cert.to_der()?).into()))
    }

    /// Fetch a certificate from the pool by its fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues DER-encoding the certificate.
    pub fn by_fingerprint(&self, fingerprint: &[u8; 32]) -> Option<&Certificate> {
        if let Some(idx) = self.by_fingerprint.get(fingerprint) {
            self.certs.get(*idx)
        } else {
            None
        }
    }
}

/// Unix timestamp, measured since the epoch (January 1, 1970, 00:00),
/// ignoring leap seconds, in milliseconds.
/// This can be unsigned as we never deal with negative timestamps.
pub type UnixTimestamp = u64;

#[derive(thiserror::Error, Debug)]
pub enum ValidationError {
    #[error(transparent)]
    Der(#[from] der::Error),
    #[error("empty chain")]
    EmptyChain,
    #[error("invalid leaf certificate")]
    InvalidLeaf,
    #[error("invalid link in chain")]
    InvalidLinkInChain,
    #[error("missing or invalid basic constraints")]
    InvalidBasicConstraints,
    #[error("issuer not in root store: {to_verify_issuer}")]
    NoPathToTrustedRoot { to_verify_issuer: String },
    #[error("mismatching signature algorithm identifier")]
    MismatchingSigAlg,
}

/// An error that's returned by either our validation logic or the hook that [`validate_chain`]
/// takes
#[derive(thiserror::Error, Debug)]
pub enum HookOrValidationError<T> {
    Hook(T),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

/// Validates a certificate chain. This is not a super strict validation
/// function. Its purpose is to reject obviously bad certificate chains.
/// Specifically, this does the following checks:
///
/// 1. Each certificate in the chain signs the previous certificate. Extra
///    intermediate certs aren't allowed.
/// 2. Each certificate in the chain is well-formed, meaning the signature
///    algorithm used to sign it matches the signature algorithm field in the
///    `TBSCertificate`.
/// 3. Every intermediate certificate has a `BasicConstraints` extension with
///    `ca = true`
/// 4. The final cert in the chain is a root or a cert signed by a root (this is
///    actually stricter than some other verification algorithms).
/// 5. The `not_after` date of the leaf certificate falls within the given
///    range.
///
/// # Arguments
/// * `raw_chain` — A list of DER-encoded certificates, starting from the leaf
/// * `roots` — The trusted root list
/// * `not_after_start` — The earliest permissible `not_after` value for the
///   leaf
/// * `not_after_end` — The earliest non-permissible `not_after` value for the
///   leaf
/// * `hook` — A closure that the leaf, intermediate certs, and a list of
///   fingerprints of the full chain (including inferred root if there is one),
///   and index of the inferred root (if there is one); and returns a value or
///   error of its own.
///
/// # Arguments for function closure `F`
/// * `leaf` - The leaf of the bootstrap chain
/// * `chain_certs` - A chain of certificates that authenticate the leaf, ending
///   in a trusted root. This can be empty if the leaf itself is a trusted root.
/// * `chain_fingerprints` - The hashes of `chain_certs`
/// * `found_root_idx` - If `raw_chain` did not already contain a trusted root,
///   the index in `roots` of the trusted root
///
/// # Errors
///
/// Returns a `ValidationError` if the chain fails to validate. Returns an error
/// of type `E` if the hook errors.
pub fn validate_chain_lax<T, E, F>(
    raw_chain: &[Vec<u8>],
    roots: &CertPool,
    not_after_start: Option<UnixTimestamp>,
    not_after_end: Option<UnixTimestamp>,
    hook: F,
) -> Result<T, HookOrValidationError<E>>
where
    F: FnOnce(Certificate, Vec<&Certificate>, Vec<[u8; 32]>, Option<usize>) -> Result<T, E>,
{
    // Parse the first element of the chain, i.e., the leaf.
    let leaf = match raw_chain.first() {
        Some(cert) => Certificate::from_der(cert).map_err(ValidationError::from)?,
        None => return Err(ValidationError::EmptyChain.into()),
    };

    // Check whether the expiry date is within the acceptable range.
    let not_after = u64::try_from(
        leaf.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_millis(),
    )
    .map_err(|_| ValidationError::InvalidLeaf)?;
    if not_after_start.is_some_and(|start| start > not_after)
        || not_after_end.is_some_and(|end| end <= not_after)
    {
        return Err(ValidationError::InvalidLeaf.into());
    }

    // Keep the owned certs in scope, but we'll create a vector of references
    // below so we can append the found root without needing to clone it.
    let chain_certs_owned: Vec<Certificate> = raw_chain[1..]
        .iter()
        .map(|bytes| Certificate::from_der(bytes))
        .collect::<Result<_, _>>()
        .map_err(ValidationError::from)?;

    // Reject mismatched signature algorithms:
    // https://github.com/google/certificate-transparency-go/pull/702.
    for cert in core::iter::once(&leaf).chain(&chain_certs_owned) {
        if !is_well_formed(cert) {
            return Err(ValidationError::MismatchingSigAlg.into());
        }
    }

    // All the intermediates plus the found root (we'll add it later).
    let mut chain_certs = chain_certs_owned.iter().collect::<Vec<_>>();
    let mut chain_fingerprints: Vec<[u8; 32]> = raw_chain[1..]
        .iter()
        .map(|v| Sha256::digest(v).into())
        .collect();

    // Walk up the chain, ensuring that each certificate signs the previous one.
    // This simplified chain validation is possible due to the constraints laid out in RFC 6962.
    let mut to_verify = &leaf;
    for (path_len, cert) in chain_certs.iter().enumerate() {
        // Check that this cert signs the previous one in the chain.
        if !is_link_valid(to_verify, cert) {
            return Err(ValidationError::InvalidLinkInChain.into());
        }
        to_verify = cert;

        // Check that intermediates have the CA Basic Constraint.
        // Precertificate signing certificates must also have CA:true.
        if cert
            .tbs_certificate
            .get::<BasicConstraints>()
            .map_err(ValidationError::from)?
            .is_none_or(|(_, bc)| {
                // If the path length constraint is specified, check it. The
                // path length constraint gives the maximum number of
                // intermediate certificates that can follow this certificate in
                // a valid certification path. Note that the end-entity
                // certificate is not included in this limit.
                if bc
                    .path_len_constraint
                    .is_some_and(|max| path_len > (max as usize))
                {
                    return true;
                }
                !bc.ca
            })
        {
            return Err(ValidationError::InvalidBasicConstraints.into());
        }
    }

    // The last certificate in the chain is either a root certificate
    // or a certificate that chains to a known root certificate.
    let mut found_root_idx = None;
    if !roots.includes(to_verify).map_err(ValidationError::from)? {
        let Some(&found_idx) = roots
            .find_potential_parents(to_verify)
            .map_err(ValidationError::from)?
            .iter()
            .find(|&&roots_idx| is_link_valid(to_verify, &roots.certs[roots_idx]))
        else {
            return Err(ValidationError::NoPathToTrustedRoot {
                to_verify_issuer: to_verify.tbs_certificate.issuer.to_string(),
            }
            .into());
        };
        found_root_idx = Some(found_idx);
        let root = &roots.certs[found_idx];
        let bytes = root.to_der().map_err(ValidationError::from)?;

        chain_certs.push(root);
        chain_fingerprints.push(Sha256::digest(bytes).into());
    }

    hook(leaf, chain_certs, chain_fingerprints, found_root_idx).map_err(HookOrValidationError::Hook)
}

/// Verify that a cert is well-formed according to RFC 5280.
fn is_well_formed(cert: &Certificate) -> bool {
    // Reject mismatched signature algorithms: https://github.com/google/certificate-transparency-go/pull/702.
    cert.signature_algorithm == cert.tbs_certificate.signature
}

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

/// Builds a certificate chain from the the given PEM files
#[macro_export]
macro_rules! build_chain {
        ($($root_file:expr),+) => {{
            let mut chain = Vec::new();
            $(
                chain.append(&mut Certificate::load_pem_chain(include_bytes!($root_file)).unwrap());
            )*
            chain
        }}
    }

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::prelude::*;
    use der::DecodePem;
    use x509_verify::x509_cert::Certificate;

    fn parse_datetime(s: &str) -> UnixTimestamp {
        u64::try_from(DateTime::parse_from_rfc3339(s).unwrap().timestamp_millis()).unwrap()
    }

    #[test]
    fn test_mismatched_sig_alg() {
        let cert = Certificate::from_pem(include_bytes!(
            "../../static_ct_api/tests/mismatching-sig-alg.pem"
        ))
        .unwrap();
        // Mismatched signature on leaf.
        assert!(!is_well_formed(&cert));
    }

    macro_rules! test_validate_chain {
        ($name:ident; $($root_file:expr),+; $($chain_file:expr),+; $not_after_start:expr; $not_after_end:expr; $want_err:expr; $want_chain_len:expr) => {
            #[test]
            fn $name() {
                let roots = build_chain!($($root_file),*);
                let chain = build_chain!($($chain_file),*);

                let result = validate_chain_lax(
                        &crate::certs_to_bytes(&chain).unwrap(),
                        &CertPool::new(roots).unwrap(),
                        $not_after_start,
                        $not_after_end,
                        |_, _, fingerprint_chain, _| {
                            assert_eq!(fingerprint_chain.len(), $want_chain_len);
                            Result::<(), ()>::Ok(())
                        },
                    );
                assert_eq!(result.is_err(), $want_err);
            }
        };
    }

    macro_rules! test_validate_chain_success {
        ($name:ident, $want_chain_len:expr, $($chain_file:expr),+) => {
            test_validate_chain!($name; "../../static_ct_api/tests/fake-ca-cert.pem", "../../static_ct_api/tests/fake-root-ca-cert.pem", "../../static_ct_api/tests/ca-cert.pem", "../../static_ct_api/tests/real-precert-intermediate.pem"; $($chain_file),+; None; None; false; $want_chain_len);
        };
    }

    macro_rules! test_validate_chain_fail {
        ($name:ident, $($chain_file:expr),+) => {
            test_validate_chain!($name; "../../static_ct_api/tests/fake-ca-cert.pem", "../../static_ct_api/tests/fake-root-ca-cert.pem", "../../static_ct_api/tests/ca-cert.pem", "../../static_ct_api/tests/real-precert-intermediate.pem"; $($chain_file),+; None; None; true; 0);
        };
    }

    test_validate_chain_fail!(
        missing_intermediate_ca,
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem"
    );
    test_validate_chain_fail!(
        wrong_cert_order,
        "../../static_ct_api/tests/fake-intermediate-cert.pem",
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem"
    );
    test_validate_chain_fail!(
        unrelated_cert_in_chain,
        "../../static_ct_api/tests/fake-intermediate-cert.pem",
        "../../static_ct_api/tests/test-cert.pem"
    );
    test_validate_chain_fail!(
        unrelated_cert_after_chain,
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-cert.pem",
        "../../static_ct_api/tests/test-cert.pem"
    );
    test_validate_chain_fail!(
        mismatched_sig_alg_on_intermediate,
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-with-mismatching-sig-alg.pem"
    );
    test_validate_chain_success!(
        valid_chain,
        2,
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-cert.pem"
    );
    test_validate_chain_success!(
        valid_chain_with_policy_constraints,
        2,
        "../../static_ct_api/tests/leaf-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-with-policy-constraints-cert.pem"
    );
    test_validate_chain_success!(
        valid_chain_with_policy_constraints_inc_root,
        2,
        "../../static_ct_api/tests/leaf-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-with-policy-constraints-cert.pem",
        "../../static_ct_api/tests/fake-root-ca-cert.pem"
    );
    test_validate_chain_success!(
        valid_chain_with_name_constraints,
        2,
        "../../static_ct_api/tests/leaf-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-with-name-constraints-cert.pem"
    );
    // CT ignores invalid name constraints, and MTC ignores them if the
    // extension is not marked critical. Other applications may wish to properly
    // check name constraints.
    test_validate_chain_success!(
        valid_chain_with_invalid_name_constraints,
        2,
        "../../static_ct_api/tests/leaf-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-with-invalid-name-constraints-cert.pem"
    );
    test_validate_chain_success!(
        valid_chain_of_len_4,
        3,
        "../../static_ct_api/tests/subleaf.chain"
    );
    test_validate_chain_fail!(
        misordered_chain_of_len_4,
        "../../static_ct_api/tests/subleaf.misordered.chain"
    );

    macro_rules! test_not_after {
        ($name:ident; $start:expr; $end:expr; $want_err:expr) => {
            test_validate_chain!($name; "../../static_ct_api/tests/fake-ca-cert.pem"; "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem", "../../static_ct_api/tests/fake-intermediate-cert.pem"; $start; $end; $want_err; 2);
        };
    }
    test_not_after!(not_after_no_range; None; None; false);
    test_not_after!(not_after_valid_range; Some(parse_datetime("2018-01-01T00:00:00Z")); Some(parse_datetime("2020-07-01T00:00:00Z")); false);
    test_not_after!(not_after_before_start; Some(parse_datetime("2020-01-01T00:00:00Z")); None; true);
    test_not_after!(not_after_after_end; None; Some(parse_datetime("1999-01-01T00:00:00Z")); true);

    test_validate_chain!(intermediate_as_accepted_root; "../../static_ct_api/tests/fake-intermediate-cert.pem"; "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem"; None; None; false; 1);
    test_validate_chain!(leaf_as_accepted_root; "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem"; "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem"; None; None; false; 0);
}
