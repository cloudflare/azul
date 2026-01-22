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

    /// Find a certificate by its subject Distinguished Name.
    pub fn find_by_subject(&self, subject: &x509_cert::name::Name) -> Option<&Certificate> {
        if let Some(indices) = self.by_name.get(&subject.to_string()) {
            indices.first().and_then(|&idx| self.certs.get(idx))
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

pub struct ValidationOptions {
    // If enabled, chain validation short-circuits as soon as either a trusted
    // root or a certificate signed by a trusted root is found, and extraneous
    // certificates at the end are discarded. This is used for MTC to support
    // cross-signed chains, for example.
    //
    // If disabled, every certificate in the raw chain must be used in the
    // verified chain. This is required for CT.
    pub stop_on_first_trusted_cert: bool,

    // Bounds on allowed NotAfter values appearing in the end-entity
    // certificate. This is only used by CT.
    pub not_after_start: Option<UnixTimestamp>,
    pub not_after_end: Option<UnixTimestamp>,
}

/// Validates a certificate chain. This is not a super strict validation
/// function. Its purpose is to reject obviously bad certificate chains.
/// Specifically, this does the following checks:
///
/// 1. Each certificate in the chain signs the previous certificate.
/// 2. Each certificate in the chain is well-formed, meaning the signature
///    algorithm used to sign it matches the signature algorithm field in the
///    `TBSCertificate`.
/// 3. Every intermediate certificate has a `BasicConstraints` extension with
///    `ca = true`, and where path length constraints are met.
/// 4. A cert in the chain is a root or a cert signed by a trusted root. If
///    `stop_on_first_trusted_cert` is set, chain validation stops as soon as a
///    path to a trusted root is found. This is useful, for example, to validate
///    cross-signed chains where the final cert in the chain may not be trusted.
///    Otherwise, all certs in the chain must be part of the path to a trusted
///    root, as is required in CT.
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
///
/// # Panics
///
/// This section is here to avoid linter complaints about the `unwrap()` below,
/// but this function won't panic.
pub fn validate_chain_lax<T, E, F>(
    raw_chain: &[Vec<u8>],
    roots: &CertPool,
    opts: &ValidationOptions,
    hook: F,
) -> Result<T, HookOrValidationError<E>>
where
    F: FnOnce(Certificate, Vec<&Certificate>, Vec<[u8; 32]>, Option<usize>) -> Result<T, E>,
{
    let (leaf_der, intermediates_der) =
        raw_chain.split_first().ok_or(ValidationError::EmptyChain)?;
    let leaf = Certificate::from_der(leaf_der).map_err(ValidationError::from)?;

    // Check that the leaf is well formed.
    check_well_formedness(&leaf)?;

    // Check whether the leaf expiry date is within the acceptable range.
    let not_after = u64::try_from(
        leaf.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_millis(),
    )
    .map_err(|_| ValidationError::InvalidLeaf)?;
    if opts.not_after_start.is_some_and(|start| start > not_after)
        || opts.not_after_end.is_some_and(|end| end <= not_after)
    {
        return Err(ValidationError::InvalidLeaf.into());
    }

    // Intermediates that are part of the chain to a trusted root.
    let mut validated_intermediates = Vec::new();
    // The current certificate to be verified.
    let mut current_cert = &leaf;

    // The path to a trusted root, if one is found.
    let mut path_to_root: Option<PathToRoot> = None;

    // Walk up the chain, checking that each certificate signs the previous one.
    for (i, intermediate_der) in intermediates_der.iter().enumerate() {
        // Before parsing the intermediate, check if we can stop early.
        if opts.stop_on_first_trusted_cert {
            path_to_root = find_path_to_root(current_cert, roots, i)?;
            if path_to_root.is_some() {
                break;
            }
        }

        // Parse the intermediate and make sure it is well formed.
        let intermediate_cert =
            Certificate::from_der(intermediate_der).map_err(ValidationError::from)?;
        check_well_formedness(&intermediate_cert)?;

        // Check basic constraints for the intermediate, passing in the number
        // of preceding intermediates in the chain (excluding the leaf).
        check_ca_basic_constraints(&intermediate_cert, i)?;

        // Check that this intermediate signs the previous cert in the chain.
        if !is_link_valid(current_cert, &intermediate_cert) {
            return Err(ValidationError::InvalidLinkInChain.into());
        }

        // Add the intermediate to the validated chain.
        validated_intermediates.push(intermediate_cert);

        // Get a reference to the intermediate we just pushed to check next.
        current_cert = validated_intermediates.last().unwrap();
    }

    // If we haven't yet found a path to a trusted root, check if we can find
    // one for the last cert in the chain. If we can't, fail chain validation.
    // At this point, `path_to_root` is `Some(...)` if all of the following
    // conditions hold:
    //
    //     1. `opts.stop_on_first_trusted_cert` is set to true
    //     2. The submitted cert chain contains at least one intermediate
    //      (otherwise we never enter the above loop).
    //     3. We found a path to a trusted cert and broke from the loop early,
    //      before processing the last cert in the chain.
    //
    // Otherwise, we still need to try to find a path to a trusted root for the
    // last cert in the chain.
    let path_to_root = if let Some(path) = path_to_root {
        path
    } else {
        let Some(path) = find_path_to_root(current_cert, roots, validated_intermediates.len())?
        else {
            return Err(ValidationError::NoPathToTrustedRoot {
                to_verify_issuer: current_cert.tbs_certificate.issuer.to_string(),
            }
            .into());
        };
        path
    };

    // Prepare arguments for the validation hook.
    let mut chain_certs = validated_intermediates.iter().collect::<Vec<_>>();
    let mut chain_fingerprints = intermediates_der
        .iter()
        .take(validated_intermediates.len())
        .map(|der| Sha256::digest(der).into())
        .collect::<Vec<_>>();

    // If the trusted root was not taken from the provided chain, add it and
    // extract its index in the root pool.
    let found_root_idx = {
        match path_to_root {
            PathToRoot::IsRoot => None,
            PathToRoot::SignedByRoot(root_pool_idx) => {
                // Append the trusted root to the validated chain.
                let root = &roots.certs[root_pool_idx];
                let root_der = root.to_der().map_err(ValidationError::from)?;
                chain_certs.push(root);
                chain_fingerprints.push(Sha256::digest(&root_der).into());
                Some(root_pool_idx)
            }
        }
    };

    hook(leaf, chain_certs, chain_fingerprints, found_root_idx).map_err(HookOrValidationError::Hook)
}

enum PathToRoot {
    IsRoot,
    SignedByRoot(usize),
}

/// Check for a path from the provided certificate to a trusted root. This can
/// be the case if the cert itself is a trusted root, or if the certificate is
/// signed by a trusted root. In the latter case, return the index in the cert
/// pool of that root.
///
/// If no path to a trusted root is found, return `None`.
///
/// # Arguments
///
/// * `cert` - The cert for which to find a path to a trusted root.
/// * `roots` - The cert pool of trusted roots.
/// * `num_intermediates` - The number of intermediate certs preceding the cert
///   in the chain. This is used for checking the path length basic constraint.
fn find_path_to_root(
    cert: &Certificate,
    roots: &CertPool,
    num_intermediates: usize,
) -> Result<Option<PathToRoot>, ValidationError> {
    // Check if the cert is itself a trusted root.
    if roots.includes(cert).map_err(ValidationError::from)? {
        return Ok(Some(PathToRoot::IsRoot));
    }

    // Check if the cert is signed by a trusted root.
    if let Some(&found_idx) = roots
        .find_potential_parents(cert)
        .map_err(ValidationError::from)?
        .iter()
        .find(|&&roots_idx| {
            is_link_valid(cert, &roots.certs[roots_idx])
                && check_ca_basic_constraints(&roots.certs[roots_idx], num_intermediates).is_ok()
        })
    {
        return Ok(Some(PathToRoot::SignedByRoot(found_idx)));
    }

    // No path to root found from this certificate.
    Ok(None)
}

/// Verify that a cert is well-formed according to RFC 5280.
fn check_well_formedness(cert: &Certificate) -> Result<(), ValidationError> {
    // Reject mismatched signature algorithms: https://github.com/google/certificate-transparency-go/pull/702.
    if cert.signature_algorithm != cert.tbs_certificate.signature {
        return Err(ValidationError::MismatchingSigAlg);
    }
    Ok(())
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
    // Currently paths are built by comparing
    //   child.tbs_certificate.issuer.to_string()
    // to
    //   issuer.tbs_certificate.subject.to_string().
    // When these are equal, there is a plausible link between these. This is NOT the actual
    // algorithm for determining whether a link is valid. A discussion on the correct algorithm can
    // be found here
    //   https://github.com/golang/go/issues/31440#issuecomment-537222858
    // The short version is: many clients do byte-by-byte comparison. This to_string() comparison is
    // strictly laxer than that. Which is probably fine for MTC and (static) CT use cases.

    // Verify the issuer's signature on the child cert
    if let Ok(key) = VerifyingKey::try_from(issuer) {
        key.verify_strict(child).is_ok()
    } else {
        false
    }
}

/// Validate Basic Constraints for a CA certificate.
///
/// # Arguments
///
/// * `ca_cert` - The CA certificate to check.
/// * `num_intermediates` - The number of intermediate certs preceding the cert
///   in the chain. This is used for checking the path length basic constraint.
fn check_ca_basic_constraints(
    ca_cert: &Certificate,
    num_intermediates: usize,
) -> Result<(), ValidationError> {
    // Check the cert's basic constraints.
    if ca_cert
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
                .is_some_and(|max| num_intermediates > (max as usize))
            {
                return true;
            }
            !bc.ca
        })
    {
        return Err(ValidationError::InvalidBasicConstraints);
    }
    Ok(())
}

/// Builds a certificate chain from the the given PEM files
#[macro_export]
macro_rules! build_chain {
        ($($root_file:expr),+) => {{
            let mut chain = Vec::new();
            $(
                chain.append(&mut Certificate::load_pem_chain(include_bytes!($root_file)).expect("failed to parse PEM file"));
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
        check_well_formedness(&cert).unwrap_err();
    }

    macro_rules! test_validate_chain {
        ($name:ident; $($root_file:expr),+; $($chain_file:expr),+; $not_after_start:expr; $not_after_end:expr; $want_err:expr; $want_chain_len:expr; $stop_on_first_trusted_cert:expr) => {
            #[test]
            fn $name() {
                let roots = build_chain!($($root_file),*);
                let chain = build_chain!($($chain_file),*);

                let result = validate_chain_lax(
                        &crate::certs_to_bytes(&chain).unwrap(),
                        &CertPool::new(roots).unwrap(),
                        &ValidationOptions {
                            stop_on_first_trusted_cert: $stop_on_first_trusted_cert,
                            not_after_start: $not_after_start,
                            not_after_end: $not_after_end,
                        },
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
        ($name:ident; $want_chain_len:expr; $($chain_file:expr),+; $stop_on_first_trusted_cert:expr) => {
            test_validate_chain!($name; "../../static_ct_api/tests/fake-ca-cert.pem", "../../static_ct_api/tests/fake-root-ca-cert.pem", "../../static_ct_api/tests/ca-cert.pem", "../../static_ct_api/tests/real-precert-intermediate.pem"; $($chain_file),+; None; None; false; $want_chain_len; $stop_on_first_trusted_cert);
        };
    }

    macro_rules! test_validate_chain_fail {
        ($name:ident; $($chain_file:expr),+; $stop_on_first_trusted_cert:expr) => {
            test_validate_chain!($name; "../../static_ct_api/tests/fake-ca-cert.pem", "../../static_ct_api/tests/fake-root-ca-cert.pem", "../../static_ct_api/tests/ca-cert.pem", "../../static_ct_api/tests/real-precert-intermediate.pem"; $($chain_file),+; None; None; true; 0; $stop_on_first_trusted_cert);
        };
    }
    test_validate_chain!(
        cloudflare_chain_with_cross_signed_gts_root_by_untrusted_globalsign_success;
        "../../static_ct_api/tests/google-gts-root-r4.pem";
        "../../static_ct_api/tests/cloudflare.pem";
        None;
        None;
        false;
        2;
        true
    );
    test_validate_chain!(
        cloudflare_chain_with_cross_signed_gts_root_by_untrusted_globalsign_fail;
        "../../static_ct_api/tests/google-gts-root-r4.pem";
        "../../static_ct_api/tests/cloudflare.pem";
        None;
        None;
        true;
        0;
        false
    );
    test_validate_chain_fail!(
        missing_intermediate_ca;
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem";
        false
    );
    test_validate_chain_fail!(
        wrong_cert_order;
        "../../static_ct_api/tests/fake-intermediate-cert.pem",
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem";
        false
    );
    test_validate_chain_fail!(
        unrelated_cert_in_chain;
        "../../static_ct_api/tests/fake-intermediate-cert.pem",
        "../../static_ct_api/tests/test-cert.pem";
        false
    );
    test_validate_chain_fail!(
        unrelated_cert_after_chain;
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-cert.pem",
        "../../static_ct_api/tests/test-cert.pem";
        false
    );
    test_validate_chain_fail!(
        mismatched_sig_alg_on_intermediate;
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-with-mismatching-sig-alg.pem";
        false
    );
    test_validate_chain_success!(
        valid_chain;
        2;
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-cert.pem";
        false
    );
    test_validate_chain_success!(
        valid_chain_inc_root;
        2;
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-ca-cert.pem";
        false
    );
    test_validate_chain_fail!(
        unrelated_cert_after_chain_inc_root;
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-ca-cert.pem",
        "../../static_ct_api/tests/test-cert.pem";
        false
    );
    test_validate_chain_success!(
        unrelated_cert_after_chain_inc_root_allowed;
        2;
        "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-cert.pem",
        "../../static_ct_api/tests/fake-ca-cert.pem",
        "../../static_ct_api/tests/test-cert.pem";
        true
    );
    test_validate_chain_success!(
        valid_chain_with_policy_constraints;
        2;
        "../../static_ct_api/tests/leaf-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-with-policy-constraints-cert.pem";
        false
    );
    test_validate_chain_success!(
        valid_chain_with_policy_constraints_inc_root;
        2;
        "../../static_ct_api/tests/leaf-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-with-policy-constraints-cert.pem",
        "../../static_ct_api/tests/fake-root-ca-cert.pem";
        false
    );
    test_validate_chain_success!(
        valid_chain_with_name_constraints;
        2;
        "../../static_ct_api/tests/leaf-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-with-name-constraints-cert.pem";
        false
    );
    // CT ignores invalid name constraints, and MTC ignores them if the
    // extension is not marked critical. Other applications may wish to properly
    // check name constraints.
    test_validate_chain_success!(
        valid_chain_with_invalid_name_constraints;
        2;
        "../../static_ct_api/tests/leaf-cert.pem",
        "../../static_ct_api/tests/fake-intermediate-with-invalid-name-constraints-cert.pem";
        false
    );
    test_validate_chain_success!(
        valid_chain_of_len_4;
        3;
        "../../static_ct_api/tests/subleaf.chain";
        false
    );
    test_validate_chain_fail!(
        misordered_chain_of_len_4;
        "../../static_ct_api/tests/subleaf.misordered.chain";
        false
    );

    macro_rules! test_not_after {
        ($name:ident; $start:expr; $end:expr; $want_err:expr) => {
            test_validate_chain!($name; "../../static_ct_api/tests/fake-ca-cert.pem"; "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem", "../../static_ct_api/tests/fake-intermediate-cert.pem"; $start; $end; $want_err; 2; false);
        };
    }
    test_not_after!(not_after_no_range; None; None; false);
    test_not_after!(not_after_valid_range; Some(parse_datetime("2018-01-01T00:00:00Z")); Some(parse_datetime("2020-07-01T00:00:00Z")); false);
    test_not_after!(not_after_before_start; Some(parse_datetime("2020-01-01T00:00:00Z")); None; true);
    test_not_after!(not_after_after_end; None; Some(parse_datetime("1999-01-01T00:00:00Z")); true);

    test_validate_chain!(intermediate_as_accepted_root; "../../static_ct_api/tests/fake-intermediate-cert.pem"; "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem"; None; None; false; 1; false);
    test_validate_chain!(leaf_as_accepted_root; "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem"; "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem"; None; None; false; 0; false);

    #[test]
    fn test_find_by_subject() {
        // Load a root CA certificate
        let root =
            Certificate::from_pem(include_bytes!("../../static_ct_api/tests/fake-ca-cert.pem"))
                .unwrap();

        // Get the subject DN before moving into pool
        let subject_dn = root.tbs_certificate.subject.clone();

        // Create a pool with this root
        let pool = CertPool::new(vec![root]).unwrap();

        // Should find the cert by its subject
        let found = pool.find_by_subject(&subject_dn);
        assert!(found.is_some(), "Should find certificate by subject DN");

        // Verify it's the same cert (compare subjects)
        assert_eq!(
            found.unwrap().tbs_certificate.subject.to_string(),
            subject_dn.to_string()
        );
    }

    #[test]
    fn test_find_by_subject_not_found() {
        // Load a certificate
        let cert = Certificate::from_pem(include_bytes!(
            "../../static_ct_api/tests/leaf-signed-by-fake-intermediate-cert.pem"
        ))
        .unwrap();

        // Create pool with just this leaf cert
        let pool = CertPool::new(vec![cert]).unwrap();

        // Try to find by a different subject (use the leaf's issuer, which isn't in pool)
        let leaf = &pool.certs[0];
        let issuer_dn = &leaf.tbs_certificate.issuer;

        // The issuer is not in the pool, so this should return None
        let not_found = pool.find_by_subject(issuer_dn);
        assert!(
            not_found.is_none(),
            "Should not find certificate not in pool"
        );
    }
}
