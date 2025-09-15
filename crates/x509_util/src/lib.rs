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
        for cert in Certificate::load_pem_chain(input)? {
            self.add_cert(cert)?;
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

type UnixTimestamp = u64;

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
    #[error("intermediate missing CA basic constraint")]
    IntermediateMissingCaBasicConstraint,
    #[error("issuer not in root store: {to_verify_issuer}")]
    NoPathToTrustedRoot { to_verify_issuer: String },
}

#[derive(thiserror::Error, Debug)]
pub enum HookOrValidationError<T> {
    Hook(T),
    #[error(transparent)]
    Valiadation(#[from] ValidationError),
}

// TODO: move some tests from static_ct_api/rfc6962 to this file

/// Validates a certificate chain. This is not a super strict validation function. Its purpose is to
/// reject obviously bad certificate chains. Accepts a hook that takes the leaf, intermediate certs,
/// and a list of fingerprints of the full chain (including inferred root), and returns a value or
/// error of its own.
///
/// # Errors
///
/// Returns a `ValidationError` if the chain fails to validate. Returns an error of type `E` if the
/// hook errors.
pub fn validate_chain<T, E, F>(
    raw_chain: &[Vec<u8>],
    roots: &CertPool,
    not_after_start: Option<UnixTimestamp>,
    not_after_end: Option<UnixTimestamp>,
    mut hook: F,
) -> Result<T, HookOrValidationError<E>>
where
    F: FnMut(&Certificate, &Vec<Certificate>, Vec<[u8; 32]>) -> Result<T, E>,
{
    if raw_chain.is_empty() {
        return Err(ValidationError::EmptyChain.into());
    }
    let mut iter = raw_chain.iter();

    // Parse the first element of the chain, i.e., the leaf
    let leaf = {
        // We can unwrap the first element because we just checked the chain is not empty
        let bytes = iter.next().unwrap();
        Certificate::from_der(bytes).map_err(ValidationError::from)?
    };

    // Check whether the expiry date is within the acceptable range for this log shard.
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

    let intermediates: Vec<Certificate> = iter
        .map(|bytes| Certificate::from_der(bytes))
        .collect::<Result<_, _>>()
        .map_err(ValidationError::from)?;
    // All the intermediates plus the inferred root (we'll add it later)
    let mut full_chain: Vec<&Certificate> = intermediates.iter().collect();
    let mut full_chain_fingerprints: Vec<[u8; 32]> = raw_chain[1..]
        .iter()
        .map(|v| Sha256::digest(v).into())
        .collect();

    // Walk up the chain, ensuring that each certificate signs the previous one.
    // This simplified chain validation is possible due to the constraints laid out in RFC 6962.
    let mut to_verify = &leaf;
    for cert in intermediates.iter() {
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
            .is_none_or(|(_, bc)| !bc.ca)
        {
            return Err(ValidationError::IntermediateMissingCaBasicConstraint.into());
        }
    }

    // The last certificate in the chain is either a root certificate
    // or a certificate that chains to a known root certificate.
    let mut inferred_root_idx = None;
    if !roots.included(to_verify).map_err(ValidationError::from)? {
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
        inferred_root_idx = Some(found_idx);
        let root = &roots.certs[found_idx];
        let bytes = root.to_der().map_err(ValidationError::from)?;

        full_chain.push(&roots.certs[found_idx]);
        full_chain_fingerprints.push(Sha256::digest(bytes).into());
    }

    hook(&leaf, &intermediates, full_chain_fingerprints).map_err(HookOrValidationError::Hook)
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
