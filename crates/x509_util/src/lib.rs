// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Utilities for X.509 operations.

use der::{Encode, Error as DerError};
use sha2::{Digest, Sha256};
use std::collections::{hash_map::Entry, HashMap};
use x509_cert::{
    ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier},
    Certificate,
};

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

    /// Search the certificate pool for potential parents for the provided certificates.
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

    /// Check if a certificate is included in the pool.
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues DER-encoding the certificate.
    pub fn included(&self, cert: &Certificate) -> Result<bool, DerError> {
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
