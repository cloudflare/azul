use der::{Encode, Error as DerError};
use std::collections::HashMap;
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
pub struct CertPool {
    by_name: HashMap<String, Vec<usize>>,
    by_subject_key_id: HashMap<Vec<u8>, Vec<usize>>,
    pub certs: Vec<Certificate>,
}

impl CertPool {
    /// Constructs a `CertPool` from the given certificates.
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues DER-encoding certificate extensions.
    pub fn new(certs: Vec<Certificate>) -> Result<Self, DerError> {
        let mut by_name = HashMap::new();
        let mut by_subject_key_id = HashMap::new();
        for (idx, cert) in certs.iter().enumerate() {
            by_name
                .entry(cert.tbs_certificate.subject.to_string())
                .or_insert_with(Vec::new)
                .push(idx);

            if let Some((_, ski)) = cert.tbs_certificate.get::<SubjectKeyIdentifier>()? {
                by_subject_key_id
                    .entry(ski.to_der()?)
                    .or_insert_with(Vec::new)
                    .push(idx);
            }
        }
        Ok(Self {
            by_name,
            by_subject_key_id,
            certs,
        })
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
}
