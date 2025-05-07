// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

use const_oid::db::rfc5280::ID_KP_SERVER_AUTH;
use der::Decode;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::IpAddr};
use x509_verify::{
    x509_cert::{
        der::Encode,
        ext::pkix::{
            name::GeneralName, AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage,
            SubjectAltName, SubjectKeyIdentifier,
        },
        Certificate,
    },
    VerifyingKey,
};

use crate::{AbridgedTLSSubject, Claims, Domain, Error, TLSSubject, UnixTimestamp};

/// Check if the subject and claims are covered by the provided 'umbilical'
/// X.509 chain.
///
/// TODO
/// - revocation checking
/// - more complete chain validation (SCTs, etc.)
///
/// # Errors
///
/// Returns an error if there are issues parsing or validating the X.509 chain,
/// or if the chain is incompatible with the provided subject and claims.
///
/// # Panics
///
/// Should not panic, as lengths are checked before `try_into` conversions.
#[allow(clippy::too_many_lines)]
pub fn check_claims_valid_for_x509(
    claims: &Claims,
    subj: &AbridgedTLSSubject,
    not_before: UnixTimestamp,
    mut not_after: UnixTimestamp,
    raw_chain: &[&[u8]],
    roots: &CertPool,
) -> Result<UnixTimestamp, Error> {
    let chain = raw_chain
        .iter()
        .map(|bytes| Certificate::from_der(bytes))
        .collect::<Result<Vec<_>, _>>()?;

    if chain.is_empty() {
        return Err(Error::EmptyChain);
    }

    let mut dns_names = Vec::new();
    let mut ip_addrs = Vec::new();
    if let Ok(Some((_, subject_alt_name))) = chain[0].tbs_certificate.get::<SubjectAltName>() {
        for name in subject_alt_name.0 {
            match name {
                GeneralName::DnsName(ia5_string) => dns_names.push(Domain(ia5_string.to_string())),
                GeneralName::IpAddress(octet_string) => match octet_string.as_bytes().len() {
                    4 => {
                        let ip: [u8; 4] = octet_string
                            .as_bytes()
                            .try_into()
                            .expect("safety: length checked in match");
                        ip_addrs.push(IpAddr::from(ip));
                    }
                    16 => {
                        let ip: [u8; 16] = octet_string
                            .as_bytes()
                            .try_into()
                            .expect("safety: length checked in match");
                        ip_addrs.push(IpAddr::from(ip));
                    }
                    _ => return Err(Error::InvalidIPAddress),
                },
                _ => {}
            }
        }
    }

    // Check if the claims are covered by the certificate.
    for ip_claim in claims.ipv4.iter().chain(&claims.ipv6) {
        let mut found = false;
        for ip in &ip_addrs {
            if ip_claim == ip {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::UncoveredClaim);
        }
    }
    for dns_claim in &claims.dns {
        let mut found = false;
        for name in &dns_names {
            if dns_claim == name {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::UncoveredClaim);
        }
    }
    for dns_wildcard_claim in &claims.dns_wildcard {
        let mut found = false;
        for name in &dns_names {
            if name == &Domain(format!("*.{}", dns_wildcard_claim.0)) {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::UncoveredClaim);
        }
    }
    if !claims.unknown.is_empty() {
        return Err(Error::UncoveredClaim);
    }

    let signature_scheme = subj.signature_scheme();
    let parsed_subj = TLSSubject::new(
        signature_scheme,
        chain[0]
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .abridge()?;
    if subj.public_key_hash() != parsed_subj.public_key_hash() {
        return Err(Error::InvalidSubject);
    }

    let public_key_hash = Sha256::digest(
        chain[0]
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    );
    if public_key_hash != subj.public_key_hash().into() {
        return Err(Error::InvalidSubject);
    }

    // Validate chain at the start of the validity period
    validate_chain(&chain, roots, not_before)?;

    let umbilical_not_after = u64::try_from(
        chain[0]
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_millis(),
    )
    .map_err(|_| Error::InvalidTimestamp)?;
    if umbilical_not_after < not_after {
        not_after = umbilical_not_after;
    }

    // Validate chain at the end of the validity period
    validate_chain(&chain, roots, not_after)?;

    // TODO revocation checks

    Ok(not_after)
}

/// Validates a certificate chain.
///
/// TODO import full suite of checks from concert
///
/// # Errors
///
/// Returns a Error if the chain fails to validate.
pub fn validate_chain(
    chain: &[Certificate],
    roots: &CertPool,
    current_time: UnixTimestamp,
) -> Result<(), Error> {
    if chain.is_empty() {
        return Err(Error::EmptyChain);
    }
    let leaf = &chain[0];

    let not_after = u64::try_from(
        leaf.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_millis(),
    )
    .map_err(|_| Error::InvalidLeaf)?;

    if not_after < current_time {
        return Err(Error::ExpiredLeaf);
    }

    // Check that Server Auth EKU is present.
    if !leaf
        .tbs_certificate
        .get::<ExtendedKeyUsage>()?
        .is_some_and(|(_, eku)| eku.0.iter().any(|v| *v == ID_KP_SERVER_AUTH))
    {
        return Err(Error::InvalidLeaf);
    }

    // We can now do the verification.

    // Walk up the chain, ensuring that each certificate signs the previous one.
    // This simplified chain validation is possible due to the constraints laid out in RFC 6962.
    let mut to_verify = leaf;
    for ca in &chain[1..] {
        if !is_link_valid(to_verify, ca) {
            return Err(Error::InvalidLinkInChain);
        }
        to_verify = ca;

        if ca
            .tbs_certificate
            .get::<BasicConstraints>()?
            .is_some_and(|(_, bc)| !bc.ca)
        {
            return Err(Error::IntermediateMissingCABasicConstraint);
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
            found = true;
            break;
        }
    }
    if !found {
        return Err(Error::NoPathToTrustedRoot { to_verify_issuer });
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
    if let Ok(key) = VerifyingKey::try_from(issuer) {
        key.verify(child).is_ok()
    } else {
        false
    }
}

/// Converts a vector of certificates into an array of DER-encoded certificates.
///
/// # Errors
///
/// Returns an error if any of the certificates cannot be DER-encoded.
pub fn certs_to_bytes(certs: &[Certificate]) -> Result<Vec<Vec<u8>>, Error> {
    Ok(certs
        .iter()
        .map(der::Encode::to_der)
        .collect::<Result<_, _>>()?)
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
    pub fn new(certs: Vec<Certificate>) -> Result<Self, Error> {
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
    pub fn find_potential_parents(&self, cert: &Certificate) -> Result<&[usize], Error> {
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
