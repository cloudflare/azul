// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause
mod checkpoint;
mod marshal;
mod tree;
mod umbilical;

use byteorder::{BigEndian, WriteBytesExt};
pub use checkpoint::*;
pub use marshal::*;
pub use tree::*;
pub use umbilical::*;

use der::{Encode, Reader, SliceReader};
use regex::Regex;
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt::Debug;
use std::net::IpAddr;
use std::sync::LazyLock;

//pub use serde::*;

// Merkle Tree Certificates API and wire format.

/// Unix timestamp, measured since the epoch (January 1, 1970, 00:00),
/// ignoring leap seconds, in milliseconds.
/// This can be unsigned as we never deal with negative timestamps.
pub type UnixTimestamp = u64;

static HASH_LEN: usize = 32;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq)]
pub enum ClaimType {
    Dns = 0,
    DnsWildcard = 1,
    Ipv4 = 2,
    Ipv6 = 3,
    Unknown(u16),
}

impl From<u16> for ClaimType {
    fn from(value: u16) -> Self {
        match value {
            0 => ClaimType::Dns,
            1 => ClaimType::DnsWildcard,
            2 => ClaimType::Ipv4,
            3 => ClaimType::Ipv6,
            other => ClaimType::Unknown(other),
        }
    }
}

impl From<ClaimType> for u16 {
    fn from(claim_type: ClaimType) -> Self {
        match claim_type {
            ClaimType::Dns => 0,
            ClaimType::DnsWildcard => 1,
            ClaimType::Ipv4 => 2,
            ClaimType::Ipv6 => 3,
            ClaimType::Unknown(value) => value,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Domain(String);

static DOMAIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$").unwrap());

impl TryFrom<&[u8]> for Domain {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let domain = core::str::from_utf8(value)?;
        Self::try_from(domain)
    }
}

impl TryFrom<&str> for Domain {
    type Error = Error;

    fn try_from(domain: &str) -> Result<Self, Self::Error> {
        if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
            return Err(Error::MalformedDomain);
        }
        // Disallow all-numeric TLDs.
        if domain
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()))
        {
            return Err(Error::MalformedDomain);
        }
        // Check that each label is valid.
        for label in domain.split('.') {
            if label.is_empty() || label.len() > 63 || !DOMAIN_RE.is_match(label) {
                return Err(Error::MalformedDomain);
            }
        }
        Ok(Self(domain.to_string()))
    }
}

impl Ord for Domain {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_labels: Vec<&str> = self.0.split('.').rev().collect();
        let other_labels: Vec<&str> = other.0.split('.').rev().collect();

        // Compare from the TLD inward (right to left)
        for (self_label, other_label) in self_labels.iter().zip(other_labels.iter()) {
            match self_label
                .to_ascii_lowercase()
                .cmp(&other_label.to_ascii_lowercase())
            {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }

        // If all compared labels were equal, the longer domain is more specific
        self_labels.len().cmp(&other_labels.len())
    }
}

impl PartialOrd for Domain {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub dns: Vec<Domain>,
    pub dns_wildcard: Vec<Domain>,
    pub ipv4: Vec<IpAddr>,
    pub ipv6: Vec<IpAddr>,
    pub unknown: Vec<UnknownClaim>,
}

// Represents a claim we do not how to interpret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownClaim {
    pub typ: ClaimType,
    pub info: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceType {
    Umbilical = 0,
    Unknown(u16),
}

impl From<u16> for EvidenceType {
    fn from(value: u16) -> Self {
        match value {
            0 => EvidenceType::Umbilical,
            other => EvidenceType::Unknown(other),
        }
    }
}

impl From<EvidenceType> for u16 {
    fn from(subject_type: EvidenceType) -> Self {
        match subject_type {
            EvidenceType::Umbilical => 0,
            EvidenceType::Unknown(value) => value,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Evidence {
    Umbilical(UmbilicalEvidence),
    Unknown(UnknownEvidence),
}

impl Evidence {
    fn typ(&self) -> EvidenceType {
        match self {
            Evidence::Umbilical(_) => EvidenceType::Umbilical,
            Evidence::Unknown(e) => e.typ(),
        }
    }
    fn info(&self) -> &[u8] {
        match self {
            Evidence::Umbilical(e) => e.info(),
            Evidence::Unknown(e) => e.info(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct UmbilicalEvidence(pub Vec<u8>);

impl UmbilicalEvidence {
    fn info(&self) -> &[u8] {
        &self.0
    }
}

impl UmbilicalEvidence {
    /// Parse the raw chain by reading the outer headers, without
    /// completely parsing certificates.
    ///
    /// # Errors
    ///
    /// Returns an error if the chain cannot be parsed.
    pub fn raw_chain(&self) -> Result<Vec<&[u8]>, Error> {
        let mut chain = Vec::new();
        let mut input = SliceReader::new(&self.0)?;
        while !input.is_finished() {
            let header = input.peek_header()?;
            let total_len = header.encoded_len()?.saturating_add(header.length);
            let cert_bytes = input.read_slice(total_len)?;
            chain.push(cert_bytes);
        }
        Ok(chain)
    }

    /// Compress umbilical evidence for storing as [`extra_data`] in data tiles.
    ///
    /// # Errors
    ///
    /// Returns an error if the chain is empty or cannot be parsed.
    pub fn compress(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::new();
        let mut iter = self.raw_chain()?.into_iter();
        let leaf = iter.next().ok_or(Error::EmptyChain)?;
        let chain_fingerprints = &iter.map(Sha256::digest).collect::<Vec<_>>().concat();

        buffer.write_length_prefixed(leaf, 3)?;
        buffer.write_length_prefixed(chain_fingerprints, 2)?;

        Ok(buffer)
    }
}

pub struct CompressedUmbilicalEvidence {
    pub x509_cert: Vec<u8>,
    pub certificate_chain: Vec<[u8; HASH_LEN]>,
}

#[derive(Debug, PartialEq)]
pub struct UnknownEvidence {
    pub typ: EvidenceType,
    pub info: Vec<u8>,
}

impl UnknownEvidence {
    fn typ(&self) -> EvidenceType {
        self.typ
    }
    fn info(&self) -> &[u8] {
        &self.info
    }
}

#[derive(Debug, PartialEq)]
pub struct EvidenceList(pub Vec<Evidence>);

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidencePolicy {
    Unset = 0,
    Empty = 1,
    Umbilical = 2,
}

impl TryFrom<&str> for EvidencePolicy {
    type Error = &'static str;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "unset" => Ok(Self::Unset),
            "empty" => Ok(Self::Empty),
            "umbilical" => Ok(Self::Umbilical),
            _ => Err("unknown evidence policy"),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectType {
    TLS = 0,
    Unknown(u16),
}

impl From<u16> for SubjectType {
    fn from(value: u16) -> Self {
        match value {
            0 => SubjectType::TLS,
            other => SubjectType::Unknown(other),
        }
    }
}

impl From<SubjectType> for u16 {
    fn from(subject_type: SubjectType) -> Self {
        match subject_type {
            SubjectType::TLS => 0,
            SubjectType::Unknown(value) => value,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Subject {
    TLS(TLSSubject),
    Unknown(UnknownSubject),
}

impl Subject {
    fn typ(&self) -> SubjectType {
        match self {
            Subject::TLS(_) => SubjectType::TLS,
            Subject::Unknown(s) => s.typ(),
        }
    }
    fn info(&self) -> &[u8] {
        match self {
            Subject::TLS(s) => s.info(),
            Subject::Unknown(s) => s.info(),
        }
    }
}

impl Subject {
    /// Return an abridged version of the subject.
    ///
    /// # Errors
    ///
    /// Errors if the subject cannot be abridged, for example because
    /// the subject type is unknown, or internal buffers are corrupted.
    pub fn abridge(&self) -> Result<AbridgedSubject, Error> {
        match self {
            Subject::TLS(s) => Ok(AbridgedSubject::TLS(s.abridge()?)),
            Subject::Unknown(_) => Err(Error::CannotAbridgeUnknownSubject),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum AbridgedSubject {
    TLS(AbridgedTLSSubject),
    Unknown(UnknownSubject),
}

impl AbridgedSubject {
    fn typ(&self) -> SubjectType {
        match self {
            AbridgedSubject::TLS(_) => SubjectType::TLS,
            AbridgedSubject::Unknown(s) => s.typ(),
        }
    }
    fn info(&self) -> &[u8] {
        match self {
            AbridgedSubject::TLS(s) => s.info(),
            AbridgedSubject::Unknown(s) => s.info(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TLSSubject {
    packed: Vec<u8>,
}

impl TLSSubject {
    /// Create a new TLS subject with the given signature scheme and public key.
    ///
    /// TODO check that the signature scheme and public key are compatible
    ///
    /// # Panics
    ///
    /// Panics if `pubkey`'s size does not fit within a u16.
    pub fn new(signature_scheme: SignatureScheme, pubkey: &[u8]) -> Self {
        let mut packed = Vec::with_capacity(4 + pubkey.len());
        packed
            .write_u16::<BigEndian>(u16::from(signature_scheme))
            .unwrap();
        packed.write_length_prefixed(pubkey, 2).unwrap();
        Self { packed }
    }

    fn info(&self) -> &[u8] {
        &self.packed
    }
}

impl TLSSubject {
    /// Abridge a TLS subject by hashing the public key.
    ///
    ///
    /// # Errors
    ///
    /// Errors if the subject cannot be abridged, for example because
    /// internal buffers are corrupted.
    pub fn abridge(&self) -> Result<AbridgedTLSSubject, Error> {
        let public_key = (&self.packed[2..]).read_length_prefixed(2)?;
        let hash = Sha256::digest(public_key);
        let mut packed = [0u8; 2 + HASH_LEN];
        packed[..2].copy_from_slice(&self.packed[..2]);
        packed[2..].copy_from_slice(&hash);
        Ok(AbridgedTLSSubject { packed })
    }
}

#[derive(Debug, PartialEq)]
pub struct AbridgedTLSSubject {
    packed: [u8; 2 + HASH_LEN],
}

impl AbridgedTLSSubject {
    pub fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::from((u16::from(self.packed[0]) << 8) + u16::from(self.packed[1]))
    }
    pub fn public_key_hash(&self) -> [u8; HASH_LEN] {
        let mut hash = [0u8; HASH_LEN];
        hash.copy_from_slice(&self.packed[2..2 + HASH_LEN]);
        hash
    }
}

impl AbridgedTLSSubject {
    fn info(&self) -> &[u8] {
        &self.packed
    }
}

// Use for either an unknown (abridged) subject
#[derive(Debug, PartialEq)]
pub struct UnknownSubject {
    typ: SubjectType,
    info: Vec<u8>,
}

impl UnknownSubject {
    fn typ(&self) -> SubjectType {
        self.typ
    }
    fn info(&self) -> &[u8] {
        &self.info
    }
}

impl UnknownSubject {}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    TLSPSSWithSHA256 = 0x0804,
    TLSPSSWithSHA384 = 0x0805,
    TLSPSSWithSHA512 = 0x0806,
    TLSECDSAWithP256AndSHA256 = 0x0403,
    TLSECDSAWithP384AndSHA384 = 0x0503,
    TLSECDSAWithP521AndSHA512 = 0x0603,
    TLSEd25519 = 0x0807,
    // Just for testing we use ML-DSA-87 with a codepoint in the
    // private use region.
    // For production SLH-DSA-128s would be a better choice.
    TLSMLDSA87 = 0x0906,
    Unknown(u16),
}

impl From<u16> for SignatureScheme {
    fn from(value: u16) -> Self {
        match value {
            0x0804 => SignatureScheme::TLSPSSWithSHA256,
            0x0805 => SignatureScheme::TLSPSSWithSHA384,
            0x0806 => SignatureScheme::TLSPSSWithSHA512,
            0x0403 => SignatureScheme::TLSECDSAWithP256AndSHA256,
            0x0503 => SignatureScheme::TLSECDSAWithP384AndSHA384,
            0x0603 => SignatureScheme::TLSECDSAWithP521AndSHA512,
            0x0807 => SignatureScheme::TLSEd25519,
            0x0906 => SignatureScheme::TLSMLDSA87,
            other => SignatureScheme::Unknown(other),
        }
    }
}

impl From<SignatureScheme> for u16 {
    fn from(subject_type: SignatureScheme) -> Self {
        match subject_type {
            SignatureScheme::TLSPSSWithSHA256 => 0x0804,
            SignatureScheme::TLSPSSWithSHA384 => 0x0805,
            SignatureScheme::TLSPSSWithSHA512 => 0x0806,
            SignatureScheme::TLSECDSAWithP256AndSHA256 => 0x0403,
            SignatureScheme::TLSECDSAWithP384AndSHA384 => 0x0503,
            SignatureScheme::TLSECDSAWithP521AndSHA512 => 0x0603,
            SignatureScheme::TLSEd25519 => 0x0807,
            SignatureScheme::TLSMLDSA87 => 0x0906,
            SignatureScheme::Unknown(value) => value,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Assertion {
    pub subject: Subject,
    pub claims: Claims,
}

#[derive(Debug, PartialEq)]
pub struct LogEntry {
    pub abridged_subject: AbridgedSubject,
    pub claims: Claims,
    pub not_after: UnixTimestamp,

    // Extra data to be stored in the data tile, but not included in the leaf hash.
    // This is useful, e.g., to store evidence.
    pub extra_data: Vec<u8>,
}

/// Add-assertion request.
#[derive(Debug)]
pub struct AssertionRequest {
    pub checksum: Option<[u8; HASH_LEN]>,
    pub assertion: Assertion,
    pub evidence: EvidenceList,
    pub not_after: UnixTimestamp,
}

impl PartialEq for AssertionRequest {
    fn eq(&self, other: &Self) -> bool {
        // Do not compare checksums.
        self.assertion == other.assertion
            && self.evidence == other.evidence
            && self.not_after == other.not_after
    }
}

/// Add-assertion response.
#[derive(serde::Serialize)]
pub struct AssertionResponse {
    pub leaf_index: u64,
}

/// Get umbilical roots response.
#[serde_as]
#[derive(serde::Serialize)]
pub struct GetUmbilicalRootsResponse {
    #[serde_as(as = "Vec<Base64>")]
    pub certificates: Vec<Vec<u8>>,
}

// TODO split into multiple more specific error types
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    UTF8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    DER(#[from] der::Error),
    #[error(transparent)]
    SliceConversion(#[from] std::array::TryFromSliceError),

    #[error("trailing data")]
    TrailingData,
    #[error("claims duplicated or not sorted")]
    MalformedClaims,
    #[error("claim must list at least one element")]
    EmptyClaim,
    #[error("claim elements must be sorted")]
    UnsortedClaim,
    #[error("invalid domain name")]
    MalformedDomain,
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("parseable unknown claim")]
    ParseableUnknownClaim,
    #[error("checksum invalid")]
    ChecksumInvalid,
    #[error("invalid subject")]
    MalformedTLSSubject,

    #[error("invalid IP address")]
    InvalidIPAddress,
    #[error("claim not covered by umbilical cert")]
    UncoveredClaim,
    #[error("invalid subject for umbilical evidence")]
    InvalidSubject,
    #[error("cannot abridge unknown subject")]
    CannotAbridgeUnknownSubject,

    #[error("empty chain")]
    EmptyChain,
    #[error("expired leaf certificate")]
    ExpiredLeaf,
    #[error("invalid leaf certificate")]
    InvalidLeaf,
    #[error("intermediate missing cA basic constraint")]
    IntermediateMissingCABasicConstraint,
    #[error("invalid link in chain")]
    InvalidLinkInChain,
    #[error("issuer not in root store: {to_verify_issuer}")]
    NoPathToTrustedRoot { to_verify_issuer: String },
}

#[cfg(test)]
mod tests {

    use crate::Domain;

    #[test]
    fn test_domain_sort() {
        let domains = [
            Domain::try_from("ABC.ABC").unwrap(),
            Domain::try_from("abc.abc").unwrap(),
            Domain::try_from("ABC.ABC").unwrap(),
            Domain::try_from("abc.abc.abc").unwrap(),
            Domain::try_from("def.abc.abc").unwrap(),
            Domain::try_from("def.abc").unwrap(),
            Domain::try_from("abc.def").unwrap(),
            Domain::try_from("abc.ghi").unwrap(),
            Domain::try_from("def.ghi").unwrap(),
        ];
        assert!(domains.is_sorted());
    }

    #[test]
    fn test_domain_validation() {
        let valid = [
            "example.com",
            "Example.com",
            "sub.example.com",
            "example.co.uk",
            "foo-bar.com",
            "xn--bcher-kva.example", // Punycode for bücher.example
            "xn--fsq.xn--0zwm56d",   // Punycode version of 例子.测试
            "a.com",
            "a.b.c.d.e.f.g.h.i.j.k.l.m", // Long but legal nested domain
            "123.com",
            "test123.example",
            "a--b.com",
        ];

        for domain in valid {
            Domain::try_from(domain).unwrap();
        }

        let a64 = "a".repeat(64);
        let example30 = "example.com.".repeat(30);
        let invalid = [
            "",                // Empty
            ".",               // Only root
            "example..com",    // Empty label
            "-example.com",    // Label starts with hyphen
            "example-.com",    // Label ends with hyphen
            "ex..ample.com",   // Consecutive dots
            &a64,              // Label too long (64 chars)
            &example30,        // Too many labels (may exceed 253 bytes)
            "exa$mple.com",    // Invalid char: $
            "example..",       // Trailing dot with empty label
            "xn--",            // Invalid punycode prefix only
            "com",             // Disallow bare TLDs
            "256.256.256.256", // Looks like IP address
            "123",             // Disallow numeric TLD
            "müller.de",       // Unicode, will normalize to xn--mller-kva.de
            "例子.测试",       // Chinese IDN
        ];

        for domain in invalid {
            Domain::try_from(domain).unwrap_err();
        }
    }
}
