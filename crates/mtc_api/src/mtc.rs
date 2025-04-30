// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

// Library for Merkle Tree Certificates.

use serde::Deserialize;
use serde_with::serde_as;
use std::{
    convert::TryFrom,
    net::{Ipv4Addr, Ipv6Addr},
};

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

// Represents a claim we do not how to interpret.
pub struct UnknownClaim {
    pub typ: ClaimType,
    pub info: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceType {
    Umbilical = 0,
    CompressedUmbilical = 1,
    Unknown(u16),
}

pub struct UnknownEvidence {
    pub typ: EvidenceType,
    pub info: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidencePolicy {
    Unset = 0,
    Empty = 1,
    Umbilical = 2,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum SubjectType {
    TLS = 0,
    Unknown(u16),
}

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
}

impl TryFrom<u16> for SignatureScheme {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0804 => Ok(SignatureScheme::TLSPSSWithSHA256),
            0x0805 => Ok(SignatureScheme::TLSPSSWithSHA384),
            0x0806 => Ok(SignatureScheme::TLSPSSWithSHA512),
            0x0403 => Ok(SignatureScheme::TLSECDSAWithP256AndSHA256),
            0x0503 => Ok(SignatureScheme::TLSECDSAWithP384AndSHA384),
            0x0603 => Ok(SignatureScheme::TLSECDSAWithP521AndSHA512),
            0x0807 => Ok(SignatureScheme::TLSEd25519),
            0x0906 => Ok(SignatureScheme::TLSMLDSA87),
            _ => Err(()),
        }
    }
}

impl From<SignatureScheme> for u16 {
    fn from(scheme: SignatureScheme) -> Self {
        scheme as u16
    }
}

pub struct TLSSubjectInfo {
    pub signature: SignatureScheme,
    pub public_key: Vec<u8>,
}

pub struct UmbilicalEvidence {
    chain: Vec<Vec<u8>>,
}

pub struct Claims {
    pub dns: Vec<String>,
    pub dns_wildcard: Vec<String>,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    pub unknown: Vec<UnknownClaim>,
}

#[derive(Deserialize)]
pub struct Assertion {
    pub subject_type: SubjectType,
    pub subject_info: Vec<u8>,
    pub claims: Vec<u8>,
}

/// Certificate Request.
#[serde_as]
#[derive(Deserialize)]
pub struct CertificateRequest {
    pub checksum: Vec<u8>,
    pub assertion: Assertion,

    pub evidence: Vec<u8>,
    pub not_after: u64,
}
