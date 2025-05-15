// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

pub mod rfc6962;
pub mod static_ct;

pub use rfc6962::*;
pub use static_ct::*;

#[derive(thiserror::Error, Debug)]
pub enum StaticCTError {
    #[error(transparent)]
    Tlog(#[from] tlog_tiles::TlogError),
    #[error(transparent)]
    Signature(#[from] signature::Error),
    #[error(transparent)]
    Note(#[from] signed_note::NoteError),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    DER(#[from] der::Error),
    #[error(transparent)]
    X509(#[from] x509_verify::spki::Error),

    #[error("missing verifier signature")]
    MissingVerifierSignature,
    #[error("timestamp is after current time")]
    InvalidTimestamp,
    #[error("checkpoint origin does not match")]
    OriginMismatch,
    #[error("unexpected extension")]
    UnexpectedExtension,
    #[error(transparent)]
    Verifier(#[from] signed_note::VerifierError),
    #[error("invalid length")]
    InvalidLength,
    #[error("malformed")]
    Malformed,
    #[error("missing leaf_index extension")]
    MissingLeafIndex,
    #[error("unknown type")]
    UnknownType,
    #[error("trailing data")]
    TrailingData,
    #[error("empty chain")]
    EmptyChain,
    #[error("invalid leaf certificate")]
    InvalidLeaf,
    #[error("intermediate missing cA basic constraint")]
    IntermediateMissingCABasicConstraint,
    #[error("invalid link in chain")]
    InvalidLinkInChain,
    #[error("issuer not in root store: {to_verify_issuer}")]
    NoPathToTrustedRoot { to_verify_issuer: String },
    #[error("CT poison extension is not critical or invalid")]
    InvalidCTPoison,
    #[error("missing precertificate signing certificate issuer")]
    MissingPrecertSigningCertificateIssuer,
    #[error(
        "{}certificate submitted to add-{}chain", if *.is_precert { "pre-" } else { "final " }, if *.is_precert { "" } else { "pre-" }
    )]
    EndpointMismatch { is_precert: bool },
}
