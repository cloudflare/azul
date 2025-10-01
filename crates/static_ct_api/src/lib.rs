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
    Der(#[from] der::Error),
    #[error(transparent)]
    X509(#[from] x509_verify::spki::Error),
    #[error(transparent)]
    Validation(#[from] x509_util::ValidationError),
    #[error("unexpected extension")]
    UnexpectedExtension,
    #[error("malformed")]
    Malformed,
    #[error("missing leaf_index extension")]
    MissingLeafIndex,
    #[error("unknown type")]
    UnknownType,
    #[error("trailing data")]
    TrailingData,
    #[error("invalid certificate chain per CT")]
    InvalidChain,
    #[error("invalid leaf certificate per CT")]
    InvalidLeaf,
    #[error("CT poison extension is not critical or invalid")]
    InvalidCTPoison,
    #[error("missing precertificate issuer")]
    MissingPrecertIssuer,
    #[error("missing precertificate signing certificate issuer")]
    MissingPrecertSigningCertificateIssuer,
    #[error(
        "{}certificate submitted to add-{}chain", if *.is_precert { "pre-" } else { "final " }, if *.is_precert { "" } else { "pre-" }
    )]
    EndpointMismatch { is_precert: bool },
}
