// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SctError {
    #[error("no SCT extension found in certificate")]
    NoSctExtension,

    #[error("policy violation: {0}")]
    Policy(#[from] PolicyError),

    #[error("{0}")]
    Other(String),
}

#[derive(Error, Debug, Clone)]
pub enum PolicyError {
    #[error("no SCTs from compliant logs (Qualified/Usable/ReadOnly)")]
    NoSCTsFromCompliantLog,

    #[error("not enough compliant SCTs: found {found}, required {required}")]
    NotEnoughCompliantSCTs { found: usize, required: usize },

    #[error("not enough unique logs: found {found}, required {required}")]
    NotEnoughUniqueLogs { found: usize, required: usize },

    #[error("not enough unique operators: found {found}, required {required}")]
    NotEnoughUniqueOperators { found: usize, required: usize },
}

/// Warnings that don't cause validation failure.
#[derive(Debug, Clone)]
pub enum SctWarning {
    InvalidSct { index: usize, reason: String },
    UnknownLog { index: usize, log_id: String },
}
