// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! WASM-compatible SCT validation, implementing Chrome's CT policy.
//!
//! Chrome's policy:
//! - Certs ≤ 180 days: 2 unique logs
//! - Certs > 180 days: 3 unique logs
//! - Always 2 unique operators
//! - Logs must be Qualified/Usable/ReadOnly
//! - Stale log list (> 70 days): auto-succeed
//!
//! Note: Does not enforce the legacy "one RFC 6962 log" requirement
//! (dropped April 15th 2025 per Chrome policy update).

pub mod error;
pub mod policy;
pub mod sct;
pub mod verify;

pub use error::{PolicyError, SctError, SctWarning};
pub use policy::check_chrome_policy;
pub use sct::{extract_scts_from_cert, ParsedSct};
pub use verify::verify_sct_signature;

use base64::prelude::*;
use der::Encode;
use hashbrown::HashMap;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use serde::Deserialize;
use spki::SubjectPublicKeyInfoRef;
use x509_cert::der::Decode;

/// Log list freshness period in seconds (70 days).
/// If the log list is older than this, SCT validation auto-succeeds.
pub const LOG_LIST_FRESHNESS_SECS: u64 = 70 * 24 * 60 * 60;

/// States that a CT log can be in.
/// See <https://googlechrome.github.io/CertificateTransparency/ct_policy.html>
#[derive(Clone, Debug, PartialEq, Copy, Eq)]
pub enum LogState {
    /// Log has been submitted but is still being evaluated.
    Pending,
    /// Log is accepting submissions, still gaining client trust.
    Qualified,
    /// Log is accepting submissions and widely trusted.
    Usable,
    /// Log is no longer accepting submissions but SCTs are still valid.
    ReadOnly,
    /// Log is no longer trusted. SCTs issued before retirement may still count.
    Retired,
    /// Log was rejected and will never be trusted.
    Rejected,
}

impl LogState {
    /// Returns true if this state counts as "compliant" for Chrome's CT policy.
    /// Qualified, Usable, and ReadOnly logs can issue compliant SCTs.
    #[must_use]
    pub fn is_compliant(&self) -> bool {
        matches!(
            self,
            LogState::Qualified | LogState::Usable | LogState::ReadOnly
        )
    }
}

impl core::fmt::Display for LogState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LogState::Pending => write!(f, "pending"),
            LogState::Qualified => write!(f, "qualified"),
            LogState::Usable => write!(f, "usable"),
            LogState::ReadOnly => write!(f, "readonly"),
            LogState::Retired => write!(f, "retired"),
            LogState::Rejected => write!(f, "rejected"),
        }
    }
}

/// A public key used for verifying SCT signatures.
/// CT logs use ECDSA P-256.
pub type VerifyingKey = P256VerifyingKey;

/// A Certificate Transparency log.
#[derive(Clone, Debug)]
pub struct CtLog {
    /// Human-readable description of the log.
    pub description: String,
    /// The log's ID (SHA-256 hash of the public key).
    pub id: [u8; 32],
    /// Public key for verifying SCT signatures.
    pub key: VerifyingKey,
    /// Current state of the log.
    pub state: LogState,
    /// Unix timestamp (seconds) when the log entered its current state.
    pub state_entered_at: u64,
    /// Current operator of the log.
    pub current_operator: String,
    /// Previous operators, as (end_timestamp, operator_name) pairs, sorted by timestamp.
    pub previous_operators: Vec<(u64, String)>,
}

impl CtLog {
    pub fn new(
        description: String,
        id: [u8; 32],
        key_der: &[u8],
        state: LogState,
        state_entered_at: u64,
        current_operator: String,
        mut previous_operators: Vec<(u64, String)>,
    ) -> Result<Self, SctError> {
        let key = parse_verifying_key(&description, key_der)?;
        previous_operators.sort_by_key(|(ts, _)| *ts);

        Ok(Self {
            description,
            id,
            key,
            state,
            state_entered_at,
            current_operator,
            previous_operators,
        })
    }

    /// Returns the operator of this log at the given timestamp.
    /// The end_timestamp in previous_operators is inclusive (operator was active at that instant).
    #[must_use]
    pub fn operator_at(&self, timestamp_secs: u64) -> &str {
        for (end_timestamp, operator) in &self.previous_operators {
            if timestamp_secs <= *end_timestamp {
                return operator;
            }
        }
        &self.current_operator
    }

    /// Returns true if the log was retired before the given timestamp.
    /// SCTs from retired logs don't count as "compliant" but may still count
    /// for uniqueness requirements.
    #[must_use]
    pub fn was_retired_before(&self, timestamp_secs: u64) -> bool {
        self.state == LogState::Retired && timestamp_secs >= self.state_entered_at
    }
}

fn parse_verifying_key(description: &str, key_der: &[u8]) -> Result<VerifyingKey, SctError> {
    let spki = SubjectPublicKeyInfoRef::try_from(key_der)
        .map_err(|e| SctError::Other(format!("invalid log key '{}': {e}", description)))?;

    P256VerifyingKey::try_from(spki).map_err(|e| {
        SctError::Other(format!(
            "invalid log key '{}': not a valid P-256 key: {e}",
            description
        ))
    })
}

/// A collection of CT logs indexed by their ID.
#[derive(Clone, Debug)]
pub struct CtLogList {
    /// Logs indexed by their 32-byte ID.
    pub logs: HashMap<[u8; 32], CtLog>,
    /// Unix timestamp (seconds) when this log list was published.
    pub log_list_timestamp: u64,
}

impl CtLogList {
    /// Creates an empty log list with the given timestamp.
    #[must_use]
    pub fn new(log_list_timestamp: u64) -> Self {
        Self {
            logs: HashMap::new(),
            log_list_timestamp,
        }
    }

    /// Parses a CT log list from Chrome's JSON format.
    pub fn from_chrome_log_list(json_bytes: &[u8]) -> Result<Self, SctError> {
        let raw: RawLogList =
            serde_json::from_slice(json_bytes).map_err(|e| SctError::Other(e.to_string()))?;

        let log_list_timestamp = parse_rfc3339_to_unix(&raw.log_list_timestamp)?;
        let mut logs = HashMap::new();

        for operator in raw.operators {
            for raw_log in operator.logs {
                let log = parse_raw_log(&operator.name, &raw_log)?;
                logs.insert(log.id, log);
            }
            if let Some(tiled_logs) = operator.tiled_logs {
                for tiled_log in tiled_logs {
                    let log = parse_raw_log(&operator.name, &tiled_log.raw_log)?;
                    logs.insert(log.id, log);
                }
            }
        }

        log::info!("Parsed {} CT logs from log list", logs.len());

        Ok(Self {
            logs,
            log_list_timestamp,
        })
    }

    /// Returns true if this log list is stale (older than 70 days).
    /// Per Chrome's CT policy, SCT validation should auto-succeed with stale lists.
    #[must_use]
    pub fn is_stale(&self, validation_time_secs: u64) -> bool {
        validation_time_secs >= self.log_list_timestamp + LOG_LIST_FRESHNESS_SECS
    }

    /// Looks up a log by its ID.
    #[must_use]
    pub fn get(&self, log_id: &[u8; 32]) -> Option<&CtLog> {
        self.logs.get(log_id)
    }
}

fn parse_raw_log(operator_name: &str, raw_log: &RawLog) -> Result<CtLog, SctError> {
    let desc = raw_log.description.clone().unwrap_or_default();

    let log_id_bytes = BASE64_STANDARD.decode(&raw_log.log_id).map_err(|e| {
        SctError::Other(format!(
            "invalid log key '{}': invalid base64 log_id: {e}",
            desc
        ))
    })?;
    let id: [u8; 32] = log_id_bytes.try_into().map_err(|v: Vec<u8>| {
        SctError::Other(format!(
            "invalid log key '{}': log_id has invalid length: {} (expected 32)",
            desc,
            v.len()
        ))
    })?;

    let key_der = BASE64_STANDARD.decode(&raw_log.key).map_err(|e| {
        SctError::Other(format!(
            "invalid log key '{}': invalid base64 key: {e}",
            desc
        ))
    })?;

    let (state, state_entered_at) = raw_log.state.to_state_and_timestamp()?;
    let previous_operators = raw_log
        .previous_operators
        .as_ref()
        .map(|ops| {
            ops.iter()
                .map(|op| {
                    let ts = parse_rfc3339_to_unix(&op.end_time)?;
                    Ok((ts, op.name.clone()))
                })
                .collect::<Result<Vec<_>, SctError>>()
        })
        .transpose()?
        .unwrap_or_default();

    CtLog::new(
        desc,
        id,
        &key_der,
        state,
        state_entered_at,
        operator_name.to_string(),
        previous_operators,
    )
}

/// Parse an RFC 3339 timestamp string to Unix seconds.
fn parse_rfc3339_to_unix(s: &str) -> Result<u64, SctError> {
    let dt = chrono::DateTime::parse_from_rfc3339(s)
        .map_err(|e| SctError::Other(format!("invalid timestamp '{s}': {e}")))?;
    Ok(dt.timestamp() as u64)
}

// JSON deserialization structures for Chrome's log list format

#[derive(Debug, Deserialize)]
struct RawLogList {
    #[allow(dead_code)]
    version: Option<String>,
    #[allow(dead_code)]
    is_all_logs: Option<bool>,
    log_list_timestamp: String,
    operators: Vec<RawOperator>,
}

#[derive(Debug, Deserialize)]
struct RawOperator {
    name: String,
    #[allow(dead_code)]
    email: Vec<String>,
    logs: Vec<RawLog>,
    tiled_logs: Option<Vec<RawTiledLog>>,
}

#[derive(Debug, Deserialize)]
struct RawLog {
    description: Option<String>,
    key: String,
    #[allow(dead_code)]
    log_id: String,
    #[allow(dead_code)]
    mmd: f64,
    #[allow(dead_code)]
    url: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "dns")]
    dns_api: Option<String>,
    #[allow(dead_code)]
    temporal_interval: Option<RawTemporalInterval>,
    #[allow(dead_code)]
    log_type: Option<String>,
    state: RawLogState,
    previous_operators: Option<Vec<RawPreviousOperator>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct RawTemporalInterval {
    #[serde(rename = "start_inclusive")]
    start: String,
    #[serde(rename = "end_exclusive")]
    end: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawLogState {
    Pending {
        timestamp: String,
    },
    Qualified {
        timestamp: String,
    },
    Usable {
        timestamp: String,
    },
    #[serde(rename = "readonly")]
    ReadOnly {
        timestamp: String,
        #[allow(dead_code)]
        final_tree_head: RawFinalTreeHead,
    },
    Retired {
        timestamp: String,
    },
    Rejected {
        timestamp: String,
    },
}

impl RawLogState {
    fn to_state_and_timestamp(&self) -> Result<(LogState, u64), SctError> {
        let (state, ts_str) = match self {
            RawLogState::Pending { timestamp } => (LogState::Pending, timestamp),
            RawLogState::Qualified { timestamp } => (LogState::Qualified, timestamp),
            RawLogState::Usable { timestamp } => (LogState::Usable, timestamp),
            RawLogState::ReadOnly { timestamp, .. } => (LogState::ReadOnly, timestamp),
            RawLogState::Retired { timestamp } => (LogState::Retired, timestamp),
            RawLogState::Rejected { timestamp } => (LogState::Rejected, timestamp),
        };
        let ts = parse_rfc3339_to_unix(ts_str)?;
        Ok((state, ts))
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct RawFinalTreeHead {
    tree_size: u64,
    sha256_root_hash: String,
}

#[derive(Debug, Deserialize)]
struct RawPreviousOperator {
    name: String,
    end_time: String,
}

#[derive(Debug, Deserialize)]
struct RawTiledLog {
    #[serde(flatten)]
    raw_log: RawLog,
    #[allow(dead_code)]
    submission_url: String,
    #[allow(dead_code)]
    monitoring_url: String,
}

/// Result of SCT validation.
#[derive(Debug)]
pub enum SctValidationResult {
    /// All SCTs are valid and policy requirements are met.
    Valid,
    /// Policy requirements are met, but some individual SCTs had issues.
    ValidWithWarnings(Vec<SctWarning>),
    /// The log list is stale (> 70 days old), so validation auto-succeeds.
    StaleLogList,
}

/// Main SCT validator.
pub struct SctValidator {
    log_list: CtLogList,
}

impl SctValidator {
    /// Creates a new validator with the given log list.
    #[must_use]
    pub fn new(log_list: CtLogList) -> Self {
        Self { log_list }
    }

    /// Validates embedded SCTs in a certificate against Chrome's CT policy.
    pub fn validate_embedded_scts(
        &self,
        leaf_der: &[u8],
        issuer_der: &[u8],
        validation_time_secs: u64,
    ) -> Result<SctValidationResult, SctError> {
        if self.log_list.is_stale(validation_time_secs) {
            log::warn!(
                "CT log list is stale (timestamp: {}, validation time: {}), auto-succeeding",
                self.log_list.log_list_timestamp,
                validation_time_secs
            );
            return Ok(SctValidationResult::StaleLogList);
        }

        let issuer_cert = x509_cert::Certificate::from_der(issuer_der)
            .map_err(|e| SctError::Other(format!("issuer: {e}")))?;
        let issuer_spki_der = issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| SctError::Other(format!("issuer SPKI: {e}")))?;

        let (scts, ct_cert_der, cert_lifetime_days) = extract_scts_from_cert(leaf_der)?;
        if scts.is_empty() {
            return Err(SctError::NoSctExtension);
        }

        let mut validated_scts = Vec::new();
        let mut warnings = Vec::new();

        for (index, sct) in scts.iter().enumerate() {
            let Some(log) = self.log_list.get(&sct.log_id) else {
                warnings.push(SctWarning::UnknownLog {
                    index,
                    log_id: BASE64_STANDARD.encode(sct.log_id),
                });
                continue;
            };

            let sct_time_secs = sct.timestamp / 1000;
            if sct_time_secs > validation_time_secs {
                warnings.push(SctWarning::InvalidSct {
                    index,
                    reason: format!(
                        "SCT timestamp {} is in the future (validation time: {})",
                        sct_time_secs, validation_time_secs
                    ),
                });
                continue;
            }

            if let Err(e) = verify_sct_signature(sct, log, &ct_cert_der, &issuer_spki_der) {
                warnings.push(SctWarning::InvalidSct {
                    index,
                    reason: format!("signature verification failed: {e}"),
                });
                continue;
            }

            validated_scts.push(policy::ValidatedSct {
                timestamp_secs: sct_time_secs,
                log,
            });
        }

        check_chrome_policy(cert_lifetime_days, &validated_scts)?;

        if warnings.is_empty() {
            Ok(SctValidationResult::Valid)
        } else {
            Ok(SctValidationResult::ValidWithWarnings(warnings))
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use x509_cert::Certificate;

    // Oct 1, 2025 (within cloudflare.pem validity window)
    const VALIDATION_TIME: u64 = 1759276800;

    fn load_test_log_list() -> CtLogList {
        CtLogList::from_chrome_log_list(include_bytes!("../tests/log_list.json"))
            .expect("failed to parse log list")
    }

    fn load_leaf_and_issuer() -> (Vec<u8>, Vec<u8>) {
        let leaf = Certificate::load_pem_chain(include_bytes!("../tests/cloudflare.pem"))
            .expect("failed to parse leaf")[0]
            .to_der()
            .expect("failed to encode leaf");
        let issuer = Certificate::load_pem_chain(include_bytes!("../tests/google-we1.pem"))
            .expect("failed to parse issuer")[0]
            .to_der()
            .expect("failed to encode issuer");
        (leaf, issuer)
    }

    #[test]
    fn valid_certificate_with_embedded_scts() {
        let (leaf, issuer) = load_leaf_and_issuer();
        let validator = SctValidator::new(load_test_log_list());

        let result = validator.validate_embedded_scts(&leaf, &issuer, VALIDATION_TIME);

        assert!(
            matches!(result, Ok(SctValidationResult::Valid | SctValidationResult::ValidWithWarnings(_))),
            "expected valid result, got: {result:?}"
        );
    }

    #[test]
    fn certificate_without_scts_fails() {
        // CA certs don't have SCTs
        let (_, issuer) = load_leaf_and_issuer();
        let validator = SctValidator::new(load_test_log_list());

        let result = validator.validate_embedded_scts(&issuer, &issuer, VALIDATION_TIME);

        assert!(
            matches!(result, Err(SctError::NoSctExtension)),
            "expected NoSctExtension error, got: {result:?}"
        );
    }

    #[test]
    fn tampered_certificate_fails_signature_verification() {
        let (mut leaf, issuer) = load_leaf_and_issuer();
        let validator = SctValidator::new(load_test_log_list());

        // flip a byte to corrupt cert
        if leaf.len() > 100 {
            leaf[100] ^= 0xFF;
        }

        let result = validator.validate_embedded_scts(&leaf, &issuer, VALIDATION_TIME);
        assert!(result.is_err(), "expected error for tampered cert, got: {result:?}");
    }

    // SCTs valid for cert's entire lifetime per Chrome policy:
    // https://googlechrome.github.io/CertificateTransparency/ct_policy.html
    #[test]
    fn future_validation_time_still_works() {
        let (leaf, issuer) = load_leaf_and_issuer();
        let validator = SctValidator::new(load_test_log_list());

        // Nov 1, 2025, still within cert validity
        let future_time = VALIDATION_TIME + 31 * 24 * 60 * 60;
        let result = validator.validate_embedded_scts(&leaf, &issuer, future_time);

        assert!(
            matches!(result, Ok(SctValidationResult::Valid | SctValidationResult::ValidWithWarnings(_))),
            "expected valid result, got: {result:?}"
        );
    }

    #[test]
    fn empty_log_list_fails_validation() {
        let (leaf, issuer) = load_leaf_and_issuer();

        // no known logs = can't verify any SCTs
        let empty_log_list = CtLogList {
            logs: HashMap::new(),
            log_list_timestamp: VALIDATION_TIME,
        };
        let validator = SctValidator::new(empty_log_list);

        let result = validator.validate_embedded_scts(&leaf, &issuer, VALIDATION_TIME);

        assert!(
            matches!(result, Err(SctError::Policy(PolicyError::NoSCTsFromCompliantLog))),
            "expected policy error for empty log list, got: {result:?}"
        );
    }
}
