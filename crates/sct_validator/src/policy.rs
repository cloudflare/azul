// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Chrome CT policy. See <https://googlechrome.github.io/CertificateTransparency/ct_policy.html>

use crate::error::PolicyError;
use crate::{CtLog, LogState};
use hashbrown::HashSet;

/// Certificate lifetime threshold in days.
/// Certificates with lifetime <= 180 days need 2 SCTs.
/// Certificates with lifetime > 180 days need 3 SCTs.
const CERT_LIFETIME_THRESHOLD_DAYS: u64 = 180;

/// Minimum unique logs required for certs with lifetime <= 180 days.
const MIN_UNIQUE_LOGS_SHORT_LIVED: usize = 2;

/// Minimum unique logs required for certs with lifetime > 180 days.
const MIN_UNIQUE_LOGS_LONG_LIVED: usize = 3;

/// Minimum unique log operators required (regardless of lifetime).
const MIN_UNIQUE_OPERATORS: usize = 2;

/// A validated SCT with its associated log.
#[derive(Debug)]
pub struct ValidatedSct<'a> {
    /// Unix timestamp in seconds when the SCT was issued.
    pub timestamp_secs: u64,
    /// The log that signed this SCT.
    pub log: &'a CtLog,
}

/// Checks if SCTs satisfy Chrome's policy. Skips SCTs from logs retired before signing.
pub fn check_chrome_policy(
    cert_lifetime_days: u64,
    validated_scts: &[ValidatedSct],
) -> Result<(), PolicyError> {
    // Track unique operators (by name at SCT signing time)
    let mut log_operators: HashSet<&str> = HashSet::new();
    // Track unique log IDs
    let mut log_ids: HashSet<[u8; 32]> = HashSet::new();
    // Count of SCTs from compliant logs
    let mut compliant_log_count = 0;
    // Count of SCTs from non-retired logs at signing time
    let mut scts_from_valid_logs = 0;

    for sct in validated_scts {
        // Skip if the log was retired before this SCT was issued
        if sct.log.was_retired_before(sct.timestamp_secs) {
            continue;
        }

        scts_from_valid_logs += 1;

        // Check current log state for compliance
        match sct.log.state {
            LogState::Qualified | LogState::Usable | LogState::ReadOnly => {
                compliant_log_count += 1;
            }
            _ => {}
        }

        // For uniqueness tracking, include Retired logs (they still count for diversity)
        match sct.log.state {
            LogState::Qualified | LogState::Usable | LogState::ReadOnly | LogState::Retired => {
                // The operator at SCT signing time matters for uniqueness
                // (logs can change operators over time)
                let operator = sct.log.operator_at(sct.timestamp_secs);
                log_operators.insert(operator);
                log_ids.insert(sct.log.id);
            }
            _ => {}
        }
    }

    // Determine minimum required unique logs based on certificate lifetime
    let min_unique_logs = if cert_lifetime_days <= CERT_LIFETIME_THRESHOLD_DAYS {
        MIN_UNIQUE_LOGS_SHORT_LIVED
    } else {
        MIN_UNIQUE_LOGS_LONG_LIVED
    };

    // Check: At least 1 compliant SCT required
    if compliant_log_count == 0 {
        return Err(PolicyError::NoSCTsFromCompliantLog);
    }

    // Check: Enough SCTs from valid (non-retired-before-signing) logs
    if scts_from_valid_logs < min_unique_logs {
        return Err(PolicyError::NotEnoughCompliantSCTs {
            found: scts_from_valid_logs,
            required: min_unique_logs,
        });
    }

    // Check: Enough unique logs
    if log_ids.len() < min_unique_logs {
        return Err(PolicyError::NotEnoughUniqueLogs {
            found: log_ids.len(),
            required: min_unique_logs,
        });
    }

    // Check: Enough unique operators
    if log_operators.len() < MIN_UNIQUE_OPERATORS {
        return Err(PolicyError::NotEnoughUniqueOperators {
            found: log_operators.len(),
            required: MIN_UNIQUE_OPERATORS,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a test log
    fn make_test_log(
        id: [u8; 32],
        operator: &str,
        state: LogState,
        state_entered_at: u64,
    ) -> CtLog {
        // Use a dummy P256 key for testing
        // This is a valid P256 public key point (not for production use)
        let dummy_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&[
            0x04, // Uncompressed point marker
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7,
            0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
            0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ])
        .unwrap();

        CtLog {
            description: "test log".to_string(),
            id,
            key: dummy_key,
            state,
            state_entered_at,
            current_operator: operator.to_string(),
            previous_operators: vec![],
        }
    }

    #[test]
    fn test_short_lived_cert_needs_two_logs() {
        let log1 = make_test_log([1u8; 32], "Google", LogState::Usable, 0);
        let log2 = make_test_log([2u8; 32], "Let's Encrypt", LogState::Usable, 0);

        let one_sct = vec![ValidatedSct {
            timestamp_secs: 1000,
            log: &log1,
        }];

        let two_scts = vec![
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log1,
            },
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log2,
            },
        ];

        // Lifetime <= 180 days: needs 2 unique logs
        let lifetime = 180;

        // One SCT should fail
        let result = check_chrome_policy(lifetime, &one_sct);
        assert!(matches!(
            result,
            Err(PolicyError::NotEnoughCompliantSCTs { .. })
        ));

        // Two SCTs from different logs/operators should pass
        let result = check_chrome_policy(lifetime, &two_scts);
        assert!(result.is_ok());
    }

    #[test]
    fn test_long_lived_cert_needs_three_logs() {
        let log1 = make_test_log([1u8; 32], "Google", LogState::Usable, 0);
        let log2 = make_test_log([2u8; 32], "Let's Encrypt", LogState::Usable, 0);
        let log3 = make_test_log([3u8; 32], "Cloudflare", LogState::Usable, 0);

        let two_scts = vec![
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log1,
            },
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log2,
            },
        ];

        let three_scts = vec![
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log1,
            },
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log2,
            },
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log3,
            },
        ];

        // Lifetime > 180 days: needs 3 unique logs
        let lifetime = 181;

        // Two SCTs should fail
        let result = check_chrome_policy(lifetime, &two_scts);
        assert!(matches!(
            result,
            Err(PolicyError::NotEnoughCompliantSCTs { .. })
        ));

        // Three SCTs should pass
        let result = check_chrome_policy(lifetime, &three_scts);
        assert!(result.is_ok());
    }

    #[test]
    fn test_requires_two_operators() {
        let log1 = make_test_log([1u8; 32], "Google", LogState::Usable, 0);
        let log2 = make_test_log([2u8; 32], "Google", LogState::Usable, 0); // Same operator

        let same_operator = vec![
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log1,
            },
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log2,
            },
        ];

        let lifetime = 180;

        // Same operator should fail
        let result = check_chrome_policy(lifetime, &same_operator);
        assert!(matches!(
            result,
            Err(PolicyError::NotEnoughUniqueOperators { .. })
        ));
    }

    #[test]
    fn test_duplicate_logs_dont_count() {
        let log1 = make_test_log([1u8; 32], "Google", LogState::Usable, 0);
        let log2 = make_test_log([2u8; 32], "Let's Encrypt", LogState::Usable, 0);

        // Two SCTs from the same log
        let duplicate_logs = vec![
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log1,
            },
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log1, // Same log
            },
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log2,
            },
        ];

        let lifetime = 181; // Needs 3 unique logs

        // Should fail because only 2 unique logs
        let result = check_chrome_policy(lifetime, &duplicate_logs);
        assert!(matches!(
            result,
            Err(PolicyError::NotEnoughUniqueLogs { .. })
        ));
    }

    #[test]
    fn test_retired_log_skipped_if_retired_before_sct() {
        let log1 = make_test_log([1u8; 32], "Google", LogState::Retired, 500);
        let log2 = make_test_log([2u8; 32], "Let's Encrypt", LogState::Usable, 0);

        // SCT issued at 1000, but log1 was retired at 500
        let scts = vec![
            ValidatedSct {
                timestamp_secs: 1000, // After retirement
                log: &log1,
            },
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log2,
            },
        ];

        let lifetime = 180;

        // Should fail because log1's SCT is skipped (retired before SCT)
        let result = check_chrome_policy(lifetime, &scts);
        assert!(matches!(
            result,
            Err(PolicyError::NotEnoughCompliantSCTs { .. })
        ));
    }

    #[test]
    fn test_no_compliant_logs() {
        let log1 = make_test_log([1u8; 32], "Google", LogState::Pending, 0);
        let log2 = make_test_log([2u8; 32], "Let's Encrypt", LogState::Rejected, 0);

        let scts = vec![
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log1,
            },
            ValidatedSct {
                timestamp_secs: 1000,
                log: &log2,
            },
        ];

        let lifetime = 180;

        // Should fail because no Qualified/Usable/ReadOnly logs
        let result = check_chrome_policy(lifetime, &scts);
        assert!(matches!(result, Err(PolicyError::NoSCTsFromCompliantLog)));
    }
}
