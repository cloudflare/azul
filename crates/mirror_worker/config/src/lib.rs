// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Configuration for [`mirror_worker`](../mirror_worker/).
//!
//! This mirror implements [`c2sp.org/tlog-mirror`][mirror] specialized for
//! [Merkle Tree Certificate][mtc] issuance logs: it mirrors the tiled logs
//! a CA publishes under a single CA cosigner key. It is configured with
//! the CAs it mirrors, keyed by `log_key_name`: the CA cosigner's
//! note-signature name, which is the CA ID (e.g. `oid/1.3.6.1.4.1.32473.2`)
//! and appears on every checkpoint the mirror ingests via
//! [`add-checkpoint`][add-cp]. Each entry gives one or more ML-DSA-44 SPKI
//! public keys the mirror accepts `subtree/v1` checkpoint signatures from.
//!
//! A CA cosigner name is distinct from the log origin: one CA cosigner key
//! covers a whole series of issuance logs, so each entry carries a required
//! `min_log_number`/`max_log_number` window. The mirror serves each log
//! number `N` in that window as its own origin `<log_key_name>.0.<N>` (per
//! [mtc-tlog][mtc], the `.0.` arc is fixed), all verified with this entry's
//! key(s).
//!
//! [mtc]: https://c2sp.org/mtc-tlog
//!
//! The mirror's own ML-DSA-44 signing key (used to produce its `subtree/v1`
//! mirror cosignature) is supplied out-of-band as a secret named
//! `MIRROR_SIGNING_KEY` (see the worker's `.dev.vars` in dev mode; use
//! `wrangler secret put MIRROR_SIGNING_KEY` for real deployments).
//!
//! [mirror]: https://c2sp.org/tlog-mirror
//! [add-cp]: https://c2sp.org/tlog-mirror#add-checkpoint

use ml_dsa::pkcs8::DecodePublicKey as _;
use ml_dsa::{MlDsa44, VerifyingKey as MlDsaVerifyingKey};
use serde::Deserialize;
use serde_with::{base64::Base64, serde_as};
use signed_note::{KeyName, NoteVerifier};
use std::collections::{BTreeSet, HashMap};
use tlog_cosignature::SubtreeV1NoteVerifier;

/// Top-level worker configuration, deserialized from `config.<env>.json`.
#[derive(Deserialize, Debug)]
pub struct AppConfig {
    pub logging_level: Option<String>,
    /// The mirror's own identity. The name appears in every cosignature
    /// line the mirror produces (and, on `/metadata`, the published
    /// mirror identity).
    pub mirror_name: String,
    /// Human-readable description for operator dashboards.
    pub description: Option<String>,
    /// URL prefix for write APIs (`add-checkpoint`, `add-entries`).
    /// Published in the `/metadata` response so clients know where to
    /// send requests.
    pub submission_prefix: String,
    /// URL prefix for read APIs (the [tlog-tiles][tiles] read interface
    /// served at `<monitoring_prefix>/<encoded origin>/...`). `None`
    /// means "same as `submission_prefix`".
    ///
    /// [tiles]: https://c2sp.org/tlog-tiles
    pub monitoring_prefix: Option<String>,
    /// How often (in seconds) the per-origin partial-tile cleaner wakes
    /// to clean orphaned partial tiles from object storage. `None` falls
    /// back to a one-hour default (see [`Self::clean_interval_secs`]).
    /// Consumed by [`mirror_worker`](../mirror_worker/)'s `cleaner_do`.
    pub clean_interval_secs: Option<u64>,
    /// CAs this mirror mirrors, keyed by `log_key_name`: the CA
    /// cosigner's note-signature name (the CA ID) carried by the
    /// checkpoints it ingests.
    #[serde(deserialize_with = "deserialize_logs")]
    pub logs: HashMap<String, LogParams>,
}

/// Deserialize [`AppConfig::logs`], rejecting duplicate `log_key_name`
/// keys. `serde_json` collapses a repeated object key onto one entry,
/// silently keeping the last value; for this config that would drop a
/// trusted CA (its keys and log-number window) without any error, so we
/// fail closed. The config is expected to be machine-generated, where a
/// generator or merge bug is a plausible source of duplicates.
fn deserialize_logs<'de, D>(deserializer: D) -> Result<HashMap<String, LogParams>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct LogsVisitor;

    impl<'de> serde::de::Visitor<'de> for LogsVisitor {
        type Value = HashMap<String, LogParams>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map of log_key_name to log parameters")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut logs = HashMap::with_capacity(access.size_hint().unwrap_or(0));
            while let Some((name, params)) = access.next_entry::<String, LogParams>()? {
                if logs.contains_key(&name) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate log_key_name {name:?} in logs"
                    )));
                }
                logs.insert(name, params);
            }
            Ok(logs)
        }
    }

    deserializer.deserialize_map(LogsVisitor)
}

impl AppConfig {
    /// The partial-tile cleaner's wake interval, in seconds, falling back
    /// to a one-hour default when the `clean_interval_secs` field is
    /// unset. An hour bounds how long an orphaned partial tile lingers
    /// without making the cleaner's periodic R2 listing a meaningful cost.
    #[must_use]
    pub fn clean_interval_secs(&self) -> u64 {
        self.clean_interval_secs.unwrap_or(3600)
    }

    /// Validate the configuration beyond what `serde` and the JSON schema
    /// can express.
    ///
    /// Specifically, this checks:
    ///
    /// 1. `mirror_name` is a valid signed-note key name (per
    ///    [c2sp.org/signed-note][note]: non-empty, no whitespace, no `+`).
    /// 2. Every `log_key_name` (i.e. every key in [`Self::logs`]) is a
    ///    valid signed-note key name.
    /// 3. Every entry in `log_public_keys` is a parseable ML-DSA-44 SPKI.
    /// 4. Within a single log entry, no two `log_public_keys` collide on
    ///    `(name, key_id)`. A `key_id` is a 32-bit hash, so a collision is
    ///    cosmically unlikely, but if one occurred the mirror could not
    ///    disambiguate signatures and every checkpoint for that log would
    ///    fail to verify.
    /// 5. `min_log_number` and `max_log_number` both lie in
    ///    `1..=`[`MAX_MTC_LOG_NUMBER`], `max_log_number >= min_log_number`,
    ///    and the window spans at most [`MAX_LOG_NUMBER_WINDOW`] log
    ///    numbers.
    /// 6. The longest origin from [`LogParams::origins`] still fits the
    ///    signed-note key name length cap, since each origin is itself
    ///    used as a checkpoint origin.
    ///
    /// `log_key_name` uniqueness across log entries is not checked here;
    /// it is enforced earlier, during deserialization (see
    /// [`deserialize_logs`]). A plain `serde_json` object silently keeps
    /// only the last value for a repeated key, so without that check a
    /// duplicate `log_key_name` would drop a trusted CA (its keys and
    /// log-number window) with no error.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error string identifying the failing
    /// field and reason. The error is intended for operator consumption
    /// (build-script panic messages, deployment-time logging) and is not
    /// machine-parseable.
    ///
    /// [note]: https://c2sp.org/signed-note
    pub fn validate(&self) -> Result<(), String> {
        KeyName::new(self.mirror_name.clone()).map_err(|e| {
            format!(
                "mirror_name {:?} is not a valid signed-note key name: {e:?}",
                self.mirror_name,
            )
        })?;

        for (log_key_name, log) in &self.logs {
            log.validate(log_key_name)?;
        }

        Ok(())
    }
}

/// Upper bound on the number of MTC log numbers a single `logs` entry's
/// `[min_log_number, max_log_number]` window may span.
///
/// Each log number expands into its own checkpoint origin, Merkle tree,
/// storage prefix, and Durable Object instance, so an accidentally huge
/// window (e.g. a mistyped `max_log_number`) would balloon the origin set
/// the worker tracks. Real deployments use a small window, so this
/// generous cap only ever trips on operator error.
pub const MAX_LOG_NUMBER_WINDOW: u64 = 1024;

/// The largest valid MTC log number.
///
/// Per [Merkle Tree Certificates, Section 5.2][mtc], a CA's issuance logs
/// are numbered consecutively from 1 to at most 65535 (2^16 - 1), so valid
/// log numbers are `1..=MAX_MTC_LOG_NUMBER`.
///
/// [mtc]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-05.html#section-5.2
pub const MAX_MTC_LOG_NUMBER: u64 = 65535;

/// Per-CA parameters: the public keys the mirror accepts checkpoint
/// signatures from, plus the MTC log-number window this CA cosigner
/// covers. The `log_key_name` (the CA cosigner's note-signature name) is
/// the key in the parent [`AppConfig::logs`] map and is not stored here.
#[serde_as]
#[derive(Deserialize, Debug)]
pub struct LogParams {
    /// Optional free-text description.
    pub description: Option<String>,
    /// One or more DER-encoded `SubjectPublicKeyInfo` blobs for the
    /// ML-DSA-44 keys that may sign checkpoints for this log. The mirror
    /// verifies incoming pending checkpoints against this list (as
    /// `subtree/v1` cosignatures) and ignores signatures from other keys.
    /// Typically one entry, but multiple are permitted for key rotation.
    #[serde_as(as = "Vec<Base64>")]
    pub log_public_keys: Vec<Vec<u8>>,
    /// Lowest accepted MTC log number. The mirror serves a distinct log at
    /// each origin `<log_key_name>.0.<N>` for `N` in `[min_log_number,
    /// max_log_number]`, all verified with this entry's key(s).
    ///
    /// This MUST be `>= 1`; log number 0 does not exist (see
    /// [`MAX_MTC_LOG_NUMBER`]).
    pub min_log_number: u64,
    /// Highest accepted MTC log number (inclusive). See
    /// [`Self::min_log_number`]; this MUST be `>= min_log_number` and
    /// `<= `[`MAX_MTC_LOG_NUMBER`].
    pub max_log_number: u64,
}

impl LogParams {
    /// The concrete checkpoint origins this entry serves:
    /// `<log_key_name>.0.<N>` for each log number `N` in the inclusive
    /// `[min_log_number, max_log_number]` window.
    ///
    /// Assumes the entry has passed [`Self::validate`], so the window is
    /// well-formed.
    #[must_use]
    pub fn origins(&self, log_key_name: &str) -> Vec<String> {
        (self.min_log_number..=self.max_log_number)
            .map(|n| format!("{log_key_name}.0.{n}"))
            .collect()
    }
}

impl LogParams {
    /// Validate this log's `log_key_name`, `log_public_keys`, and
    /// log-number window. Called by [`AppConfig::validate`] for each
    /// entry; takes the `log_key_name` (which lives in the parent map) as
    /// an argument.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error string. See [`AppConfig::validate`]
    /// for the list of conditions checked.
    pub fn validate(&self, log_key_name: &str) -> Result<(), String> {
        let key_name = KeyName::new(log_key_name.to_owned()).map_err(|e| {
            format!("log {log_key_name:?}: log_key_name is not a valid signed-note key name: {e:?}")
        })?;

        // The log-number window must be in range and ordered. MTC log
        // numbers are numbered consecutively from 1 to MAX_MTC_LOG_NUMBER;
        // log number 0 does not exist.
        let (min, max) = (self.min_log_number, self.max_log_number);
        if min < 1 {
            return Err(format!(
                "log {log_key_name:?}: min_log_number is 0, but MTC log numbers start at 1",
            ));
        }
        if max > MAX_MTC_LOG_NUMBER {
            return Err(format!(
                "log {log_key_name:?}: max_log_number ({max}) exceeds the maximum MTC log \
                 number ({MAX_MTC_LOG_NUMBER})",
            ));
        }
        if min > max {
            return Err(format!(
                "log {log_key_name:?}: min_log_number ({min}) must be <= max_log_number ({max})",
            ));
        }
        // `max - min` cannot overflow: `min <= max` was just checked.
        if max - min >= MAX_LOG_NUMBER_WINDOW {
            return Err(format!(
                "log {log_key_name:?}: log-number window [{min}, {max}] spans more than \
                 {MAX_LOG_NUMBER_WINDOW} log numbers; refusing to expand it into that many \
                 origins (likely a typo)",
            ));
        }

        // Each origin from `origins()` is itself used as a signed-note key
        // name (the checkpoint origin), so it must fit KeyName's length
        // cap even though log_key_name alone already passed. The longest
        // origin appends ".0.<max_log_number>".
        let longest_origin = format!("{log_key_name}.0.{max}");
        if longest_origin.len() > KeyName::MAX_LEN {
            return Err(format!(
                "log {log_key_name:?}: its longest origin {longest_origin:?} is \
                 {} bytes, over the {}-byte signed-note key name limit; shorten log_key_name",
                longest_origin.len(),
                KeyName::MAX_LEN,
            ));
        }

        // Every log_public_keys entry must be a parseable ML-DSA-44 SPKI,
        // and the (name, key_id) pairs derived from them must be unique
        // within this log.
        let mut seen_ids: BTreeSet<u32> = BTreeSet::new();
        for (i, spki) in self.log_public_keys.iter().enumerate() {
            let vk = MlDsaVerifyingKey::<MlDsa44>::from_public_key_der(spki).map_err(|e| {
                format!(
                    "log {log_key_name:?}: log_public_keys[{i}] is not a valid ML-DSA-44 SPKI: {e}"
                )
            })?;
            let v = SubtreeV1NoteVerifier::new(key_name.clone(), vk);
            if !seen_ids.insert(v.key_id()) {
                return Err(format!(
                    "log {log_key_name:?}: log_public_keys[{i}] shares a (name, key_id) pair with \
                     an earlier key; mirror would be unable to disambiguate signatures from it",
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a real ML-DSA-44 SPKI deterministically from a seed byte.
    fn spki_for(seed: u8) -> Vec<u8> {
        use ml_dsa::pkcs8::EncodePublicKey as _;
        use ml_dsa::{Keypair as _, SigningKey};
        let sk = SigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from([seed; 32]));
        sk.verifying_key().to_public_key_der().unwrap().to_vec()
    }

    fn good_app_config() -> AppConfig {
        AppConfig {
            logging_level: None,
            mirror_name: "mirror.example/m".to_owned(),
            description: None,
            submission_prefix: "https://mirror.example/".to_owned(),
            monitoring_prefix: None,
            clean_interval_secs: None,
            logs: HashMap::from([(
                "example.com/log1".to_owned(),
                LogParams {
                    description: None,
                    log_public_keys: vec![spki_for(1)],
                    min_log_number: 1,
                    max_log_number: 1,
                },
            )]),
        }
    }

    /// Helper: construct a fresh single-log config and let the caller
    /// mutate.
    fn with_log<F: FnOnce(&mut LogParams)>(f: F) -> AppConfig {
        let mut cfg = good_app_config();
        let log = cfg.logs.values_mut().next().unwrap();
        f(log);
        cfg
    }

    #[test]
    fn validate_accepts_minimal_good_config() {
        good_app_config()
            .validate()
            .expect("known-good config validates");
    }

    #[test]
    fn validate_rejects_empty_mirror_name() {
        let mut cfg = good_app_config();
        cfg.mirror_name = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("mirror_name"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_mirror_name_with_plus() {
        let mut cfg = good_app_config();
        cfg.mirror_name = "mirror+example".to_owned();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("mirror_name"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_mirror_name_with_ascii_whitespace() {
        let mut cfg = good_app_config();
        cfg.mirror_name = "mirror example".to_owned();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("mirror_name"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_mirror_name_with_unicode_whitespace() {
        let mut cfg = good_app_config();
        cfg.mirror_name = "mirror\u{00a0}name".to_owned(); // U+00A0 NBSP
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("mirror_name"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_empty_log_key_name() {
        let mut cfg = good_app_config();
        let log = cfg.logs.drain().next().unwrap().1;
        cfg.logs.insert(String::new(), log);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("log_key_name") && err.contains("\"\""),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn validate_rejects_log_key_name_with_plus() {
        let mut cfg = good_app_config();
        let log = cfg.logs.drain().next().unwrap().1;
        cfg.logs.insert("example.com/with+plus".to_owned(), log);
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("log_key_name"), "unexpected error: {err}");
    }

    #[test]
    fn deserialize_rejects_duplicate_log_key_name() {
        let json = r#"{
            "mirror_name": "mirror.example/m",
            "submission_prefix": "https://mirror.example/",
            "logs": {
                "example.com/log1": {"log_public_keys": [], "min_log_number": 1, "max_log_number": 1},
                "example.com/log1": {"log_public_keys": [], "min_log_number": 2, "max_log_number": 2}
            }
        }"#;
        let err = serde_json::from_str::<AppConfig>(json)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("duplicate log_key_name"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn deserialize_accepts_distinct_log_key_names() {
        let json = r#"{
            "mirror_name": "mirror.example/m",
            "submission_prefix": "https://mirror.example/",
            "logs": {
                "example.com/log1": {"log_public_keys": [], "min_log_number": 1, "max_log_number": 1},
                "example.com/log2": {"log_public_keys": [], "min_log_number": 2, "max_log_number": 2}
            }
        }"#;
        let cfg = serde_json::from_str::<AppConfig>(json).expect("distinct keys deserialize");
        assert_eq!(cfg.logs.len(), 2);
    }

    #[test]
    fn validate_accepts_log_number_window() {
        let cfg = with_log(|log| {
            log.min_log_number = 40;
            log.max_log_number = 45;
        });
        cfg.validate()
            .expect("a valid log-number window is accepted");
    }

    #[test]
    fn validate_rejects_inverted_window() {
        let cfg = with_log(|log| {
            log.min_log_number = 45;
            log.max_log_number = 40;
        });
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("must be <="), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_log_number_zero() {
        // MTC log numbers start at 1; log number 0 does not exist.
        let cfg = with_log(|log| {
            log.min_log_number = 0;
            log.max_log_number = 5;
        });
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("start at 1"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_log_number_above_maximum() {
        let cfg = with_log(|log| {
            log.min_log_number = 1;
            log.max_log_number = MAX_MTC_LOG_NUMBER + 1;
        });
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("exceeds the maximum MTC log number"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn validate_accepts_window_at_the_cap() {
        // Exactly MAX_LOG_NUMBER_WINDOW log numbers ([1, CAP]) is allowed.
        let cfg = with_log(|log| {
            log.min_log_number = 1;
            log.max_log_number = MAX_LOG_NUMBER_WINDOW;
        });
        cfg.validate()
            .expect("a window spanning exactly the cap is accepted");
    }

    #[test]
    fn validate_rejects_oversized_window() {
        // One past the cap ([1, CAP+1], i.e. CAP+1 numbers) is rejected.
        let cfg = with_log(|log| {
            log.min_log_number = 1;
            log.max_log_number = MAX_LOG_NUMBER_WINDOW + 1;
        });
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("spans more than"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_origin_exceeding_key_name_limit() {
        // A log_key_name that is a valid KeyName on its own (<= 255 bytes),
        // but whose ".0.<log number>" origin pushes past the limit. The
        // window stays within the span cap while keeping a 5-digit max.
        let cfg = AppConfig {
            logging_level: None,
            mirror_name: "mirror.example/m".to_owned(),
            description: None,
            submission_prefix: "https://mirror.example/".to_owned(),
            monitoring_prefix: None,
            clean_interval_secs: None,
            logs: HashMap::from([(
                "a".repeat(250),
                LogParams {
                    description: None,
                    log_public_keys: vec![spki_for(1)],
                    min_log_number: 64512,
                    max_log_number: 65535,
                },
            )]),
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("longest origin") && err.contains("limit"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn origins_with_window_expands_to_mtc_log_ids() {
        let log = LogParams {
            description: None,
            log_public_keys: vec![spki_for(1)],
            min_log_number: 40,
            max_log_number: 42,
        };
        assert_eq!(
            log.origins("oid/1.3.6.1.4.1.32473.2"),
            vec![
                "oid/1.3.6.1.4.1.32473.2.0.40",
                "oid/1.3.6.1.4.1.32473.2.0.41",
                "oid/1.3.6.1.4.1.32473.2.0.42",
            ],
        );
    }

    #[test]
    fn validate_rejects_invalid_spki() {
        let cfg = with_log(|log| log.log_public_keys = vec![b"not-der".to_vec()]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("log_public_keys[0]") && err.contains("ML-DSA-44 SPKI"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn validate_accepts_multiple_distinct_keys() {
        let cfg = with_log(|log| log.log_public_keys = vec![spki_for(1), spki_for(2)]);
        cfg.validate()
            .expect("two distinct ML-DSA-44 keys are valid");
    }

    #[test]
    fn validate_rejects_duplicate_keys_within_log() {
        let cfg = with_log(|log| log.log_public_keys = vec![spki_for(1), spki_for(1)]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("log_public_keys[1]") && err.contains("(name, key_id)"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn validate_includes_log_key_name_in_per_log_errors() {
        let cfg = with_log(|log| log.log_public_keys = vec![b"junk".to_vec()]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("example.com/log1"),
            "error should reference the failing log_key_name: {err}",
        );
    }
}
