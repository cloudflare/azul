// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Configuration for [`witness_worker`](../witness_worker/).
//!
//! A [`c2sp.org/tlog-witness`][spec] witness is configured with a list of
//! logs it trusts. Each entry gives the log's origin (the first line of its
//! checkpoint notes) and one or more SPKI-encoded public keys that the witness
//! will accept signatures from on an incoming checkpoint.
//!
//! The witness's own signing key is supplied out-of-band as a secret named
//! `WITNESS_SIGNING_KEY` (see the worker's `.dev.vars` in dev mode; use
//! `wrangler secret put WITNESS_SIGNING_KEY` for real deployments).
//!
//! [spec]: https://c2sp.org/tlog-witness

use ed25519_dalek::pkcs8::DecodePublicKey as _;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use serde::Deserialize;
use serde_with::{base64::Base64, serde_as};
use signed_note::{Ed25519NoteVerifier, KeyName, NoteVerifier};
use std::collections::{BTreeSet, HashMap};

/// Top-level worker configuration, deserialized from `config.<env>.json`.
#[derive(Deserialize, Debug)]
pub struct AppConfig {
    pub logging_level: Option<String>,
    /// The witness's own identity. The name appears in every cosignature line
    /// the witness produces.
    pub witness_name: String,
    /// Human-readable description for operator dashboards.
    pub description: Option<String>,
    /// URL prefix for write APIs (`add-checkpoint`). Published in the
    /// `/metadata` response so clients know where to send requests.
    pub submission_prefix: String,
    /// URL prefix for read APIs. Currently unused by the tlog-witness spec
    /// but reserved for future monitor-facing endpoints. Published in
    /// `/metadata` alongside `submission_prefix`; `None` means "same as
    /// `submission_prefix`".
    pub monitoring_prefix: Option<String>,
    /// Logs the witness is configured to cosign, keyed by the log's
    /// `origin` line — the first line of a checkpoint note, and the stable
    /// public identifier of the log. Using `origin` directly as the map
    /// key makes uniqueness an invariant of the JSON shape itself (a
    /// duplicate entry is a duplicate JSON object key, which the
    /// deserializer rejects), so the worker doesn't need a runtime
    /// duplicate-origin check.
    pub logs: HashMap<String, LogParams>,
}

impl AppConfig {
    /// Validate the configuration beyond what `serde` and the JSON schema
    /// can express.
    ///
    /// Specifically, this checks:
    ///
    /// 1. `witness_name` is a valid signed-note key name (per
    ///    [c2sp.org/signed-note][note]: non-empty, no whitespace, no `+`).
    /// 2. Every log `origin` (i.e. every key in [`Self::logs`]) is a valid
    ///    signed-note key name.
    /// 3. Every entry in `log_public_keys` is a parseable Ed25519 SPKI.
    /// 4. Within a single log entry, no two `log_public_keys` collide on
    ///    `(name, key_id)` — a `key_id` is a 32-bit hash so a collision is
    ///    cosmically unlikely, but if one occurred the witness could not
    ///    disambiguate signatures and every checkpoint for that log would
    ///    fail to verify.
    ///
    /// Origin uniqueness across log entries is *not* checked here because
    /// it is already enforced by the JSON object shape: duplicate keys in
    /// `logs` are duplicate JSON object keys, which `serde_json` rejects
    /// at deserialization time.
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
        // (1) witness_name is a valid signed-note key name.
        KeyName::new(self.witness_name.clone()).map_err(|e| {
            format!(
                "witness_name {:?} is not a valid signed-note key name: {e:?}",
                self.witness_name,
            )
        })?;

        // (2-4) per-log validation.
        for (origin, log) in &self.logs {
            log.validate(origin)?;
        }

        Ok(())
    }
}

/// Per-log parameters: the public keys the witness is willing to accept
/// checkpoint signatures from. The log's `origin` is the key in the parent
/// [`AppConfig::logs`] map and is not stored here.
#[serde_as]
#[derive(Deserialize, Debug)]
pub struct LogParams {
    /// Optional free-text description.
    pub description: Option<String>,
    /// One or more DER-encoded `SubjectPublicKeyInfo` blobs for keys that may
    /// sign checkpoints for this log. The witness verifies incoming
    /// checkpoints against this list and ignores signatures from other keys.
    /// Typically one entry, but multiple are permitted for key rotation.
    #[serde_as(as = "Vec<Base64>")]
    pub log_public_keys: Vec<Vec<u8>>,
}

impl LogParams {
    /// Validate this log's `origin` and `log_public_keys`. Called by
    /// [`AppConfig::validate`] for each entry; takes the origin (which
    /// lives in the parent map) as an argument.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error string. See [`AppConfig::validate`]
    /// for the list of conditions checked.
    pub fn validate(&self, origin: &str) -> Result<(), String> {
        // Origin must be a valid signed-note key name.
        let origin_name = KeyName::new(origin.to_owned()).map_err(|e| {
            format!("log {origin:?}: origin is not a valid signed-note key name: {e:?}")
        })?;

        // Every log_public_keys entry must be a parseable Ed25519 SPKI,
        // and the (name, key_id) pairs derived from them must be unique
        // within this log.
        let mut seen_ids: BTreeSet<u32> = BTreeSet::new();
        for (i, spki) in self.log_public_keys.iter().enumerate() {
            let vk = Ed25519VerifyingKey::from_public_key_der(spki).map_err(|e| {
                format!("log {origin:?}: log_public_keys[{i}] is not a valid Ed25519 SPKI: {e}")
            })?;
            let v = Ed25519NoteVerifier::new(origin_name.clone(), vk);
            if !seen_ids.insert(v.key_id()) {
                return Err(format!(
                    "log {origin:?}: log_public_keys[{i}] shares a (name, key_id) pair with an \
                     earlier key; witness would be unable to disambiguate signatures from it",
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a real Ed25519 SPKI deterministically from a seed byte.
    fn spki_for(seed: u8) -> Vec<u8> {
        use ed25519_dalek::pkcs8::EncodePublicKey as _;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        sk.verifying_key().to_public_key_der().unwrap().to_vec()
    }

    fn good_app_config() -> AppConfig {
        AppConfig {
            logging_level: None,
            witness_name: "witness.example/w".to_owned(),
            description: None,
            submission_prefix: "https://witness.example/".to_owned(),
            monitoring_prefix: None,
            logs: HashMap::from([(
                "example.com/log1".to_owned(),
                LogParams {
                    description: None,
                    log_public_keys: vec![spki_for(1)],
                },
            )]),
        }
    }

    /// Helper: construct a fresh single-log config and let the caller mutate.
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
    fn validate_rejects_empty_witness_name() {
        let mut cfg = good_app_config();
        cfg.witness_name = String::new();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("witness_name"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_witness_name_with_plus() {
        let mut cfg = good_app_config();
        cfg.witness_name = "witness+example".to_owned();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("witness_name"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_witness_name_with_ascii_whitespace() {
        let mut cfg = good_app_config();
        cfg.witness_name = "witness example".to_owned();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("witness_name"), "unexpected error: {err}");
    }

    /// `KeyName::new` rejects via `char::is_whitespace`, which covers
    /// Unicode whitespace beyond the ASCII set that JSON Schema's `\s`
    /// pattern catches. Pin this so the schema regex and the runtime
    /// constructor stay in agreement.
    #[test]
    fn validate_rejects_witness_name_with_unicode_whitespace() {
        let mut cfg = good_app_config();
        cfg.witness_name = "witness\u{00a0}name".to_owned(); // U+00A0 NBSP
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("witness_name"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_empty_origin() {
        let mut cfg = good_app_config();
        let log = cfg.logs.drain().next().unwrap().1;
        cfg.logs.insert(String::new(), log);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("origin") && err.contains("\"\""),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn validate_rejects_origin_with_plus() {
        let mut cfg = good_app_config();
        let log = cfg.logs.drain().next().unwrap().1;
        cfg.logs.insert("example.com/with+plus".to_owned(), log);
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("origin"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_origin_with_unicode_whitespace() {
        let mut cfg = good_app_config();
        let log = cfg.logs.drain().next().unwrap().1;
        cfg.logs.insert("example.com\u{00a0}log1".to_owned(), log);
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("origin"), "unexpected error: {err}");
    }

    #[test]
    fn validate_rejects_invalid_spki() {
        let cfg = with_log(|log| log.log_public_keys = vec![b"not-der".to_vec()]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("log_public_keys[0]") && err.contains("Ed25519 SPKI"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn validate_accepts_multiple_distinct_keys() {
        let cfg = with_log(|log| log.log_public_keys = vec![spki_for(1), spki_for(2)]);
        cfg.validate().expect("two distinct Ed25519 keys are valid");
    }

    /// Re-using the same SPKI in `log_public_keys` produces an identical
    /// `(name, key_id)` and so trips the collision check. This is a
    /// realistic operator misconfiguration (paste-twice during key
    /// rotation), distinct from the cosmically-rare 32-bit `key_id` hash
    /// collision.
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
    fn validate_includes_origin_in_per_log_errors() {
        let cfg = with_log(|log| log.log_public_keys = vec![b"junk".to_vec()]);
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("example.com/log1"),
            "error should reference the failing origin: {err}",
        );
    }
}
