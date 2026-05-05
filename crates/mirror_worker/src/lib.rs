// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! A transparency-log mirror implementing [c2sp.org/tlog-mirror][spec] on
//! Cloudflare Workers.
//!
//! The mirror exposes the spec's submission endpoints — currently
//! [`add-checkpoint`][add-cp] (this crate slice) and, in upcoming slices,
//! [`add-entries`][add-e] and the [tlog-tiles][tiles] read interface.
//!
//! Per-origin persistent state — the *pending checkpoint* (the latest
//! signed checkpoint the mirror has accepted but not yet fully ingested
//! entries for) and, eventually, the *mirror checkpoint* (the latest
//! state for which the mirror has cosigned and made entries available) —
//! lives in a [`MirrorState`] Durable Object, one per log origin. The
//! DO's single-threaded execution model provides the atomic
//! "check-old-state, verify, persist-new-state" sequence the spec
//! requires.
//!
//! [spec]: https://c2sp.org/tlog-mirror
//! [add-cp]: https://c2sp.org/tlog-mirror#add-checkpoint
//! [add-e]: https://c2sp.org/tlog-mirror#add-entries
//! [tiles]: https://c2sp.org/tlog-tiles
//! [`MirrorState`]: mirror_state_do::MirrorState

use config::AppConfig;
use signed_note::{Ed25519NoteVerifier, KeyName, NoteVerifier, VerifierList};
use std::collections::HashMap;
use std::sync::LazyLock;

mod frontend_worker;
mod mirror_state_do;

/// The binding name used in `wrangler.jsonc` for the [`MirrorState`] DO.
///
/// [`MirrorState`]: mirror_state_do::MirrorState
pub(crate) const MIRROR_STATE_BINDING: &str = "MIRROR_STATE";

/// The compile-time-embedded worker configuration.
pub(crate) static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("config.json must be valid at build time")
});

/// Per-origin cache of the parsed trusted log keys.
///
/// `build.rs` calls [`AppConfig::validate`] and refuses to compile a
/// mirror with a malformed config, so by the time this static is built
/// every origin and SPKI is known to parse cleanly. The `expect` calls
/// below treat parse failures as `unreachable!` rather than as
/// recoverable errors.
///
/// Values are plain `(KeyName, VerifyingKey)` pairs rather than a
/// pre-built `VerifierList`, because `Box<dyn NoteVerifier>` is not
/// `Sync` and so cannot live inside a `LazyLock`. Building the
/// `VerifierList` per request from these cached keys is cheap
/// (`Ed25519NoteVerifier::new` is just field assignment).
pub(crate) static LOG_KEYS: LazyLock<HashMap<String, Vec<LogKey>>> = LazyLock::new(|| {
    CONFIG
        .logs
        .iter()
        .map(|(origin, log)| (origin.clone(), parse_log_keys(origin, log)))
        .collect()
});

/// A parsed trusted log key.
#[derive(Clone)]
pub(crate) struct LogKey {
    pub origin: KeyName,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

/// Build a list of parsed keys for a single configured log.
///
/// Both fields (origin as a [`KeyName`], each SPKI as an Ed25519
/// `VerifyingKey`) are validated up front by
/// [`config::AppConfig::validate`] in `build.rs`, so the parse calls
/// below are guarded by `expect` rather than recoverable error
/// propagation. A panic here would indicate `validate` and this function
/// have drifted out of sync.
fn parse_log_keys(origin: &str, log: &config::LogParams) -> Vec<LogKey> {
    use ed25519_dalek::pkcs8::DecodePublicKey as _;
    let origin_name = KeyName::new(origin.to_owned())
        .expect("origin validated as a signed-note KeyName by AppConfig::validate");
    log.log_public_keys
        .iter()
        .map(|spki| {
            let verifying_key = ed25519_dalek::VerifyingKey::from_public_key_der(spki)
                .expect("SPKI validated as Ed25519 by AppConfig::validate");
            LogKey {
                origin: origin_name.clone(),
                verifying_key,
            }
        })
        .collect()
}

/// Build a [`VerifierList`] for a given origin from the cached keys, or
/// `None` if no log is configured at that origin.
pub(crate) fn log_verifiers(origin: &str) -> Option<VerifierList> {
    let keys = LOG_KEYS.get(origin)?;
    let verifiers: Vec<Box<dyn NoteVerifier>> = keys
        .iter()
        .map(|k| {
            Box::new(Ed25519NoteVerifier::new(k.origin.clone(), k.verifying_key))
                as Box<dyn NoteVerifier>
        })
        .collect();
    Some(VerifierList::new(verifiers))
}

#[cfg(test)]
mod dev_config_tests {
    //! Tests that pin invariants between `config.dev.json` and the
    //! integration-test fixtures that mirror it.
    //!
    //! If either of these tests fails, the dev keypair embedded in
    //! `crates/integration_tests/` and the SPKI in
    //! `crates/mirror_worker/config.dev.json` have drifted out of sync;
    //! rotate both together. The dev mirror reuses the same Ed25519 log
    //! keypair that the dev witness uses (from
    //! `crates/integration_tests/tests/tlog_witness.rs`) so a single
    //! rotation rolls both worker configs forward.

    use base64::prelude::*;
    use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};

    /// The raw JSON contents of `config.dev.json`. Read at test time
    /// rather than via `CONFIG`, because `CONFIG` is built from the
    /// `OUT_DIR/config.json` copy that `build.rs` stages based on
    /// `$DEPLOY_ENV`, which may not be `dev` during `cargo test`.
    const DEV_CONFIG: &str = include_str!("../config.dev.json");

    /// Dev log PEM. MUST match the constant in
    /// `crates/integration_tests/tests/tlog_witness.rs`; duplicated here
    /// so this unit test can fail closed without `integration_tests`
    /// being in scope. If you rotate the dev key, update both copies and
    /// the SPKI in `config.dev.json`.
    const DEV_LOG_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIA2VCmSeCNVJTboEACcXvVahZHSHEJDxSl94aej1Q8hQ\n\
        -----END PRIVATE KEY-----\n";

    #[test]
    fn dev_config_spki_matches_embedded_pem() {
        // Extract the first (and only) log's first public key from
        // config.dev.json without pulling in the full config parser —
        // this keeps the test robust to unrelated config-shape changes.
        let parsed: serde_json::Value = serde_json::from_str(DEV_CONFIG).unwrap();
        let b64 = parsed["logs"]["example.com/log1"]["log_public_keys"][0]
            .as_str()
            .expect("config.dev.json must have logs[\"example.com/log1\"].log_public_keys[0]");
        let config_spki = BASE64_STANDARD.decode(b64).expect("SPKI is base64");

        // Derive the SPKI from the PEM and compare.
        let sk = ed25519_dalek::SigningKey::from_pkcs8_pem(DEV_LOG_SIGNING_KEY_PEM)
            .expect("parse dev log PEM");
        let derived_spki = sk.verifying_key().to_public_key_der().unwrap().to_vec();

        assert_eq!(
            config_spki, derived_spki,
            "config.dev.json SPKI and DEV_LOG_SIGNING_KEY_PEM have drifted; \
             a future integration-test run will 403",
        );
    }
}

// The `#[event(fetch)]` entry point lives in [`frontend_worker`].
