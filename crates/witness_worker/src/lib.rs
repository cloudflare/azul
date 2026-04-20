// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! A transparency-log witness implementing [c2sp.org/tlog-witness][spec] on
//! Cloudflare Workers.
//!
//! The witness exposes a single endpoint today, [`add-checkpoint`][add]: a
//! client (typically the log itself) submits a new checkpoint along with a
//! consistency proof from the witness's latest recorded state, and the
//! witness returns a timestamped `cosignature/v1` signature.
//!
//! Per-log state (the latest cosigned tree size and root hash) is persisted
//! in a [`WitnessState`] Durable Object, one per log origin. The DO's
//! single-threaded execution model provides the atomic "check-old-size,
//! update-latest, return-cosignature" sequence that the spec requires.
//!
//! [spec]: https://c2sp.org/tlog-witness
//! [add]: https://c2sp.org/tlog-witness#add-checkpoint

use config::AppConfig;
use ed25519_dalek::{
    pkcs8::{DecodePrivateKey as _, DecodePublicKey as _, EncodePublicKey as _},
    SigningKey as Ed25519SigningKey,
};
use signed_note::{Ed25519NoteVerifier, KeyName, NoteVerifier, VerifierList};
use std::collections::{BTreeSet, HashMap};
use std::sync::{LazyLock, OnceLock};
use tlog_tiles::CosignatureV1CheckpointSigner;
#[allow(clippy::wildcard_imports)]
use worker::*;

mod frontend_worker;
mod witness_state_do;

/// The binding name used in `wrangler.jsonc` for the [`WitnessState`] DO.
///
/// [`WitnessState`]: witness_state_do::WitnessState
pub(crate) const WITNESS_STATE_BINDING: &str = "WITNESS_STATE";

/// The compile-time-embedded worker configuration.
pub(crate) static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("config.json must be valid at build time")
});

/// Per-origin cache of the parsed trusted log keys.
///
/// Populated eagerly on first access, so any configuration error —
/// non-Ed25519 SPKI, invalid DER, or an origin whose `(name, key_id)`
/// space is ambiguous across two configured keys — causes the worker to
/// abort at startup rather than failing at request-handling time with an
/// HTTP 400/500.
///
/// A `(name, key_id)` collision is cosmically unlikely in normal operation
/// (32-bit `key_id` is derived from the SPKI so it would require two
/// distinct keys to hash to the same prefix) but detecting it here gives
/// the operator a loud, single point of failure instead of silently
/// locking the log out: `Note::verify` surfaces `NoteError::AmbiguousKey`
/// for every affected checkpoint signature.
///
/// Values are plain `(VerifyingKey, key_id)` pairs rather than a
/// pre-built `VerifierList`, because `Box<dyn NoteVerifier>` is not
/// `Sync` and so cannot live inside a `LazyLock`. Building the
/// `VerifierList` per request from these cached keys is cheap
/// (`Ed25519NoteVerifier::new` is just field assignment) and keeps the
/// startup-time validation entirely in this module.
pub(crate) static LOG_KEYS: LazyLock<HashMap<String, Vec<LogKey>>> = LazyLock::new(|| {
    let mut out = HashMap::with_capacity(CONFIG.logs.len());
    for (id, log) in &CONFIG.logs {
        out.insert(log.origin.clone(), parse_log_keys(id, log));
    }
    out
});

/// A parsed trusted log key.
#[derive(Clone)]
pub(crate) struct LogKey {
    pub origin: KeyName,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

/// Build a list of parsed keys for a single configured log, panicking on
/// any configuration error.
fn parse_log_keys(log_id: &str, log: &config::LogParams) -> Vec<LogKey> {
    let origin_name = KeyName::new(log.origin.clone()).unwrap_or_else(|e| {
        panic!(
            "log {log_id:?}: origin {:?} is not a valid signed-note key name: {e:?}",
            log.origin,
        )
    });
    let mut out: Vec<LogKey> = Vec::with_capacity(log.log_public_keys.len());
    let mut seen_ids: BTreeSet<u32> = BTreeSet::new();
    for (i, spki) in log.log_public_keys.iter().enumerate() {
        let vk = ed25519_dalek::VerifyingKey::from_public_key_der(spki).unwrap_or_else(|e| {
            panic!("log {log_id:?}: log_public_keys[{i}] is not a valid Ed25519 SPKI: {e}")
        });
        // Computing the Ed25519 key_id costs one SHA-256 hash, but it's
        // a one-time startup cost and it lets us catch collisions here.
        let v = Ed25519NoteVerifier::new(origin_name.clone(), vk);
        assert!(
            seen_ids.insert(v.key_id()),
            "log {log_id:?}: log_public_keys[{i}] shares a (name, key_id) pair with an earlier key; \
             witness would be unable to disambiguate signatures from it",
        );
        out.push(LogKey {
            origin: origin_name.clone(),
            verifying_key: vk,
        });
    }
    out
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

/// The witness's Ed25519 signing key, loaded lazily from the `WITNESS_SIGNING_KEY`
/// secret on first use.
static WITNESS_SIGNING_KEY: OnceLock<Ed25519SigningKey> = OnceLock::new();

/// Cached DER-encoded `SubjectPublicKeyInfo` for the witness's verifying
/// key, derived from [`WITNESS_SIGNING_KEY`] on first use. Serving
/// `/metadata` copies out of this slot instead of recomputing the SPKI
/// on every request.
static WITNESS_PUBLIC_KEY_DER: OnceLock<Vec<u8>> = OnceLock::new();

/// Load (or return the already-cached) witness signing key.
///
/// # Errors
///
/// Returns an error if the `WITNESS_SIGNING_KEY` secret is missing or is not
/// a valid PKCS#8 PEM Ed25519 key.
pub(crate) fn load_witness_signing_key(env: &Env) -> Result<&'static Ed25519SigningKey> {
    if let Some(key) = WITNESS_SIGNING_KEY.get() {
        return Ok(key);
    }
    let pem = env.secret("WITNESS_SIGNING_KEY")?.to_string();
    let key = Ed25519SigningKey::from_pkcs8_pem(&pem).map_err(|e| e.to_string())?;
    Ok(WITNESS_SIGNING_KEY.get_or_init(|| key))
}

/// Build a [`CosignatureV1CheckpointSigner`] from the witness's configured
/// name and the loaded signing key.
///
/// `cosignature/v1` is the Ed25519-only timestamped cosignature format
/// specified in [c2sp.org/tlog-cosignature][cosig-spec]; this is what
/// [`tlog-witness`][witness-spec] requires in response bodies.
///
/// [cosig-spec]: https://c2sp.org/tlog-cosignature
/// [witness-spec]: https://c2sp.org/tlog-witness
///
/// # Errors
///
/// Returns an error if the witness signing key is not available or if the
/// configured `witness_name` is not a valid [`KeyName`].
pub(crate) fn load_witness_cosigner(env: &Env) -> Result<CosignatureV1CheckpointSigner> {
    let name = KeyName::new(CONFIG.witness_name.clone())
        .map_err(|e| Error::from(format!("invalid witness_name: {e:?}")))?;
    let key = load_witness_signing_key(env)?.clone();
    Ok(CosignatureV1CheckpointSigner::new(name, key))
}

/// Return the DER-encoded `SubjectPublicKeyInfo` for the witness's own
/// verifying key. Used by the `/metadata` endpoint so clients can learn
/// the witness's identity without hitting a separate endpoint. The SPKI
/// is computed once and cached in [`WITNESS_PUBLIC_KEY_DER`].
///
/// # Errors
///
/// Returns an error if the signing key is not available or if PKCS#8
/// encoding fails (should never happen for a valid Ed25519 key).
pub(crate) fn load_witness_public_key_der(env: &Env) -> Result<&'static [u8]> {
    if let Some(der) = WITNESS_PUBLIC_KEY_DER.get() {
        return Ok(der);
    }
    let sk = load_witness_signing_key(env)?;
    let der = sk
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| Error::from(format!("encoding SPKI: {e}")))?
        .to_vec();
    Ok(WITNESS_PUBLIC_KEY_DER.get_or_init(|| der))
}

#[cfg(test)]
mod dev_config_tests {
    //! Tests that pin invariants between `config.dev.json` and the
    //! integration-test fixtures that mirror it.
    //!
    //! If either of these tests fails, the dev keypair in
    //! `crates/integration_tests/tests/tlog_witness.rs` and the SPKI in
    //! `crates/witness_worker/config.dev.json` have drifted out of sync;
    //! rotate both together.

    use base64::prelude::*;
    use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};

    /// The raw JSON contents of `config.dev.json`. Read at test time
    /// rather than via `CONFIG`, because `CONFIG` is built from the
    /// `OUT_DIR/config.json` copy that `build.rs` stages based on
    /// `$DEPLOY_ENV`, which may not be `dev` during `cargo test`.
    const DEV_CONFIG: &str = include_str!("../config.dev.json");

    /// Dev log PEM. MUST match the constant in
    /// `crates/integration_tests/tests/tlog_witness.rs`; duplicated here so
    /// this unit test can fail closed without `integration_tests` being
    /// in scope. If you rotate the dev key, update both copies and the
    /// SPKI in `config.dev.json`.
    const DEV_LOG_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIA2VCmSeCNVJTboEACcXvVahZHSHEJDxSl94aej1Q8hQ\n\
        -----END PRIVATE KEY-----\n";

    #[test]
    fn dev_config_spki_matches_embedded_pem() {
        // Extract the first (and only) log's first public key from
        // config.dev.json without pulling in the full config parser —
        // this keeps the test robust to unrelated config-shape changes.
        let parsed: serde_json::Value = serde_json::from_str(DEV_CONFIG).unwrap();
        let b64 = parsed["logs"]["example1"]["log_public_keys"][0]
            .as_str()
            .expect("config.dev.json must have logs.example1.log_public_keys[0]");
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
