// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! A transparency-log mirror implementing [c2sp.org/tlog-mirror][mirror] on
//! Cloudflare Workers, specialized for MTC issuance logs.
//!
//! This worker handles the [`add-checkpoint`][add-cp] submission endpoint,
//! which updates the pending checkpoint for a log origin, and publishes
//! the mirror's identity and per-log configuration at `/metadata`.
//!
//! Per-origin persistent state lives in a `MirrorState` Durable Object,
//! one per log origin. Its single-threaded execution model provides the
//! atomic check-old-state, verify, persist-new-state sequence the spec
//! requires.
//!
//! [mirror]: https://c2sp.org/tlog-mirror
//! [add-cp]: https://c2sp.org/tlog-mirror#add-checkpoint

use config::AppConfig;
use ml_dsa::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
use ml_dsa::{MlDsa44, VerifyingKey as MlDsaVerifyingKey};
use pkcs8::{PrivateKeyInfoRef, SecretDocument, der::oid::db::fips204::ID_ML_DSA_44};
use signed_note::{KeyName, NoteVerifier, VerifierList};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, OnceLock};
use tlog_cosignature::SubtreeV1NoteVerifier;
#[allow(clippy::wildcard_imports)]
use worker::*;

mod frontend_worker;
mod mirror_state_do;

/// The binding name used in `wrangler.jsonc` for the `MirrorState` DO.
pub(crate) const MIRROR_STATE_BINDING: &str = "MIRROR_STATE";

/// The compile-time-embedded worker configuration.
///
/// `build.rs` validates `config.<DEPLOY_ENV>.json` against the schema and
/// [`AppConfig::validate`], then stages it under `OUT_DIR/config.json`, so
/// this parse is infallible in a crate that compiled.
pub(crate) static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("config.json must be valid at build time")
});

/// Per-origin cache of the parsed trusted log keys, keyed by the
/// concrete checkpoint origin. An MTC log-number window expands to one
/// entry per accepted log number (origin `<log_key_name>.0.<N>`), so the
/// map keys are the full set of origins this mirror serves.
///
/// All log numbers of a CA share the same key(s), and a parsed
/// ML-DSA-44 [`LogKey`] is ~25 KiB (it precomputes the expanded NTT
/// matrix), so the value is an [`Arc`]: every origin in a window points
/// at one shared allocation rather than cloning the key per log number.
///
/// Values are [`LogKey`] pairs rather than a pre-built `VerifierList`,
/// because `Box<dyn NoteVerifier>` is not `Sync` and so cannot live
/// inside a `LazyLock`. Building the `VerifierList` per request is cheap
/// (`SubtreeV1NoteVerifier::new` is just a key-ID hash).
pub(crate) static LOG_KEYS: LazyLock<HashMap<String, Arc<Vec<LogKey>>>> = LazyLock::new(|| {
    let mut map: HashMap<String, Arc<Vec<LogKey>>> = HashMap::new();
    for (log_key_name, log) in &CONFIG.logs {
        let keys = Arc::new(parse_log_keys(log_key_name, log));
        for origin in log.origins(log_key_name) {
            map.insert(origin, Arc::clone(&keys));
        }
    }
    map
});

/// A parsed trusted log key: the note-signature `name` (the
/// `log_key_name`, constant across an MTC CA's log-number window) and the
/// ML-DSA-44 verifying key.
#[derive(Clone)]
pub(crate) struct LogKey {
    pub name: KeyName,
    pub verifying_key: MlDsaVerifyingKey<MlDsa44>,
}

/// Build the parsed keys for a single configured log.
///
/// `build.rs` runs [`config::AppConfig::validate`] and refuses to compile
/// a malformed config, so the `log_key_name` and each SPKI are known to
/// parse; the `expect`s below would only fire if `validate` drifted out
/// of sync with this function.
fn parse_log_keys(log_key_name: &str, log: &config::LogParams) -> Vec<LogKey> {
    use ml_dsa::pkcs8::DecodePublicKey as _;
    let name = KeyName::new(log_key_name.to_owned())
        .expect("log_key_name validated as a signed-note KeyName by AppConfig::validate");
    log.log_public_keys
        .iter()
        .map(|spki| {
            let verifying_key = MlDsaVerifyingKey::<MlDsa44>::from_public_key_der(spki)
                .expect("SPKI validated as ML-DSA-44 by AppConfig::validate");
            LogKey {
                name: name.clone(),
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
            Box::new(SubtreeV1NoteVerifier::new(
                k.name.clone(),
                k.verifying_key.clone(),
            )) as Box<dyn NoteVerifier>
        })
        .collect();
    Some(VerifierList::new(verifiers))
}

// ---------------------------------------------------------------------------
// Mirror cosigner key
// ---------------------------------------------------------------------------

/// The mirror's signing material.
///
/// The mirror is an MTC cosigner, which per [c2sp.org/mtc-tlog][mtc] MUST
/// use an ML-DSA-44 key and produce [`subtree/v1`][cosig] messages, so
/// this worker supports only that algorithm. Holds the DER-encoded
/// `SubjectPublicKeyInfo` computed once at load and served by `/metadata`.
///
/// [mtc]: https://c2sp.org/mtc-tlog
/// [cosig]: https://c2sp.org/tlog-cosignature
pub(crate) struct MirrorSigner {
    public_key_der: Vec<u8>,
}

impl MirrorSigner {
    /// DER-encoded `SubjectPublicKeyInfo` for the mirror's ML-DSA-44
    /// verifying key.
    pub(crate) fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    /// Stable string identifying the cosignature algorithm, published in
    /// `/metadata`. Always `"subtree/v1"` (the only algorithm an MTC
    /// mirror cosigner may use).
    #[allow(clippy::unused_self)]
    pub(crate) fn algorithm(&self) -> &'static str {
        "subtree/v1"
    }
}

/// Cached mirror signer, so the PKCS#8 parse happens at most once per
/// worker instance.
static MIRROR_SIGNER: OnceLock<MirrorSigner> = OnceLock::new();

/// Load (or return the already-cached) mirror signer.
///
/// The `MIRROR_SIGNING_KEY` PKCS#8 PEM secret MUST carry an ML-DSA-44 key
/// (`id-ml-dsa-44`); the mirror cosigns with `subtree/v1`.
///
/// # Errors
///
/// Returns an error if the `MIRROR_SIGNING_KEY` secret is missing, the PEM
/// is malformed, or the key is not ML-DSA-44.
pub(crate) fn load_mirror_signer(env: &Env) -> Result<&'static MirrorSigner> {
    if let Some(s) = MIRROR_SIGNER.get() {
        return Ok(s);
    }
    let pem = env.secret("MIRROR_SIGNING_KEY")?.to_string();
    let signer = build_mirror_signer(&pem)?;
    Ok(MIRROR_SIGNER.get_or_init(|| signer))
}

/// Build a [`MirrorSigner`] from a PKCS#8 PEM string.
///
/// Split out from [`load_mirror_signer`] so unit tests can exercise the
/// parse/validation without a `worker::Env`. The key MUST be ML-DSA-44;
/// any other algorithm is rejected (the mirror's cosigner must be an MTC
/// cosigner, see [`MirrorSigner`]).
fn build_mirror_signer(pem: &str) -> Result<MirrorSigner> {
    let (_label, doc) =
        SecretDocument::from_pem(pem).map_err(|e| Error::from(format!("PEM parse: {e}")))?;
    let pk_info = PrivateKeyInfoRef::try_from(doc.as_bytes())
        .map_err(|e| Error::from(format!("PrivateKeyInfo parse: {e}")))?;
    match pk_info.algorithm.oid {
        ID_ML_DSA_44 => {
            // ml-dsa's PKCS#8 stores only the 32-byte seed; `from_pkcs8_der`
            // expands it on the way in.
            let expanded = ml_dsa::ExpandedSigningKey::<MlDsa44>::from_pkcs8_der(doc.as_bytes())
                .map_err(|e| Error::from(format!("ML-DSA-44 PKCS#8 parse: {e}")))?;
            let public_key_der = expanded
                .verifying_key()
                .to_public_key_der()
                .map_err(|e| Error::from(format!("ML-DSA-44 SPKI encode: {e}")))?
                .to_vec();
            Ok(MirrorSigner { public_key_der })
        }
        oid => Err(Error::from(format!(
            "unsupported MIRROR_SIGNING_KEY algorithm OID {oid}: expected id-ml-dsa-44 \
             ({ID_ML_DSA_44}). The mirror's cosigner must be an MTC cosigner (ML-DSA-44, \
             subtree/v1)."
        ))),
    }
}

/// Return the DER-encoded `SubjectPublicKeyInfo` for the mirror's own
/// verifying key. Used by the `/metadata` endpoint.
///
/// # Errors
///
/// Returns an error if the signing key is not available.
pub(crate) fn load_mirror_public_key_der(env: &Env) -> Result<&'static [u8]> {
    Ok(load_mirror_signer(env)?.public_key_der())
}

#[cfg(test)]
mod signer_tests {
    //! Unit tests for the mirror signer loader: only ML-DSA-44 keys are
    //! accepted; other algorithms and malformed PEMs are rejected.
    //! Ed25519 keys are generated only to exercise the rejection path, so
    //! `ed25519-dalek` is a dev-dependency.

    use super::build_mirror_signer;
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    /// Generate a deterministic Ed25519 PEM from a seed byte. Used only to
    /// check that a non-ML-DSA-44 key is rejected.
    fn ed25519_pem(seed: u8) -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        sk.to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("encode PEM")
            .to_string()
    }

    /// Generate a deterministic ML-DSA-44 PEM from a seed byte, using the
    /// seed-only PKCS#8 encoding an operator gets from `openssl genpkey
    /// -algorithm ML-DSA-44`, so this exercises the real load path.
    fn ml_dsa_44_pem(seed: u8) -> String {
        use ml_dsa::SigningKey;
        use pkcs8::EncodePrivateKey as _;
        let sk = SigningKey::<ml_dsa::MlDsa44>::from_seed(&ml_dsa::B32::from([seed; 32]));
        sk.to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("encode ML-DSA-44 PEM")
            .to_string()
    }

    #[test]
    fn ml_dsa_44_pem_loads_with_subtree_v1_algorithm() {
        let signer = build_mirror_signer(&ml_dsa_44_pem(2)).expect("build ML-DSA-44 signer");
        assert_eq!(signer.algorithm(), "subtree/v1");
        assert!(
            !signer.public_key_der().is_empty(),
            "ML-DSA-44 SPKI must be non-empty",
        );
    }

    /// The mirror cosigner MUST be ML-DSA-44 (an MTC cosigner). An Ed25519
    /// key (a valid tlog cosigner key in general, but not an MTC one) is
    /// refused, with an error naming the expected algorithm.
    #[test]
    fn ed25519_key_is_rejected() {
        let Err(err) = build_mirror_signer(&ed25519_pem(3)) else {
            panic!("Ed25519 MIRROR_SIGNING_KEY must be rejected")
        };
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported") && msg.contains("id-ml-dsa-44"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn malformed_pem_is_rejected() {
        let Err(err) = build_mirror_signer("not-a-pem") else {
            panic!("malformed PEM must not parse")
        };
        let msg = err.to_string();
        assert!(
            msg.contains("PEM parse") || msg.contains("PrivateKeyInfo"),
            "unexpected error: {msg}",
        );
    }
}

#[cfg(test)]
mod dev_config_tests {
    //! Tests that pin invariants between `config.dev.json` / `.dev.vars`
    //! and the integration-test fixtures that mirror them; a failure means
    //! they have drifted and must be rotated together.
    //!
    //! The dev config models an MTC CA: the `logs` key is the CA cosigner
    //! ID (`oid/1.3.6.1.4.1.32473.2`) whose ML-DSA-44 keypair signs
    //! `subtree/v1` checkpoints. The mirror's own cosigner key in
    //! `.dev.vars` is independent and is pinned only to "parses cleanly".

    use base64::prelude::*;
    use ml_dsa::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
    use ml_dsa::{Keypair as _, MlDsa44, SigningKey};

    /// Raw `config.dev.json`, read directly rather than via `CONFIG`,
    /// which is built from the `$DEPLOY_ENV` copy `build.rs` stages and
    /// may not be `dev` during `cargo test`.
    const DEV_CONFIG: &str = include_str!("../config.dev.json");

    /// Raw `.dev.vars` contents.
    const DEV_VARS: &str = include_str!("../.dev.vars");

    /// Dev log PEM (ML-DSA-44, seed-only PKCS#8), duplicated from
    /// `crates/integration_tests/tests/tlog_mirror.rs` so this test can
    /// fail closed without that crate in scope. Rotate both copies and the
    /// SPKI in `config.dev.json` together.
    const DEV_LOG_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MDQCAQAwCwYJYIZIAWUDBAMRBCKAIBERERERERERERERERERERERERERERERERER\n\
        ERERERER\n\
        -----END PRIVATE KEY-----\n";

    /// Extract a `.dev.vars` value by key. Lines are `KEY="value"` with
    /// embedded newlines as literal `\n`, which we un-escape so the parsed
    /// PEM round-trips.
    fn dev_var(key: &str) -> String {
        let line = DEV_VARS
            .lines()
            .find(|l| l.starts_with(&format!("{key}=")))
            .unwrap_or_else(|| panic!(".dev.vars must define {key}"));
        let rhs = line
            .strip_prefix(&format!("{key}="))
            .unwrap()
            .trim_matches('"');
        rhs.replace("\\n", "\n")
    }

    #[test]
    fn dev_config_spki_matches_embedded_pem() {
        // Pull the log's first public key straight from the JSON, so the
        // test is robust to unrelated config-shape changes.
        let parsed: serde_json::Value = serde_json::from_str(DEV_CONFIG).unwrap();
        let b64 = parsed["logs"]["oid/1.3.6.1.4.1.32473.2"]["log_public_keys"][0]
            .as_str()
            .expect(
                "config.dev.json must have logs[\"oid/1.3.6.1.4.1.32473.2\"].log_public_keys[0]",
            );
        let config_spki = BASE64_STANDARD.decode(b64).expect("SPKI is base64");

        // Derive the SPKI from the PEM and compare.
        let sk = SigningKey::<MlDsa44>::from_pkcs8_pem(DEV_LOG_SIGNING_KEY_PEM)
            .expect("parse dev log PEM");
        let derived_spki = sk.verifying_key().to_public_key_der().unwrap().to_vec();

        assert_eq!(
            config_spki, derived_spki,
            "config.dev.json SPKI and DEV_LOG_SIGNING_KEY_PEM have drifted; \
             integration tests would 403",
        );
    }

    /// `MIRROR_SIGNING_KEY` in `.dev.vars` parses cleanly through the
    /// same `build_mirror_signer` code path that production uses. Pins
    /// that an operator-typo in `.dev.vars` is caught at unit-test
    /// time, not at the first request to a running `wrangler dev`.
    #[test]
    fn dev_vars_mirror_signing_key_parses() {
        let pem = dev_var("MIRROR_SIGNING_KEY");
        let signer = super::build_mirror_signer(&pem)
            .expect("MIRROR_SIGNING_KEY in .dev.vars must parse via build_mirror_signer");
        assert_eq!(
            signer.algorithm(),
            "subtree/v1",
            "dev MIRROR_SIGNING_KEY must load as a subtree/v1 signer",
        );
    }
}
