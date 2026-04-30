// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! A transparency-log witness implementing [c2sp.org/tlog-witness][spec] on
//! Cloudflare Workers.
//!
//! The witness exposes two endpoints today:
//!
//! - [`add-checkpoint`][add]: a client (typically the log itself) submits
//!   a new checkpoint along with a consistency proof from the witness's
//!   latest recorded state, and the witness returns a timestamped
//!   cosignature over the checkpoint.
//! - [`sign-subtree`][signsub] (OPTIONAL, only when the witness is
//!   configured with an ML-DSA-44 key): a client asks the witness to
//!   cosign a subtree `[start, end)` of a tree the witness has previously
//!   cosigned, supplying a consistency proof from the subtree to a
//!   reference checkpoint. The witness returns a `subtree/v1` cosignature.
//!
//! Per-log state (the latest cosigned tree size and root hash) is persisted
//! in a [`WitnessState`] Durable Object, one per log origin. The DO's
//! single-threaded execution model provides the atomic "check-old-size,
//! update-latest, return-cosignature" sequence that the spec requires.
//!
//! # Cosignature algorithm
//!
//! A given witness deployment runs with a single signing algorithm,
//! selected by the OID embedded in the `WITNESS_SIGNING_KEY` PKCS#8
//! secret:
//!
//! - `id-Ed25519` (`1.3.101.112`): the witness produces
//!   [`cosignature/v1`][cosig] signatures and exposes only
//!   `add-checkpoint`. Requests to `sign-subtree` return 404.
//! - `id-ml-dsa-44` (`2.16.840.1.101.3.4.3.17`): the witness produces
//!   [`subtree/v1`][cosig] signatures and exposes both endpoints. The
//!   `add-checkpoint` response is a `subtree/v1` cosignature over the
//!   whole tree (start = 0, end = checkpoint size), per the
//!   [tlog-witness] spec.
//!
//! Operators choose the algorithm by which key they generate and load.
//! There is no separate config field — the OID is the source of truth.
//!
//! [spec]: https://c2sp.org/tlog-witness
//! [add]: https://c2sp.org/tlog-witness#add-checkpoint
//! [signsub]: https://c2sp.org/tlog-witness#sign-subtree
//! [cosig]: https://c2sp.org/tlog-cosignature
//! [tlog-witness]: https://c2sp.org/tlog-witness
//! [`WitnessState`]: witness_state_do::WitnessState

use config::AppConfig;
use ed25519_dalek::{
    pkcs8::{DecodePrivateKey as _, DecodePublicKey as _, EncodePublicKey as _},
    SigningKey as Ed25519SigningKey,
};
use ml_dsa::MlDsa44;
use pkcs8::{
    der::oid::db::{fips204::ID_ML_DSA_44, rfc8410::ID_ED_25519},
    PrivateKeyInfoRef, SecretDocument,
};
use signed_note::{Ed25519NoteVerifier, KeyName, NoteVerifier, VerifierList};
use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};
use tlog_cosignature::{CosignatureV1CheckpointSigner, SubtreeV1CheckpointSigner};
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
/// `build.rs` calls [`AppConfig::validate`] and refuses to compile a
/// witness with a malformed config, so by the time this static is built
/// every origin and SPKI is known to parse cleanly. The `expect` calls
/// below treat parse failures as `unreachable!` rather than as recoverable
/// errors.
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

/// The witness's signing material plus the cosignature algorithm derived
/// from the OID embedded in the loaded PKCS#8 PEM.
///
/// One variant per supported cosignature format. The handler dispatches
/// on this enum: `add-checkpoint` works for both, and `sign-subtree`
/// is wired up only for [`Self::SubtreeV1`].
///
/// Each variant carries the signer plus the DER-encoded
/// `SubjectPublicKeyInfo` for the matching verifying key. The SPKI is
/// computed once at construction and reused by `/metadata` so we don't
/// re-encode the verifying key on every request, and so the signer
/// types themselves don't need to expose their internal verifying keys.
///
/// Both signer fields are boxed so the enum has a small, balanced
/// stack footprint — the expanded ML-DSA-44 key is ~64 KiB and even
/// the Ed25519 path's signer is ~470 bytes, both large enough that
/// indirection is worth the single allocation at load time.
pub(crate) enum WitnessSigner {
    /// Ed25519 / [`cosignature/v1`][spec].
    ///
    /// [spec]: https://c2sp.org/tlog-cosignature
    CosignatureV1 {
        signer: Box<CosignatureV1CheckpointSigner>,
        public_key_der: Vec<u8>,
    },
    /// ML-DSA-44 / [`subtree/v1`][spec]. Supports both the checkpoint
    /// case (via `add-checkpoint`) and arbitrary subtrees (via
    /// `sign-subtree`).
    ///
    /// [spec]: https://c2sp.org/tlog-cosignature
    SubtreeV1 {
        signer: Box<SubtreeV1CheckpointSigner>,
        public_key_der: Vec<u8>,
    },
}

impl WitnessSigner {
    /// Return the DER-encoded `SubjectPublicKeyInfo` for the witness's
    /// verifying key, in whatever algorithm this signer was loaded with.
    pub(crate) fn public_key_der(&self) -> &[u8] {
        match self {
            Self::CosignatureV1 { public_key_der, .. } | Self::SubtreeV1 { public_key_der, .. } => {
                public_key_der
            }
        }
    }

    /// Return a reference to the inner [`CheckpointSigner`] trait object
    /// for the `add-checkpoint` path, which is algorithm-agnostic.
    pub(crate) fn as_checkpoint_signer(&self) -> &dyn tlog_tiles::CheckpointSigner {
        match self {
            Self::CosignatureV1 { signer, .. } => &**signer,
            Self::SubtreeV1 { signer, .. } => &**signer,
        }
    }
}

/// Cached witness signer, built lazily on first request.
///
/// Held as a `OnceLock<WitnessSigner>` so the PKCS#8 parse + algorithm
/// dispatch happens at most once per worker instance. Subsequent
/// requests reuse the parsed key.
static WITNESS_SIGNER: OnceLock<WitnessSigner> = OnceLock::new();

/// Load (or return the already-cached) witness signer.
///
/// The signing algorithm is derived from the OID in the
/// `WITNESS_SIGNING_KEY` PKCS#8 PEM secret:
///
/// - `id-Ed25519` → [`WitnessSigner::CosignatureV1`].
/// - `id-ml-dsa-44` → [`WitnessSigner::SubtreeV1`].
///
/// # Errors
///
/// Returns an error if the `WITNESS_SIGNING_KEY` secret is missing,
/// the PEM is malformed, the OID is neither Ed25519 nor ML-DSA-44, or
/// the configured `witness_name` is not a valid signed-note key name.
pub(crate) fn load_witness_signer(env: &Env) -> Result<&'static WitnessSigner> {
    if let Some(s) = WITNESS_SIGNER.get() {
        return Ok(s);
    }
    // Concurrent cold-start requests will each parse the PEM and expand
    // the ML-DSA-44 key, dropping the loser's result. Deduplication
    // would need `OnceLock::get_or_try_init` (unstable, rust-lang/rust#109737).
    let pem = env.secret("WITNESS_SIGNING_KEY")?.to_string();
    let signer = build_witness_signer(&pem)?;
    Ok(WITNESS_SIGNER.get_or_init(|| signer))
}

/// Build a [`WitnessSigner`] from a PKCS#8 PEM string.
///
/// Split out from [`load_witness_signer`] so unit tests can exercise the
/// algorithm dispatch without a `worker::Env`.
fn build_witness_signer(pem: &str) -> Result<WitnessSigner> {
    let name = KeyName::new(CONFIG.witness_name.clone())
        .map_err(|e| Error::from(format!("invalid witness_name: {e:?}")))?;
    let (_label, doc) =
        SecretDocument::from_pem(pem).map_err(|e| Error::from(format!("PEM parse: {e}")))?;
    let pk_info = PrivateKeyInfoRef::try_from(doc.as_bytes())
        .map_err(|e| Error::from(format!("PrivateKeyInfo parse: {e}")))?;
    match pk_info.algorithm.oid {
        ID_ED_25519 => {
            let key = Ed25519SigningKey::from_pkcs8_pem(pem)
                .map_err(|e| Error::from(format!("Ed25519 PKCS#8 parse: {e}")))?;
            let public_key_der = key
                .verifying_key()
                .to_public_key_der()
                .map_err(|e| Error::from(format!("Ed25519 SPKI encode: {e}")))?
                .to_vec();
            Ok(WitnessSigner::CosignatureV1 {
                signer: Box::new(CosignatureV1CheckpointSigner::new(name, key)),
                public_key_der,
            })
        }
        ID_ML_DSA_44 => {
            // ml-dsa's PKCS#8 stores only the 32-byte seed; the
            // `ExpandedSigningKey` `TryFrom<PrivateKeyInfoRef>` impl
            // (used by `from_pkcs8_pem`) expands it on the way in. The
            // expanded key never leaves this worker.
            let expanded = ml_dsa::ExpandedSigningKey::<MlDsa44>::from_pkcs8_pem(pem)
                .map_err(|e| Error::from(format!("ML-DSA-44 PKCS#8 parse: {e}")))?;
            let public_key_der = expanded
                .verifying_key()
                .to_public_key_der()
                .map_err(|e| Error::from(format!("ML-DSA-44 SPKI encode: {e}")))?
                .to_vec();
            Ok(WitnessSigner::SubtreeV1 {
                signer: Box::new(SubtreeV1CheckpointSigner::new(name, expanded)),
                public_key_der,
            })
        }
        oid => Err(Error::from(format!(
            "unsupported WITNESS_SIGNING_KEY algorithm OID {oid}: \
             expected id-Ed25519 ({ID_ED_25519}) or id-ml-dsa-44 ({ID_ML_DSA_44})"
        ))),
    }
}

/// Return the DER-encoded `SubjectPublicKeyInfo` for the witness's own
/// verifying key. Used by the `/metadata` endpoint so clients can learn
/// the witness's identity without hitting a separate endpoint. The SPKI
/// was computed once at signer construction and stored alongside the
/// signer in [`WitnessSigner`].
///
/// # Errors
///
/// Returns an error if the signing key is not available.
pub(crate) fn load_witness_public_key_der(env: &Env) -> Result<&'static [u8]> {
    Ok(load_witness_signer(env)?.public_key_der())
}

#[cfg(test)]
mod tests {
    //! Unit tests for the OID-dispatching signer loader.
    //!
    //! `build_witness_signer` consumes a PKCS#8 PEM and returns a
    //! [`WitnessSigner`] whose variant is dictated entirely by the OID
    //! in the PEM's `AlgorithmIdentifier`. These tests cover both
    //! supported algorithms and the error path for an unsupported OID.

    use super::{build_witness_signer, WitnessSigner};
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    /// Generate a deterministic Ed25519 PEM from a seed byte.
    fn ed25519_pem(seed: u8) -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        sk.to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("encode PEM")
            .to_string()
    }

    /// Generate a deterministic ML-DSA-44 PEM from a seed byte.
    ///
    /// Uses the seed-only PKCS#8 encoding (the same format the
    /// `RustCrypto` `ml-dsa` crate emits and that an operator would
    /// produce with `openssl genpkey -algorithm ML-DSA-44`) so this
    /// exercises the real load path.
    fn ml_dsa_44_pem(seed: u8) -> String {
        use ml_dsa::KeyGen as _;
        use pkcs8::EncodePrivateKey as _;
        let sk = ml_dsa::MlDsa44::from_seed(&ml_dsa::B32::from([seed; 32]));
        sk.to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("encode ML-DSA-44 PEM")
            .to_string()
    }

    #[test]
    fn ed25519_pem_dispatches_to_cosignature_v1() {
        let signer = build_witness_signer(&ed25519_pem(1)).expect("build Ed25519 signer");
        assert!(matches!(signer, WitnessSigner::CosignatureV1 { .. }));
        assert!(
            !signer.public_key_der().is_empty(),
            "Ed25519 SPKI must be non-empty",
        );
    }

    #[test]
    fn ml_dsa_44_pem_dispatches_to_subtree_v1() {
        let signer = build_witness_signer(&ml_dsa_44_pem(2)).expect("build ML-DSA-44 signer");
        assert!(matches!(signer, WitnessSigner::SubtreeV1 { .. }));
        assert!(
            !signer.public_key_der().is_empty(),
            "ML-DSA-44 SPKI must be non-empty",
        );
    }

    /// A P-256 PKCS#8 PEM — a well-formed, supported-by-pkcs8 algorithm
    /// that this witness intentionally doesn't accept. The error message
    /// must mention "unsupported" so an operator who pasted the wrong
    /// key sees that the algorithm choice is the issue.
    #[test]
    fn unsupported_oid_is_rejected_with_helpful_error() {
        // Generate a P-256 PKCS#8 PEM at test time so we don't bake an
        // arbitrary key blob into the source.
        use p256::elliptic_curve::Generate as _;
        use p256::pkcs8::EncodePrivateKey as _;
        let sk = p256::SecretKey::generate();
        let pem = sk
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("encode P-256 PEM");
        let msg = match build_witness_signer(&pem) {
            Ok(_) => panic!("must reject P-256"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("unsupported"),
            "error must mention the algorithm is unsupported: {msg}",
        );
    }

    #[test]
    fn malformed_pem_is_rejected() {
        let msg = match build_witness_signer("not a PEM") {
            Ok(_) => panic!("must reject"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.to_lowercase().contains("pem"),
            "error must mention PEM: {msg}",
        );
    }
}

#[cfg(test)]
mod dev_config_tests {
    //! Tests that pin invariants among the dev fixtures:
    //!
    //! - `config.dev.json` lists the log's Ed25519 public key. The same
    //!   public key is derived at test time from the log signing PEM
    //!   embedded in `crates/integration_tests/tests/tlog_witness.rs`,
    //!   and we pin the SPKI against it.
    //! - `.dev.vars` carries the witness's ML-DSA-44 signing key. We
    //!   pin its byte content against a fixed PKCS#8 PEM constant in
    //!   this module so a rotation of either side is caught
    //!   immediately. The integration tests learn the witness's
    //!   public key at runtime from `/metadata`, so they don't need
    //!   their own copy of the witness PEM.
    //!
    //! If `dev_config_spki_matches_embedded_pem` fails, rotate the
    //! dev log key in `config.dev.json` together with the
    //! `LOG_SIGNING_KEY_PEM` constant in
    //! `crates/integration_tests/tests/tlog_witness.rs`.
    //!
    //! If `dev_vars_witness_key_matches_embedded_pem` fails, rotate
    //! the witness key in `.dev.vars` together with the
    //! `DEV_WITNESS_SIGNING_KEY_PEM` constant below.

    use base64::prelude::*;
    use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};

    /// The raw JSON contents of `config.dev.json`. Read at test time
    /// rather than via `CONFIG`, because `CONFIG` is built from the
    /// `OUT_DIR/config.json` copy that `build.rs` stages based on
    /// `$DEPLOY_ENV`, which may not be `dev` during `cargo test`.
    const DEV_CONFIG: &str = include_str!("../config.dev.json");

    /// Raw `.dev.vars` content; read at test time so we can verify the
    /// witness PEM has not drifted from the integration-test
    /// constant. Wrangler-style key=quoted-value file with a single
    /// `WITNESS_SIGNING_KEY` line.
    const DEV_VARS: &str = include_str!("../.dev.vars");

    /// Dev log PEM (Ed25519). MUST match the constant in
    /// `crates/integration_tests/tests/tlog_witness.rs`; duplicated here
    /// so this unit test can fail closed without `integration_tests`
    /// being in scope. If you rotate the dev log key, update both copies
    /// and the SPKI in `config.dev.json`.
    const DEV_LOG_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIA2VCmSeCNVJTboEACcXvVahZHSHEJDxSl94aej1Q8hQ\n\
        -----END PRIVATE KEY-----\n";

    /// Dev witness PEM (ML-DSA-44 seed-only PKCS#8). MUST match the
    /// value of `WITNESS_SIGNING_KEY` in `.dev.vars`. The seed here is
    /// `[0x42; 32]` — deterministic, repo-public, dev-only. To rotate,
    /// change the seed, regenerate the PEM, and update both
    /// `.dev.vars` and this constant. The integration tests pick up
    /// the new public key automatically from `/metadata`; they don't
    /// need updating.
    const DEV_WITNESS_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MDQCAQAwCwYJYIZIAWUDBAMRBCKAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC\n\
        QkJCQkJC\n\
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

    /// Pin the relationship between the witness signing key in
    /// `.dev.vars` and the ML-DSA-44 PEM that the integration tests
    /// expect. `.dev.vars` stores the PEM with literal `\n` escapes
    /// (it's read by wrangler as a key=value file); we unescape them
    /// before comparing.
    #[test]
    fn dev_vars_witness_key_matches_embedded_pem() {
        // Find the `WITNESS_SIGNING_KEY="..."` line and extract its
        // quoted value with `\n` escapes converted to real newlines.
        let line = DEV_VARS
            .lines()
            .find(|l| l.starts_with("WITNESS_SIGNING_KEY="))
            .expect(".dev.vars must define WITNESS_SIGNING_KEY");
        let quoted = line
            .strip_prefix("WITNESS_SIGNING_KEY=")
            .unwrap()
            .trim_start_matches('"')
            .trim_end_matches('"');
        let actual = quoted.replace("\\n", "\n");
        assert_eq!(
            actual, DEV_WITNESS_SIGNING_KEY_PEM,
            ".dev.vars WITNESS_SIGNING_KEY does not match DEV_WITNESS_SIGNING_KEY_PEM \
             (rotate both together with crates/integration_tests/tests/tlog_witness.rs)",
        );
    }
}

// The `#[event(fetch)]` entry point lives in [`frontend_worker`].
