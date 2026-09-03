// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! A configurable transparency-log witness and mirror on
//! Cloudflare Workers.
//!
//! This worker handles the [`add-checkpoint`][add-cp] and
//! [`add-entries`][add-e] submission endpoints, the OPTIONAL
//! [`sign-subtree`][signsub] endpoint, and publishes enabled identities and
//! per-log configuration at `/metadata`. The [tlog-tiles][tiles] read
//! interface is served directly from object storage (see the `storage`
//! module).
//!
//! Per-origin persistent state lives in a `MirrorState` Durable Object,
//! one per log origin. Its single-threaded execution model provides the
//! atomic check-old-state, verify, persist-new-state sequence the spec
//! requires.
//!
//! [mirror]: https://c2sp.org/tlog-mirror
//! [add-cp]: https://c2sp.org/tlog-mirror#add-checkpoint
//! [add-e]: https://c2sp.org/tlog-mirror#add-entries
//! [signsub]: https://c2sp.org/tlog-witness#sign-subtree
//! [tiles]: https://c2sp.org/tlog-tiles

use base64::Engine as _;
use config::{AppConfig, CheckpointAlgorithm};
use ed25519_dalek::{
    SigningKey as Ed25519SigningKey,
    pkcs8::{DecodePrivateKey as _, DecodePublicKey as _, EncodePublicKey as _},
};
use ml_dsa::{MlDsa44, VerifyingKey as MlDsaVerifyingKey};
use pkcs8::{
    PrivateKeyInfoRef, SecretDocument,
    der::oid::db::{fips204::ID_ML_DSA_44, rfc8410::ID_ED_25519},
};
use signed_note::{Ed25519NoteVerifier, KeyName, NoteVerifier, VerifierList};
use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};
use tlog_cosignature::{
    CosignatureV1CheckpointSigner, SubtreeV1CheckpointSigner, SubtreeV1NoteVerifier,
};
use tlog_mirror::TicketSealer;
#[allow(clippy::wildcard_imports)]
use worker::*;

/// Initialize Sentry from the `SENTRY_DSN` environment variable.
///
/// Does nothing when the variable is absent or empty, allowing
/// deployments without Sentry support. Called at the top of the frontend
/// `fetch` handler and in each Durable Object's `new`, so a panic anywhere
/// in the worker is captured and flushed.
pub(crate) use generic_log_worker::obs::sentry::init_from_env as init_sentry;

mod add_entries;
mod body;
mod cleaner_do;
mod commit;
mod frontend_worker;
mod mirror_state_do;
mod storage;
mod stream_buffer;

pub(crate) const MIRROR_STATE_BINDING: &str = "MIRROR_STATE";

/// The binding name used in `wrangler.jsonc` for the `MirrorCleaner` DO.
pub(crate) const MIRROR_CLEANER_BINDING: &str = "MIRROR_CLEANER";

#[derive(Clone, Copy)]
pub(crate) struct EnabledRoles {
    witness: bool,
    mirror: bool,
}

pub(crate) const fn enabled_roles(mode: config::Mode) -> EnabledRoles {
    EnabledRoles {
        witness: mode.witness_enabled(),
        mirror: mode.mirror_enabled(),
    }
}

impl EnabledRoles {
    pub(crate) const fn witness(self) -> bool {
        self.witness
    }

    pub(crate) const fn mirror(self) -> bool {
        self.mirror
    }

    pub(crate) const fn combined(self) -> bool {
        self.witness && self.mirror
    }
}

/// The compile-time-embedded worker configuration.
///
/// `build.rs` validates `config.<DEPLOY_ENV>.json` against the schema and
/// [`AppConfig::validate`], then stages it under `OUT_DIR/config.json`, so
/// this parse is infallible in a crate that compiled.
pub(crate) static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("config.json must be valid at build time")
});

/// Per-origin cache of parsed trusted checkpoint signers.
/// Values are parsed keys rather than a pre-built `VerifierList`,
/// because `Box<dyn NoteVerifier>` is not `Sync` and so cannot live
/// inside a `LazyLock`.
pub(crate) static LOG_KEYS: LazyLock<HashMap<String, Vec<LogKey>>> = LazyLock::new(|| {
    CONFIG
        .logs
        .iter()
        .map(|(origin, log)| (origin.clone(), parse_log_keys(log)))
        .collect()
});

/// A parsed trusted source checkpoint signer.
#[derive(Clone)]
pub(crate) enum LogKey {
    Ed25519 {
        name: KeyName,
        verifying_key: ed25519_dalek::VerifyingKey,
    },
    SubtreeV1 {
        name: KeyName,
        verifying_key: MlDsaVerifyingKey<MlDsa44>,
    },
}

/// Build the parsed keys for a single configured log.
///
/// `build.rs` validates each signer name, algorithm, and SPKI before this
/// function runs.
fn parse_log_keys(log: &config::LogParams) -> Vec<LogKey> {
    log.checkpoint_signers
        .iter()
        .map(|signer| {
            let name = KeyName::new(signer.name.clone())
                .expect("checkpoint signer name validated by AppConfig::validate");
            match signer.algorithm {
                CheckpointAlgorithm::Ed25519 => LogKey::Ed25519 {
                    name,
                    verifying_key: ed25519_dalek::VerifyingKey::from_public_key_der(
                        &signer.public_key,
                    )
                    .expect("SPKI validated as Ed25519 by AppConfig::validate"),
                },
                CheckpointAlgorithm::SubtreeV1 => LogKey::SubtreeV1 {
                    name,
                    verifying_key: MlDsaVerifyingKey::<MlDsa44>::from_public_key_der(
                        &signer.public_key,
                    )
                    .expect("SPKI validated as ML-DSA-44 by AppConfig::validate"),
                },
            }
        })
        .collect()
}

/// Every configured source-log origin, as `'static` string slices.
///
/// This is the set of Durable Object names for the per-origin
/// `MirrorState`/`MirrorCleaner` instances; the DOs recover their own
/// origin by matching the runtime-provided DO name against this set.
pub(crate) fn log_origins() -> impl Iterator<Item = &'static str> {
    LOG_KEYS.keys().map(String::as_str)
}

/// Build a [`VerifierList`] for a given origin from the cached keys, or
/// `None` if no log is configured at that origin.
pub(crate) fn log_verifiers(origin: &str) -> Option<VerifierList> {
    let keys = LOG_KEYS.get(origin)?;
    Some(log_verifiers_for_keys(keys))
}

fn log_verifiers_for_keys(keys: &[LogKey]) -> VerifierList {
    let verifiers: Vec<Box<dyn NoteVerifier>> = keys
        .iter()
        .map(|key| match key {
            LogKey::Ed25519 {
                name,
                verifying_key,
            } => Box::new(Ed25519NoteVerifier::new(name.clone(), *verifying_key))
                as Box<dyn NoteVerifier>,
            LogKey::SubtreeV1 {
                name,
                verifying_key,
            } => Box::new(SubtreeV1NoteVerifier::new(
                name.clone(),
                verifying_key.clone(),
            )) as Box<dyn NoteVerifier>,
        })
        .collect();
    VerifierList::new(verifiers)
}

/// Identity signing material selected by the PKCS#8 algorithm OID.
pub(crate) enum IdentitySigner {
    CosignatureV1 {
        signer: Box<CosignatureV1CheckpointSigner>,
        public_key_der: Vec<u8>,
    },
    SubtreeV1 {
        signer: Box<SubtreeV1CheckpointSigner>,
        public_key_der: Vec<u8>,
    },
}

impl IdentitySigner {
    /// DER-encoded `SubjectPublicKeyInfo` for the mirror's verifying key.
    pub(crate) fn public_key_der(&self) -> &[u8] {
        match self {
            Self::CosignatureV1 { public_key_der, .. } | Self::SubtreeV1 { public_key_der, .. } => {
                public_key_der
            }
        }
    }

    pub(crate) fn algorithm(&self) -> &'static str {
        match self {
            Self::CosignatureV1 { .. } => "cosignature/v1",
            Self::SubtreeV1 { .. } => "subtree/v1",
        }
    }

    pub(crate) fn supports_sign_subtree(&self) -> bool {
        matches!(self, Self::SubtreeV1 { .. })
    }

    pub(crate) fn as_subtree_signer(&self) -> Option<&SubtreeV1CheckpointSigner> {
        match self {
            Self::CosignatureV1 { .. } => None,
            Self::SubtreeV1 { signer, .. } => Some(signer),
        }
    }

    /// The inner [`CheckpointSigner`] trait object, used by the
    /// `add-entries` handler to emit the mirror's checkpoint cosignature
    /// on a successful upload.
    ///
    /// [`CheckpointSigner`]: tlog_checkpoint::CheckpointSigner
    pub(crate) fn as_checkpoint_signer(&self) -> &dyn tlog_checkpoint::CheckpointSigner {
        match self {
            Self::CosignatureV1 { signer, .. } => &**signer,
            Self::SubtreeV1 { signer, .. } => &**signer,
        }
    }
}

/// Cached mirror signer, so the PKCS#8 parse happens at most once per
/// worker instance.
static MIRROR_SIGNER: OnceLock<IdentitySigner> = OnceLock::new();
static WITNESS_SIGNER: OnceLock<IdentitySigner> = OnceLock::new();

/// Load (or return the already-cached) mirror signer.
///
/// The algorithm is derived from the PKCS#8 OID.
///
/// # Errors
///
/// Returns an error if the `MIRROR_SIGNING_KEY` secret is missing, the PEM
/// is malformed, or the key is neither Ed25519 nor ML-DSA-44.
pub(crate) fn load_mirror_signer(env: &Env) -> Result<&'static IdentitySigner> {
    if !enabled_roles(CONFIG.mode).mirror() {
        return Err(Error::from("mirror identity is disabled"));
    }
    if let Some(s) = MIRROR_SIGNER.get() {
        return Ok(s);
    }
    let pem = env.secret("MIRROR_SIGNING_KEY")?.to_string();
    let signer = build_identity_signer(&CONFIG.mirror_config().name, "MIRROR_SIGNING_KEY", &pem)?;
    Ok(MIRROR_SIGNER.get_or_init(|| signer))
}

/// Build identity signing material from a PKCS#8 PEM string.
///
/// Split out from [`load_mirror_signer`] so unit tests can exercise the
/// parse and algorithm dispatch without a `worker::Env`.
fn build_identity_signer(
    identity_name: &str,
    secret_name: &str,
    pem: &str,
) -> Result<IdentitySigner> {
    let name = KeyName::new(identity_name.to_owned())
        .map_err(|e| Error::from(format!("invalid identity name: {e:?}")))?;
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
            Ok(IdentitySigner::CosignatureV1 {
                signer: Box::new(CosignatureV1CheckpointSigner::new(name, key)),
                public_key_der,
            })
        }
        ID_ML_DSA_44 => {
            let (signer, public_key_der) =
                SubtreeV1CheckpointSigner::from_pkcs8_pem_with_public_key(name, pem)
                    .map_err(Error::from)?;
            Ok(IdentitySigner::SubtreeV1 {
                signer: Box::new(signer),
                public_key_der,
            })
        }
        oid => Err(Error::from(format!(
            "unsupported {secret_name} algorithm OID {oid}: expected id-Ed25519 \
             ({ID_ED_25519}) or id-ml-dsa-44 ({ID_ML_DSA_44})"
        ))),
    }
}

pub(crate) fn load_witness_signer(env: &Env) -> Result<&'static IdentitySigner> {
    if !enabled_roles(CONFIG.mode).witness() {
        return Err(Error::from("witness identity is disabled"));
    }
    if let Some(signer) = WITNESS_SIGNER.get() {
        return Ok(signer);
    }
    let pem = env.secret("WITNESS_SIGNING_KEY")?.to_string();
    let identity = CONFIG
        .witness
        .as_ref()
        .expect("validated witness mode must have witness config");
    let signer = build_identity_signer(&identity.name, "WITNESS_SIGNING_KEY", &pem)?;
    Ok(WITNESS_SIGNER.get_or_init(|| signer))
}

/// Load enabled identity keys and reject key reuse across roles.
pub(crate) fn validate_identity_keys(env: &Env) -> Result<()> {
    if !enabled_roles(CONFIG.mode).combined() {
        return Ok(());
    }
    let witness = load_witness_signer(env)?;
    let mirror = load_mirror_signer(env)?;
    ensure_distinct_identity_keys(witness, mirror).map_err(Error::from)
}

fn ensure_distinct_identity_keys(
    witness: &IdentitySigner,
    mirror: &IdentitySigner,
) -> std::result::Result<(), &'static str> {
    if witness.public_key_der() != mirror.public_key_der() {
        return Ok(());
    }
    Err("witness and mirror identities must use distinct signing keys")
}

/// Cached ticket authenticator, built lazily on first request.
///
/// The mirror's ticket scheme (base64 blobs returned in the
/// `text/x.tlog.mirror-info` 409 response body and round-tripped via the
/// `add-entries` request) is sealed with AES-256-GCM-SIV, a fresh random
/// nonce per ticket, with the log origin bound as associated data. See
/// [`tlog_mirror::TicketSealer`]; this static holds a single instance
/// keyed off the `MIRROR_TICKET_KEY` secret.
static TICKET_SEALER: OnceLock<TicketSealer> = OnceLock::new();

/// Load (or return the already-cached) ticket authenticator.
///
/// The `MIRROR_TICKET_KEY` secret is 32 raw bytes encoded as standard
/// base64 (RFC 4648 section 4, no URL-safe variant). Operators can
/// generate one with `head -c 32 /dev/urandom | base64` and load it via
/// `wrangler secret put MIRROR_TICKET_KEY`.
///
/// # Errors
///
/// Returns an error if the `MIRROR_TICKET_KEY` secret is missing, is not
/// valid base64, or does not decode to exactly 32 bytes.
pub(crate) fn load_ticket_sealer(env: &Env) -> Result<&'static TicketSealer> {
    if let Some(t) = TICKET_SEALER.get() {
        return Ok(t);
    }
    let b64 = env.secret("MIRROR_TICKET_KEY")?.to_string();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| Error::from(format!("MIRROR_TICKET_KEY base64 decode: {e}")))?;
    let key: [u8; 32] = raw.try_into().map_err(|v: Vec<u8>| {
        Error::from(format!(
            "MIRROR_TICKET_KEY must decode to exactly 32 bytes; got {}",
            v.len()
        ))
    })?;
    Ok(TICKET_SEALER.get_or_init(|| TicketSealer::new(&key)))
}

#[cfg(test)]
mod signer_tests {
    use super::{
        IdentitySigner, build_identity_signer, enabled_roles, ensure_distinct_identity_keys,
        log_verifiers_for_keys, parse_log_keys,
    };
    use base64::Engine as _;
    use config::{CheckpointAlgorithm, CheckpointSigner, LogParams};
    use ed25519_dalek::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
    use ml_dsa::ExpandedSigningKey;
    use signed_note::{KeyName, Note};
    use tlog_checkpoint::{CheckpointSigner as _, CheckpointText};
    use tlog_core::record_hash;
    use tlog_cosignature::SubtreeV1CheckpointSigner;

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
        let signer = build_identity_signer("mirror.example", "TEST_KEY", &ml_dsa_44_pem(2))
            .expect("build ML-DSA-44 signer");
        assert!(matches!(signer, IdentitySigner::SubtreeV1 { .. }));
        assert_eq!(signer.algorithm(), "subtree/v1");
        assert!(signer.supports_sign_subtree());
        assert!(
            !signer.public_key_der().is_empty(),
            "ML-DSA-44 SPKI must be non-empty",
        );
    }

    #[test]
    fn ed25519_pem_loads_with_cosignature_v1_algorithm() {
        let signer = build_identity_signer("mirror.example", "TEST_KEY", &ed25519_pem(3))
            .expect("build Ed25519 signer");
        assert!(matches!(signer, IdentitySigner::CosignatureV1 { .. }));
        assert_eq!(signer.algorithm(), "cosignature/v1");
        assert!(!signer.supports_sign_subtree());
        assert!(signer.as_subtree_signer().is_none());
    }

    #[test]
    fn independently_generated_identity_keys_are_distinct() {
        let witness = build_identity_signer("witness.example", "TEST_KEY", &ed25519_pem(3))
            .expect("build witness signer");
        let mirror = build_identity_signer("mirror.example", "TEST_KEY", &ed25519_pem(4))
            .expect("build mirror signer");
        ensure_distinct_identity_keys(&witness, &mirror).unwrap();
    }

    #[test]
    fn reused_identity_key_is_rejected() {
        let witness = build_identity_signer("witness.example", "TEST_KEY", &ed25519_pem(3))
            .expect("build witness signer");
        let mirror = build_identity_signer("mirror.example", "TEST_KEY", &ed25519_pem(3))
            .expect("build mirror signer");
        assert!(ensure_distinct_identity_keys(&witness, &mirror).is_err());
    }

    #[test]
    fn malformed_pem_is_rejected() {
        let Err(err) = build_identity_signer("mirror.example", "TEST_KEY", "not-a-pem") else {
            panic!("malformed PEM must not parse")
        };
        let msg = err.to_string();
        assert!(
            msg.contains("PEM parse") || msg.contains("PrivateKeyInfo"),
            "unexpected error: {msg}",
        );
    }

    #[test]
    fn configured_mixed_log_verifiers_verify_both_algorithms() {
        let ed_key = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
        let ml_key = ExpandedSigningKey::<ml_dsa::MlDsa44>::from_seed(&ml_dsa::B32::from([13; 32]));
        let log = LogParams {
            description: None,
            checkpoint_signers: vec![
                CheckpointSigner {
                    name: "log.example/ed".to_owned(),
                    algorithm: CheckpointAlgorithm::Ed25519,
                    public_key: ed_key.verifying_key().to_public_key_der().unwrap().to_vec(),
                },
                CheckpointSigner {
                    name: "log.example/ml".to_owned(),
                    algorithm: CheckpointAlgorithm::SubtreeV1,
                    public_key: ml_key.verifying_key().to_public_key_der().unwrap().to_vec(),
                },
            ],
        };
        let keys = parse_log_keys(&log);
        let checkpoint_bytes = format!(
            "log.example\n1\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(record_hash(b"entry").0)
        );
        let checkpoint = CheckpointText::from_bytes(checkpoint_bytes.as_bytes()).unwrap();

        let ed_signer = tlog_checkpoint::Ed25519CheckpointSigner::new(
            KeyName::new("log.example/ed".to_owned()).unwrap(),
            ed_key,
        );
        let ed_signature = ed_signer.sign(1, &checkpoint).unwrap();
        let ed_note = Note::new(checkpoint_bytes.as_bytes(), &[ed_signature]).unwrap();
        ed_note.verify(&log_verifiers_for_keys(&keys)).unwrap();

        let ml_signer = SubtreeV1CheckpointSigner::new(
            KeyName::new("log.example/ml".to_owned()).unwrap(),
            ml_key,
        );
        let ml_signature = ml_signer.sign(1, &checkpoint).unwrap();
        let ml_note = Note::new(checkpoint_bytes.as_bytes(), &[ml_signature]).unwrap();
        ml_note.verify(&log_verifiers_for_keys(&keys)).unwrap();
    }

    #[test]
    fn standalone_role_policy_gates_routes_metadata_and_secrets() {
        let witness = enabled_roles(config::Mode::Witness);
        assert!(witness.witness());
        assert!(!witness.mirror());

        let mirror = enabled_roles(config::Mode::Mirror);
        assert!(!mirror.witness());
        assert!(mirror.mirror());

        let combined = enabled_roles(config::Mode::WitnessAndMirror);
        assert!(combined.witness());
        assert!(combined.mirror());
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
    //! `subtree/v1` checkpoints. The role identity keys in `.dev.vars` are
    //! independent.

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
        let b64 =
            parsed["logs"]["oid/1.3.6.1.4.1.32473.2.0.1"]["checkpoint_signers"][0]["public_key"]
                .as_str()
                .expect("config.dev.json must contain the MTC checkpoint signer public key");
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

    #[test]
    fn dev_vars_mirror_signing_key_parses() {
        let pem = dev_var("MIRROR_SIGNING_KEY");
        let signer = super::build_identity_signer("dev.mirror.example", "MIRROR_SIGNING_KEY", &pem)
            .expect("MIRROR_SIGNING_KEY in .dev.vars must parse");
        assert_eq!(
            signer.algorithm(),
            "subtree/v1",
            "dev MIRROR_SIGNING_KEY must load as a subtree/v1 signer",
        );
    }

    #[test]
    fn dev_vars_witness_signing_key_parses() {
        let signer = super::build_identity_signer(
            "dev.witness.example",
            "WITNESS_SIGNING_KEY",
            &dev_var("WITNESS_SIGNING_KEY"),
        )
        .expect("WITNESS_SIGNING_KEY in .dev.vars must parse");
        assert_eq!(signer.algorithm(), "subtree/v1");
    }

    #[test]
    fn dev_vars_witness_and_mirror_public_keys_differ() {
        let witness = SigningKey::<MlDsa44>::from_pkcs8_pem(&dev_var("WITNESS_SIGNING_KEY"))
            .expect("WITNESS_SIGNING_KEY in .dev.vars must parse");
        let mirror = SigningKey::<MlDsa44>::from_pkcs8_pem(&dev_var("MIRROR_SIGNING_KEY"))
            .expect("MIRROR_SIGNING_KEY in .dev.vars must parse");

        assert_ne!(
            witness.verifying_key().to_public_key_der().unwrap(),
            mirror.verifying_key().to_public_key_der().unwrap(),
            "dev witness and mirror identities must use distinct public keys",
        );
    }

    /// `MIRROR_TICKET_KEY` in `.dev.vars` is base64 of exactly 32 bytes,
    /// the precondition for [`crate::load_ticket_sealer`].
    #[test]
    fn dev_vars_ticket_key_is_32_bytes_base64() {
        let b64 = dev_var("MIRROR_TICKET_KEY");
        let raw = BASE64_STANDARD
            .decode(b64.trim())
            .expect("MIRROR_TICKET_KEY must be valid base64");
        assert_eq!(
            raw.len(),
            32,
            "MIRROR_TICKET_KEY must decode to exactly 32 bytes; got {}",
            raw.len()
        );
    }
}
