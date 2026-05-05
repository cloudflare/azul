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

use base64::Engine as _;
use config::AppConfig;
use ed25519_dalek::{
    pkcs8::{DecodePrivateKey as _, EncodePublicKey as _},
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
use tlog_mirror::TicketMacer;
#[allow(clippy::wildcard_imports)]
use worker::*;

mod add_entries;
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

// ---------------------------------------------------------------------------
// Mirror cosigner key
// ---------------------------------------------------------------------------

/// The mirror's signing material plus the cosignature algorithm
/// derived from the OID embedded in the loaded PKCS#8 PEM.
///
/// One variant per supported cosignature format. Both the Ed25519
/// `cosignature/v1` and the ML-DSA-44 `subtree/v1` variants are valid
/// [tlog-cosignatures][cosig]; the spec does not constrain mirrors to
/// a single algorithm. Operators choose by which key they generate
/// and load — the OID in the PKCS#8 PEM is the source of truth.
///
/// Each variant carries the signer plus the DER-encoded
/// `SubjectPublicKeyInfo` for the matching verifying key. The SPKI is
/// computed once at construction and reused by `/metadata` so we don't
/// re-encode the verifying key on every request, and so the signer
/// types themselves don't need to expose their internal verifying keys.
///
/// Both signer fields are boxed so the enum has a small, balanced
/// stack footprint — the expanded ML-DSA-44 key is ~64 KiB and even
/// the Ed25519 path's signer is several hundred bytes, both large
/// enough that indirection is worth the single allocation at load
/// time.
///
/// [cosig]: https://c2sp.org/tlog-cosignature
pub(crate) enum MirrorSigner {
    /// Ed25519 / [`cosignature/v1`][spec].
    ///
    /// [spec]: https://c2sp.org/tlog-cosignature
    CosignatureV1 {
        signer: Box<CosignatureV1CheckpointSigner>,
        public_key_der: Vec<u8>,
    },
    /// ML-DSA-44 / [`subtree/v1`][spec].
    ///
    /// [spec]: https://c2sp.org/tlog-cosignature
    SubtreeV1 {
        signer: Box<SubtreeV1CheckpointSigner>,
        public_key_der: Vec<u8>,
    },
}

impl MirrorSigner {
    /// DER-encoded `SubjectPublicKeyInfo` for the mirror's verifying
    /// key, in whatever algorithm this signer was loaded with.
    pub(crate) fn public_key_der(&self) -> &[u8] {
        match self {
            Self::CosignatureV1 { public_key_der, .. } | Self::SubtreeV1 { public_key_der, .. } => {
                public_key_der
            }
        }
    }

    /// Stable string identifying the cosignature algorithm. Published
    /// in `/metadata` so clients know whether to expect
    /// `cosignature/v1` or `subtree/v1` cosignatures.
    pub(crate) fn algorithm(&self) -> &'static str {
        match self {
            Self::CosignatureV1 { .. } => "cosignature/v1",
            Self::SubtreeV1 { .. } => "subtree/v1",
        }
    }

    /// The inner [`CheckpointSigner`] trait object, used by the
    /// `add-entries` handler when emitting the mirror cosignature on a
    /// successful upload (a future slice).
    ///
    /// [`CheckpointSigner`]: tlog_checkpoint::CheckpointSigner
    #[allow(dead_code)] // Wired up in slice C4 (add-entries handler).
    pub(crate) fn as_checkpoint_signer(&self) -> &dyn tlog_checkpoint::CheckpointSigner {
        match self {
            Self::CosignatureV1 { signer, .. } => &**signer,
            Self::SubtreeV1 { signer, .. } => &**signer,
        }
    }
}

/// Cached mirror signer, built lazily on first request.
///
/// Held as a `OnceLock<MirrorSigner>` so the PKCS#8 parse + algorithm
/// dispatch happens at most once per worker instance. Subsequent
/// requests reuse the parsed key. Concurrent cold-start requests will
/// each parse the PEM and (for ML-DSA-44) expand the ~64 KiB
/// `ExpandedSigningKey`, dropping the loser's result; deduplication
/// would need [`OnceLock::get_or_try_init`] (unstable, see
/// `rust-lang/rust#109737`).
static MIRROR_SIGNER: OnceLock<MirrorSigner> = OnceLock::new();

/// Load (or return the already-cached) mirror signer.
///
/// The signing algorithm is derived from the OID in the
/// `MIRROR_SIGNING_KEY` PKCS#8 PEM secret:
///
/// - `id-Ed25519` → [`MirrorSigner::CosignatureV1`].
/// - `id-ml-dsa-44` → [`MirrorSigner::SubtreeV1`].
///
/// # Errors
///
/// Returns an error if the `MIRROR_SIGNING_KEY` secret is missing,
/// the PEM is malformed, the OID is neither Ed25519 nor ML-DSA-44, or
/// the configured `mirror_name` is not a valid signed-note key name.
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
/// Split out from [`load_mirror_signer`] so unit tests can exercise
/// the algorithm dispatch without a `worker::Env`.
fn build_mirror_signer(pem: &str) -> Result<MirrorSigner> {
    let name = KeyName::new(CONFIG.mirror_name.clone())
        .map_err(|e| Error::from(format!("invalid mirror_name: {e:?}")))?;
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
            Ok(MirrorSigner::CosignatureV1 {
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
            Ok(MirrorSigner::SubtreeV1 {
                signer: Box::new(SubtreeV1CheckpointSigner::new(name, expanded)),
                public_key_der,
            })
        }
        oid => Err(Error::from(format!(
            "unsupported MIRROR_SIGNING_KEY algorithm OID {oid}: \
             expected id-Ed25519 ({ID_ED_25519}) or id-ml-dsa-44 ({ID_ML_DSA_44})"
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

// ---------------------------------------------------------------------------
// Ticket key
// ---------------------------------------------------------------------------

/// Cached ticket authenticator, built lazily on first request.
///
/// The mirror's ticket scheme — base64-encoded blobs returned in the
/// `text/x.tlog.mirror-info` 409 response body and round-tripped via
/// the `add-entries` request — is authenticated with HMAC-SHA-256
/// truncated to 128 bits. See [`tlog_mirror::TicketMacer`] for the
/// construction; this static holds a single instance keyed off the
/// `MIRROR_TICKET_KEY` secret.
#[allow(dead_code)] // Wired up in slice C4 (add-entries handler).
static TICKET_MACER: OnceLock<TicketMacer> = OnceLock::new();

/// Load (or return the already-cached) ticket authenticator.
///
/// The `MIRROR_TICKET_KEY` secret is **32 raw bytes encoded as
/// standard base64** (RFC 4648 §4, no URL-safe variant, no padding
/// stripping). Operators can generate one with:
///
/// ```sh
/// head -c 32 /dev/urandom | base64
/// ```
///
/// and load it via `wrangler secret put MIRROR_TICKET_KEY`.
///
/// # Errors
///
/// Returns an error if the `MIRROR_TICKET_KEY` secret is missing, is
/// not valid base64, or does not decode to exactly 32 bytes.
#[allow(dead_code)] // Wired up in slice C4 (add-entries handler).
pub(crate) fn load_ticket_macer(env: &Env) -> Result<&'static TicketMacer> {
    if let Some(t) = TICKET_MACER.get() {
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
    Ok(TICKET_MACER.get_or_init(|| TicketMacer::new(&key)))
}

#[cfg(test)]
mod signer_tests {
    //! Unit tests for the OID-dispatching signer loader.
    //!
    //! `build_mirror_signer` consumes a PKCS#8 PEM and returns a
    //! [`MirrorSigner`] whose variant is dictated entirely by the OID
    //! in the PEM's `AlgorithmIdentifier`. These tests cover both
    //! supported algorithms and the error path for an unsupported OID.

    use super::{build_mirror_signer, MirrorSigner};
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
        let signer = build_mirror_signer(&ed25519_pem(1)).expect("build Ed25519 signer");
        assert!(matches!(signer, MirrorSigner::CosignatureV1 { .. }));
        assert_eq!(signer.algorithm(), "cosignature/v1");
        assert!(
            !signer.public_key_der().is_empty(),
            "Ed25519 SPKI must be non-empty",
        );
    }

    #[test]
    fn ml_dsa_44_pem_dispatches_to_subtree_v1() {
        let signer = build_mirror_signer(&ml_dsa_44_pem(2)).expect("build ML-DSA-44 signer");
        assert!(matches!(signer, MirrorSigner::SubtreeV1 { .. }));
        assert_eq!(signer.algorithm(), "subtree/v1");
        assert!(
            !signer.public_key_der().is_empty(),
            "ML-DSA-44 SPKI must be non-empty",
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
    //! Tests that pin invariants between `config.dev.json` /
    //! `.dev.vars` and the integration-test fixtures that mirror them.
    //!
    //! If any of these tests fails, the dev secrets in
    //! `crates/mirror_worker/.dev.vars` or the dev keypair embedded in
    //! `crates/integration_tests/` and the SPKI in
    //! `crates/mirror_worker/config.dev.json` have drifted; rotate
    //! together. The dev mirror reuses the same Ed25519 *log* keypair
    //! that the dev witness uses (from
    //! `crates/integration_tests/tests/tlog_witness.rs`) so a single
    //! rotation rolls both worker configs forward. The mirror's own
    //! ML-DSA-44 cosigner key in `.dev.vars` is independent and is
    //! pinned only to "parses cleanly".

    use base64::prelude::*;
    use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};

    /// The raw JSON contents of `config.dev.json`. Read at test time
    /// rather than via `CONFIG`, because `CONFIG` is built from the
    /// `OUT_DIR/config.json` copy that `build.rs` stages based on
    /// `$DEPLOY_ENV`, which may not be `dev` during `cargo test`.
    const DEV_CONFIG: &str = include_str!("../config.dev.json");

    /// The raw contents of `.dev.vars`. Read at test time so we can
    /// pin that the keys load cleanly via the same code path as
    /// production secrets.
    const DEV_VARS: &str = include_str!("../.dev.vars");

    /// Dev log PEM. MUST match the constant in
    /// `crates/integration_tests/tests/tlog_witness.rs`; duplicated here
    /// so this unit test can fail closed without `integration_tests`
    /// being in scope. If you rotate the dev key, update both copies and
    /// the SPKI in `config.dev.json`.
    const DEV_LOG_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIA2VCmSeCNVJTboEACcXvVahZHSHEJDxSl94aej1Q8hQ\n\
        -----END PRIVATE KEY-----\n";

    /// Extract a `.dev.vars` value by key. The format is
    /// `KEY="value"` per line, with embedded `\n` as literal
    /// backslash-n (un-escaped on read by `wrangler dev`). For our
    /// pin tests we re-escape `\n` ourselves so the parsed PEM round-trips.
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

    /// `MIRROR_SIGNING_KEY` in `.dev.vars` parses cleanly through the
    /// same `build_mirror_signer` code path that production uses. Pins
    /// that an operator-typo in `.dev.vars` is caught at unit-test
    /// time, not at the first request to a running `wrangler dev`.
    #[test]
    fn dev_vars_mirror_signing_key_parses() {
        let pem = dev_var("MIRROR_SIGNING_KEY");
        let signer = super::build_mirror_signer(&pem)
            .expect("MIRROR_SIGNING_KEY in .dev.vars must parse via build_mirror_signer");
        // The dev key is ML-DSA-44 (seed [0x42; 32]); pin that.
        assert!(
            matches!(signer, super::MirrorSigner::SubtreeV1 { .. }),
            "dev MIRROR_SIGNING_KEY must dispatch to subtree/v1; \
             rotating to a different algorithm is intentional but requires \
             updating this test and the integration tests",
        );
    }

    /// `MIRROR_TICKET_KEY` in `.dev.vars` is base64 of exactly 32
    /// bytes, the precondition for [`crate::load_ticket_macer`].
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

// The `#[event(fetch)]` entry point lives in [`frontend_worker`].
