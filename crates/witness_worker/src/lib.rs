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
    pkcs8::{DecodePrivateKey as _, EncodePublicKey as _},
    SigningKey as Ed25519SigningKey,
};
use signed_note::KeyName;
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

/// The witness's Ed25519 signing key, loaded lazily from the `WITNESS_SIGNING_KEY`
/// secret on first use.
static WITNESS_SIGNING_KEY: OnceLock<Ed25519SigningKey> = OnceLock::new();

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
/// verifying key. Used by the `/metadata` endpoint so clients can learn the
/// witness's identity without hitting a separate endpoint.
///
/// # Errors
///
/// Returns an error if the signing key is not available or if PKCS#8
/// encoding fails (should never happen for a valid Ed25519 key).
pub(crate) fn load_witness_public_key_der(env: &Env) -> Result<Vec<u8>> {
    let sk = load_witness_signing_key(env)?;
    let der = sk
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| Error::from(format!("encoding SPKI: {e}")))?;
    Ok(der.to_vec())
}

// The `#[event(fetch)]` entry point lives in [`frontend_worker`].
