// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use config::AppConfig;
use ed25519_dalek::{pkcs8::DecodePrivateKey as _, SigningKey as Ed25519SigningKey};
use ietf_mtc_api::{MtcCosigner, MtcSigningKey, MtcVerifyingKey, TrustAnchorID};
use signed_note::KeyName;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{LazyLock, OnceLock};
#[allow(clippy::wildcard_imports)]
use worker::*;

mod batcher_do;
mod cleaner_do;
mod frontend_worker;
mod sequence_metadata;
mod sequencer_do;

pub(crate) use sequence_metadata::IetfMtcSequenceMetadata;

// Application configuration.
static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str::<AppConfig>(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("Failed to parse config")
});

type CachedKeys = (MtcSigningKey, MtcVerifyingKey);
static KEY_MAP: OnceLock<HashMap<String, OnceLock<CachedKeys>>> = OnceLock::new();

/// Return the key pair for the given log, using a per-log cache.
///
/// Uses `OnceLock::get()` to check the cache without blocking.  If the cache
/// is not yet populated (either empty or being initialized by another request),
/// the key pair is parsed directly from the secret without waiting.  This
/// avoids the cross-request `OnceLock::get_or_init` deadlock that the Workers
/// runtime detects when two requests concurrently initialize the same cell.
pub(crate) fn load_key_pair(env: &Env, name: &str) -> Result<CachedKeys> {
    let once = &KEY_MAP.get_or_init(|| {
        CONFIG
            .logs
            .keys()
            .map(|n| (n.clone(), OnceLock::new()))
            .collect()
    })[name];

    // Fast path: already cached.
    if let Some(keys) = once.get() {
        return Ok(keys.clone());
    }

    // Slow path: parse from secret.  We do not call get_or_init here because
    // that would block if another request is currently initializing the cell,
    // which the Workers runtime detects and cancels as a cross-request deadlock.
    // Instead, parse directly and attempt to store the result; if another
    // request beat us to it, use its cached value.
    let pem = env.secret(&format!("SIGNING_KEY_{name}"))?.to_string();
    let keys = parse_key_pair(&pem).map_err(worker::Error::from)?;
    Ok(once.get_or_init(|| keys).clone())
}

fn parse_key_pair(pem: &str) -> std::result::Result<(MtcSigningKey, MtcVerifyingKey), String> {
    let sk = Ed25519SigningKey::from_pkcs8_pem(pem).map_err(|e| e.to_string())?;
    let vk = sk.verifying_key();
    Ok((MtcSigningKey::Ed25519(sk), MtcVerifyingKey::Ed25519(vk)))
}

pub(crate) fn load_checkpoint_cosigner(env: &Env, name: &str) -> MtcCosigner {
    let log_id = TrustAnchorID::from_str(&CONFIG.logs[name].log_id).unwrap();
    let cosigner_id = TrustAnchorID::from_str(&CONFIG.logs[name].cosigner_id).unwrap();
    let (sk, vk) = load_key_pair(env, name).unwrap();
    MtcCosigner::new_checkpoint(cosigner_id, log_id, sk, vk)
}

pub(crate) fn load_origin(name: &str) -> KeyName {
    // https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md#parameters
    // The origin line SHOULD be the schema-less URL prefix of the log with no
    // trailing slashes. For example, a log with prefix
    // https://rome.ct.example.com/tevere/ will use rome.ct.example.com/tevere
    // as the checkpoint origin line.
    KeyName::new(
        CONFIG.logs[name]
            .submission_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string(),
    )
    .expect("invalid origin name")
}
