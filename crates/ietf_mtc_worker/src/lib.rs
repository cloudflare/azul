// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use config::AppConfig;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ietf_mtc_api::{MtcCosigner, TrustAnchorID};
use pkcs8::DecodePrivateKey;
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

static SIGNING_KEY_MAP: OnceLock<HashMap<String, OnceLock<Ed25519SigningKey>>> = OnceLock::new();

pub(crate) fn load_signing_key(env: &Env, name: &str) -> Result<&'static Ed25519SigningKey> {
    load_ed25519_key(env, name, &SIGNING_KEY_MAP, &format!("SIGNING_KEY_{name}"))
}

pub(crate) fn load_ed25519_key(
    env: &Env,
    name: &str,
    key_map: &'static OnceLock<HashMap<String, OnceLock<Ed25519SigningKey>>>,
    binding: &str,
) -> Result<&'static Ed25519SigningKey> {
    let once = &key_map.get_or_init(|| {
        CONFIG
            .logs
            .keys()
            .map(|name| (name.clone(), OnceLock::new()))
            .collect()
    })[name];
    if let Some(key) = once.get() {
        Ok(key)
    } else {
        let key = Ed25519SigningKey::from_pkcs8_pem(&env.secret(binding)?.to_string())
            .map_err(|e| e.to_string())?;
        Ok(once.get_or_init(|| key))
    }
}

pub(crate) fn load_checkpoint_cosigner(env: &Env, name: &str) -> MtcCosigner {
    let log_id = TrustAnchorID::from_str(&CONFIG.logs[name].log_id).unwrap();
    let cosigner_id = TrustAnchorID::from_str(&CONFIG.logs[name].cosigner_id).unwrap();
    let signing_key = load_signing_key(env, name).unwrap().clone();
    MtcCosigner::new_checkpoint(cosigner_id, log_id, signing_key)
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
