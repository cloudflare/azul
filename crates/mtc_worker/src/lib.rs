// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use config::AppConfig;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::pkcs8::DecodePrivateKey;
use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};
use tlog_tiles::{LookupKey, SequenceMetadata};
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_cert::Certificate;
use x509_util::CertPool;

mod batcher_do;
mod frontend_worker;
mod sequencer_do;

// Application configuration.
static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str::<AppConfig>(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("Failed to parse config")
});

static ROOTS: LazyLock<CertPool> = LazyLock::new(|| {
    CertPool::new(
        Certificate::load_pem_chain(include_bytes!(concat!(env!("OUT_DIR"), "/roots.pem")))
            .expect("Failed to parse roots"),
    )
    .unwrap()
});

static SIGNING_KEY_MAP: OnceLock<HashMap<String, OnceLock<Ed25519SigningKey>>> = OnceLock::new();
static WITNESS_KEY_MAP: OnceLock<HashMap<String, OnceLock<Ed25519SigningKey>>> = OnceLock::new();

pub(crate) fn load_signing_key(env: &Env, name: &str) -> Result<&'static Ed25519SigningKey> {
    load_ed25519_key(env, name, &SIGNING_KEY_MAP, &format!("SIGNING_KEY_{name}"))
}

pub(crate) fn load_witness_key(env: &Env, name: &str) -> Result<&'static Ed25519SigningKey> {
    load_ed25519_key(env, name, &WITNESS_KEY_MAP, &format!("WITNESS_KEY_{name}"))
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
