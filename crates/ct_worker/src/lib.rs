#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use generic_log_worker::config::AppConfig;
use p256::{ecdsa::SigningKey as EcdsaSigningKey, pkcs8::DecodePrivateKey};
use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};
use tlog_tiles::{LookupKey, SequenceMetadata};
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_util::CertPool;
use x509_verify::x509_cert::Certificate;

mod batcher_do;
mod ctlog;
mod frontend_worker;
mod sequencer_do;
mod util;

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

static SIGNING_KEY_MAP: OnceLock<HashMap<String, OnceLock<EcdsaSigningKey>>> = OnceLock::new();
static WITNESS_KEY_MAP: OnceLock<HashMap<String, OnceLock<Ed25519SigningKey>>> = OnceLock::new();

pub(crate) fn load_signing_key(env: &Env, name: &str) -> Result<&'static EcdsaSigningKey> {
    let once = &SIGNING_KEY_MAP.get_or_init(|| {
        CONFIG
            .logs
            .keys()
            .map(|name| (name.clone(), OnceLock::new()))
            .collect()
    })[name];
    if let Some(key) = once.get() {
        Ok(key)
    } else {
        let key = EcdsaSigningKey::from_pkcs8_pem(
            &env.secret(&format!("SIGNING_KEY_{name}"))?.to_string(),
        )
        .map_err(|e| e.to_string())?;
        Ok(once.get_or_init(|| key))
    }
}

pub(crate) fn load_witness_key(env: &Env, name: &str) -> Result<&'static Ed25519SigningKey> {
    let once = &WITNESS_KEY_MAP.get_or_init(|| {
        CONFIG
            .logs
            .keys()
            .map(|name| (name.clone(), OnceLock::new()))
            .collect()
    })[name];
    if let Some(key) = once.get() {
        Ok(key)
    } else {
        let key = Ed25519SigningKey::from_pkcs8_pem(
            &env.secret(&format!("WITNESS_KEY_{name}"))?.to_string(),
        )
        .map_err(|e| e.to_string())?;
        Ok(once.get_or_init(|| key))
    }
}
