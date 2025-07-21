// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use config::AppConfig;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::{ecdsa::SigningKey as EcdsaSigningKey, pkcs8::DecodePrivateKey};
use signed_note::KeyName;
use static_ct_api::StaticCTCheckpointSigner;
use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};
use tlog_tiles::{CheckpointSigner, Ed25519CheckpointSigner, SequenceMetadata};
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

pub(crate) fn load_checkpoint_signers(env: &Env, name: &str) -> Vec<Box<dyn CheckpointSigner>> {
    let origin = load_origin(name);
    let signing_key = load_signing_key(env, name).unwrap().clone();
    let witness_key = load_witness_key(env, name).unwrap().clone();

    // Make the checkpoint signers from the secret keys and put them in a vec
    let signer = StaticCTCheckpointSigner::new(origin.clone(), signing_key)
        .map_err(|e| format!("could not create static-ct checkpoint signer: {e}"))
        .unwrap();
    let witness = Ed25519CheckpointSigner::new(origin, witness_key)
        .map_err(|e| format!("could not create ed25519 checkpoint signer: {e}"))
        .unwrap();

    vec![Box::new(signer), Box::new(witness)]
}

pub(crate) fn load_origin(name: &str) -> KeyName {
    // https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#checkpoints
    // The origin line MUST be the submission prefix of the log as a schema-less URL with no trailing slashes.
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
