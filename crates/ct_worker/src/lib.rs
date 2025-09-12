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
use tokio::sync::OnceCell;
use worker::{Env, Result};
use x509_util::CertPool;

use crate::ccadb_roots_cron::update_ccadb_roots;

mod batcher_do;
mod ccadb_roots_cron;
mod cleaner_do;
mod frontend_worker;
mod sequencer_do;

// A KV namespace with this binding must be configured in 'wrangler.jsonc' if
// any log shards have 'enable_ccadb_roots=true'.
const CCADB_ROOTS_NAMESPACE: &str = "ccadb_roots";

// Application configuration.
static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str::<AppConfig>(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("Failed to parse config")
});

static SIGNING_KEY_MAP: OnceLock<HashMap<String, OnceLock<EcdsaSigningKey>>> = OnceLock::new();
static WITNESS_KEY_MAP: OnceLock<HashMap<String, OnceLock<Ed25519SigningKey>>> = OnceLock::new();
static ROOTS: OnceCell<CertPool> = OnceCell::const_new();

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

fn ccadb_roots_filename(name: &str) -> String {
    format!("roots_{name}.pem")
}

async fn load_roots(env: &Env, name: &str) -> Result<&'static CertPool> {
    // Load embedded roots.
    ROOTS
        .get_or_try_init(|| async {
            let pem = include_bytes!(concat!(env!("OUT_DIR"), "/roots.pem"));
            let mut pool = CertPool::default();
            // load_pem_chain fails on empty input: https://github.com/RustCrypto/formats/pull/1965
            if !pem.is_empty() {
                pool.append_certs_from_pem(pem)
                    .map_err(|e| format!("failed to load PEM chain: {e}"))?;
            }

            // Load additional roots from the CCADB roots file in Workers KV.
            if CONFIG.logs[name].enable_ccadb_roots {
                let key = ccadb_roots_filename(name);
                let kv = env.kv(CCADB_ROOTS_NAMESPACE)?;
                let pem = if let Some(pem) = kv.get(&key).text().await? {
                    pem
                } else {
                    // The roots file might not exist if the CCADB roots cron job hasn't
                    // run yet. Try to create it once before failing.
                    update_ccadb_roots(&[&key], &kv).await?;
                    kv.get(&key)
                        .text()
                        .await?
                        .ok_or(format!("{name}: '{key}' not found in KV"))?
                };
                pool.append_certs_from_pem(pem.as_bytes())
                    .map_err(|e| format!("failed to add CCADB certs to pool: {e}"))?;
            }
            Ok(pool)
        })
        .await
}
