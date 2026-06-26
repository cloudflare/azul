// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use crate::ccadb_roots_cron::{CCADB_ROOTS_NAMESPACE, ccadb_roots_filename, update_ccadb_roots};
use config::{AppConfig, LogType};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::{ecdsa::SigningKey as EcdsaSigningKey, pkcs8::DecodePrivateKey};
use signed_note::KeyName;
use static_ct_api::StaticCTCheckpointSigner;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use tlog_checkpoint::{CheckpointSigner, Ed25519CheckpointSigner};
use worker::{Date, Env, Result, send::SendWrapper};
use x509_util::CertPool;

mod batcher_do;
mod ccadb_roots_cron;
mod cleaner_do;
mod frontend_worker;
mod sequence_metadata;
mod sequencer_do;

pub(crate) use sequence_metadata::StaticCTSequenceMetadata;

// Application configuration.
static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    serde_json::from_str::<AppConfig>(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("Failed to parse config")
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
    let witness = Ed25519CheckpointSigner::new(origin, witness_key);

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

struct CachedRoot {
    not_after: SendWrapper<Date>,
    pool: Arc<CertPool>,
}

impl CachedRoot {
    fn new(pool: CertPool) -> Self {
        // this is an extreme case where a worker isolate lasts for more than a day, which is the
        // time it takes for the update roots cron job to run.
        const ONE_DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;
        let now = Date::now();
        Self {
            not_after: SendWrapper(Date::new(worker::DateInit::Millis(
                now.as_millis() + ONE_DAY_MILLIS,
            ))),
            pool: Arc::new(pool),
        }
    }

    fn not_expired(&self) -> bool {
        let now = Date::now();
        now.as_millis() < self.not_after.as_millis()
    }
}

async fn load_roots(env: &Env, name: &str) -> Result<Arc<CertPool>> {
    static ROOTS: LazyLock<Mutex<HashMap<String, CachedRoot>>> = LazyLock::new(Mutex::default);

    // Fast path: already initialized.
    if let Some(pool) = ROOTS.lock().unwrap().get(name)
        && pool.not_expired()
    {
        return Ok(Arc::clone(&pool.pool));
    }

    let log_config = &CONFIG.logs[name];

    // Build the pool for this request. If another request concurrently built
    // and stored one first, we discard ours and return the stored value.
    // This avoids awaiting an OnceLock initialized by another request context,
    // which the Workers runtime would cancel as a cross-request deadlock.
    let mut pool = CertPool::default();

    if log_config.log_type == Some(LogType::Test) {
        let pem = include_bytes!(concat!(env!("OUT_DIR"), "/roots.pem"));
        // load_pem_chain fails on empty input: https://github.com/RustCrypto/formats/pull/1965
        if !pem.is_empty() {
            pool.append_certs_from_pem(pem)
                .map_err(|e| format!("failed to load PEM chain: {e}"))?;
        }
    }

    // Load additional roots from the CCADB roots file in Workers KV.
    if log_config.enable_ccadb_roots {
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

    // Store the pool if no other request got there first; either way return
    // the value now in the cell.
    let mut roots = ROOTS.lock().unwrap();
    let _ = roots.insert(name.to_string(), CachedRoot::new(pool));
    Ok(Arc::clone(&roots.get(name).expect("just set").pool))
}
