// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

mod batcher_do;
mod frontend_worker;
mod metrics;
mod mtcalog;
mod sequencer_do;
mod util;

use config::AppConfig;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use metrics::{millis_diff_as_secs, AsF64, ObjectMetrics};
use mtc_api::{CertPool, UnixTimestamp};
use mtcalog::UploadOptions;
use p256::{ecdsa::SigningKey as EcdsaSigningKey, pkcs8::DecodePrivateKey};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};
use util::now_millis;
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_verify::x509_cert::Certificate;

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

fn get_stub(env: &Env, name: &str, shard_id: Option<u8>, binding: &str) -> Result<Stub> {
    let namespace = env.durable_object(binding)?;
    let object_name = if let Some(id) = shard_id {
        &format!("{name}_{id:x}")
    } else {
        name
    };
    let object_id = namespace.id_from_name(object_name)?;
    if let Some(hint) = &CONFIG.cas[name].location_hint {
        Ok(object_id.get_stub_with_location_hint(hint)?)
    } else {
        Ok(object_id.get_stub()?)
    }
}

fn load_signing_key(env: &Env, name: &str) -> Result<&'static EcdsaSigningKey> {
    let once = &SIGNING_KEY_MAP.get_or_init(|| {
        CONFIG
            .cas
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

fn load_witness_key(env: &Env, name: &str) -> Result<&'static Ed25519SigningKey> {
    let once = &WITNESS_KEY_MAP.get_or_init(|| {
        CONFIG
            .cas
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

// Public R2 bucket from which to serve this log's static assets.
fn load_public_bucket(env: &Env, name: &str) -> Result<Bucket> {
    env.bucket(&format!("public_{name}"))
}

#[derive(Deserialize)]
struct QueryParams {
    name: String,
}

type LookupKey = [u8; 16];
type SequenceMetadata = (u64, UnixTimestamp);

// Compare-and-swap backend.
trait LockBackend {
    async fn put(&self, key: &str, checkpoint: &[u8]) -> Result<()>;
    async fn swap(&self, key: &str, old: &[u8], new: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
}

impl LockBackend for State {
    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.storage().put(key, value).await
    }
    async fn swap(&self, key: &str, old: &[u8], new: &[u8]) -> Result<()> {
        let old_value = self.storage().get::<Vec<u8>>(key).await?;
        if old_value != old {
            return Err("checkpoints do not match".into());
        }
        self.storage().put(key, new).await
    }
    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.storage().get::<Vec<u8>>(key).await
    }
}

trait ObjectBackend {
    async fn upload(&self, key: &str, data: &[u8], opts: &UploadOptions) -> Result<()>;
    async fn fetch(&self, key: &str) -> Result<Option<Vec<u8>>>;
}

struct ObjectBucket {
    sequence_interval: u64,
    bucket: Bucket,
    metrics: Option<ObjectMetrics>,
}

impl ObjectBackend for ObjectBucket {
    async fn upload(&self, key: &str, data: &[u8], opts: &UploadOptions) -> Result<()> {
        let start = now_millis();
        let mut metadata = HttpMetadata::default();
        if let Some(content_type) = &opts.content_type {
            metadata.content_type = Some(content_type.to_string());
        } else {
            metadata.content_type = Some("application/octet-stream".into());
        }
        if opts.immutable {
            metadata.cache_control = Some("public, max-age=604800, immutable".into());
        } else {
            metadata.cache_control = Some(format!(
                "public, max-age={}, must-revalidate",
                self.sequence_interval
            ));
        }
        self.metrics
            .as_ref()
            .inspect(|&m| m.upload_size_bytes.observe(data.len().as_f64()));
        self.bucket
            .put(key, data.to_vec())
            .http_metadata(metadata)
            .execute()
            .await
            .inspect_err(|_| {
                self.metrics
                    .as_ref()
                    .inspect(|&m| m.errors.with_label_values(&["put"]).inc());
            })?;
        self.metrics.as_ref().inspect(|&m| {
            m.duration
                .with_label_values(&["put"])
                .observe(millis_diff_as_secs(start, now_millis()));
        });
        Ok(())
    }
    async fn fetch(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let start = now_millis();
        let res = match self.bucket.get(key).execute().await? {
            Some(obj) => {
                let body = obj
                    .body()
                    .ok_or_else(|| format!("missing object body: {key}"))?;
                let bytes = body.bytes().await.inspect_err(|_| {
                    self.metrics.as_ref().inspect(|&m| {
                        m.errors.with_label_values(&["get"]).inc();
                    });
                })?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        };
        self.metrics.as_ref().inspect(|&m| {
            m.duration
                .with_label_values(&["get"])
                .observe(millis_diff_as_secs(start, now_millis()));
        });
        res
    }
}
