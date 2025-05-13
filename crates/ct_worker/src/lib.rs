// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

mod batcher_do;
mod ctlog;
mod frontend_worker;
mod metrics;
mod sequencer_do;
mod util;

use byteorder::{BigEndian, WriteBytesExt};
use config::AppConfig;
use ctlog::UploadOptions;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use metrics::{millis_diff_as_secs, AsF64, ObjectMetrics};
use p256::{ecdsa::SigningKey as EcdsaSigningKey, pkcs8::DecodePrivateKey};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use static_ct_api::{LookupKey, UnixTimestamp};
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::sync::{LazyLock, OnceLock};
use util::now_millis;
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_util::CertPool;
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
    if let Some(hint) = &CONFIG.logs[name].location_hint {
        Ok(object_id.get_stub_with_location_hint(hint)?)
    } else {
        Ok(object_id.get_stub()?)
    }
}

fn load_signing_key(env: &Env, name: &str) -> Result<&'static EcdsaSigningKey> {
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

fn load_witness_key(env: &Env, name: &str) -> Result<&'static Ed25519SigningKey> {
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

// Public R2 bucket from which to serve this log's static assets.
fn load_public_bucket(env: &Env, name: &str) -> Result<Bucket> {
    env.bucket(&format!("public_{name}"))
}

// KV namespace to use for this log's deduplication cache.
fn load_cache_kv(env: &Env, name: &str) -> Result<kv::KvStore> {
    env.kv(&format!("cache_{name}"))
}

#[derive(Deserialize)]
struct QueryParams {
    name: String,
}

type SequenceMetadata = (u64, UnixTimestamp);

trait CacheWrite {
    /// Put the provided sequenced entries into the cache. This does NOT overwrite existing entries.
    async fn put_entries(&mut self, entries: &[(LookupKey, SequenceMetadata)]) -> Result<()>;
}

trait CacheRead {
    /// Read an entry from the deduplication cache.
    fn get_entry(&self, key: &LookupKey) -> Option<SequenceMetadata>;
}

struct DedupCache {
    memory: MemoryCache,
    storage: Storage,
}

impl CacheWrite for DedupCache {
    /// Write entries to both the short-term deduplication cache and its backup in DO Storage.
    async fn put_entries(&mut self, entries: &[(LookupKey, SequenceMetadata)]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        self.memory.put_entries(entries);
        self.store(entries).await
    }
}

impl CacheRead for DedupCache {
    /// Check the short-term deduplication cache only. The long-term deduplication
    /// cache gets checked by the Worker frontend when handling add-chain requests.
    fn get_entry(&self, key: &LookupKey) -> Option<SequenceMetadata> {
        self.memory.get_entry(key)
    }
}

impl DedupCache {
    // Batches are written at most once per second, and we only need them deduplicate
    // entries long enough for KV's eventual consistency guarantees (~60s).
    // Cap at 128 so we can use a single get_multiple call to get all batches at once.
    // https://developers.cloudflare.com/durable-objects/api/storage-api/#get
    const MAX_BATCHES: usize = 128;
    const FIFO_HEAD_KEY: &str = "fifo:head";
    const FIFO_TAIL_KEY: &str = "fifo:tail";

    fn fifo_key(idx: usize) -> String {
        format!("fifo:{idx}")
    }

    // Load batches of cache entries from DO storage into the in-memory cache.
    async fn load(&mut self) -> Result<()> {
        let head = self
            .storage
            .get::<usize>(Self::FIFO_HEAD_KEY)
            .await
            .unwrap_or_default();
        let tail = self
            .storage
            .get::<usize>(Self::FIFO_TAIL_KEY)
            .await
            .unwrap_or_default();
        let keys = (0..(tail - head)).map(Self::fifo_key).collect::<Vec<_>>();
        let map = self.storage.get_multiple(keys.clone()).await?;
        for value in map.values() {
            let batch = serde_wasm_bindgen::from_value::<ByteBuf>(value?)?;
            self.memory
                .put_entries(&deserialize_entries(&batch.into_vec())?);
        }
        Ok(())
    }

    // Store a batch of cache entries in DO storage.
    async fn store(&mut self, entries: &[(LookupKey, SequenceMetadata)]) -> Result<()> {
        let head = self
            .storage
            .get::<usize>(Self::FIFO_HEAD_KEY)
            .await
            .unwrap_or_default();
        let tail = self
            .storage
            .get::<usize>(Self::FIFO_TAIL_KEY)
            .await
            .unwrap_or_default();
        // Check if the cache is full.
        if tail - head >= Self::MAX_BATCHES {
            // Evict the oldest item by incrementing the head.
            self.storage.put(Self::FIFO_HEAD_KEY, head + 1).await?;
        }
        let insert_idx = tail % Self::MAX_BATCHES;
        self.storage
            .put::<&ByteBuf>(
                &Self::fifo_key(insert_idx),
                &ByteBuf::from(serialize_entries(entries)),
            )
            .await?;
        self.storage.put(Self::FIFO_TAIL_KEY, tail + 1).await
    }
}

fn serialize_entries(entries: &[(LookupKey, SequenceMetadata)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 * entries.len());
    for (k, (idx, ts)) in entries {
        buf.write_all(k).unwrap();
        buf.write_u64::<BigEndian>(*idx).unwrap();
        buf.write_u64::<BigEndian>(*ts).unwrap();
    }
    buf
}

fn deserialize_entries(buf: &[u8]) -> Result<Vec<(LookupKey, SequenceMetadata)>> {
    if buf.len() % 32 != 0 {
        return Err("invalid buffer length".into());
    }
    let mut entries = Vec::with_capacity(buf.len() / 32);
    for i in 0..buf.len() / 32 {
        let key: [u8; 16] = buf[i * 32..i * 32 + 16].try_into().unwrap();
        let value = (
            u64::from_be_bytes(buf[i * 32 + 16..i * 32 + 24].try_into().unwrap()),
            u64::from_be_bytes(buf[i * 32 + 24..i * 32 + 32].try_into().unwrap()),
        );
        entries.push((key, value));
    }
    Ok(entries)
}

// A fixed-size in-memory FIFO cache.
struct MemoryCache {
    max_size: usize,
    map: HashMap<LookupKey, SequenceMetadata>,
    fifo: VecDeque<LookupKey>,
}

impl MemoryCache {
    fn new(max_size: usize) -> Self {
        assert_ne!(max_size, 0);
        Self {
            max_size,
            fifo: VecDeque::with_capacity(max_size),
            map: HashMap::with_capacity(max_size),
        }
    }

    // Get an entry from the in-memory cache.
    fn get_entry(&self, key: &LookupKey) -> Option<SequenceMetadata> {
        self.map.get(key).copied()
    }

    // Put a batch of entries into the in-memory cache,
    // evicting old entries to make room if necessary.
    fn put_entries(&mut self, entries: &[(LookupKey, SequenceMetadata)]) {
        for (key, value) in entries {
            if self.map.contains_key(key) {
                continue;
            }
            if self.map.len() == self.max_size {
                // Evict oldest entry to make room.
                self.map.remove(&self.fifo.pop_front().unwrap());
            }
            self.fifo.push_back(*key);
            self.map.insert(*key, *value);
        }
    }
}

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
