// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

use base64::prelude::BASE64_STANDARD;
use base64::Engine;

pub mod batcher_do;
pub mod cleaner_do;
pub mod log_ops;
mod metrics;
pub mod sequencer_do;
pub mod util;

pub use batcher_do::*;
pub use cleaner_do::*;
pub use log_ops::upload_issuers;
pub use sequencer_do::*;

use byteorder::{BigEndian, WriteBytesExt};
use log::Level;
use log_ops::UploadOptions;
use metrics::{millis_diff_as_secs, AsF64, ObjectMetrics};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::str::FromStr;
use std::sync::Once;
use tlog_tiles::{LookupKey, PendingLogEntry, SequenceMetadata};
use util::now_millis;
use worker::{
    js_sys, kv, kv::KvStore, wasm_bindgen, Bucket, Env, Error, HttpMetadata, Result, State,
    Storage, Stub,
};

pub const SEQUENCER_BINDING: &str = "SEQUENCER";
pub const BATCHER_BINDING: &str = "BATCHER";
pub const CLEANER_BINDING: &str = "CLEANER";

const BATCH_ENDPOINT: &str = "/add_batch";
pub const ENTRY_ENDPOINT: &str = "/add_entry";
pub const METRICS_ENDPOINT: &str = "/metrics";

static INIT_LOGGING: Once = Once::new();

/// Initialize logging and panic handling for the Worker. This should be called
/// in the Worker's start event handler.
///
/// # Panics
///
/// Panics if the logger has already been initialized, which should never happen
/// due to the use of `sync::Once`.
pub fn init_logging(level: Option<&str>) {
    let level = level
        .and_then(|level| Level::from_str(level).ok())
        .unwrap_or(Level::Info);
    console_error_panic_hook::set_once();
    INIT_LOGGING.call_once(|| {
        console_log::init_with_level(level).expect("error initializing logger");
    });
}

/// Wrapper around `bitcode::serialize`.
///
/// # Errors
/// Will return a `worker::Error` wrapping any serialization errors.
pub fn serialize<T>(t: &T) -> Result<Vec<u8>>
where
    T: Serialize + ?Sized,
{
    bitcode::serialize(t).map_err(|e| Error::RustError(e.to_string()))
}

/// Wrapper around `bitcode::deserialize`.
///
/// # Errors
/// Will return a `worker::Error` wrapping any deserialization errors.
pub fn deserialize<'de, T>(bytes: &'de [u8]) -> Result<T>
where
    T: Deserialize<'de>,
{
    bitcode::deserialize::<T>(bytes).map_err(|e| Error::RustError(e.to_string()))
}

/// Get the name for this Durable Object enumerating all possibilities.
///
/// # Panics
/// Panics if the name can't be found (e.g., if the wrong binding is used).
pub fn get_durable_object_name<'a>(
    env: &Env,
    state: &State,
    binding: &str,
    name_shard_tuples: &mut impl Iterator<Item = (&'a str, u8)>,
) -> &'a str {
    let id = state.id();
    let namespace = env.durable_object(binding).unwrap();

    let (name, _) = name_shard_tuples
        .find(|(name, num_shards)| {
            if *num_shards > 0 {
                for shard_id in 0..*num_shards {
                    if id
                        == namespace
                            .id_from_name(&format!("{name}_{shard_id:x}"))
                            .unwrap()
                    {
                        return true;
                    }
                }
                false
            } else {
                id == namespace.id_from_name(name).unwrap()
            }
        })
        .expect("unable to find durable object name");
    name
}

/// Retrieve a Durable Object stub for the given parameters.
///
/// # Errors
///
/// Errors if the stub cannot be retrieved, for example if the location hint
/// corresponds to an invalid location.
pub fn get_durable_object_stub(
    env: &Env,
    name: &str,
    shard_id: Option<u8>,
    binding: &str,
    location_hint: Option<&str>,
) -> Result<Stub> {
    let namespace = env.durable_object(binding)?;
    let object_name = if let Some(id) = shard_id {
        &format!("{name}_{id:x}")
    } else {
        name
    };
    let object_id = namespace.id_from_name(object_name)?;
    if let Some(hint) = location_hint {
        Ok(object_id.get_stub_with_location_hint(hint)?)
    } else {
        Ok(object_id.get_stub()?)
    }
}

/// Return a handle for the public R2 bucket from which to serve this log's
/// static assets.
///
/// # Errors
///
/// Returns an error if the handle for the bucket cannot be created, for example
/// if the bucket does not exist.
pub fn load_public_bucket(env: &Env, name: &str) -> Result<Bucket> {
    env.bucket(&format!("public_{name}"))
}

/// Returns a handle for the KV namespace to use for this log's deduplication
/// cache.
///
/// # Errors
///
/// Returns an error if the handle for the KV namespace cannot be created, for
/// example if the namespace does not exist.
pub fn load_cache_kv(env: &Env, name: &str) -> Result<kv::KvStore> {
    env.kv(&format!("cache_{name}"))
}

/// Given a pending entry, returns the corresponding metadata from the dedup
/// cache, if it exists.
///
/// # Errors
///
/// Returns an error if there are issues retrieving the metadata.
pub async fn get_cached_metadata(
    kv: &KvStore,
    lookup_key: &LookupKey,
) -> Result<Option<SequenceMetadata>> {
    // Query the cache and return the entry metadata if it exists
    let metadata_opt = kv
        .get(&BASE64_STANDARD.encode(lookup_key))
        .bytes_with_metadata::<SequenceMetadata>()
        .await?
        .1;
    Ok(metadata_opt)
}

/// Makes an empty entry in the dedup cache with `pending.lookup_key()` as the
/// key, and `metadata` as the metadata.
///
/// # Errors
///
/// Returns an error if either the KV namespace doesn't exist, or if there is an
/// exception when writing the value.
pub async fn put_cache_entry_metadata<L: PendingLogEntry>(
    kv: &KvStore,
    pending: &L,
    metadata: SequenceMetadata,
) -> Result<()> {
    // Get the lookup key.
    let lookup_key = pending.lookup_key();

    // Store key => "", with metadata
    kv.put(&BASE64_STANDARD.encode(lookup_key), "")?
        .metadata::<SequenceMetadata>(metadata)?
        .execute()
        .await
        .map_err(Error::from)
}

trait CacheWrite {
    /// Put the provided sequenced entries into the cache. This does NOT overwrite existing entries.
    async fn put_entries(&self, entries: &[(LookupKey, SequenceMetadata)]) -> Result<()>;
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
    async fn put_entries(&self, entries: &[(LookupKey, SequenceMetadata)]) -> Result<()> {
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
    async fn load(&self) -> Result<()> {
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
    async fn store(&self, entries: &[(LookupKey, SequenceMetadata)]) -> Result<()> {
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
    map: RefCell<HashMap<LookupKey, SequenceMetadata>>,
    fifo: RefCell<VecDeque<LookupKey>>,
}

impl MemoryCache {
    fn new(max_size: usize) -> Self {
        assert_ne!(max_size, 0);
        Self {
            max_size,
            fifo: RefCell::new(VecDeque::with_capacity(max_size)),
            map: RefCell::new(HashMap::with_capacity(max_size)),
        }
    }

    // Get an entry from the in-memory cache.
    fn get_entry(&self, key: &LookupKey) -> Option<SequenceMetadata> {
        self.map.borrow().get(key).copied()
    }

    // Put a batch of entries into the in-memory cache,
    // evicting old entries to make room if necessary.
    fn put_entries(&self, entries: &[(LookupKey, SequenceMetadata)]) {
        let mut map = self.map.borrow_mut();
        let mut fifo = self.fifo.borrow_mut();
        for (key, value) in entries {
            if map.contains_key(key) {
                continue;
            }
            if map.len() == self.max_size {
                // Evict oldest entry to make room.
                map.remove(&fifo.pop_front().unwrap());
            }
            fifo.push_back(*key);
            map.insert(*key, *value);
        }
    }
}

// Compare-and-swap backend.
trait LockBackend {
    const MAX_PART_BYTES: usize;
    const MAX_PARTS: usize;
    async fn put_multipart(&self, key: &str, value: &[u8]) -> Result<()>;
    async fn get_multipart(&self, key: &str) -> Result<Vec<u8>>;
    async fn put(&self, key: &str, value: &[u8]) -> Result<()>;
    async fn swap(&self, key: &str, old: &[u8], new: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
}

impl LockBackend for State {
    // DO value size limit is 2MB.
    // https://developers.cloudflare.com/durable-objects/platform/limits/
    const MAX_PART_BYTES: usize = 1 << 21;
    // KV API supports putting and getting up to 128 values at a time. If this
    // is ever exceeded, the Worker has already run out of memory.
    // https://developers.cloudflare.com/durable-objects/api/storage-api/#kv-api
    const MAX_PARTS: usize = 128;

    // Write a value to DO storage in multiple parts, each limited to
    // `MAX_PART_BYTES` bytes. Also write a manifest file that includes the
    // total length of the value and a checksum.
    async fn put_multipart(&self, key: &str, value: &[u8]) -> Result<()> {
        if value.len() > Self::MAX_PART_BYTES * Self::MAX_PARTS {
            return Err("value too large".into());
        }
        let len_bytes = u32::try_from(value.len())
            .map_err(|e| e.to_string())?
            .to_be_bytes();
        let manifest = len_bytes
            .into_iter()
            .chain(Sha256::digest(value))
            .collect::<Vec<u8>>();
        self.storage().put(key, manifest).await?;

        // Encode keys suffixes as two hex digits so they'll be in the correct
        // order when sorted in increasing order of UTF-8 encodings.
        let key_iter = (0..).map(|i| format!("{key}_{i:02x}"));
        let obj = js_sys::Object::new();
        for (k, v) in key_iter.zip(value.chunks(Self::MAX_PART_BYTES)) {
            let value = js_sys::Uint8Array::new_with_length(
                u32::try_from(v.len()).map_err(|_| "u32 conversion failed")?,
            );
            value.copy_from(v);
            js_sys::Reflect::set(&obj, &wasm_bindgen::JsValue::from_str(&k), &value.into())?;
        }
        self.storage().put_multiple_raw(obj).await
    }

    // Read a value from DO storage that is split across multiple parts.
    // First read a manifest containing the full length and checksum, then
    // get the values.
    async fn get_multipart(&self, key: &str) -> Result<Vec<u8>> {
        let manifest = self.storage().get::<Vec<u8>>(key).await?;
        if manifest.len() != 4 + 32 {
            return Err("invalid manifest length".into());
        }
        let len = u32::from_be_bytes(
            manifest[..4]
                .try_into()
                .map_err(|_| "u32 conversion failed")?,
        ) as usize;
        let checksum: [u8; 32] = manifest[4..4 + 32]
            .try_into()
            .map_err(|_| "slice conversion failed")?;
        if len > Self::MAX_PART_BYTES * Self::MAX_PARTS {
            return Err("value too large".into());
        }
        let mut result = Vec::with_capacity(len);
        let keys = (0..len.div_ceil(Self::MAX_PART_BYTES))
            .map(|i| format!("{key}_{i:02x}"))
            .collect::<Vec<_>>();
        // Keys in the map are sorted in increasing order of UTF-8 encodings, so we
        // can just append the values.
        // https://developers.cloudflare.com/durable-objects/api/storage-api/#kv-api
        let parts_map = self.storage().get_multiple(keys).await?;
        for value in parts_map.values() {
            result.extend(serde_wasm_bindgen::from_value::<Vec<u8>>(value?)?);
        }

        if checksum != *Sha256::digest(&result) {
            return Err("checksum failed".into());
        }
        Ok(result)
    }
    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.storage().put(key, value).await
    }
    async fn swap(&self, key: &str, expected_old: &[u8], new: &[u8]) -> Result<()> {
        let old = self.storage().get::<Vec<u8>>(key).await?;
        if old != expected_old {
            return Err("old value does not match expected".into());
        }
        self.put(key, new).await
    }
    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.storage().get::<Vec<u8>>(key).await
    }
}

pub trait ObjectBackend {
    /// Upload the object with the given key and data to the object backend,
    /// adding additional HTTP metadata headers based on the provided options.
    ///
    /// # Errors
    ///
    /// Will return an error if the put operation fails.
    #[allow(async_fn_in_trait)]
    async fn upload<S: AsRef<str>, D: Into<Vec<u8>>>(
        &self,
        key: S,
        data: D,
        opts: &UploadOptions,
    ) -> Result<()>;

    /// Fetch the object with the given key from the object backend. Returns the
    /// object body bytes if the object exists, or otherwise None.
    ///
    /// # Errors
    ///
    /// Will return an error if bucket get operation fails or if the returned
    /// object is missing a body.
    #[allow(async_fn_in_trait)]
    async fn fetch<S: AsRef<str>>(&self, key: S) -> Result<Option<Vec<u8>>>;
}

pub struct ObjectBucket {
    bucket: Bucket,
    metrics: Option<ObjectMetrics>,
}

impl ObjectBucket {
    pub fn new(bucket: Bucket) -> Self {
        ObjectBucket {
            bucket,
            metrics: None,
        }
    }
}

impl ObjectBackend for ObjectBucket {
    async fn upload<S: AsRef<str>, D: Into<Vec<u8>>>(
        &self,
        key: S,
        data: D,
        opts: &UploadOptions,
    ) -> Result<()> {
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
            metadata.cache_control = Some("no-store".into());
        }
        let value: Vec<u8> = data.into();
        self.metrics
            .as_ref()
            .inspect(|&m| m.upload_size_bytes.observe(value.len().as_f64()));
        self.bucket
            .put(key.as_ref(), value.clone())
            .http_metadata(metadata)
            .execute()
            .await
            .inspect_err(|_| {
                self.metrics
                    .as_ref()
                    .inspect(|&m| m.errors.with_label_values(&["put"]).inc());
            })?;

        // SAFETY: immediately fetch the uploaded object to make sure that it was persisted.
        // TODO: sentry reporting
        if let Some(fetched) = self.fetch(key.as_ref()).await? {
            if fetched != value {
                return Err(Error::RustError(format!(
                    "tile persisted with wrong contents: {}",
                    key.as_ref()
                )));
            }
        } else {
            return Err(Error::RustError(format!(
                "tile not persisted: {}",
                key.as_ref()
            )));
        }

        self.metrics.as_ref().inspect(|&m| {
            m.duration
                .with_label_values(&["put"])
                .observe(millis_diff_as_secs(start, now_millis()));
        });
        Ok(())
    }

    async fn fetch<S: AsRef<str>>(&self, key: S) -> Result<Option<Vec<u8>>> {
        let start = now_millis();
        let res = match self.bucket.get(key.as_ref()).execute().await? {
            Some(obj) => {
                let body = obj
                    .body()
                    .ok_or_else(|| format!("missing object body: {}", key.as_ref()))?;
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
