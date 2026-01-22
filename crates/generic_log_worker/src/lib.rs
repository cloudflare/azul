// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

use base64::prelude::BASE64_STANDARD;
use base64::Engine;

pub mod batcher_do;
pub mod cleaner_do;
pub mod log_ops;
pub mod obs;
pub mod sequencer_do;
pub mod util;

pub use batcher_do::*;
pub use cleaner_do::*;
pub use log_ops::upload_issuers;
pub use sequencer_do::*;

use byteorder::{BigEndian, WriteBytesExt};
use log::{error, info};
use log_ops::UploadOptions;
use obs::metrics::{millis_diff_as_secs, AsF64, ObjectMetrics};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Write;
use std::time::Duration;
use tlog_tiles::{LookupKey, PendingLogEntry, SequenceMetadata};
use tokio::sync::Mutex;
use util::now_millis;
use worker::{
    js_sys, kv, kv::KvStore, wasm_bindgen, Bucket, Delay, Env, Error, HttpMetadata, Result, State,
    Storage, Stub,
};

use crate::obs::metrics::SequencerMetrics;

pub const SEQUENCER_BINDING: &str = "SEQUENCER";
pub const BATCHER_BINDING: &str = "BATCHER";
pub const CLEANER_BINDING: &str = "CLEANER";

const BATCH_ENDPOINT: &str = "/add_batch";
pub const ENTRY_ENDPOINT: &str = "/add_entry";

/// Initialize logging and panic handling for the Worker. This should be called
/// in the Worker's start event handler.
///
/// # Panics
///
/// Panics if the logger has already been initialized, which should never happen
/// due to the use of `sync::Once`.
pub fn init_logging(level: Option<&str>) {
    obs::logs::init(level);
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

/// Gets the value from the given DO storage backend with the given key. Returns `Ok(None)` if no such
/// key exists.
async fn get_maybe<T: DeserializeOwned>(storage: &Storage, key: &str) -> Result<Option<T>> {
    match storage.get::<T>(key).await {
        Ok(val) => Ok(Some(val)),
        // Return None if the result of the get is "No such value in storage."
        Err(Error::JsError(ref e)) if e == "No such value in storage." => Ok(None),
        Err(e) => Err(e),
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

/// Result of validating head/tail indices for the dedup cache ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeadTailValidation {
    /// The validated/corrected head index.
    head: u32,
    /// The original tail index (unchanged).
    tail: u32,
    /// Whether the head needed to be corrected.
    head_corrected: bool,
}

/// Validates and normalizes head/tail values for the dedup cache ring buffer.
/// Returns the corrected head value and whether a correction was needed.
fn validate_head_tail(
    head: u32,
    tail: u32,
    max_batches: u32,
    log_name: &str,
) -> HeadTailValidation {
    let mut corrected_head = head;
    let mut head_corrected = false;

    // Check that the head isn't somehow ahead of the tail. This should never happen.
    // At one batch per second, the tail would take 136 years to overflow.
    if corrected_head > tail {
        error!("{log_name}: cache head ({head}) is greater than tail ({tail}), setting to equal");
        corrected_head = tail;
        head_corrected = true;
    }

    // Check that tail is not too far ahead of head.
    // We can subtract safely because we checked for underflow above.
    if tail - corrected_head > max_batches {
        error!(
            "{log_name}: delta too high ({} > {}), setting head to tail - max_batches",
            tail - corrected_head,
            max_batches
        );
        corrected_head = tail.saturating_sub(max_batches);
        head_corrected = true;
    }

    HeadTailValidation {
        head: corrected_head,
        tail,
        head_corrected,
    }
}

/// Computes the storage keys to load for the dedup cache, bounded by max_batches.
/// Uses modular indexing to map logical indices to physical storage keys.
fn compute_cache_keys_to_load(head: u32, tail: u32, max_batches: u32) -> Vec<String> {
    // Ensure we never load more than max_batches keys, even if head/tail are corrupted
    let delta = tail.saturating_sub(head).min(max_batches);
    (0..delta)
        .map(|i| DedupCache::fifo_key((head.wrapping_add(i)) % max_batches))
        .collect()
}

impl DedupCache {
    // Batches are written at most once per second, and we only need them to
    // deduplicate entries long enough for KV's eventual consistency guarantees
    // (~60s). Cap at 128 so we can use a single get_multiple call to get all
    // batches at once.
    // https://developers.cloudflare.com/durable-objects/api/storage-api/#get
    const MAX_BATCHES: u32 = 128;
    const FIFO_HEAD_KEY: &str = "fifo:head";
    const FIFO_TAIL_KEY: &str = "fifo:tail";

    fn fifo_key(idx: u32) -> String {
        format!("fifo:{idx}")
    }

    // Load batches of cache entries from DO storage into the in-memory cache. log_name is the name
    // of the log this dedup cache belongs to (for debugging purposes)
    async fn load(&self, log_name: &str, metrics: &SequencerMetrics) -> Result<()> {
        // TODO: Find a cleaner way to do a dedup cache without an ever growing head/tail and error
        // conditions to manage. The storage SQL API with a time-based cache might be a good choice

        // Get the head and tail of the dedup cache, picking 0 if uninitialized
        let head = get_maybe::<u32>(&self.storage, Self::FIFO_HEAD_KEY)
            .await?
            .unwrap_or_default();
        let tail = get_maybe::<u32>(&self.storage, Self::FIFO_TAIL_KEY)
            .await?
            .unwrap_or_default();

        info!(
            "{log_name}: Dedup cache state: head={:?}, tail={:?}",
            head, tail
        );

        // Validate and correct head/tail if needed
        let validation = validate_head_tail(head, tail, Self::MAX_BATCHES, log_name);
        if validation.head_corrected {
            self.storage
                .put(Self::FIFO_HEAD_KEY, validation.head)
                .await?;
        }

        // Collect all the recent values from storage and put them in the memory backend.
        // compute_cache_keys_to_load guarantees we never load more than MAX_BATCHES keys.
        let keys = compute_cache_keys_to_load(validation.head, validation.tail, Self::MAX_BATCHES);
        let map = self.storage.get_multiple(keys).await?;
        for value in map.values() {
            let batch = serde_wasm_bindgen::from_value::<ByteBuf>(value?)?;
            self.memory
                .put_entries(&deserialize_entries(&batch.into_vec())?);
        }

        info!(
            "{log_name}: Loaded {} entries into dedup cache",
            self.memory.map.borrow().len()
        );
        metrics
            .dedup_cache_size
            .set(self.memory.map.borrow().len() as f64);

        Ok(())
    }

    // Store a batch of cache entries in DO storage.
    async fn store(&self, entries: &[(LookupKey, SequenceMetadata)]) -> Result<()> {
        // Get the head and tail of the dedup cache, picking 0 if uninitialized
        let head = get_maybe::<u32>(&self.storage, Self::FIFO_HEAD_KEY)
            .await?
            .unwrap_or_default();
        let tail = get_maybe::<u32>(&self.storage, Self::FIFO_TAIL_KEY)
            .await?
            .unwrap_or_default();

        // If the cache will have gotten too big after this store operation, evict some items at the
        // head. In practice, the delta never exceed MAX_BATCHES, but we handle the case where it
        // somehow gets larger too
        let delta = tail.saturating_sub(head);
        if delta >= Self::MAX_BATCHES {
            // Move the head up to at least tail - MAX_BATCHES + 1
            self.storage
                .put(
                    Self::FIFO_HEAD_KEY,
                    tail.saturating_sub(Self::MAX_BATCHES) + 1,
                )
                .await?;
        }

        // Insert at the tail (mod cache size)
        let insert_idx = tail % Self::MAX_BATCHES;
        self.storage
            .put::<&ByteBuf>(
                &Self::fifo_key(insert_idx),
                &ByteBuf::from(serialize_entries(entries)),
            )
            .await?;

        // Increment the tail
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
    if !buf.len().is_multiple_of(32) {
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

// R2 retry config: 3 retries with exponential backoff (100ms -> 200ms -> 400ms).
pub const R2_MAX_RETRIES: u32 = 3;
pub const R2_BASE_DELAY_MS: u64 = 100;

/// Retries an async operation with exponential backoff.
///
/// # Errors
///
/// Returns the last error if all retry attempts fail.
pub async fn with_retry<T, F, Fut>(max_retries: u32, base_delay_ms: u64, operation: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_error = None;
    for attempt in 0..=max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                if attempt < max_retries {
                    let delay_ms = base_delay_ms * (1 << attempt);
                    Delay::from(Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }
    Err(last_error.expect("with_retry: at least one attempt should have been made"))
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
        let content_type = opts
            .content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".into());
        let cache_control = if opts.immutable {
            "public, max-age=604800, immutable"
        } else {
            "no-store"
        };
        let value: Vec<u8> = data.into();
        let key_str = key.as_ref();
        self.metrics
            .as_ref()
            .inspect(|&m| m.upload_size_bytes.observe(value.len().as_f64()));

        with_retry(R2_MAX_RETRIES, R2_BASE_DELAY_MS, || async {
            let metadata = HttpMetadata {
                content_type: Some(content_type.clone()),
                cache_control: Some(cache_control.into()),
                ..Default::default()
            };
            self.bucket
                .put(key_str, value.clone())
                .http_metadata(metadata)
                .execute()
                .await
        })
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

    async fn fetch<S: AsRef<str>>(&self, key: S) -> Result<Option<Vec<u8>>> {
        let start = now_millis();
        let key_str = key.as_ref();
        let res = with_retry(R2_MAX_RETRIES, R2_BASE_DELAY_MS, || async {
            match self.bucket.get(key_str).execute().await? {
                Some(obj) => {
                    let body = obj
                        .body()
                        .ok_or_else(|| format!("missing object body: {}", key_str))?;
                    let bytes = body.bytes().await?;
                    Ok(Some(bytes))
                }
                None => Ok(None),
            }
        })
        .await
        .inspect_err(|_| {
            self.metrics
                .as_ref()
                .inspect(|&m| m.errors.with_label_values(&["get"]).inc());
        });
        self.metrics.as_ref().inspect(|&m| {
            m.duration
                .with_label_values(&["get"])
                .observe(millis_diff_as_secs(start, now_millis()));
        });
        res
    }
}

/// A read-only ObjectBucket that caches every fetch no matter how big
///
/// **NOTE:** The cache here has no size limit. If you use a `CachedRoObjectBucket` for too many
/// fetches, you will run out of memory.
pub struct CachedRoObjectBucket {
    bucket: ObjectBucket,
    cache: Mutex<BTreeMap<String, Option<Vec<u8>>>>,
}

impl CachedRoObjectBucket {
    pub fn new(bucket: ObjectBucket) -> Self {
        CachedRoObjectBucket {
            bucket,
            cache: Mutex::new(BTreeMap::new()),
        }
    }
}

impl ObjectBackend for CachedRoObjectBucket {
    async fn upload<S: AsRef<str>, D: Into<Vec<u8>>>(
        &self,
        _key: S,
        _data: D,
        _opts: &UploadOptions,
    ) -> Result<()> {
        unimplemented!("CachedRoObjectBucket does not implement ObjectBackend::upload")
    }

    async fn fetch<S: AsRef<str>>(&self, key: S) -> Result<Option<Vec<u8>>> {
        // See if the key is in the cache
        match self.cache.blocking_lock().entry(key.as_ref().to_string()) {
            // If so, return the value
            Entry::Occupied(oentry) => Ok(oentry.get().clone()),
            // Otherwise, fetch the value, cache it, and return it
            Entry::Vacant(ventry) => {
                let val = self.bucket.fetch(key).await?;
                ventry.insert(val.clone());
                Ok(val)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== HeadTailValidation Tests ====================

    #[test]
    fn test_validate_head_tail_normal() {
        // Normal case: head < tail, delta within bounds
        let result = validate_head_tail(10, 20, 128, "test");
        assert_eq!(result.head, 10);
        assert_eq!(result.tail, 20);
        assert!(!result.head_corrected);
    }

    #[test]
    fn test_validate_head_tail_empty_cache() {
        // Empty cache: head == tail == 0
        let result = validate_head_tail(0, 0, 128, "test");
        assert_eq!(result.head, 0);
        assert_eq!(result.tail, 0);
        assert!(!result.head_corrected);
    }

    #[test]
    fn test_validate_head_tail_head_equals_tail() {
        // head == tail (empty cache after some operations)
        let result = validate_head_tail(100, 100, 128, "test");
        assert_eq!(result.head, 100);
        assert_eq!(result.tail, 100);
        assert!(!result.head_corrected);
    }

    #[test]
    fn test_validate_head_tail_head_greater_than_tail() {
        // Corrupted state: head > tail
        let result = validate_head_tail(100, 50, 128, "test");
        assert_eq!(result.head, 50); // head reset to tail
        assert_eq!(result.tail, 50);
        assert!(result.head_corrected);
    }

    #[test]
    fn test_validate_head_tail_delta_too_large() {
        // INCIDENT SCENARIO: head=0, tail=4_000_000
        // This was the root cause of the 20-day outage
        let result = validate_head_tail(0, 4_000_000, 128, "test");
        assert_eq!(result.head, 4_000_000 - 128); // head moved up
        assert_eq!(result.tail, 4_000_000);
        assert!(result.head_corrected);
        assert!(result.tail - result.head <= 128);
    }

    #[test]
    fn test_validate_head_tail_delta_exactly_max() {
        // Edge case: delta exactly equals max_batches
        let result = validate_head_tail(0, 128, 128, "test");
        assert_eq!(result.head, 0);
        assert_eq!(result.tail, 128);
        assert!(!result.head_corrected);
    }

    #[test]
    fn test_validate_head_tail_delta_one_over_max() {
        // Edge case: delta is max_batches + 1
        let result = validate_head_tail(0, 129, 128, "test");
        assert_eq!(result.head, 1); // head moved up by 1
        assert_eq!(result.tail, 129);
        assert!(result.head_corrected);
    }

    #[test]
    fn test_validate_head_tail_with_different_max_batches() {
        // Test with a smaller max_batches value
        let result = validate_head_tail(0, 100, 10, "test");
        assert_eq!(result.head, 90);
        assert_eq!(result.tail, 100);
        assert!(result.head_corrected);
    }

    // ==================== compute_cache_keys_to_load Tests ====================

    #[test]
    fn test_compute_cache_keys_empty() {
        // Empty cache: head == tail
        let keys = compute_cache_keys_to_load(0, 0, 128);
        assert!(keys.is_empty());
    }

    #[test]
    fn test_compute_cache_keys_single_entry() {
        let keys = compute_cache_keys_to_load(0, 1, 128);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "fifo:0");
    }

    #[test]
    fn test_compute_cache_keys_multiple_entries() {
        let keys = compute_cache_keys_to_load(5, 10, 128);
        assert_eq!(keys.len(), 5);
        assert_eq!(keys[0], "fifo:5");
        assert_eq!(keys[1], "fifo:6");
        assert_eq!(keys[2], "fifo:7");
        assert_eq!(keys[3], "fifo:8");
        assert_eq!(keys[4], "fifo:9");
    }

    #[test]
    fn test_compute_cache_keys_bounded_by_max_batches() {
        // Even with a huge delta, keys should be bounded
        let keys = compute_cache_keys_to_load(0, 4_000_000, 128);
        assert_eq!(keys.len(), 128);
    }

    #[test]
    fn test_compute_cache_keys_wrapping() {
        // Test modular indexing when head is near the wrap point
        let keys = compute_cache_keys_to_load(126, 130, 128);
        assert_eq!(keys.len(), 4);
        assert_eq!(keys[0], "fifo:126");
        assert_eq!(keys[1], "fifo:127");
        assert_eq!(keys[2], "fifo:0"); // wrapped
        assert_eq!(keys[3], "fifo:1"); // wrapped
    }

    #[test]
    fn test_compute_cache_keys_head_greater_than_tail_returns_empty() {
        // If head > tail (corrupted), saturating_sub returns 0
        let keys = compute_cache_keys_to_load(100, 50, 128);
        assert!(keys.is_empty());
    }

    // ==================== serialize/deserialize_entries Tests ====================

    #[test]
    fn test_serialize_deserialize_entries_roundtrip() {
        let entries = vec![
            ([1u8; 16], (100u64, 200u64)),
            ([2u8; 16], (300u64, 400u64)),
            ([0xffu8; 16], (u64::MAX, u64::MAX)),
        ];
        let serialized = serialize_entries(&entries);
        let deserialized = deserialize_entries(&serialized).unwrap();
        assert_eq!(entries, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_empty() {
        let entries: Vec<(LookupKey, SequenceMetadata)> = vec![];
        let serialized = serialize_entries(&entries);
        assert!(serialized.is_empty());
        let deserialized = deserialize_entries(&serialized).unwrap();
        assert!(deserialized.is_empty());
    }

    #[test]
    fn test_deserialize_invalid_length() {
        let buf = vec![0u8; 31]; // Not a multiple of 32
        assert!(deserialize_entries(&buf).is_err());
    }

    #[test]
    fn test_deserialize_invalid_length_one_extra() {
        let buf = vec![0u8; 33]; // 32 + 1
        assert!(deserialize_entries(&buf).is_err());
    }

    // ==================== MemoryCache Tests ====================

    #[test]
    fn test_memory_cache_basic_get_put() {
        let cache = MemoryCache::new(10);
        let key = [1u8; 16];
        let metadata = (42u64, 1000u64);

        assert!(cache.get_entry(&key).is_none());
        cache.put_entries(&[(key, metadata)]);
        assert_eq!(cache.get_entry(&key), Some(metadata));
    }

    #[test]
    fn test_memory_cache_multiple_entries() {
        let cache = MemoryCache::new(10);
        let entries: Vec<(LookupKey, SequenceMetadata)> = (0..5u8)
            .map(|i| ([i; 16], (i as u64, i as u64 * 100)))
            .collect();

        cache.put_entries(&entries);

        for (key, metadata) in &entries {
            assert_eq!(cache.get_entry(key), Some(*metadata));
        }
    }

    #[test]
    fn test_memory_cache_eviction() {
        let cache = MemoryCache::new(3);

        // Add 5 entries to a cache with max size 3
        for i in 0..5u8 {
            let key = [i; 16];
            cache.put_entries(&[(key, (i as u64, 0))]);
        }

        // First 2 entries should be evicted (FIFO order)
        assert!(cache.get_entry(&[0u8; 16]).is_none());
        assert!(cache.get_entry(&[1u8; 16]).is_none());
        // Last 3 should remain
        assert!(cache.get_entry(&[2u8; 16]).is_some());
        assert!(cache.get_entry(&[3u8; 16]).is_some());
        assert!(cache.get_entry(&[4u8; 16]).is_some());
    }

    #[test]
    fn test_memory_cache_duplicate_key_not_added() {
        let cache = MemoryCache::new(10);
        let key = [1u8; 16];

        cache.put_entries(&[(key, (100, 200))]);
        cache.put_entries(&[(key, (999, 999))]); // Duplicate, should be ignored

        // Original value should be preserved
        assert_eq!(cache.get_entry(&key), Some((100, 200)));
    }

    #[test]
    fn test_memory_cache_batch_put() {
        let cache = MemoryCache::new(5);
        let entries: Vec<(LookupKey, SequenceMetadata)> =
            (0..3u8).map(|i| ([i; 16], (i as u64, 0))).collect();

        cache.put_entries(&entries);

        assert_eq!(cache.map.borrow().len(), 3);
        assert_eq!(cache.fifo.borrow().len(), 3);
    }

    // ==================== DedupCache::fifo_key Tests ====================

    #[test]
    fn test_fifo_key_generation() {
        assert_eq!(DedupCache::fifo_key(0), "fifo:0");
        assert_eq!(DedupCache::fifo_key(127), "fifo:127");
        assert_eq!(DedupCache::fifo_key(128), "fifo:128");
        assert_eq!(DedupCache::fifo_key(u32::MAX), format!("fifo:{}", u32::MAX));
    }
}
