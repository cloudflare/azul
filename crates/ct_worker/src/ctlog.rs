// Ported from "sunlight" (https://github.com/FiloSottile/sunlight)
// Copyright 2023 The Sunlight Authors
// Licensed under ISC License found in the LICENSE file or at https://opensource.org/license/isc-license-txt
//
// This ports code from the original Go project "sunlight" and adapts it to Rust idioms.
//
// Modifications and Rust implementation Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Core functionality for a [Static CT API](https://c2sp.org/static-ct-api) log, including
//! creating and loading logs from persistent storage, adding leaves to logs, and sequencing logs.
//!
//! This file contains code ported from the original project [sunlight](https://github.com/FiloSottile/sunlight).
//!
//! References:
//! - [http.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/internal/ctlog/http.go)
//! - [ctlog.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/internal/ctlog/ctlog.go)
//! - [ctlog_test.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/internal/ctlog/ctlog_test.go)
//! - [testlog_test.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/internal/ctlog/testlog_test.go)

use crate::{
    ctlog,
    metrics::{millis_diff_as_secs, AsF64, Metrics},
    util::now_millis,
    CacheRead, CacheWrite, LockBackend, LookupKey, ObjectBackend, SequenceMetadata,
};
use anyhow::{anyhow, bail};
use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use futures_util::future::try_join_all;
use log::{debug, error, info, trace, warn};
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use static_ct_api::{LogEntry, TileIterator, TreeWithTimestamp, TILE_HEIGHT, TILE_WIDTH};
use std::time::Duration;
use std::{
    cmp::{Ord, Ordering},
    sync::LazyLock,
};
use std::{collections::HashMap, fmt::Write};
use thiserror::Error;
use tlog_tiles::{Error as TlogError, Hash, HashReader, Tile, HASH_SIZE};
use tokio::sync::watch::{self, Receiver, Sender};

/// The maximum tile level is 63 (<c2sp.org/static-ct-api>), so safe to use [`u8::MAX`] as
/// the special level for data tiles. The Go implementation uses -1.
const DATA_TILE_KEY: u8 = u8::MAX;
const CHECKPOINT_KEY: &str = "checkpoint";

/// Configuration for a CT log.
#[derive(Clone)]
pub(crate) struct LogConfig {
    pub(crate) name: String,
    pub(crate) origin: String,
    pub(crate) signing_key: EcdsaSigningKey,
    pub(crate) witness_key: Ed25519SigningKey,
    pub(crate) pool_size: usize,
    pub(crate) sequence_interval: Duration,
}

/// Ephemeral state for pooling entries to the CT log.
///
/// The pool is written to by `add_leaf_to_pool`, and by the sequencer
/// when rotating `current_pool` and `in_sequencing`.
///
/// As long as the above-mentioned blocks run synchronously (no 'await's), Durable Objects'
/// single-threaded execution guarantees that `add_leaf_to_pool` will never add to a pool that
/// already started sequencing, and that cache reads will see entries from older pools before
/// they are rotated out of `in_sequencing`.
/// <https://blog.cloudflare.com/durable-objects-easy-fast-correct-choose-three/#background-durable-objects-are-single-threaded>
#[derive(Default, Debug)]
pub(crate) struct PoolState {
    current_pool: Pool,
    // in_sequencing is the [Pool::by_hash] map of the pool that's currently being
    // sequenced. These entries might not be sequenced yet or might not yet be
    // committed to the deduplication cache.
    in_sequencing: HashMap<LookupKey, u64>,
    in_sequencing_done: Option<Receiver<SequenceMetadata>>,
}

// State owned by the sequencing loop.
#[derive(Debug)]
pub(crate) struct SequenceState {
    tree: TreeWithTimestamp,
    checkpoint: Vec<u8>,
    // edge_tiles is a map from level to the right-most tile of that level.
    edge_tiles: HashMap<u8, TileWithBytes>,
}

/// A description of a transparency log tile along with the contained bytes.
#[derive(Clone, Default, Debug)]
struct TileWithBytes {
    tile: Tile,
    b: Vec<u8>,
}

/// An error that can occur when creating a log.
#[derive(Error, Debug)]
pub(crate) enum CreateError {
    #[error("log exists")]
    LogExists,
    #[error("failed to create log: {}", .0)]
    Other(#[from] anyhow::Error),
}

/// Create a log, updating the object and lock backends.
/// This should only ever need to be called once but is safe to call multiple times.
///
/// If the log already exists, returns an [`CreateError::LogExists`]
/// to allow the caller to differentiate it from other errors.
pub(crate) async fn create_log(
    config: &LogConfig,
    object: &impl ObjectBackend,
    lock: &impl LockBackend,
) -> Result<(), CreateError> {
    let name = &config.name;
    if lock.get(CHECKPOINT_KEY).await.is_ok() {
        return Err(CreateError::LogExists);
    }
    if object
        .fetch(CHECKPOINT_KEY)
        .await
        .map_err(|e| anyhow!("failed to retrieve checkpoint from object storage: {}", e))?
        .is_some()
    {
        return Err(
            anyhow!("checkpoint missing from database but present in object storage").into(),
        );
    }

    let timestamp = now_millis();
    let tree = TreeWithTimestamp::new(0, tlog_tiles::EMPTY_HASH, timestamp);
    let sth = tree
        .sign(
            &config.origin,
            &config.signing_key,
            &config.witness_key,
            &mut rand::thread_rng(),
        )
        .map_err(|e| anyhow!("failed to sign checkpoint: {}", e))?;
    lock.put(CHECKPOINT_KEY, &sth)
        .await
        .map_err(|e| anyhow!("failed to upload checkpoint to lock backend: {}", e))?;
    object
        .upload(CHECKPOINT_KEY, &sth, &OPTS_CHECKPOINT)
        .await
        .map_err(|e| anyhow!("failed to upload checkpoint to object backend: {}", e))?;

    info!("{name}: Created log; timestamp={timestamp}");
    Ok(())
}

impl SequenceState {
    /// Loads the sequencing state for a log from object and lock backends.
    /// This is called when initially loading a log (e.g., when it is started on a new machine),
    /// and when reloading (e.g., to recover after a fatal sequencing error).
    ///
    /// This will return an error if the log has not been created, or if recovery fails.
    pub(crate) async fn load(
        config: &LogConfig,
        object: &impl ObjectBackend,
        lock: &impl LockBackend,
    ) -> Result<Self, anyhow::Error> {
        // Load the checkpoint from the DO storage. If we crashed during serialization, the one
        // in DO storage is going to be the latest.
        let stored_checkpoint = lock.get(CHECKPOINT_KEY).await?;
        let name = &config.name;
        debug!(
            "{name}: Loaded checkpoint; checkpoint={}",
            std::str::from_utf8(&stored_checkpoint)?
        );
        let (c, timestamp) = static_ct_api::open_checkpoint(
            &config.origin,
            config.signing_key.verifying_key(),
            &config.witness_key.verifying_key(),
            now_millis(),
            &stored_checkpoint,
        )?;

        // Load the checkpoint from the object storage backend, verify it, and compare it to the
        // DO storage checkpoint.
        let sth = object
            .fetch(CHECKPOINT_KEY)
            .await?
            .ok_or(anyhow!("no checkpoint in object storage"))?;
        debug!(
            "{name}: Loaded checkpoint from object storage; checkpoint={}",
            std::str::from_utf8(&stored_checkpoint)?
        );
        let (c1, _) = static_ct_api::open_checkpoint(
            &config.origin,
            config.signing_key.verifying_key(),
            &config.witness_key.verifying_key(),
            now_millis(),
            &sth,
        )?;

        match (Ord::cmp(&c1.size(), &c.size()), c1.hash() == c.hash()) {
            (Ordering::Equal, false) => {
                bail!(
                    "{name}: checkpoint hash mismatch: {} != {}",
                    c1.hash(),
                    c.hash()
                )
            }
            (Ordering::Greater, _) => bail!(
                "{name}: checkpoint in object storage is newer than DO storage checkpoint: {} > {}",
                c1.size(),
                c.size()
            ),
            (Ordering::Less, _) => {
                // It's possible that we crashed between committing a new checkpoint to DO storage and
                // uploading it to the object storage backend. Apply the staged tiles before continuing.
                warn!(
                    "{name}: Checkpoint in object storage is older than DO storage checkpoint; old_size={}, size={}", c1.size(), c.size()
                );
                let staged_uploads = object
                    .fetch(&staging_path(c.size(), c.hash()))
                    .await?
                    .ok_or(anyhow!("no staging uploads in object storage"))?;
                apply_staged_uploads(object, &staged_uploads).await?;
            }
            (Ordering::Equal, true) => {} // Normal case: the sizes are the same and the hashes match.
        }

        // Fetch the tiles on the right edge, and verify them against the checkpoint.
        let mut edge_tiles = HashMap::new();
        if c.size() > 0 {
            // Fetch the right-most edge tiles by reading the last leaf. TileHashReader will fetch
            // and verify the right tiles as a side-effect.
            edge_tiles = read_edge_tiles(object, c.size(), c.hash()).await?;

            // Fetch the right-most data tile.
            let mut data_tile = edge_tiles
                .get(&0)
                .ok_or(anyhow!("no level 0 tile found"))?
                .clone();
            data_tile.tile.set_is_data();
            data_tile.b = object
                .fetch(&static_ct_api::tile_path(&data_tile.tile))
                .await?
                .ok_or(anyhow!("no data tile in object storage"))?;
            edge_tiles.insert(DATA_TILE_KEY, data_tile.clone());

            // Verify the data tile against the level 0 tile.
            let start = u64::from(TILE_WIDTH) * data_tile.tile.level_index();
            for (i, entry) in TileIterator::new(
                edge_tiles.get(&DATA_TILE_KEY).unwrap().b.clone(),
                data_tile.tile.width() as usize,
            )
            .enumerate()
            {
                let got = tlog_tiles::record_hash(&entry?.merkle_tree_leaf());
                let exp = edge_tiles.get(&0).unwrap().tile.hash_at_index(
                    &edge_tiles.get(&0).unwrap().b,
                    tlog_tiles::stored_hash_index(0, start + i as u64),
                )?;
                if got != exp {
                    bail!(
                        "tile leaf entry {} hashes to {got}, level 0 hash is {exp}",
                        start + i as u64,
                    );
                }
            }
        }

        for tile in &edge_tiles {
            trace!("{name}: Edge tile; tile={tile:?}");
        }

        info!(
            "{name}: Loaded log; size={}, timestamp={timestamp}",
            c.size()
        );

        Ok(Self {
            edge_tiles,
            tree: TreeWithTimestamp::new(c.size(), *c.hash(), timestamp),
            checkpoint: stored_checkpoint,
        })
    }
}

/// Result of an [`add_leaf_to_pool`] request containing either a cached log
/// entry or a pending entry that must be resolved.
pub(crate) enum AddLeafResult {
    Cached(SequenceMetadata),
    Pending((u64, Receiver<SequenceMetadata>)),
    RateLimited,
}

impl AddLeafResult {
    /// Resolve an `AddLeafResult` to a leaf entry, or None if the
    /// entry was not sequenced.
    pub(crate) async fn resolve(self) -> Option<SequenceMetadata> {
        match self {
            AddLeafResult::Cached(entry) => Some(entry),
            AddLeafResult::Pending((pool_index, mut rx)) => {
                // Wait until sequencing completes for this entry's pool.
                if rx.changed().await.is_ok() {
                    let (first_index, timestamp) = *rx.borrow();
                    Some((first_index + pool_index, timestamp))
                } else {
                    warn!("sender dropped");
                    None
                }
            }
            AddLeafResult::RateLimited => None,
        }
    }
}
pub(crate) enum AddLeafResultSource {
    InSequencing,
    Pool,
    Cache,
    Sequencer,
    RateLimit,
}

impl std::fmt::Display for AddLeafResultSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddLeafResultSource::InSequencing => write!(f, "sequencing"),
            AddLeafResultSource::Pool => write!(f, "pool"),
            AddLeafResultSource::Cache => write!(f, "cache"),
            AddLeafResultSource::Sequencer => write!(f, "sequencer"),
            AddLeafResultSource::RateLimit => write!(f, "ratelimit"),
        }
    }
}

/// Add a leaf (a certificate or pre-certificate) to the pool of pending entries.
///
/// If the entry is has already been sequenced and is in the cache, return immediately
/// with a [`AddLeafResult::Cached`]. If the pool is full, return
/// [`AddLeafResult::RateLimited`]. Otherwise, return a [`AddLeafResult::Pending`] which
/// can be resolved once the entry has been sequenced.
pub(crate) fn add_leaf_to_pool(
    state: &mut PoolState,
    pool_size: usize,
    cache: &impl CacheRead,
    leaf: &LogEntry,
) -> (AddLeafResult, AddLeafResultSource) {
    let hash = compute_cache_hash(leaf.is_precert, &leaf.certificate, &leaf.issuer_key_hash);
    let pool_index: u64;
    let rx: Receiver<SequenceMetadata>;
    let source: AddLeafResultSource;

    if let Some(index) = state.in_sequencing.get(&hash) {
        // Entry is being sequenced.
        pool_index = *index;
        rx = state.in_sequencing_done.clone().unwrap();
        source = AddLeafResultSource::InSequencing;
    } else if let Some(index) = state.current_pool.by_hash.get(&hash) {
        // Entry is already pending.
        pool_index = *index;
        rx = state.current_pool.done.subscribe();
        source = AddLeafResultSource::Pool;
    } else if let Some(v) = cache.get_entry(&hash) {
        // Entry is cached.
        return (AddLeafResult::Cached(v), AddLeafResultSource::Cache);
    } else {
        // This is a new entry. Add it to the pool.
        if pool_size > 0 && state.current_pool.pending_leaves.len() >= pool_size {
            return (AddLeafResult::RateLimited, AddLeafResultSource::RateLimit);
        }
        state.current_pool.pending_leaves.push(leaf.clone());
        pool_index = (state.current_pool.pending_leaves.len() as u64) - 1;
        state.current_pool.by_hash.insert(hash, pool_index);
        rx = state.current_pool.done.subscribe();
        source = AddLeafResultSource::Sequencer;
    };

    (AddLeafResult::Pending((pool_index, rx)), source)
}

/// Uploads any newly-observed issuers to the object backend, returning the paths of those uploaded.
pub(crate) async fn upload_issuers(
    object: &impl ObjectBackend,
    issuers: &[&[u8]],
    name: &str,
) -> worker::Result<()> {
    let issuer_futures: Vec<_> = issuers
        .iter()
        .map(|issuer| async move {
            let fingerprint: [u8; 32] = Sha256::digest(issuer).into();
            let path = format!("issuer/{}", hex::encode(fingerprint));

            if let Some(old) = object.fetch(&path).await? {
                if old != *issuer {
                    return Err(worker::Error::RustError(format!(
                        "invalid existing issuer: {}",
                        hex::encode(old)
                    )));
                }
                Ok(None)
            } else {
                object.upload(&path, issuer, &OPTS_ISSUER).await?;
                Ok(Some(path))
            }
        })
        .collect();

    for path in try_join_all(issuer_futures)
        .await?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
    {
        {
            info!("{name}: Observed new issuer; path={path}");
        }
    }

    Ok(())
}

/// Sequences the current pool of pending entries in the ephemeral state.
pub(crate) async fn sequence(
    pool_state: &mut PoolState,
    sequence_state: &mut Option<SequenceState>,
    config: &LogConfig,
    object: &impl ObjectBackend,
    lock: &impl LockBackend,
    cache: &mut impl CacheWrite,
    metrics: &Metrics,
) -> Result<(), anyhow::Error> {
    let mut p = std::mem::take(&mut pool_state.current_pool);
    pool_state.in_sequencing = std::mem::take(&mut p.by_hash);
    pool_state.in_sequencing_done = Some(p.done.subscribe());

    metrics
        .seq_pool_size
        .observe(p.pending_leaves.len().as_f64());

    let result =
        match sequence_pool(sequence_state, config, object, lock, cache, &mut p, metrics).await {
            Ok(()) => {
                metrics.seq_count.with_label_values(&[""]).inc();
                Ok(())
            }
            Err(SequenceError::Fatal(e)) => {
                // Clear ephemeral sequencing state, as it may no longer be valid.
                // It will be loaded again the next time sequence_pool is called.
                metrics.seq_count.with_label_values(&["fatal"]).inc();
                error!("{}: Fatal sequencing error {e}", config.name);
                *sequence_state = None;
                Err(anyhow!(e))
            }
            Err(SequenceError::NonFatal(e)) => {
                metrics.seq_count.with_label_values(&["non-fatal"]).inc();
                error!("{}: Non-fatal sequencing error {e}", config.name);
                Ok(())
            }
        };

    // Once [sequence_pool] returns, the entries are either in the deduplication
    // cache or finalized with an error. In the latter case, we don't want
    // a resubmit to deduplicate against the failed sequencing.
    pool_state.in_sequencing.clear();
    pool_state.in_sequencing_done = None;

    result
}

/// An error that can occur when sequencing a pool.
#[derive(Error, Debug)]
enum SequenceError {
    #[error("fatal sequencing error: {}", .0)]
    Fatal(String),
    #[error("non-fatal sequencing error: {}", .0)]
    NonFatal(String),
}

/// Sequences the passed-in pool of entries.
/// If the sequencing completes successfully, pending requests are notified.
/// If a non-fatal sequencing error occurs, pending requests will receive an error but the log will continue as normal.
/// If a fatal sequencing error occurs, the ephemeral log state must be reloaded before the next sequencing.
#[allow(clippy::too_many_lines)]
async fn sequence_pool(
    sequence_state: &mut Option<SequenceState>,
    config: &LogConfig,
    object: &impl ObjectBackend,
    lock: &impl LockBackend,
    cache: &mut impl CacheWrite,
    p: &mut Pool,
    metrics: &Metrics,
) -> Result<(), SequenceError> {
    let start = now_millis();
    // Retrieve old sequencing state.
    let old = match &sequence_state {
        Some(s) => s,
        None => &SequenceState::load(config, object, lock)
            .await
            .map_err(|e| SequenceError::Fatal(e.to_string()))?,
    };
    let name = &config.name;

    let old_size = old.tree.size();
    let old_time = old.tree.time();
    let timestamp = now_millis();

    // Load the current partial data tile, if any.
    let mut tile_uploads: Vec<UploadAction> = Vec::new();
    let mut edge_tiles = old.edge_tiles.clone();
    let mut data_tile: Vec<u8> = Vec::new();
    if let Some(t) = edge_tiles.get(&DATA_TILE_KEY) {
        if t.tile.width() < TILE_WIDTH {
            data_tile.clone_from(&t.b);
        }
    }
    let mut overlay = HashMap::new();
    let mut n = old_size;
    let mut sequenced_leaves: Vec<LogEntry> = Vec::new();

    for leaf in &mut p.pending_leaves {
        leaf.leaf_index = n;
        leaf.timestamp = timestamp;
        sequenced_leaves.push(leaf.clone());
        let tile_leaf = leaf.tile_leaf();
        metrics.seq_leaf_size.observe(tile_leaf.len().as_f64());
        data_tile.extend(tile_leaf);

        // Compute the new tree hashes and add them to the hashReader overlay
        // (we will use them later to insert more leaves and finally to produce
        // the new tiles).
        let hashes = tlog_tiles::stored_hashes(
            n,
            &leaf.merkle_tree_leaf(),
            &HashReaderWithOverlay {
                edge_tiles: &edge_tiles,
                overlay: &overlay,
            },
        )
        .map_err(|e| {
            SequenceError::NonFatal(format!(
                "couldn't compute new hashes for leaf {leaf:?}: {e}"
            ))
        })?;
        for (i, h) in hashes.iter().enumerate() {
            let id = tlog_tiles::stored_hash_index(0, n) + i as u64;
            overlay.insert(id, *h);
        }

        n += 1;

        // If the data tile is full, stage it.
        if n % u64::from(TILE_WIDTH) == 0 {
            stage_data_tile(n, &mut edge_tiles, &mut tile_uploads, &data_tile);
            metrics.seq_data_tile_size.observe(data_tile.len().as_f64());
            data_tile.clear();
        }
    }

    // Stage leftover partial data tile, if any.
    if n != old_size && n % u64::from(TILE_WIDTH) != 0 {
        stage_data_tile(n, &mut edge_tiles, &mut tile_uploads, &data_tile);
        metrics.seq_data_tile_size.observe(data_tile.len().as_f64());
    }

    // Produce and stage new tree tiles.
    let tiles = Tile::new_tiles(TILE_HEIGHT, old_size, n);
    for tile in tiles {
        let data = tile
            .read_data(&HashReaderWithOverlay {
                edge_tiles: &edge_tiles,
                overlay: &overlay,
            })
            .map_err(|e| {
                SequenceError::NonFatal(format!("couldn't generate tile {tile:?}: {e}"))
            })?;
        // Assuming new_tiles_for_size produces tiles in order, this tile should
        // always be further right than the one in edge_tiles, but double check.
        if edge_tiles.get(&tile.level()).is_none_or(|t| {
            t.tile.level_index() < tile.level_index()
                || (t.tile.level_index() == tile.level_index() && t.tile.width() < tile.width())
        }) {
            debug!(
                "{name}: staging tree tile: old_tree_size={old_size}, tree_size={n}, tile={tile:?}, size={}",
                data.len()
            );
            edge_tiles.insert(
                tile.level(),
                TileWithBytes {
                    tile,
                    b: data.clone(),
                },
            );
        }
        let action = UploadAction {
            key: static_ct_api::tile_path(&tile),
            data,
            opts: OPTS_HASH_TILE.clone(),
        };
        tile_uploads.push(action);
    }

    let tree = TreeWithTimestamp::from_hash_reader(
        n,
        &HashReaderWithOverlay {
            edge_tiles: &edge_tiles,
            overlay: &overlay,
        },
        timestamp,
    )
    .map_err(|e| SequenceError::NonFatal(format!("couldn't compute tree head: {e}")))?;

    // Upload tiles to staging, where they can be recovered by [SequenceState::load] if we
    // crash right after updating DO storage.
    let staged_uploads = marshal_staged_uploads(&tile_uploads)
        .map_err(|e| SequenceError::NonFatal(format!("couldn't marshal staged uploads: {e}")))?;
    object
        .upload(
            &staging_path(tree.size(), tree.hash()),
            &staged_uploads,
            &OPTS_STAGING,
        )
        .await
        .map_err(|e| SequenceError::NonFatal(format!("couldn't upload staged tiles: {e}")))?;

    let new_checkpoint = tree
        .sign(
            &config.origin,
            &config.signing_key,
            &config.witness_key,
            &mut rand::thread_rng(),
        )
        .map_err(|e| SequenceError::NonFatal(format!("couldn't sign checkpoint: {e}")))?;

    // This is a critical error, since we don't know the state of the
    // checkpoint in the database at this point. Bail and let [SequenceState::load] get us
    // to a good state after restart.
    lock.swap(CHECKPOINT_KEY, &old.checkpoint, &new_checkpoint)
        .await
        .map_err(|e| {
            SequenceError::Fatal(format!("couldn't upload checkpoint to database: {e}"))
        })?;

    // At this point the pool is fully serialized: new entries were persisted to
    // object storage (in staging) and the checkpoint was comitted to the
    // database. If we were to crash after this, recovery would be clean from
    // database and object storage.
    *sequence_state = Some(SequenceState {
        tree,
        checkpoint: new_checkpoint.clone(),
        edge_tiles,
    });

    // Use apply_staged_uploads instead of going over tile_uploads directly, to exercise the same
    // code path as LoadLog.
    // An error here is fatal, since we can't continue leaving behind missing tiles. The next
    // run of sequence would not upload them again, while LoadLog will retry uploading them
    // from the staging bundle.
    apply_staged_uploads(object, &staged_uploads)
        .await
        .map_err(|e| SequenceError::Fatal(format!("couldn't upload a tile: {e}")))?;

    // If we fail to upload, return an error so that we don't produce SCTs that, although
    // safely serialized, wouldn't be part of a publicly visible tree.
    object
        .upload(CHECKPOINT_KEY, &new_checkpoint, &OPTS_CHECKPOINT)
        .await
        .map_err(|e| {
            SequenceError::NonFatal(format!("couldn't upload checkpoint to object storage: {e}"))
        })?;

    // Return SCTs to clients. Clients can recover the leaf index
    // from the old tree size and their index in the sequenced pool.
    p.done.send_replace((old_size, timestamp));

    // At this point if the cache put fails, there's no reason to return errors to users. The
    // only consequence of cache false negatives are duplicated leaves anyway. In fact, an
    // error might cause the clients to resubmit, producing more cache false negatives and
    // duplicates.
    if let Err(e) = cache
        .put_entries(
            &sequenced_leaves
                .iter()
                .map(|entry| {
                    (
                        ctlog::compute_cache_hash(
                            entry.is_precert,
                            &entry.certificate,
                            &entry.issuer_key_hash,
                        ),
                        (entry.leaf_index, entry.timestamp),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .await
    {
        warn!(
            "{name}: Cache put failed (entries={}): {e}",
            sequenced_leaves.len()
        );
    }

    for tile in &sequence_state.as_ref().unwrap().edge_tiles {
        trace!("{name}: Edge tile: {tile:?}");
    }
    info!(
        "{name}: Sequenced pool; tree_size={n}, entries: {}, tiles: {}, timestamp: {timestamp}, duration: {:.2}s, since_last: {:.2}s",
        n - old_size,
        tile_uploads.len(),
        millis_diff_as_secs(start, now_millis()),
        millis_diff_as_secs(old_time, timestamp)
    );

    metrics
        .seq_duration
        .observe(millis_diff_as_secs(start, now_millis()));
    metrics
        .seq_delay
        .observe(millis_diff_as_secs(old_time, timestamp) - config.sequence_interval.as_secs_f64());
    metrics.seq_tiles.inc_by(tile_uploads.len().as_f64());
    metrics.tree_size.set(n.as_f64());
    metrics.tree_time.set(timestamp.as_f64());

    Ok(())
}

// Stage a data tile. This is used as a helper function for [`sequence_pool`].
fn stage_data_tile(
    n: u64,
    edge_tiles: &mut HashMap<u8, TileWithBytes>,
    tile_uploads: &mut Vec<UploadAction>,
    data_tile: &[u8],
) {
    let mut tile = Tile::from_index(TILE_HEIGHT, tlog_tiles::stored_hash_index(0, n - 1));
    tile.set_is_data();
    edge_tiles.insert(
        DATA_TILE_KEY,
        TileWithBytes {
            tile,
            b: data_tile.to_owned(),
        },
    );
    let action = UploadAction {
        key: static_ct_api::tile_path(&tile),
        data: data_tile.to_owned(),
        opts: OPTS_DATA_TILE.clone(),
    };
    tile_uploads.push(action);
}

/// Applies previously-staged uploads to the object backend where contents can be retrieved by log clients.
async fn apply_staged_uploads(
    object: &impl ObjectBackend,
    staged_uploads: &[u8],
) -> Result<(), anyhow::Error> {
    let uploads: Vec<UploadAction> = serde_json::from_slice(staged_uploads)?;
    let upload_futures: Vec<_> = uploads
        .iter()
        .map(|u| object.upload(&u.key, &u.data, &u.opts))
        .collect();
    try_join_all(upload_futures).await?;

    Ok(())
}

/// Read and verify the tiles on the right edge of the tree from the object backend.
async fn read_edge_tiles(
    object: &impl ObjectBackend,
    tree_size: u64,
    tree_hash: &Hash,
) -> Result<HashMap<u8, TileWithBytes>, anyhow::Error> {
    // Ideally we would use `tlog_tiles::TileHashReader::read_hashes` to read and verify tiles
    // (like the Go implementation does), but this doesn't work out of the box since we need
    // async calls to retrieve tiles from object storage, and async trait support in Rust is
    // limited.
    // TODO: try using async-trait or block_on as a workaround.
    let (tiles_with_bytes, _) = read_and_verify_tiles(
        object,
        tree_size,
        tree_hash,
        &[tlog_tiles::stored_hash_index(0, tree_size - 1)],
    )
    .await?;

    let mut edge_tiles: HashMap<u8, TileWithBytes> = HashMap::new();
    for tile in tiles_with_bytes {
        if edge_tiles.get(&tile.tile.level()).is_none_or(|t| {
            t.tile.level_index() < tile.tile.level_index()
                || (t.tile.level_index() == tile.tile.level_index()
                    && t.tile.width() < tile.tile.width())
        }) {
            edge_tiles.insert(tile.tile.level(), tile);
        }
    }

    Ok(edge_tiles)
}

/// Read and authenticate the tiles at the given indexes, returning all tiles needed for verification.
#[allow(clippy::too_many_lines)]
async fn read_and_verify_tiles(
    object: &impl ObjectBackend,
    tree_size: u64,
    tree_hash: &Hash,
    indexes: &[u64],
) -> Result<(Vec<TileWithBytes>, Vec<usize>), anyhow::Error> {
    let mut tile_order: HashMap<Tile, usize> = HashMap::new(); // tile_order[tileKey(tiles[i])] = i
    let mut tiles = Vec::new();

    // Plan to fetch tiles necessary to recompute tree hash.
    // If it matches, those tiles are authenticated.
    let stx = tlog_tiles::sub_tree_index(0, tree_size, vec![]);
    let mut stx_tile_order = vec![0; stx.len()];
    for (i, &x) in stx.iter().enumerate() {
        let tile = Tile::from_index(TILE_HEIGHT, x);
        let tile = tile.parent(0, tree_size).expect("missing parent");
        if let Some(&j) = tile_order.get(&tile) {
            stx_tile_order[i] = j;
        } else {
            stx_tile_order[i] = tiles.len();
            tile_order.insert(tile, tiles.len());
            tiles.push(tile);
        }
    }

    // Plan to fetch tiles containing the indexes, along with any parent tiles needed
    // for authentication. For most calls, the parents are being fetched anyway.
    let mut index_tile_order = vec![0; indexes.len()];
    for (i, &x) in indexes.iter().enumerate() {
        if x >= tlog_tiles::stored_hash_index(0, tree_size) {
            bail!("indexes not in tree");
        }
        let tile = Tile::from_index(TILE_HEIGHT, x);
        // Walk up parent tiles until we find one we've requested.
        // That one will be authenticated.
        let mut k = 0;
        loop {
            let p = tile.parent(k, tree_size).expect("missing parent");
            if let Some(&j) = tile_order.get(&p) {
                if k == 0 {
                    index_tile_order[i] = j;
                }
                break;
            }
            k += 1;
        }

        // Walk back down recording child tiles after parents.
        // This loop ends by revisiting the tile for this index
        // (tile.parent(0, r.tree.N)) unless k == 0, in which
        // case the previous loop did it.
        for k in (0..k).rev() {
            let p = tile.parent(k, tree_size).expect("missing parent");
            if p.width() != (1 << p.height()) {
                // Only full tiles have parents.
                // This tile has a parent, so it must be full.
                bail!("bad math: {} {} {:?}", tree_size, x, p);
            }
            tile_order.insert(p, tiles.len());
            if k == 0 {
                index_tile_order[i] = tiles.len();
            }
            tiles.push(p);
        }
    }

    // Fetch all the tile data.
    let mut data = Vec::new();
    for tile in &tiles {
        let result = object
            .fetch(&static_ct_api::tile_path(tile))
            .await?
            .ok_or(anyhow!(
                "no tile {} in object storage",
                static_ct_api::tile_path(tile)
            ))?;
        data.push(result);
    }
    if data.len() != tiles.len() {
        bail!(
            "bad result slice (len={}, want {})",
            data.len(),
            tiles.len()
        );
    }
    for (i, tile) in tiles.iter().enumerate() {
        if data[i].len() != tile.width() as usize * HASH_SIZE {
            bail!(
                "bad result slice ({} len={}, want {})",
                static_ct_api::tile_path(tile),
                data[i].len(),
                tile.width() as usize * HASH_SIZE
            );
        }
    }

    // Authenticate the initial tiles against the tree hash.
    // They are arranged so that parents are authenticated before children.
    // First the tiles needed for the tree hash.
    let mut th = tiles[stx_tile_order[stx.len() - 1]]
        .hash_at_index(&data[stx_tile_order[stx.len() - 1]], stx[stx.len() - 1])?;
    for i in (0..stx.len() - 1).rev() {
        let h = tiles[stx_tile_order[i]].hash_at_index(&data[stx_tile_order[i]], stx[i])?;
        th = tlog_tiles::node_hash(h, th);
    }
    if th != *tree_hash {
        bail!(TlogError::InconsistentTile.to_string());
    }

    // Authenticate full tiles against their parents.
    for i in stx.len()..tiles.len() {
        let tile = tiles[i];
        let p = tile.parent(1, tree_size).expect("missing parent");
        let j = tile_order.get(&p).ok_or(anyhow!(
            "bad math: {} {:?}: lost parent of {:?}",
            tree_size,
            indexes,
            tile
        ))?;
        let h = p.hash_at_index(
            &data[*j],
            tlog_tiles::stored_hash_index(p.level() * p.height(), tile.level_index()),
        )?;
        if h != Tile::subtree_hash(&data[i]) {
            bail!(TlogError::InconsistentTile.to_string());
        }
    }

    // Now we have all the tiles needed for the requested indexes,
    // and we've authenticated the full tile set against the trusted tree hash.

    let tiles_with_bytes: Vec<TileWithBytes> = tiles
        .into_iter()
        .zip(data.into_iter())
        .map(|(tile, b)| TileWithBytes { tile, b })
        .collect();

    Ok((tiles_with_bytes, index_tile_order))
}

/// Returns hashes from `edge_tiles` of from the overlay cache.
#[derive(Debug)]
struct HashReaderWithOverlay<'a> {
    edge_tiles: &'a HashMap<u8, TileWithBytes>,
    overlay: &'a HashMap<u64, Hash>,
}

impl HashReader for HashReaderWithOverlay<'_> {
    fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, TlogError> {
        let mut list = Vec::with_capacity(indexes.len());
        for &id in indexes {
            if let Some(h) = self.overlay.get(&id) {
                list.push(*h);
                continue;
            }
            let Some(t) = self
                .edge_tiles
                .get(&Tile::from_index(TILE_HEIGHT, id).level())
            else {
                return Err(TlogError::IndexesNotInTree);
            };
            let h = t.tile.hash_at_index(&t.b, id)?;
            list.push(h);
        }
        Ok(list)
    }
}

/// A pool of pending log entries that are sequenced together. Clients subscribe
/// to pools to learn when their submitted entries have been processed.
#[derive(Debug)]
struct Pool {
    pending_leaves: Vec<LogEntry>,
    by_hash: HashMap<LookupKey, u64>,
    // Sends the index of the first sequenced entry in the pool,
    // and the pool's sequencing timestamp.
    done: Sender<SequenceMetadata>,
}

impl Default for Pool {
    /// Returns a pool initialized with a watch channel.
    fn default() -> Self {
        let (tx, _) = watch::channel((0, 0));
        Self {
            pending_leaves: vec![],
            by_hash: HashMap::new(),
            done: tx,
        }
    }
}

/// Compute the cache key for a log entry.
pub(crate) fn compute_cache_hash(
    is_precert: bool,
    certificate: &[u8],
    issuer_key_hash: &[u8; 32],
) -> LookupKey {
    let mut buffer = Vec::new();
    if is_precert {
        // Add entry type = 1 (precert_entry)
        buffer.write_u16::<BigEndian>(1).unwrap();

        // Add issuer key hash
        buffer.extend_from_slice(issuer_key_hash);

        // Add certificate with a 24-bit length prefix
        buffer
            .write_uint::<BigEndian>(certificate.len() as u64, 3)
            .unwrap();
        buffer.extend_from_slice(certificate);
    } else {
        // Add entry type = 0 (x509_entry)
        buffer.write_u16::<BigEndian>(0).unwrap();

        // Add certificate with a 24-bit length prefix
        buffer
            .write_uint::<BigEndian>(certificate.len() as u64, 3)
            .unwrap();
        buffer.extend_from_slice(certificate);
    }

    // Compute the SHA-256 hash of the buffer
    let hash = Sha256::digest(&buffer);

    // Return the first 16 bytes of the hash as the cacheHash
    let mut cache_hash = [0u8; 16];
    cache_hash.copy_from_slice(&hash[..16]);

    cache_hash
}

/// A pending upload.
#[derive(Debug, Serialize, Deserialize)]
struct UploadAction {
    key: String,
    data: Vec<u8>,
    opts: UploadOptions,
}

/// Marshal a set of pending uploads into a staging bundle.
fn marshal_staged_uploads(uploads: &[UploadAction]) -> Result<Vec<u8>, anyhow::Error> {
    // TODO: Golang library uses tar
    Ok(serde_json::to_vec(uploads)?)
}

/// [`UploadOptions`] are used as part of the [`ObjectBackend::upload`] method, and are
/// marshaled to JSON and stored in the staging bundles.
#[derive(Debug, Default, Serialize, Clone, Deserialize)]
pub(crate) struct UploadOptions {
    /// The MIME type of the data. If empty, defaults to
    /// "application/octet-stream".
    pub(crate) content_type: Option<String>,

    /// Immutable is true if the data is never updated after being uploaded.
    pub(crate) immutable: bool,
}

/// Options for uploading checkpoints.
static OPTS_CHECKPOINT: LazyLock<UploadOptions> = LazyLock::new(|| UploadOptions {
    content_type: Some("text/plain; charset=utf-8".to_string()),
    immutable: false,
});
/// Options for uploading staging bundles.
static OPTS_STAGING: LazyLock<UploadOptions> = LazyLock::new(|| UploadOptions {
    content_type: None,
    immutable: false,
});
/// Options for uploading issuers.
static OPTS_ISSUER: LazyLock<UploadOptions> = LazyLock::new(|| UploadOptions {
    content_type: Some("application/pkix-cert".to_string()),
    immutable: true,
});
/// Options for uploading data tiles.
static OPTS_DATA_TILE: LazyLock<UploadOptions> = LazyLock::new(|| UploadOptions {
    content_type: None,
    immutable: true,
});
/// Options for uploading hash tiles.
static OPTS_HASH_TILE: LazyLock<UploadOptions> = LazyLock::new(|| UploadOptions {
    content_type: None,
    immutable: true,
});

/// Returns the path to which to upload staging bundles.
fn staging_path(mut tree_size: u64, tree_hash: &Hash) -> String {
    // Encode size in three-digit chunks like [static_ct_api::tile_path].
    let mut n_str = format!("{:03}", tree_size % 1000);
    while tree_size >= 1000 {
        tree_size /= 1000;
        write!(n_str, "/x{:03}", tree_size % 1000).unwrap();
    }

    format!("staging/{}/{}", n_str, hex::encode(tree_hash.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{util, LookupKey, SequenceMetadata};
    use futures_executor::block_on;
    use itertools::Itertools;
    use rand::{
        rngs::{OsRng, SmallRng},
        Rng, RngCore, SeedableRng,
    };
    use signed_note::{Note, VerifierList};
    use static_ct_api::{RFC6962Verifier, TILE_HEIGHT, TILE_WIDTH};
    use std::cell::{Cell, RefCell};
    use tlog_tiles::Checkpoint;

    #[test]
    fn test_sequence_one_leaf_short() {
        sequence_one_leaf(u64::from(TILE_WIDTH) + 2);
    }

    #[test]
    #[ignore] // This test is skipped as it takes a long time, but can be run with `cargo test -- --ignored`.
    fn test_sequence_one_leaf_long() {
        sequence_one_leaf((u64::from(TILE_WIDTH) + 2) * u64::from(TILE_HEIGHT));
    }

    fn sequence_one_leaf(n: u64) {
        let mut log = TestLog::new();
        for i in 0..n {
            let res = log.add_certificate();
            log.sequence().unwrap();
            // Wait until sequencing completes for this entry's pool.
            let (leaf_index, _) = block_on(res.resolve()).unwrap();
            assert_eq!(leaf_index, i);
            log.check(i + 1);
        }
        log.check(n);
    }

    #[test]
    #[ignore] // This test is skipped as it takes a long time, but can be run with `cargo test -- --ignored`.
    fn test_sequence_large_log() {
        let mut log = TestLog::new();

        for _ in 0..5 {
            log.add_certificate();
        }
        log.sequence().unwrap();
        log.check(5);

        for i in 0..500_u64 {
            for k in 0..3000_u64 {
                let certificate = (i * 3000 + k).to_be_bytes().to_vec();
                let leaf = LogEntry {
                    certificate,
                    ..Default::default()
                };
                add_leaf_to_pool(&mut log.pool_state, log.config.pool_size, &log.cache, &leaf);
            }
            log.sequence().unwrap();
        }
        log.check(5 + 500 * 3000);
    }

    #[test]
    fn test_sequence_empty_pool() {
        let mut log = TestLog::new();
        let sequence_twice = |log: &mut TestLog, size: u64| {
            log.sequence().unwrap();
            let t1 = log.check(size);
            log.sequence().unwrap();
            let t2 = log.check(size);
            assert!(t2 > t1);
        };
        let add_certs = |log: &mut TestLog, n: usize| {
            for _ in 0..n {
                log.add_certificate();
            }
        };

        sequence_twice(&mut log, 0);
        add_certs(&mut log, 5);
        sequence_twice(&mut log, 5);
        add_certs(&mut log, TILE_WIDTH as usize - 5 - 1);
        sequence_twice(&mut log, u64::from(TILE_WIDTH) - 1);
        add_certs(&mut log, 1);
        sequence_twice(&mut log, u64::from(TILE_WIDTH));
        add_certs(&mut log, 1);
        sequence_twice(&mut log, u64::from(TILE_WIDTH) + 1);
    }

    #[test]
    fn sequence_upload_count() {
        let mut log = TestLog::new();

        for _ in 0..=TILE_WIDTH {
            log.add_certificate();
        }
        log.sequence().unwrap();

        let mut old = 0;
        let uploads = |log: &mut TestLog, old: &mut usize| -> usize {
            let new = log.object.uploads.get();
            let n = new - *old;
            *old = new;
            n
        };
        uploads(&mut log, &mut old);

        // Empty rounds should cause only two uploads (an empty staging bundle and
        // the checkpoint).
        log.sequence().unwrap();
        assert_eq!(uploads(&mut log, &mut old), 2);

        // One entry in steady state (not at tile boundary) should cause four
        // uploads (the staging bundle, the checkpoint, a level -1 tile, and a level
        // 0 tile).
        log.add_certificate();
        log.sequence().unwrap();
        assert_eq!(uploads(&mut log, &mut old), 4);

        // A tile width worth of entries should cause six uploads (the staging
        // bundle, the checkpoint, two level -1 tiles, two level 0 tiles, and one
        // level 1 tile).
        for _ in 0..TILE_WIDTH {
            log.add_certificate();
        }
        log.sequence().unwrap();
        assert_eq!(uploads(&mut log, &mut old), 7);
    }

    #[test]
    fn test_sequence_upload_paths() {
        // Freeze time, acquiring lock so other tests aren't impacted.
        let _lock = util::TIME_MUX.lock();
        let old_time = now_millis();
        util::set_freeze_time(true);
        util::set_global_time(0);

        let mut log = TestLog::new();

        for i in 0..u64::from(TILE_WIDTH) + 5 {
            log.add_certificate_with_seed(i);
        }
        log.sequence().unwrap();
        for i in 0..u64::from(TILE_WIDTH) + 10 {
            log.add_certificate_with_seed(1000 + i);
        }
        log.sequence().unwrap();

        log.check(u64::from(TILE_WIDTH) * 2 + 15);

        let keys = log
            .object
            .objects
            .borrow()
            .keys()
            .cloned()
            .sorted()
            .collect::<Vec<_>>();

        // NOTE: the staging paths differ from the corresponding Go tests since we use a different PRNG.
        let expected = vec![
            CHECKPOINT_KEY,
            "issuer/1b48a2acbba79932d3852ccde41197f678256f3c2a280e9edf9aad272d6e9c92",
            "issuer/559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
            "issuer/6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d",
            "issuer/81365bbc90b5b3991c762eebada7c6d84d1e39a0a1d648cb4fe5a9890b089da8",
            "issuer/df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c",
            "staging/261/c582ac633f03e2eb0164aba1ecd03492a9a604a2c439c9e8a4cb760e3203f26a",
            "staging/527/450860e0a56d23fee7a408e2f0c6d0c740ca536b495f15b198f7e34b61c34ea9",
            "tile/0/000",
            "tile/0/001",
            "tile/0/001.p/5",
            "tile/0/002.p/15",
            "tile/1/000.p/1",
            "tile/1/000.p/2",
            "tile/data/000",
            "tile/data/001",
            "tile/data/001.p/5",
            "tile/data/002.p/15",
        ];

        assert_eq!(keys, expected);

        // Reset time
        util::set_freeze_time(false);
        util::set_global_time(old_time);
    }

    #[test]
    fn test_duplicates_certificates() {
        test_duplicates(false);
    }

    #[test]
    fn test_duplicates_pre_certificates() {
        test_duplicates(true);
    }

    fn test_duplicates(is_precert: bool) {
        let mut log = TestLog::new();
        log.add_with_seed(is_precert, rand::thread_rng().next_u64()); // 1
        log.add_with_seed(is_precert, rand::thread_rng().next_u64()); // 2
        log.sequence().unwrap();
        log.add_with_seed(is_precert, rand::thread_rng().next_u64()); // 3
        log.add_with_seed(is_precert, rand::thread_rng().next_u64()); // 4

        // Two pairs of duplicates from the by_hash pool.
        let res01 = log.add_with_seed(is_precert, 0); // 5
        let res02 = log.add_with_seed(is_precert, 0);
        let res11 = log.add_with_seed(is_precert, 1); // 6
        let res12 = log.add_with_seed(is_precert, 1);
        log.sequence().unwrap();
        log.sequence().unwrap();
        log.check(6);

        let entry01 = block_on(res01.resolve()).unwrap();
        let entry02 = block_on(res02.resolve()).unwrap();
        assert_eq!(entry01, entry02);

        let entry11 = block_on(res11.resolve()).unwrap();
        let entry12 = block_on(res12.resolve()).unwrap();
        assert_eq!(entry11, entry12);

        // A duplicate from the cache.
        let res03 = log.add_with_seed(is_precert, 0);
        log.sequence().unwrap();
        let entry03 = block_on(res03.resolve()).unwrap();
        assert_eq!(entry01, entry03);

        // A pair of duplicates from the in_sequencing pool.
        let res21 = log.add_with_seed(is_precert, 2); // 7
        let mut p = log.sequence_start();
        let res22 = log.add_with_seed(is_precert, 2);
        log.sequence_finish(&mut p);
        let entry21 = block_on(res21.resolve()).unwrap();
        let entry22 = block_on(res22.resolve()).unwrap();
        assert_eq!(entry21, entry22);

        // A failed sequencing immediately allows resubmission (i.e., the failed
        // entry in the inSequencing pool is not picked up).
        log.object.mode.set(ObjectBreakMode::FailStagingButPersist);
        let res = log.add_with_seed(is_precert, 3);
        log.sequence().unwrap();
        assert!(block_on(res.resolve()).is_none());

        log.object.mode.set(ObjectBreakMode::None);
        let res = log.add_with_seed(is_precert, 3); // 8
        log.sequence().unwrap();
        block_on(res.resolve()).unwrap();
        log.check(8);
    }

    #[test]
    fn test_reload_log_certificates() {
        test_reload_log(false);
    }

    #[test]
    fn test_reload_log_pre_certificates() {
        test_reload_log(true);
    }

    fn test_reload_log(is_precert: bool) {
        let mut log = TestLog::new();
        let n = u64::from(TILE_WIDTH) + 2;
        for i in 0..n {
            log.add(is_precert);
            log.sequence().unwrap();
            log.check(i + 1);

            log.sequence_state =
                Some(block_on(SequenceState::load(&log.config, &log.object, &log.lock)).unwrap());
            log.sequence().unwrap();
            log.check(i + 1);
        }
    }

    #[test]
    fn test_reload_wrong_origin() {
        let mut log = TestLog::new();
        log.sequence_state =
            Some(block_on(SequenceState::load(&log.config, &log.object, &log.lock)).unwrap());

        let mut c = log.config.clone();
        c.origin = "wrong".to_string();
        block_on(SequenceState::load(&c, &log.object, &log.lock)).unwrap_err();
    }

    #[test]
    fn test_reload_wrong_key() {
        let mut log = TestLog::new();
        log.sequence_state =
            Some(block_on(SequenceState::load(&log.config, &log.object, &log.lock)).unwrap());

        let mut c = log.config.clone();
        c.signing_key = EcdsaSigningKey::random(&mut OsRng);
        block_on(SequenceState::load(&c, &log.object, &log.lock)).unwrap_err();

        c = log.config.clone();
        c.witness_key = Ed25519SigningKey::generate(&mut OsRng);
        block_on(SequenceState::load(&c, &log.object, &log.lock)).unwrap_err();
    }

    #[test]
    fn test_staging_collision() {
        let mut log = TestLog::new();
        log.add_certificate();
        log.sequence().unwrap();

        // Freeze time, acquiring lock so other tests aren't impacted.
        let _lock = util::TIME_MUX.lock();
        util::set_freeze_time(true);

        log.add_certificate_with_seed('A' as u64);
        log.add_certificate_with_seed('B' as u64);

        log.lock.mode.set(LockBreakMode::FailLockAndNotPersist);
        log.sequence().unwrap_err();
        log.check(1);

        log.lock.mode.set(LockBreakMode::None);
        log.sequence_state =
            Some(block_on(SequenceState::load(&log.config, &log.object, &log.lock)).unwrap());
        log.check(1);

        // First, cause the exact same staging bundle to be uploaded.

        log.add_certificate_with_seed('A' as u64);
        log.add_certificate_with_seed('B' as u64);
        log.sequence().unwrap();
        log.check(3);

        // Again, but now due to a staging bundle upload error.

        util::set_global_time(now_millis() + 1);

        log.add_certificate_with_seed('C' as u64);
        log.add_certificate_with_seed('D' as u64);

        log.object.mode.set(ObjectBreakMode::FailStagingButPersist);
        log.sequence().unwrap();
        log.check(3);

        log.object.mode.set(ObjectBreakMode::None);

        log.add_certificate_with_seed('C' as u64);
        log.add_certificate_with_seed('D' as u64);
        log.sequence().unwrap();
        log.check(5);

        // Reset time
        util::set_freeze_time(false);
    }

    #[test]
    fn test_fatal_error() {
        let mut log = TestLog::new();

        log.add_certificate();
        log.add_certificate();
        log.sequence().unwrap();

        log.lock.mode.set(LockBreakMode::FailLockAndNotPersist);
        let res = log.add_certificate();
        log.sequence().unwrap_err();
        assert!(block_on(res.resolve()).is_none());
        log.check(2);

        log.lock.mode.set(LockBreakMode::None);
        log.sequence_state =
            Some(block_on(SequenceState::load(&log.config, &log.object, &log.lock)).unwrap());
        log.add_certificate();
        log.sequence().unwrap();
        log.check(3);
    }

    macro_rules! test_sequence_errors {
        ($name:ident, $object_mode:expr, $lock_mode:expr, $expect_progress:expr, $expect_fatal:expr) => {
            #[test]
            fn $name() {
                let break_seq = |log: &mut TestLog, broken: &mut bool| {
                    log.object.mode.set($object_mode);
                    log.lock.mode.set($lock_mode);
                    *broken = true;
                };
                let unbreak_seq = |log: &mut TestLog, broken: &mut bool| {
                    log.object.mode.set(ObjectBreakMode::None);
                    log.lock.mode.set(LockBreakMode::None);
                    *broken = false;
                };
                let sequence =
                    |log: &mut TestLog, expected_size: &mut u64, broken: bool, added: u64| {
                        let result = log.sequence();
                        if broken && $expect_fatal {
                            assert!(result.is_err());
                        } else {
                            assert!(result.is_ok());
                        }
                        if !broken || $expect_progress {
                            *expected_size += added;
                        }
                        log.check(*expected_size);
                        if result.is_err() {
                            if broken {
                                log.object.mode.set(ObjectBreakMode::None);
                                log.lock.mode.set(LockBreakMode::None);
                            }
                            log.sequence_state = Some(
                                block_on(SequenceState::load(&log.config, &log.object, &log.lock))
                                    .unwrap(),
                            );
                            if broken {
                                log.object.mode.set($object_mode);
                                log.lock.mode.set($lock_mode);
                            }
                        }
                    };
                let mut log = TestLog::new();
                let mut broken = false;
                let mut expected_size = 0;

                for _ in 0..u64::from(TILE_WIDTH) - 2 {
                    log.add_certificate();
                }
                sequence(
                    &mut log,
                    &mut expected_size,
                    broken,
                    u64::from(TILE_WIDTH) - 2,
                );

                break_seq(&mut log, &mut broken);

                let res1 = log.add_certificate();
                let res2 = log.add_certificate();
                let res3 = log.add_certificate();
                sequence(&mut log, &mut expected_size, broken, 3);
                assert!(block_on(res1.resolve()).is_none());
                assert!(block_on(res2.resolve()).is_none());
                assert!(block_on(res3.resolve()).is_none());

                // Re-failing the same tile sizes.
                let res1 = log.add_certificate();
                let res2 = log.add_certificate();
                let res3 = log.add_certificate();
                sequence(&mut log, &mut expected_size, broken, 3);
                assert!(block_on(res1.resolve()).is_none());
                assert!(block_on(res2.resolve()).is_none());
                assert!(block_on(res3.resolve()).is_none());

                unbreak_seq(&mut log, &mut broken);

                // Succeeding with the same size that failed.
                let res1 = log.add_certificate();
                let res2 = log.add_certificate();
                let res3 = log.add_certificate();
                sequence(&mut log, &mut expected_size, broken, 3);
                block_on(res1.resolve()).unwrap();
                block_on(res2.resolve()).unwrap();
                block_on(res3.resolve()).unwrap();

                log = TestLog::new();
                expected_size = 0;
                for _ in 0..u64::from(TILE_WIDTH) - 2 {
                    log.add_certificate();
                }
                sequence(
                    &mut log,
                    &mut expected_size,
                    broken,
                    u64::from(TILE_WIDTH) - 2,
                );

                break_seq(&mut log, &mut broken);
                let res1 = log.add_certificate();
                let res2 = log.add_certificate();
                let res3 = log.add_certificate();
                sequence(&mut log, &mut expected_size, broken, 3);
                assert!(block_on(res1.resolve()).is_none());
                assert!(block_on(res2.resolve()).is_none());
                assert!(block_on(res3.resolve()).is_none());

                unbreak_seq(&mut log, &mut broken);

                // Succeeding with a different set of tiles.
                log.add_certificate();
                sequence(&mut log, &mut expected_size, broken, 1);
            }
        };
    }

    // A fatal error while uploading to the lock backend. The upload is
    // retried, and the same tiles are generated and uploaded again.
    test_sequence_errors!(
        lock_upload,
        ObjectBreakMode::None,
        LockBreakMode::FailLockAndNotPersist,
        false,
        true
    );
    // An error while uploading to the lock backend, where the lock is
    // persisted anyway, such as a response timeout.
    test_sequence_errors!(
        lock_upload_persisted,
        ObjectBreakMode::None,
        LockBreakMode::FailLockButPersist,
        true,
        true
    );
    test_sequence_errors!(
        checkpoint_upload,
        ObjectBreakMode::FailCheckpointAndNotPersist,
        LockBreakMode::None,
        true,
        false
    );
    test_sequence_errors!(
        checkpoint_upload_persisted,
        ObjectBreakMode::FailCheckpointButPersist,
        LockBreakMode::None,
        true,
        false
    );
    test_sequence_errors!(
        staging_upload,
        ObjectBreakMode::FailStagingAndNotPersist,
        LockBreakMode::None,
        false,
        false
    );
    test_sequence_errors!(
        staging_upload_persisted,
        ObjectBreakMode::FailStagingButPersist,
        LockBreakMode::None,
        false,
        false
    );
    test_sequence_errors!(
        data_tile_upload,
        ObjectBreakMode::FailDataTileAndNotPersist,
        LockBreakMode::None,
        true,
        true
    );
    test_sequence_errors!(
        data_tile_upload_persisted,
        ObjectBreakMode::FailDataTileButPersist,
        LockBreakMode::None,
        true,
        true
    );
    test_sequence_errors!(
        tile0_upload,
        ObjectBreakMode::FailTile0AndNotPersist,
        LockBreakMode::None,
        true,
        true
    );
    test_sequence_errors!(
        tile0_upload_persisted,
        ObjectBreakMode::FailTile0ButPersist,
        LockBreakMode::None,
        true,
        true
    );

    // TODO: benchmark_sequence

    const CHAINS: &[&[&[u8]]] = &[
        &["A".as_bytes(), "rootX".as_bytes()],
        &["B".as_bytes(), "C".as_bytes(), "rootX".as_bytes()],
        &["A".as_bytes(), "rootY".as_bytes()],
        &[],
    ];

    #[derive(Copy, Clone)]
    enum ObjectBreakMode {
        None,
        FailCheckpointAndNotPersist,
        FailCheckpointButPersist,
        FailStagingAndNotPersist,
        FailStagingButPersist,
        FailDataTileAndNotPersist,
        FailDataTileButPersist,
        FailTile0AndNotPersist,
        FailTile0ButPersist,
    }

    // Make use of interior mutability here to avoid needing to make trait mutable for tests:
    // https://ricardomartins.cc/2016/06/08/interior-mutability
    struct TestObjectBackend {
        objects: RefCell<HashMap<String, Vec<u8>>>,
        uploads: Cell<usize>,
        mode: Cell<ObjectBreakMode>,
    }

    impl TestObjectBackend {
        fn new() -> Self {
            Self {
                objects: RefCell::new(HashMap::new()),
                uploads: Cell::new(0),
                mode: Cell::new(ObjectBreakMode::None),
            }
        }
    }

    impl ObjectBackend for TestObjectBackend {
        async fn upload(
            &self,
            key: &str,
            data: &[u8],
            _opts: &super::UploadOptions,
        ) -> worker::Result<()> {
            let new_count = self.uploads.get() + 1;
            self.uploads.set(new_count);
            let (apply, is_err) = match self.mode.get() {
                ObjectBreakMode::None => (true, false),
                ObjectBreakMode::FailCheckpointAndNotPersist => {
                    (key != CHECKPOINT_KEY, key == CHECKPOINT_KEY)
                }
                ObjectBreakMode::FailCheckpointButPersist => (true, key == CHECKPOINT_KEY),
                ObjectBreakMode::FailStagingAndNotPersist => {
                    (!key.starts_with("staging/"), key.starts_with("staging/"))
                }
                ObjectBreakMode::FailStagingButPersist => (true, key.starts_with("staging/")),
                ObjectBreakMode::FailDataTileAndNotPersist => (
                    !key.starts_with("tile/data/"),
                    key.starts_with("tile/data/"),
                ),
                ObjectBreakMode::FailDataTileButPersist => (true, key.starts_with("tile/data/")),
                ObjectBreakMode::FailTile0AndNotPersist => {
                    (!key.starts_with("tile/0/"), key.starts_with("tile/0/"))
                }
                ObjectBreakMode::FailTile0ButPersist => (true, key.starts_with("tile/0/")),
            };
            if apply {
                self.objects
                    .borrow_mut()
                    .insert(key.to_string(), data.to_vec());
            }
            if is_err {
                Err("upload failure".into())
            } else {
                Ok(())
            }
        }
        async fn fetch(&self, key: &str) -> worker::Result<Option<Vec<u8>>> {
            if let Some(data) = self.objects.borrow().get(key) {
                Ok(Some(data.clone()))
            } else {
                Ok(None)
            }
        }
    }

    struct TestCacheBackend(HashMap<LookupKey, SequenceMetadata>);

    impl CacheRead for TestCacheBackend {
        fn get_entry(&self, key: &LookupKey) -> Option<SequenceMetadata> {
            self.0.get(key).copied()
        }
    }

    impl CacheWrite for TestCacheBackend {
        async fn put_entries(
            &mut self,
            entries: &[(LookupKey, SequenceMetadata)],
        ) -> worker::Result<()> {
            for (key, value) in entries {
                if self.0.contains_key(key) {
                    continue;
                }
                self.0.insert(*key, *value);
            }
            Ok(())
        }
    }

    #[derive(Copy, Clone)]
    enum LockBreakMode {
        None,
        FailLockAndNotPersist,
        FailLockButPersist,
    }

    struct TestLockBackend {
        lock: RefCell<HashMap<String, Vec<u8>>>,
        mode: Cell<LockBreakMode>,
    }

    impl TestLockBackend {
        fn new() -> Self {
            Self {
                lock: RefCell::new(HashMap::new()),
                mode: Cell::new(LockBreakMode::None),
            }
        }
    }

    impl LockBackend for TestLockBackend {
        async fn put(&self, key: &str, value: &[u8]) -> worker::Result<()> {
            self.lock
                .borrow_mut()
                .insert(key.to_string(), value.to_vec());
            Ok(())
        }
        async fn swap(&self, key: &str, old: &[u8], new: &[u8]) -> worker::Result<()> {
            if let Some(old_value) = self.lock.borrow().get(key) {
                if old_value != old {
                    return Err("old values do not match".into());
                }
            } else {
                return Err("old value not present".into());
            }
            let (apply, is_err) = match self.mode.get() {
                LockBreakMode::None => (true, false),
                LockBreakMode::FailLockAndNotPersist => (false, true),
                LockBreakMode::FailLockButPersist => (true, true),
            };
            if apply {
                self.lock.borrow_mut().insert(key.to_string(), new.to_vec());
            }
            if is_err {
                Err("failed to swap value".into())
            } else {
                Ok(())
            }
        }
        async fn get(&self, key: &str) -> worker::Result<Vec<u8>> {
            if let Some(value) = self.lock.borrow().get(key) {
                Ok(value.clone())
            } else {
                Err("key doesn't exist".into())
            }
        }
    }

    struct TestLog {
        config: LogConfig,
        pool_state: PoolState,
        sequence_state: Option<SequenceState>,
        lock: TestLockBackend,
        object: TestObjectBackend,
        cache: TestCacheBackend,
        metrics: Metrics,
    }

    impl TestLog {
        fn new() -> Self {
            let cache = TestCacheBackend(HashMap::new());
            let object = TestObjectBackend::new();
            let lock = TestLockBackend::new();
            let config = LogConfig {
                name: "TestLog".to_string(),
                origin: "example.com/TestLog".to_string(),
                witness_key: Ed25519SigningKey::generate(&mut OsRng),
                signing_key: EcdsaSigningKey::random(&mut OsRng),
                pool_size: 0,
                sequence_interval: Duration::from_secs(1),
            };
            let pool_state = PoolState::default();
            let metrics = Metrics::new();
            block_on(create_log(&config, &object, &lock)).unwrap();
            Self {
                config,
                pool_state,
                sequence_state: None,
                lock,
                object,
                cache,
                metrics,
            }
        }
        fn sequence(&mut self) -> Result<(), anyhow::Error> {
            block_on(sequence(
                &mut self.pool_state,
                &mut self.sequence_state,
                &self.config,
                &self.object,
                &self.lock,
                &mut self.cache,
                &self.metrics,
            ))
        }
        fn sequence_start(&mut self) -> Pool {
            let mut p = std::mem::take(&mut self.pool_state.current_pool);
            self.pool_state.in_sequencing = std::mem::take(&mut p.by_hash);
            self.pool_state.in_sequencing_done = Some(p.done.subscribe());
            p
        }
        fn sequence_finish(&mut self, p: &mut Pool) {
            block_on(sequence_pool(
                &mut self.sequence_state,
                &self.config,
                &self.object,
                &self.lock,
                &mut self.cache,
                p,
                &self.metrics,
            ))
            .unwrap();
            self.pool_state.in_sequencing.clear();
        }
        fn add_certificate(&mut self) -> AddLeafResult {
            self.add_certificate_with_seed(rand::thread_rng().next_u64())
        }
        fn add_certificate_with_seed(&mut self, seed: u64) -> AddLeafResult {
            self.add_with_seed(false, seed)
        }
        fn add(&mut self, is_precert: bool) -> AddLeafResult {
            self.add_with_seed(is_precert, rand::thread_rng().next_u64())
        }
        fn add_with_seed(&mut self, is_precert: bool, seed: u64) -> AddLeafResult {
            let mut rng = SmallRng::seed_from_u64(seed);
            let mut certificate = vec![0; rng.gen_range(8..12)];
            rng.fill(&mut certificate[..]);
            let mut pre_certificate: Vec<u8>;
            let mut issuer_key_hash = [0; 32];
            if is_precert {
                pre_certificate = vec![0; rng.gen_range(1..5)];
                rng.fill(&mut pre_certificate[..]);
                rng.fill(&mut issuer_key_hash);
            } else {
                pre_certificate = Vec::new();
            }
            let issuers = CHAINS[rng.gen_range(0..CHAINS.len())];
            let leaf = LogEntry {
                certificate,
                pre_certificate,
                is_precert,
                issuer_key_hash,
                chain_fingerprints: issuers.iter().map(|&x| Sha256::digest(x).into()).collect(),
                leaf_index: 0,
                timestamp: 0,
            };

            block_on(upload_issuers(&self.object, issuers, &self.config.name)).unwrap();

            add_leaf_to_pool(
                &mut self.pool_state,
                self.config.pool_size,
                &self.cache,
                &leaf,
            )
            .0
        }

        fn check(&self, size: u64) -> u64 {
            let sth = block_on(self.object.fetch(CHECKPOINT_KEY))
                .unwrap()
                .ok_or(anyhow!("no checkpoint in object storage"))
                .unwrap();
            let v = RFC6962Verifier::new(
                "example.com/TestLog",
                self.config.signing_key.verifying_key(),
            )
            .unwrap();
            let n = Note::from_bytes(&sth).unwrap();
            let (verified_sigs, _) = n
                .verify(&VerifierList::new(vec![Box::new(v.clone())]))
                .unwrap();
            assert_eq!(verified_sigs.len(), 1);
            let sth_timestamp =
                static_ct_api::rfc6962_signature_timestamp(&verified_sigs[0]).unwrap();

            let c = Checkpoint::from_bytes(n.text()).unwrap();

            assert_eq!(c.origin(), "example.com/TestLog");
            assert_eq!(c.extension(), "");

            {
                let sth: Vec<u8> = block_on(self.lock.get(CHECKPOINT_KEY)).unwrap();
                let v = RFC6962Verifier::new(
                    "example.com/TestLog",
                    self.config.signing_key.verifying_key(),
                )
                .unwrap();
                let n = Note::from_bytes(&sth).unwrap();
                let (verified_sigs, _) = n
                    .verify(&VerifierList::new(vec![Box::new(v.clone())]))
                    .unwrap();
                assert_eq!(verified_sigs.len(), 1);
                let sth_timestamp1 =
                    static_ct_api::rfc6962_signature_timestamp(&verified_sigs[0]).unwrap();
                let c1 = Checkpoint::from_bytes(n.text()).unwrap();

                assert_eq!(c1.origin(), c.origin());
                assert_eq!(c1.extension(), c.extension());
                if c1.size() == c.size() {
                    assert_eq!(c1.hash(), c.hash());
                }
                assert!(sth_timestamp1 >= sth_timestamp);
                assert!(c1.size() >= c.size());
                assert_eq!(c1.size(), size);
            }

            if c.size() == 0 {
                let expected = Sha256::digest([]);
                assert_eq!(c.hash(), &Hash(expected.into()));
                return sth_timestamp;
            }

            let indexes: Vec<u64> = (0..c.size())
                .map(|n| tlog_tiles::stored_hash_index(0, n))
                .collect();
            // [read_tile_hashes] checks the inclusion of every hash in the provided tree,
            // so this checks the validity of the entire Merkle tree.
            let leaf_hashes = read_tile_hashes(&self.object, c.size(), c.hash(), &indexes).unwrap();

            let mut last_tile =
                Tile::from_index(TILE_HEIGHT, tlog_tiles::stored_hash_count(c.size() - 1));
            last_tile.set_is_data();

            for n in 0..last_tile.level_index() {
                let tile = if n == last_tile.level_index() {
                    last_tile
                } else {
                    Tile::new(TILE_HEIGHT, 0, n, TILE_WIDTH, true)
                };
                for (i, entry) in TileIterator::new(
                    block_on(self.object.fetch(&static_ct_api::tile_path(&tile)))
                        .unwrap()
                        .unwrap(),
                    tile.width() as usize,
                )
                .enumerate()
                {
                    let entry = entry.unwrap();
                    let idx = n * u64::from(TILE_WIDTH) + i as u64;
                    assert_eq!(entry.leaf_index, idx);
                    assert!(entry.timestamp <= sth_timestamp);
                    assert_eq!(
                        leaf_hashes[usize::try_from(idx).unwrap()],
                        tlog_tiles::record_hash(&entry.merkle_tree_leaf())
                    );

                    assert!(!entry.certificate.is_empty());
                    if entry.is_precert {
                        assert!(!entry.pre_certificate.is_empty());
                        assert_ne!(entry.issuer_key_hash, [0; 32]);
                    } else {
                        assert!(entry.pre_certificate.is_empty());
                        assert_eq!(entry.issuer_key_hash, [0; 32]);
                    }

                    for fp in entry.chain_fingerprints {
                        let b = block_on(self.object.fetch(&format!("issuer/{}", hex::encode(fp))))
                            .unwrap()
                            .unwrap();
                        assert_eq!(Sha256::digest(b).to_vec(), fp);
                    }
                }
            }

            sth_timestamp
        }
    }

    fn read_tile_hashes(
        object: &impl ObjectBackend,
        tree_size: u64,
        tree_hash: &Hash,
        indexes: &[u64],
    ) -> Result<Vec<Hash>, anyhow::Error> {
        let (tiles_with_bytes, index_tile_order) =
            block_on(read_and_verify_tiles(object, tree_size, tree_hash, indexes))?;

        let mut hashes = Vec::new();
        for (i, &x) in indexes.iter().enumerate() {
            let j = index_tile_order[i];
            let h = tiles_with_bytes[j]
                .tile
                .hash_at_index(&tiles_with_bytes[j].b, x)?;
            hashes.push(h);
        }

        Ok(hashes)
    }
}
