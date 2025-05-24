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
    metrics::{millis_diff_as_secs, AsF64, Metrics},
    util::now_millis,
    CacheRead, CacheWrite, LockBackend, LookupKey, ObjectBackend, SequenceMetadata,
};
use anyhow::{anyhow, bail};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use futures_util::future::try_join_all;
use log::{debug, error, info, trace, warn};
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use static_ct_api::{
    LogEntryTrait, PendingLogEntryTrait, TileIterator, TreeWithTimestamp, UnixTimestamp,
};
use std::collections::HashMap;
use std::time::Duration;
use std::{
    cmp::{Ord, Ordering},
    sync::LazyLock,
};
use thiserror::Error;
use tlog_tiles::{Hash, HashReader, PathElem, Tile, TlogError, TlogTile, HASH_SIZE};
use tokio::sync::watch::{channel, Receiver, Sender};

/// The maximum tile level is 63 (<c2sp.org/static-ct-api>), so safe to use [`u8::MAX`] as
/// the special level for data tiles. The Go implementation uses -1.
const DATA_TILE_KEY: u8 = u8::MAX;
const CHECKPOINT_KEY: &str = "checkpoint";
const STAGING_KEY: &str = "staging";

// Limit on the number of entries per batch. Tune this parameter to avoid
// running into various size limitations. For instance, unexpectedly large
// leaves (e.g., with PQ signatures) could cause us to exceed the 128MB Workers
// memory limit. Storing 4000 10KB certificates is 40MB.
const MAX_POOL_SIZE: usize = 4000;

/// Configuration for a CT log.
#[derive(Clone)]
pub(crate) struct LogConfig {
    pub(crate) name: String,
    pub(crate) origin: String,
    pub(crate) signing_key: EcdsaSigningKey,
    pub(crate) witness_key: Ed25519SigningKey,
    pub(crate) sequence_interval: Duration,
    pub(crate) max_pending_entry_holds: usize,
}

/// Ephemeral state for pooling entries to the CT log.
///
/// The pool is written to by `add_leaf_to_pool`, and by the sequencer
/// when rotating pending and in-sequencing entries.
///
/// As long as the above-mentioned blocks run synchronously (no 'await's), Durable Objects'
/// single-threaded execution guarantees that `add_leaf_to_pool` will never add to a pool that
/// already started sequencing, and that cache reads will see entries from older pools before
/// they are rotated out of `in_sequencing`.
/// <https://blog.cloudflare.com/durable-objects-easy-fast-correct-choose-three/#background-durable-objects-are-single-threaded>
#[derive(Debug)]
pub(crate) struct PoolState<P: PendingLogEntryTrait> {
    // How many times the oldest entry has been held back from sequencing.
    oldest_pending_entry_holds: usize,

    // Entries that are ready to be sequenced, along with the Sender used to
    // send metadata to receivers once the corresponding entry is sequenced.
    pending_entries: Vec<(P, Sender<SequenceMetadata>)>,

    // Deduplication cache for entries currently pending sequencing.
    pending_dedup: HashMap<LookupKey, Receiver<SequenceMetadata>>,

    // Deduplication cache for entries currently being sequenced.
    in_sequencing_dedup: HashMap<LookupKey, Receiver<SequenceMetadata>>,
}

impl<P: PendingLogEntryTrait> Default for PoolState<P> {
    fn default() -> Self {
        PoolState {
            holds: 0,
            pending_entries: Default::default(),
            pending: Default::default(),
            in_sequencing: Default::default(),
        }
    }
}

impl<E: PendingLogEntryTrait> PoolState<E> {
    // Check if the key is already in the pool. If so, return a Receiver from
    // which to read the entry metadata when it is sequenced.
    fn check(&self, key: &LookupKey) -> Option<AddLeafResult> {
        if let Some(rx) = self.in_sequencing_dedup.get(key) {
            // Entry is being sequenced.
            Some(AddLeafResult::Pending {
                rx: rx.clone(),
                source: PendingSource::InSequencing,
            })
        } else {
            self.pending_dedup
                .get(key)
                .map(|rx| AddLeafResult::Pending {
                    rx: rx.clone(),
                    source: PendingSource::Pool,
                })
        }
    }
    // Add a new entry to the pool.
    fn add(&mut self, key: LookupKey, entry: E) -> AddLeafResult {
        if self.pending_entries.len() >= MAX_POOL_SIZE {
            return AddLeafResult::RateLimited;
        }
        let (tx, rx) = channel((0, 0));
        self.pending_entries.push((entry, tx));
        self.pending_dedup.insert(key, rx.clone());

        AddLeafResult::Pending {
            rx,
            source: PendingSource::Sequencer,
        }
    }
    // Take the entries from the pool that are ready to be sequenced and the
    // corresponding Senders to update when the entries have been sequenced.
    //
    // Hold back any leftover entries that would be published as a partial tile
    // unless they have already been held back `max_pending_entry_holds` times.
    fn take(
        &mut self,
        old_size: u64,
        max_pending_entry_holds: usize,
    ) -> Vec<(E, Sender<SequenceMetadata>)> {
        let new_size = old_size + self.pending_entries.len() as u64;
        let leftover = new_size % u64::from(TlogTile::FULL_WIDTH);

        let publishing_full_tile =
            new_size / u64::from(TlogTile::FULL_WIDTH) > old_size / u64::from(TlogTile::FULL_WIDTH);
        if publishing_full_tile {
            // We're going to publish at least one full tile which will contain
            // any leftover entries from the previous sequencing. Reset the
            // count since the new leftover entries have not yet been held back.
            self.oldest_pending_entry_holds = 0;
        }
        // Flush all of the leftover entries if the oldest is before the cutoff.
        let flush_oldest = self.oldest_pending_entry_holds >= max_pending_entry_holds;

        if leftover == 0 || flush_oldest {
            // Sequence everything. Either there are no leftovers or they have
            // already been held back the maximum number of times.
            self.oldest_pending_entry_holds = 0;
            self.in_sequencing_dedup = std::mem::take(&mut self.pending_dedup);
            std::mem::take(&mut self.pending_entries)
        } else {
            // Hold back the leftovers to avoid creating a partial tile.
            self.oldest_pending_entry_holds += 1;

            if publishing_full_tile {
                // Return the pending entries to be published in full tiles and
                // retain the rest.
                let split_index = self.pending_entries.len() - usize::try_from(leftover).unwrap();
                let leftover_entries = self.pending_entries.split_off(split_index);
                let leftover_pending = leftover_entries
                    .iter()
                    .filter_map(|(entry, _)| {
                        let lookup_key = entry.lookup_key();
                        self.pending_dedup
                            .remove(&lookup_key)
                            .map(|rx| (lookup_key, rx))
                    })
                    .collect::<HashMap<_, _>>();
                self.in_sequencing_dedup =
                    std::mem::replace(&mut self.pending_dedup, leftover_pending);
                std::mem::replace(&mut self.pending_entries, leftover_entries)
            } else {
                // We didn't fill up a full tile, so nothing to return.
                Vec::new()
            }
        }
    }
    // Reset the map of in-sequencing entries. This should be called after
    // sequencing completes.
    fn reset(&mut self) {
        self.in_sequencing_dedup.clear();
    }
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
    tile: TlogTile,
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
    pub(crate) async fn load<E: PendingLogEntryTrait, L: LogEntryTrait<E>>(
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
                let staged_uploads = lock.get_multipart(STAGING_KEY).await?;
                apply_staged_uploads(object, &staged_uploads, c.size(), c.hash()).await?;
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
            data_tile.tile.set_data_with_path(PathElem::Data);
            data_tile.b = object
                .fetch(&data_tile.tile.path())
                .await?
                .ok_or(anyhow!("no data tile in object storage"))?;
            edge_tiles.insert(DATA_TILE_KEY, data_tile.clone());

            // Verify the data tile against the level 0 tile.
            let start = u64::from(TlogTile::FULL_WIDTH) * data_tile.tile.level_index();
            for (i, entry) in TileIterator::<E, L>::new(
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
    Pending {
        rx: Receiver<SequenceMetadata>,
        source: PendingSource,
    },
    RateLimited,
}

impl AddLeafResult {
    /// Resolve an `AddLeafResult` to a leaf entry, or None if the
    /// entry was not sequenced.
    pub(crate) async fn resolve(self) -> Option<SequenceMetadata> {
        match self {
            AddLeafResult::Cached(entry) => Some(entry),
            AddLeafResult::Pending { mut rx, source: _ } => {
                // Wait until sequencing completes for this entry's pool.
                if rx.changed().await.is_ok() {
                    Some(*rx.borrow())
                } else {
                    warn!("sender dropped");
                    None
                }
            }
            AddLeafResult::RateLimited => None,
        }
    }

    pub(crate) fn source(&self) -> &'static str {
        match self {
            AddLeafResult::Cached(_) => "cache",
            AddLeafResult::RateLimited => "ratelimit",
            AddLeafResult::Pending { rx: _, source } => match source {
                PendingSource::InSequencing => "sequencing",
                PendingSource::Pool => "pool",
                PendingSource::Sequencer => "sequencer",
            },
        }
    }
}
pub(crate) enum PendingSource {
    InSequencing,
    Pool,
    Sequencer,
}

/// Add a leaf (a certificate or pre-certificate) to the pool of pending entries.
///
/// If the entry has already been sequenced and is in the cache, return immediately
/// with a [`AddLeafResult::Cached`]. If the pool is full, return
/// [`AddLeafResult::RateLimited`]. Otherwise, return a [`AddLeafResult::Pending`] which
/// can be resolved once the entry has been sequenced.
pub(crate) fn add_leaf_to_pool<E: PendingLogEntryTrait>(
    state: &mut PoolState<E>,
    cache: &impl CacheRead,
    entry: E,
) -> AddLeafResult {
    let hash = entry.lookup_key();

    if let Some(result) = state.check(&hash) {
        // Entry is already pending or being sequenced.
        result
    } else if let Some(v) = cache.get_entry(&hash) {
        // Entry is cached.
        AddLeafResult::Cached(v)
    } else {
        // This is a new entry. Add it to the pool.
        state.add(hash, entry)
    }
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
pub(crate) async fn sequence<E: PendingLogEntryTrait, L: LogEntryTrait<E>>(
    pool_state: &mut PoolState<E>,
    sequence_state: &mut Option<SequenceState>,
    config: &LogConfig,
    object: &impl ObjectBackend,
    lock: &impl LockBackend,
    cache: &mut impl CacheWrite,
    metrics: &Metrics,
) -> Result<(), anyhow::Error> {
    // Retrieve old sequencing state.
    let old = if let Some(s) = sequence_state {
        s
    } else {
        match SequenceState::load::<E, L>(config, object, lock).await {
            Ok(s) => sequence_state.insert(s),
            Err(e) => {
                metrics.seq_count.with_label_values(&["fatal"]).inc();
                error!("{}: Fatal sequencing error {e}", config.name);
                bail!(e);
            }
        }
    };

    let entries = pool_state.take(old.tree.size(), config.max_pending_entry_holds);
    metrics.seq_pool_size.observe(entries.len().as_f64());

    let result =
        match sequence_entries::<E, L>(old, config, object, lock, cache, entries, metrics).await {
            Ok(()) => {
                metrics.seq_count.with_label_values(&[""]).inc();
                Ok(())
            }
            Err(SequenceError::Fatal(e)) => {
                // Clear ephemeral sequencing state, as it may no longer be valid.
                // It will be loaded again the next time sequence is called.
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

    // Once [`sequence_entries`] returns, the entries are either in the deduplication
    // cache or finalized with an error. In the latter case, we don't want
    // a resubmit to deduplicate against the failed sequencing.
    pool_state.reset();

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
async fn sequence_entries<P: PendingLogEntryTrait, L: LogEntryTrait<P>>(
    sequence_state: &mut SequenceState,
    config: &LogConfig,
    object: &impl ObjectBackend,
    lock: &impl LockBackend,
    cache: &mut impl CacheWrite,
    entries: Vec<(P, Sender<SequenceMetadata>)>,
    metrics: &Metrics,
) -> Result<(), SequenceError> {
    let name = &config.name;

    let old_size = sequence_state.tree.size();
    let old_time = sequence_state.tree.time();
    let timestamp = now_millis();

    // Load the current partial data tile, if any.
    let mut tile_uploads: Vec<UploadAction> = Vec::new();
    let mut edge_tiles = sequence_state.edge_tiles.clone();
    let mut data_tile: Vec<u8> = Vec::new();
    if let Some(t) = edge_tiles.get(&DATA_TILE_KEY) {
        if t.tile.width() < TlogTile::FULL_WIDTH {
            data_tile.clone_from(&t.b);
        }
    }
    let mut overlay = HashMap::new();
    let mut n = old_size;
    let mut sequenced_entries: Vec<(L, u64, UnixTimestamp)> = Vec::with_capacity(entries.len());
    let mut sequenced_metadata = Vec::with_capacity(entries.len());

    for (entry, sender) in entries {
        let sequenced_entry = L::new(entry, timestamp, n);
        let tile_leaf = sequenced_entry.tile_leaf();
        let merkle_tree_leaf = sequenced_entry.merkle_tree_leaf();
        metrics.seq_leaf_size.observe(tile_leaf.len().as_f64());
        data_tile.extend(tile_leaf);

        // Compute the new tree hashes and add them to the hashReader overlay
        // (we will use them later to insert more leaves and finally to produce
        // the new tiles).
        let hashes = tlog_tiles::stored_hashes(
            n,
            &merkle_tree_leaf,
            &HashReaderWithOverlay {
                edge_tiles: &edge_tiles,
                overlay: &overlay,
            },
        )
        .map_err(|e| {
            SequenceError::NonFatal(format!(
                "couldn't compute new hashes for leaf {sequenced_entry:?}: {e}",
            ))
        })?;
        for (i, h) in hashes.iter().enumerate() {
            let id = tlog_tiles::stored_hash_index(0, n) + i as u64;
            overlay.insert(id, *h);
        }

        n += 1;

        // If the data tile is full, stage it.
        if n % u64::from(TlogTile::FULL_WIDTH) == 0 {
            stage_data_tile(n, &mut edge_tiles, &mut tile_uploads, &data_tile);
            metrics.seq_data_tile_size.observe(data_tile.len().as_f64());
            data_tile.clear();
        }

        sequenced_metadata.push((sender, (n, timestamp)));
        sequenced_entries.push((sequenced_entry, n, timestamp));
    }

    // Stage leftover partial data tile, if any.
    if n != old_size && n % u64::from(TlogTile::FULL_WIDTH) != 0 {
        stage_data_tile(n, &mut edge_tiles, &mut tile_uploads, &data_tile);
        metrics.seq_data_tile_size.observe(data_tile.len().as_f64());
    }

    // Produce and stage new tree tiles.
    let tiles = TlogTile::new_tiles(old_size, n);
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
            key: tile.path(),
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
    let staged_uploads = marshal_staged_uploads(&tile_uploads, tree.size(), tree.hash())
        .map_err(|e| SequenceError::NonFatal(format!("couldn't marshal staged uploads: {e}")))?;
    lock.put_multipart(STAGING_KEY, &staged_uploads)
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
    lock.swap(CHECKPOINT_KEY, &sequence_state.checkpoint, &new_checkpoint)
        .await
        .map_err(|e| {
            SequenceError::Fatal(format!("couldn't upload checkpoint to database: {e}"))
        })?;

    // At this point the pool is fully serialized: new entries were persisted to
    // durable storage (in staging) and the checkpoint was committed to the
    // database. If we were to crash after this, recovery would be clean from
    // database and object storage.
    *sequence_state = SequenceState {
        tree,
        checkpoint: new_checkpoint,
        edge_tiles,
    };

    // Use apply_staged_uploads instead of going over tile_uploads directly, to exercise the same
    // code path as LoadLog.
    // An error here is fatal, since we can't continue leaving behind missing tiles. The next
    // run of sequence would not upload them again, while LoadLog will retry uploading them
    // from the staging bundle.
    apply_staged_uploads(
        object,
        &staged_uploads,
        sequence_state.tree.size(),
        sequence_state.tree.hash(),
    )
    .await
    .map_err(|e| SequenceError::Fatal(format!("couldn't upload a tile: {e}")))?;

    // If we fail to upload, return an error so that we don't produce SCTs that, although
    // safely serialized, wouldn't be part of a publicly visible tree.
    object
        .upload(CHECKPOINT_KEY, &sequence_state.checkpoint, &OPTS_CHECKPOINT)
        .await
        .map_err(|e| {
            SequenceError::NonFatal(format!("couldn't upload checkpoint to object storage: {e}"))
        })?;

    // Return SCTs to clients.
    for (sender, metadata) in sequenced_metadata {
        sender.send_replace(metadata);
    }

    // At this point if the cache put fails, there's no reason to return errors to users. The
    // only consequence of cache false negatives are duplicated leaves anyway. In fact, an
    // error might cause the clients to resubmit, producing more cache false negatives and
    // duplicates.
    if let Err(e) = cache
        .put_entries(
            &sequenced_entries
                .iter()
                .map(|entry| (entry.0.inner().lookup_key(), (entry.1, entry.2)))
                .collect::<Vec<_>>(),
        )
        .await
    {
        warn!(
            "{name}: Cache put failed (entries={}): {e}",
            sequenced_entries.len()
        );
    }

    for tile in &sequence_state.edge_tiles {
        trace!("{name}: Edge tile: {tile:?}");
    }
    info!(
        "{name}: Sequenced pool; tree_size={n}, entries: {}, tiles: {}, timestamp: {timestamp}, duration: {:.2}s, since_last: {:.2}s",
        n - old_size,
        tile_uploads.len(),
        millis_diff_as_secs(timestamp, now_millis()),
        millis_diff_as_secs(old_time, timestamp)
    );

    metrics
        .seq_duration
        .observe(millis_diff_as_secs(timestamp, now_millis()));
    metrics
        .seq_delay
        .observe(millis_diff_as_secs(old_time, timestamp) - config.sequence_interval.as_secs_f64());
    metrics.seq_tiles.inc_by(tile_uploads.len().as_f64());
    metrics.tree_size.set(n.as_f64());
    metrics.tree_time.set(timestamp.as_f64());

    Ok(())
}

// Stage a data tile. This is used as a helper function for [`sequence_entries`].
fn stage_data_tile(
    n: u64,
    edge_tiles: &mut HashMap<u8, TileWithBytes>,
    tile_uploads: &mut Vec<UploadAction>,
    data_tile: &[u8],
) {
    let mut tile = TlogTile::from_index(tlog_tiles::stored_hash_index(0, n - 1));
    tile.set_data_with_path(PathElem::Data);
    edge_tiles.insert(
        DATA_TILE_KEY,
        TileWithBytes {
            tile,
            b: data_tile.to_owned(),
        },
    );
    let action = UploadAction {
        key: tile.path(),
        data: data_tile.to_owned(),
        opts: OPTS_DATA_TILE.clone(),
    };
    tile_uploads.push(action);
}

/// Applies previously-staged uploads to the object backend where contents can be retrieved by log clients.
async fn apply_staged_uploads(
    object: &impl ObjectBackend,
    staged_uploads: &[u8],
    size: u64,
    hash: &Hash,
) -> Result<(), anyhow::Error> {
    if staged_uploads.len() < 8 + HASH_SIZE {
        bail!("malformed staging bundle");
    }
    let staged_size = u64::from_be_bytes(staged_uploads[..8].try_into()?);
    let staged_hash = &Hash(staged_uploads[8..8 + HASH_SIZE].try_into()?);
    if staged_size != size || staged_hash != hash {
        bail!("staging bundle does not match current tree");
    }
    let uploads: Vec<UploadAction> = serde_json::from_slice(&staged_uploads[8 + HASH_SIZE..])?;
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
    let mut tile_order: HashMap<TlogTile, usize> = HashMap::new(); // tile_order[tileKey(tiles[i])] = i
    let mut tiles = Vec::new();

    // Plan to fetch tiles necessary to recompute tree hash.
    // If it matches, those tiles are authenticated.
    let stx = tlog_tiles::sub_tree_index(0, tree_size, vec![]);
    let mut stx_tile_order = vec![0; stx.len()];
    for (i, &x) in stx.iter().enumerate() {
        let tile = TlogTile::from_index(x);
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
        let tile = TlogTile::from_index(x);
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
    let mut data = Vec::with_capacity(tiles.len());
    for tile in &tiles {
        let result = object
            .fetch(&tile.path())
            .await?
            .ok_or(anyhow!("no tile {} in object storage", tile.path()))?;
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
                tile.path(),
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
            let Some(t) = self.edge_tiles.get(&TlogTile::from_index(id).level()) else {
                return Err(TlogError::IndexesNotInTree);
            };
            let h = t.tile.hash_at_index(&t.b, id)?;
            list.push(h);
        }
        Ok(list)
    }
}

/// A pending upload.
#[derive(Debug, Serialize, Deserialize)]
struct UploadAction {
    key: String,
    data: Vec<u8>,
    opts: UploadOptions,
}

/// Marshal a set of pending uploads into a staging bundle.
fn marshal_staged_uploads(
    uploads: &[UploadAction],
    size: u64,
    hash: &Hash,
) -> Result<Vec<u8>, anyhow::Error> {
    Ok(size
        .to_be_bytes()
        .into_iter()
        .chain(hash.0.iter().copied())
        .chain(serde_json::to_vec(uploads)?)
        .collect::<Vec<_>>())
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
    use static_ct_api::{LogEntry, PendingLogEntry, RFC6962Verifier};
    use std::cell::RefCell;
    use tlog_tiles::{Checkpoint, TlogTile};

    #[test]
    fn test_sequence_one_leaf_short() {
        sequence_one_leaf(u64::from(TlogTile::FULL_WIDTH) + 2);
    }

    #[test]
    #[ignore] // This test is skipped as it takes a long time, but can be run with `cargo test -- --ignored`.
    fn test_sequence_one_leaf_long() {
        sequence_one_leaf((u64::from(TlogTile::FULL_WIDTH) + 2) * u64::from(TlogTile::HEIGHT));
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
                let leaf = PendingLogEntry {
                    certificate,
                    ..Default::default()
                };
                add_leaf_to_pool(&mut log.pool_state, &log.cache, leaf);
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
        add_certs(&mut log, TlogTile::FULL_WIDTH as usize - 5 - 1);
        sequence_twice(&mut log, u64::from(TlogTile::FULL_WIDTH) - 1);
        add_certs(&mut log, 1);
        sequence_twice(&mut log, u64::from(TlogTile::FULL_WIDTH));
        add_certs(&mut log, 1);
        sequence_twice(&mut log, u64::from(TlogTile::FULL_WIDTH) + 1);
    }

    #[test]
    fn sequence_upload_count() {
        let mut log = TestLog::new();

        for _ in 0..=TlogTile::FULL_WIDTH {
            log.add_certificate();
        }
        log.sequence().unwrap();

        let mut old = 0;
        let uploads = |log: &mut TestLog, old: &mut usize| -> usize {
            let new = *log.object.uploads.borrow();
            let n = new - *old;
            *old = new;
            n
        };
        uploads(&mut log, &mut old);

        // Empty rounds should cause only one upload (the checkpoint).
        log.sequence().unwrap();
        assert_eq!(uploads(&mut log, &mut old), 1);

        // One entry in steady state (not at tile boundary) should cause three
        // uploads (the checkpoint, a level -1 tile, and a level 0 tile).
        log.add_certificate();
        log.sequence().unwrap();
        assert_eq!(uploads(&mut log, &mut old), 3);

        // A tile width worth of entries should cause five uploads (the
        // checkpoint, two level -1 tiles, two level 0 tiles, and one level 1
        // tile).
        for _ in 0..TlogTile::FULL_WIDTH {
            log.add_certificate();
        }
        log.sequence().unwrap();
        assert_eq!(uploads(&mut log, &mut old), 6);
    }

    #[test]
    fn test_sequence_upload_paths() {
        // Freeze time, acquiring lock so other tests aren't impacted.
        let _lock = util::TIME_MUX.lock();
        let old_time = now_millis();
        util::set_freeze_time(true);
        util::set_global_time(0);

        let mut log = TestLog::new();

        for i in 0..u64::from(TlogTile::FULL_WIDTH) + 5 {
            log.add_certificate_with_seed(i);
        }
        log.sequence().unwrap();
        for i in 0..u64::from(TlogTile::FULL_WIDTH) + 10 {
            log.add_certificate_with_seed(1000 + i);
        }
        log.sequence().unwrap();

        log.check(u64::from(TlogTile::FULL_WIDTH) * 2 + 15);

        let keys = log
            .object
            .objects
            .borrow()
            .keys()
            .cloned()
            .sorted()
            .collect::<Vec<_>>();

        let expected = vec![
            CHECKPOINT_KEY,
            "issuer/1b48a2acbba79932d3852ccde41197f678256f3c2a280e9edf9aad272d6e9c92",
            "issuer/559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
            "issuer/6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d",
            "issuer/81365bbc90b5b3991c762eebada7c6d84d1e39a0a1d648cb4fe5a9890b089da8",
            "issuer/df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c",
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

        // Two pairs of duplicates from the pending pool.
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
        let entries = log.sequence_start();
        let res22 = log.add_with_seed(is_precert, 2);
        log.sequence_finish(entries);
        let entry21 = block_on(res21.resolve()).unwrap();
        let entry22 = block_on(res22.resolve()).unwrap();
        assert_eq!(entry21, entry22);

        // A failed sequencing immediately allows resubmission (i.e., the failed
        // entry in the inSequencing pool is not picked up).
        *log.lock.mode.borrow_mut() = StorageMode::Break {
            prefix: STAGING_KEY,
            persist: true,
        };
        let res = log.add_with_seed(is_precert, 3);
        log.sequence().unwrap();
        assert!(block_on(res.resolve()).is_none());

        *log.lock.mode.borrow_mut() = StorageMode::Ok;
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
        let n = u64::from(TlogTile::FULL_WIDTH) + 2;
        for i in 0..n {
            log.add(is_precert);
            log.sequence().unwrap();
            log.check(i + 1);

            log.sequence_state = Some(
                block_on(SequenceState::load::<PendingLogEntry, LogEntry>(
                    &log.config,
                    &log.object,
                    &log.lock,
                ))
                .unwrap(),
            );
            log.sequence().unwrap();
            log.check(i + 1);
        }
    }

    #[test]
    fn test_reload_wrong_origin() {
        let mut log = TestLog::new();
        log.sequence_state = Some(
            block_on(SequenceState::load::<PendingLogEntry, LogEntry>(
                &log.config,
                &log.object,
                &log.lock,
            ))
            .unwrap(),
        );

        let mut c = log.config.clone();
        c.origin = "wrong".to_string();
        block_on(SequenceState::load::<PendingLogEntry, LogEntry>(
            &c,
            &log.object,
            &log.lock,
        ))
        .unwrap_err();
    }

    #[test]
    fn test_reload_wrong_key() {
        let mut log = TestLog::new();
        log.sequence_state = Some(
            block_on(SequenceState::load::<PendingLogEntry, LogEntry>(
                &log.config,
                &log.object,
                &log.lock,
            ))
            .unwrap(),
        );

        let mut c = log.config.clone();
        c.signing_key = EcdsaSigningKey::random(&mut OsRng);
        block_on(SequenceState::load::<PendingLogEntry, LogEntry>(
            &c,
            &log.object,
            &log.lock,
        ))
        .unwrap_err();

        c = log.config.clone();
        c.witness_key = Ed25519SigningKey::generate(&mut OsRng);
        block_on(SequenceState::load::<PendingLogEntry, LogEntry>(
            &c,
            &log.object,
            &log.lock,
        ))
        .unwrap_err();
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

        *log.lock.mode.borrow_mut() = StorageMode::Break {
            prefix: CHECKPOINT_KEY,
            persist: false,
        };
        log.sequence().unwrap_err();
        log.check(1);

        *log.lock.mode.borrow_mut() = StorageMode::Ok;
        log.sequence_state = Some(
            block_on(SequenceState::load::<PendingLogEntry, LogEntry>(
                &log.config,
                &log.object,
                &log.lock,
            ))
            .unwrap(),
        );
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

        *log.lock.mode.borrow_mut() = StorageMode::Break {
            prefix: STAGING_KEY,
            persist: true,
        };
        log.sequence().unwrap();
        log.check(3);

        *log.lock.mode.borrow_mut() = StorageMode::Ok;

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

        *log.lock.mode.borrow_mut() = StorageMode::Break {
            prefix: CHECKPOINT_KEY,
            persist: false,
        };
        let res = log.add_certificate();
        log.sequence().unwrap_err();
        assert!(block_on(res.resolve()).is_none());
        log.check(2);

        *log.lock.mode.borrow_mut() = StorageMode::Ok;
        log.sequence_state = Some(
            block_on(SequenceState::load::<PendingLogEntry, LogEntry>(
                &log.config,
                &log.object,
                &log.lock,
            ))
            .unwrap(),
        );
        log.add_certificate();
        log.sequence().unwrap();
        log.check(3);
    }

    #[test]
    fn test_sequence_holds() {
        let mut log = TestLog::new();

        // Hold entries at most one sequencing round.
        log.config.max_pending_entry_holds = 1;
        log.add_certificate();
        log.add_certificate();
        log.sequence().unwrap();
        log.check(0); // 2 pending entries are held
        for _ in 0..TlogTile::FULL_WIDTH + 3 {
            log.add_certificate();
        }
        log.sequence().unwrap(); // 5 pending entries from the new batch are held
        log.check(u64::from(TlogTile::FULL_WIDTH));
        log.sequence().unwrap(); // all pending entries sequenced
        log.check(u64::from(TlogTile::FULL_WIDTH) + 5);

        // Hold entries at most two sequencing rounds.
        log.config.max_pending_entry_holds = 2;
        log.add_certificate();
        log.add_certificate();
        log.sequence().unwrap(); // 2 entries held
        log.add_certificate(); // will be sequenced with the older held ones
        log.sequence().unwrap(); // 3 entries held
        log.check(u64::from(TlogTile::FULL_WIDTH) + 5); // still held
        log.sequence().unwrap();
        log.check(u64::from(TlogTile::FULL_WIDTH) + 8); // all pending entries sequenced

        for _ in 0..TlogTile::FULL_WIDTH * 2 {
            log.add_certificate();
        }
        log.sequence().unwrap(); // 8 pending entries are held
        log.sequence().unwrap(); // still held
        log.check(u64::from(TlogTile::FULL_WIDTH) * 3);
        log.sequence().unwrap();
        log.check(u64::from(TlogTile::FULL_WIDTH) * 3 + 8); // all pending entries sequenced
    }

    macro_rules! test_sequence_errors {
        ($name:ident, $object_mode:expr, $lock_mode:expr, $expect_progress:expr, $expect_fatal:expr) => {
            #[test]
            fn $name() {
                let break_seq = |log: &mut TestLog, broken: &mut bool| {
                    *log.object.mode.borrow_mut() = $object_mode;
                    *log.lock.mode.borrow_mut() = $lock_mode;
                    *broken = true;
                };
                let unbreak_seq = |log: &mut TestLog, broken: &mut bool| {
                    *log.object.mode.borrow_mut() = StorageMode::Ok;
                    *log.lock.mode.borrow_mut() = StorageMode::Ok;
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
                                *log.object.mode.borrow_mut() = StorageMode::Ok;
                                *log.lock.mode.borrow_mut() = StorageMode::Ok;
                            }
                            log.sequence_state = Some(
                                block_on(SequenceState::load::<PendingLogEntry, LogEntry>(
                                    &log.config,
                                    &log.object,
                                    &log.lock,
                                ))
                                .unwrap(),
                            );
                            if broken {
                                *log.object.mode.borrow_mut() = $object_mode;
                                *log.lock.mode.borrow_mut() = $lock_mode;
                            }
                        }
                    };
                let mut log = TestLog::new();
                let mut broken = false;
                let mut expected_size = 0;

                for _ in 0..u64::from(TlogTile::FULL_WIDTH) - 2 {
                    log.add_certificate();
                }
                sequence(
                    &mut log,
                    &mut expected_size,
                    broken,
                    u64::from(TlogTile::FULL_WIDTH) - 2,
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
                for _ in 0..u64::from(TlogTile::FULL_WIDTH) - 2 {
                    log.add_certificate();
                }
                sequence(
                    &mut log,
                    &mut expected_size,
                    broken,
                    u64::from(TlogTile::FULL_WIDTH) - 2,
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
        StorageMode::Ok,
        StorageMode::Break {
            prefix: CHECKPOINT_KEY,
            persist: false,
        },
        false,
        true
    );
    // An error while uploading to the lock backend, where the lock is
    // persisted anyway, such as a response timeout.
    test_sequence_errors!(
        lock_upload_persisted,
        StorageMode::Ok,
        StorageMode::Break {
            prefix: CHECKPOINT_KEY,
            persist: true,
        },
        true,
        true
    );
    test_sequence_errors!(
        checkpoint_upload,
        StorageMode::Break {
            prefix: CHECKPOINT_KEY,
            persist: false
        },
        StorageMode::Ok,
        true,
        false
    );
    test_sequence_errors!(
        checkpoint_upload_persisted,
        StorageMode::Break {
            prefix: CHECKPOINT_KEY,
            persist: true
        },
        StorageMode::Ok,
        true,
        false
    );
    test_sequence_errors!(
        staging_upload,
        StorageMode::Ok,
        StorageMode::Break {
            prefix: STAGING_KEY,
            persist: false,
        },
        false,
        false
    );
    test_sequence_errors!(
        staging_upload_persisted,
        StorageMode::Ok,
        StorageMode::Break {
            prefix: STAGING_KEY,
            persist: true,
        },
        false,
        false
    );
    test_sequence_errors!(
        data_tile_upload,
        StorageMode::Break {
            prefix: "tile/data/",
            persist: false
        },
        StorageMode::Ok,
        true,
        true
    );
    test_sequence_errors!(
        data_tile_upload_persisted,
        StorageMode::Break {
            prefix: "tile/data/",
            persist: true
        },
        StorageMode::Ok,
        true,
        true
    );
    test_sequence_errors!(
        tile0_upload,
        StorageMode::Break {
            prefix: "tile/0/",
            persist: false
        },
        StorageMode::Ok,
        true,
        true
    );
    test_sequence_errors!(
        tile0_upload_persisted,
        StorageMode::Break {
            prefix: "tile/0/",
            persist: true
        },
        StorageMode::Ok,
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

    enum StorageMode {
        Ok,
        Break { prefix: &'static str, persist: bool },
    }

    impl StorageMode {
        fn check(&self, key: &str) -> (bool, bool) {
            match self {
                StorageMode::Break { prefix, persist } if key.starts_with(prefix) => {
                    (false, *persist)
                }
                _ => (true, true),
            }
        }
    }

    // Make use of interior mutability here to avoid needing to make trait mutable for tests:
    // https://ricardomartins.cc/2016/06/08/interior-mutability
    struct TestObjectBackend {
        objects: RefCell<HashMap<String, Vec<u8>>>,
        uploads: RefCell<usize>,
        mode: RefCell<StorageMode>,
    }

    impl TestObjectBackend {
        fn new() -> Self {
            Self {
                objects: RefCell::new(HashMap::new()),
                uploads: RefCell::new(0),
                mode: RefCell::new(StorageMode::Ok),
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
            *self.uploads.borrow_mut() += 1;
            let (ok, persist) = self.mode.borrow().check(key);
            if persist {
                self.objects
                    .borrow_mut()
                    .insert(key.to_string(), data.to_vec());
            }
            if ok {
                Ok(())
            } else {
                Err("upload failure".into())
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

    struct TestLockBackend {
        lock: RefCell<HashMap<String, Vec<u8>>>,
        mode: RefCell<StorageMode>,
    }

    impl TestLockBackend {
        fn new() -> Self {
            Self {
                lock: RefCell::new(HashMap::new()),
                mode: RefCell::new(StorageMode::Ok),
            }
        }
    }

    impl LockBackend for TestLockBackend {
        const MAX_PART_BYTES: usize = 100;
        const MAX_PARTS: usize = 10;
        async fn put_multipart(&self, key: &str, value: &[u8]) -> worker::Result<()> {
            self.put(key, value).await
        }
        async fn get_multipart(&self, key: &str) -> worker::Result<Vec<u8>> {
            self.get(key).await
        }
        async fn put(&self, key: &str, value: &[u8]) -> worker::Result<()> {
            let (ok, persist) = self.mode.borrow().check(key);
            if persist {
                self.lock
                    .borrow_mut()
                    .insert(key.to_string(), value.to_vec());
            }
            if ok {
                Ok(())
            } else {
                Err("failed to put value".into())
            }
        }
        async fn swap(&self, key: &str, old: &[u8], new: &[u8]) -> worker::Result<()> {
            if let Some(old_value) = self.lock.borrow().get(key) {
                if old_value != old {
                    return Err("old values do not match".into());
                }
            } else {
                return Err("old value not present".into());
            }
            self.put(key, new).await
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
        pool_state: PoolState<PendingLogEntry>,
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
                sequence_interval: Duration::from_secs(1),
                max_pending_entry_holds: 0,
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
            block_on(sequence::<PendingLogEntry, LogEntry>(
                &mut self.pool_state,
                &mut self.sequence_state,
                &self.config,
                &self.object,
                &self.lock,
                &mut self.cache,
                &self.metrics,
            ))
        }
        fn sequence_start(&mut self) -> Vec<(PendingLogEntry, Sender<SequenceMetadata>)> {
            let sequence_state: &mut SequenceState =
                if let Some(state) = self.sequence_state.as_mut() {
                    state
                } else {
                    let state = block_on(SequenceState::load::<PendingLogEntry, LogEntry>(
                        &self.config,
                        &self.object,
                        &self.lock,
                    ))
                    .unwrap();
                    self.sequence_state.insert(state)
                };
            self.pool_state.take(
                sequence_state.tree.size(),
                self.config.max_pending_entry_holds,
            )
        }
        fn sequence_finish(&mut self, entries: Vec<(PendingLogEntry, Sender<SequenceMetadata>)>) {
            block_on(sequence_entries::<PendingLogEntry, LogEntry>(
                self.sequence_state.as_mut().unwrap(),
                &self.config,
                &self.object,
                &self.lock,
                &mut self.cache,
                entries,
                &self.metrics,
            ))
            .unwrap();
            self.pool_state.reset();
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
            let leaf = PendingLogEntry {
                certificate,
                pre_certificate,
                is_precert,
                issuer_key_hash,
                chain_fingerprints: issuers.iter().map(|&x| Sha256::digest(x).into()).collect(),
            };

            block_on(upload_issuers(&self.object, issuers, &self.config.name)).unwrap();

            add_leaf_to_pool(&mut self.pool_state, &self.cache, leaf)
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

            let mut last_tile = TlogTile::from_index(tlog_tiles::stored_hash_count(c.size() - 1));
            last_tile.set_data_with_path(PathElem::Data);

            for n in 0..last_tile.level_index() {
                let tile = if n == last_tile.level_index() {
                    last_tile
                } else {
                    TlogTile::new(0, n, TlogTile::FULL_WIDTH, Some(PathElem::Data))
                };
                for (i, entry) in TileIterator::<PendingLogEntry, LogEntry>::new(
                    block_on(self.object.fetch(&tile.path())).unwrap().unwrap(),
                    tile.width() as usize,
                )
                .enumerate()
                {
                    let entry = entry.unwrap();
                    let idx = n * u64::from(TlogTile::FULL_WIDTH) + i as u64;
                    assert_eq!(entry.leaf_index, idx);
                    assert!(entry.timestamp <= sth_timestamp);
                    assert_eq!(
                        leaf_hashes[usize::try_from(idx).unwrap()],
                        tlog_tiles::record_hash(&entry.merkle_tree_leaf())
                    );

                    assert!(!entry.inner.certificate.is_empty());
                    if entry.inner.is_precert {
                        assert!(!entry.inner.pre_certificate.is_empty());
                        assert_ne!(entry.inner.issuer_key_hash, [0; 32]);
                    } else {
                        assert!(entry.inner.pre_certificate.is_empty());
                        assert_eq!(entry.inner.issuer_key_hash, [0; 32]);
                    }

                    for fp in entry.inner.chain_fingerprints {
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

        let mut hashes = Vec::with_capacity(indexes.len());
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
