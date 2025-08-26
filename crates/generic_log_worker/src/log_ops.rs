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
    metrics::{millis_diff_as_secs, AsF64, SequencerMetrics},
    util::now_millis,
    CacheRead, CacheWrite, LockBackend, LookupKey, ObjectBackend, SequenceMetadata,
    SequencerConfig,
};
use anyhow::{anyhow, bail};
use futures_util::future::try_join_all;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signed_note::VerifierList;
use std::collections::HashMap;
use std::{
    cell::RefCell,
    cmp::{Ord, Ordering},
    string::String,
    sync::LazyLock,
};
use thiserror::Error;
use tlog_tiles::{
    Hash, HashReader, LogEntry, PendingLogEntry, PreloadedTlogTileReader, Proof, Subtree,
    TileHashReader, TileIterator, TlogError, TlogTile, TlogTileRecorder, TreeWithTimestamp,
    UnixTimestamp, HASH_SIZE,
};
use tokio::sync::watch::{channel, Receiver, Sender};

/// The maximum tile level is 63 (<c2sp.org/static-ct-api>), so safe to use [`u8::MAX`] as
/// the special level for data tiles. The Go implementation uses -1.
const DATA_TILE_LEVEL_KEY: u8 = u8::MAX;
/// Same as above, anything above 63 is fine to use as the level key.
const AUX_TILE_LEVEL_KEY: u8 = u8::MAX - 1;
/// Path used to store checkpoints, both in the object storage and lock backends.
pub const CHECKPOINT_KEY: &str = "checkpoint";
/// Path used to store staging bundles in the lock backend.
const STAGING_KEY: &str = "staging";

// Limit on the number of entries per batch. Tune this parameter to avoid
// running into various size limitations. For instance, unexpectedly large
// leaves (e.g., with PQ signatures) could cause us to exceed the 128MB Workers
// memory limit. Storing 4000 10KB certificates is 40MB.
const MAX_POOL_SIZE: usize = 4000;

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
pub(crate) struct PoolState<P: PendingLogEntry> {
    // How many times sequencing has been skipped for any entries in the pool.
    sequence_skips: usize,

    // Entries that are ready to be sequenced, along with the Sender used to
    // send metadata to receivers once the corresponding entry is sequenced.
    pending_entries: Vec<(P, Sender<SequenceMetadata>)>,

    // Deduplication cache for entries currently pending sequencing.
    pending_dedup: HashMap<LookupKey, Receiver<SequenceMetadata>>,

    // Deduplication cache for entries currently being sequenced.
    in_sequencing_dedup: HashMap<LookupKey, Receiver<SequenceMetadata>>,

    // Ring buffer tracking insertion timestamps for the most recent entries
    // that are potentially skippable.
    leftover_timestamps_millis: [UnixTimestamp; TlogTile::FULL_WIDTH as usize],

    // The next slot to insert an entry timestamp, when reduced modulo
    // `TlogTile::FULL_WIDTH`.
    leftover_timestamps_next_slot: usize,
}

impl<P: PendingLogEntry> Default for PoolState<P> {
    fn default() -> Self {
        PoolState {
            sequence_skips: 0,
            pending_entries: Vec::default(),
            pending_dedup: HashMap::default(),
            in_sequencing_dedup: HashMap::default(),
            leftover_timestamps_millis: [0; TlogTile::FULL_WIDTH as usize],
            leftover_timestamps_next_slot: 0,
        }
    }
}

impl<E: PendingLogEntry> PoolState<E> {
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
        self.leftover_timestamps_millis
            [self.leftover_timestamps_next_slot % TlogTile::FULL_WIDTH as usize] = now_millis();
        self.leftover_timestamps_next_slot += 1;

        AddLeafResult::Pending {
            rx,
            source: PendingSource::Sequencer,
        }
    }
    // Take the entries from the pool that are ready to be sequenced, along with
    // the corresponding Senders to update when the entries have been sequenced.
    //
    // Skip sequencing leftover entries that would be published as a partial
    // tile unless they have already been held back `max_sequence_skips` times
    // or have been in the pool longer than `sequence_skip_threshold_millis`.
    //
    // The return value is an Option that indicates whether or not a new
    // checkpoint should be produced (even if there are no new entries).
    fn take(
        &mut self,
        old_size: u64,
        max_sequence_skips: usize,
        sequence_skip_threshold_millis: Option<u64>,
    ) -> Option<Vec<(E, Sender<SequenceMetadata>)>> {
        let new_size = old_size + self.pending_entries.len() as u64;
        let publishing_full_tile =
            new_size / u64::from(TlogTile::FULL_WIDTH) > old_size / u64::from(TlogTile::FULL_WIDTH);
        let num_leftover_entries =
            usize::try_from(new_size % u64::from(TlogTile::FULL_WIDTH)).unwrap();
        let oldest_leftover_timestamp_millis: UnixTimestamp = self.leftover_timestamps_millis[(self
            .leftover_timestamps_next_slot
            - num_leftover_entries)
            % TlogTile::FULL_WIDTH as usize];
        let oldest_leftover_is_expired = sequence_skip_threshold_millis
            .is_some_and(|threshold| now_millis() > oldest_leftover_timestamp_millis + threshold);

        if publishing_full_tile && max_sequence_skips > 0 && !oldest_leftover_is_expired {
            // Sequence full tiles and skip the rest.

            // If there are leftover entries, this is the first time they have
            // been skipped. Otherwise, set skip count to zero.
            self.sequence_skips = usize::from(num_leftover_entries != 0);
            let split_index = self.pending_entries.len() - num_leftover_entries;
            let leftover_entries = self.pending_entries.split_off(split_index);
            let leftover_dedup = leftover_entries
                .iter()
                .filter_map(|(entry, _)| {
                    let lookup_key = entry.lookup_key();
                    self.pending_dedup
                        .remove(&lookup_key)
                        .map(|rx| (lookup_key, rx))
                })
                .collect::<HashMap<_, _>>();
            self.in_sequencing_dedup = std::mem::replace(&mut self.pending_dedup, leftover_dedup);
            Some(std::mem::replace(
                &mut self.pending_entries,
                leftover_entries,
            ))
        } else if self.sequence_skips >= max_sequence_skips || oldest_leftover_is_expired {
            // Sequence everything. We have reached the skip threshold, and even
            // if there are no entries, we want to create a new checkpoint.
            self.sequence_skips = 0;
            self.in_sequencing_dedup = std::mem::take(&mut self.pending_dedup);
            Some(std::mem::take(&mut self.pending_entries))
        } else {
            // Skip this checkpoint. There are no full tiles to sequence, and
            // we're below the thresholds to skip the leftover entries.
            self.sequence_skips += 1;
            None
        }
    }
    // Reset the map of in-sequencing entries. This should be called after
    // sequencing completes since the entries are either in the deduplication
    // cache or finalized with an error. In the latter case, we don't want
    // a resubmit to deduplicate against the failed sequencing.
    fn reset_in_sequencing_dedup(&mut self) {
        self.in_sequencing_dedup.clear();
    }
}

// State owned by the sequencing loop.
#[derive(Default, Debug, Clone)]
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
    config: &SequencerConfig,
    object: &impl ObjectBackend,
    lock: &impl LockBackend,
) -> Result<(), CreateError> {
    let name = &config.name;

    // To reset a dev log without deleting the existing checkpoints from DO
    // storage and R2, you can temporarily disable the below checks for the
    // specific targeted log name. Make sure to clean up afterwards or the log
    // will keep reseting every time the sequencer DO is re-initialized.
    //
    //     if name != "dev1" {
    //         <check if log exists>
    //     }
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

    // Construct the checkpoint signers
    let dyn_signers = config
        .checkpoint_signers
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>();
    // Construct the checkpoint extension
    let extensions = (config.checkpoint_extension)(timestamp);

    let sth = tree
        .sign(
            config.origin.as_str(),
            &extensions.iter().map(String::as_str).collect::<Vec<_>>(),
            &dyn_signers,
            &mut rand::thread_rng(),
        )
        .map_err(|e| anyhow!("failed to sign checkpoint: {}", e))?;
    lock.put(CHECKPOINT_KEY, &sth)
        .await
        .map_err(|e| anyhow!("failed to upload checkpoint to lock backend: {}", e))?;
    object
        .upload(CHECKPOINT_KEY, sth, &OPTS_CHECKPOINT)
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
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn load<L: LogEntry>(
        config: &SequencerConfig,
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

        // Construct the VerifierList containing the signing and witness pubkeys
        let verifiers = VerifierList::new(
            config
                .checkpoint_signers
                .iter()
                .map(|s| s.verifier())
                .collect(),
        );

        let (c, timestamp) = tlog_tiles::open_checkpoint(
            config.origin.as_str(),
            &verifiers,
            now_millis(),
            &stored_checkpoint,
        )?;

        let timestamp = match timestamp {
            Some(timestamp) => timestamp,
            None if L::REQUIRE_CHECKPOINT_TIMESTAMP => {
                bail!("no verifiers with timestamped signatures were used")
            }
            _ => 0,
        };

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
        let (c1, _) =
            tlog_tiles::open_checkpoint(config.origin.as_str(), &verifiers, now_millis(), &sth)?;

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
            // Fetch the right-most tree tiles.
            edge_tiles = read_edge_tiles(object, c.size(), c.hash()).await?;

            // Fetch the right-most data tile.
            let (level0_tile, level0_tile_bytes) = {
                let x = edge_tiles.get(&0).ok_or(anyhow!("no level 0 tile found"))?;
                (x.tile, &x.b)
            };
            let data_tile = level0_tile.with_data_path(L::Pending::DATA_TILE_PATH);
            let data_tile_bytes = object
                .fetch(&data_tile.path())
                .await?
                .ok_or(anyhow!("no data tile in object storage"))?;

            // Verify the data tile against the level 0 tile.
            let start = u64::from(TlogTile::FULL_WIDTH) * data_tile.level_index();
            for (i, entry) in
                TileIterator::<L>::new(&data_tile_bytes, data_tile.width() as usize).enumerate()
            {
                let got = entry?.merkle_tree_leaf();
                let exp = level0_tile.hash_at_index(
                    level0_tile_bytes,
                    tlog_tiles::stored_hash_index(0, start + i as u64),
                )?;
                if got != exp {
                    bail!(
                        "tile leaf entry {} hashes to {got}, level 0 hash is {exp}",
                        start + i as u64,
                    );
                }
            }

            // Store the data tile.
            edge_tiles.insert(
                DATA_TILE_LEVEL_KEY,
                TileWithBytes {
                    tile: data_tile,
                    b: data_tile_bytes,
                },
            );

            // Fetch and store the right-most auxiliary tile, if configured.
            if let Some(path_elem) = L::Pending::AUX_TILE_PATH {
                let aux_tile = level0_tile.with_data_path(path_elem);
                let aux_tile_bytes = object
                    .fetch(&aux_tile.path())
                    .await?
                    .ok_or(anyhow!("no auxiliary tile in object storage"))?;

                edge_tiles.insert(
                    AUX_TILE_LEVEL_KEY,
                    TileWithBytes {
                        tile: aux_tile,
                        b: aux_tile_bytes,
                    },
                );
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

    /// Returns the current checkpoint
    pub(crate) fn checkpoint(&self) -> &[u8] {
        &self.checkpoint
    }

    /// Proves inclusion of the last leaf in the current tree.
    #[cfg(test)]
    pub(crate) fn prove_inclusion_of_last_elem(&self) -> Proof {
        let tree_size = self.tree.size();
        let reader = HashReaderWithOverlay {
            edge_tiles: &self.edge_tiles,
            overlay: &HashMap::default(),
        };
        // We can unwrap because edge_tiles is guaranteed to contain the tiles
        // necessary to prove this.
        tlog_tiles::inclusion_proof(tree_size, tree_size - 1, &reader).unwrap()
    }

    /// Proves that this tree of size n is compatible with the subtree of size
    /// n-1. In other words, prove that we appended 1 element to the tree.
    ///
    /// # Errors
    /// Errors when the last tree was size 0. We cannot prove consistency with
    /// respect to an empty tree
    #[cfg(test)]
    pub(crate) fn prove_consistency_of_single_append(&self) -> Result<Proof, TlogError> {
        let tree_size = self.tree.size();
        let reader = HashReaderWithOverlay {
            edge_tiles: &self.edge_tiles,
            overlay: &HashMap::default(),
        };
        tlog_tiles::consistency_proof(tree_size, tree_size - 1, &reader)
    }
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error(transparent)]
    Tlog(#[from] tlog_tiles::TlogError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Returns a verified inclusion proof that the leaf at index `leaf_index` is
/// included in the current tree of size `cur_tree_size` with hash
/// `cur_tree_hash`.
///
/// # Errors
///
/// Errors when the leaf index is not within the tree, or the desired tiles do
/// not exist as bucket objects.
pub async fn prove_inclusion(
    cur_tree_size: u64,
    cur_tree_hash: Hash,
    leaf_index: u64,
    object: &impl ObjectBackend,
) -> Result<Proof, ProofError> {
    prove_subtree_inclusion(
        cur_tree_size,
        cur_tree_hash,
        0,
        cur_tree_size,
        leaf_index,
        object,
    )
    .await
}

/// Returns a verified inclusion proof that the leaf at index `leaf_index` is
/// included in the subtree `[start, end)`. `cur_tree_size` and `cur_tree_hash`
/// allow us to select the correct partial tiles.
///
/// # Errors
///
/// Errors when the leaf index is not within the subtree, or the desired tiles
/// do not exist as bucket objects.
pub async fn prove_subtree_inclusion(
    cur_tree_size: u64,
    cur_tree_hash: Hash,
    start: u64,
    end: u64,
    leaf_index: u64,
    object: &impl ObjectBackend,
) -> Result<Proof, ProofError> {
    // Fetch the tiles needed for the proof.
    let n = &Subtree::new(start, end)?;
    let mut indexes = tlog_tiles::subtree_inclusion_proof_indexes(n, leaf_index)?;

    // Fetch the leaf and subtree hashes to verify the proof. These aren't
    // needed to construct the proof, but fetch them so they're available in
    // `tile_reader`.
    indexes.append(&mut tlog_tiles::subtree_hash_indexes(n));
    let leaf_shx = tlog_tiles::stored_hash_index(0, leaf_index);
    indexes.push(leaf_shx);
    indexes.sort_unstable();
    indexes.dedup();

    let tile_reader = tile_reader_for_indexes(cur_tree_size, &indexes, object).await?;

    // Construct the proof.
    let hash_reader = TileHashReader::new(cur_tree_size, cur_tree_hash, &tile_reader);
    let proof = tlog_tiles::subtree_inclusion_proof(n, leaf_index, &hash_reader)?;

    // Verify the proof.
    let n_hash = tlog_tiles::subtree_hash(n, &hash_reader)?;
    let leaf_hash: Hash = hash_reader
        .read_hashes(&[leaf_shx])?
        .into_iter()
        .next()
        .ok_or(anyhow!("failed to read leaf hash"))?;
    tlog_tiles::verify_subtree_inclusion_proof(&proof, n, n_hash, leaf_index, leaf_hash)?;

    Ok(proof)
}

/// Returns a verified consistency proof, proving the tree with `cur_tree_size`
/// and hash `cur_tree_hash` is an extension of the tree with `prev_tree_size`.
///
/// # Errors
///
/// Errors when the desired tiles do not exist as bucket objects, or if the
/// proof fails.
pub async fn prove_consistency(
    cur_tree_hash: Hash,
    cur_tree_size: u64,
    prev_tree_size: u64,
    object: &impl ObjectBackend,
) -> Result<Proof, ProofError> {
    prove_subtree_consistency(cur_tree_hash, cur_tree_size, 0, prev_tree_size, object).await
}

/// Returns a verified consistency proof, proving the tree with `cur_tree_size`
/// and hash `cur_tree_hash` is consistent with the subtree `[start, end)`.
///
/// # Errors
///
/// Errors when the desired tiles do not exist as bucket objects, or if the
/// proof fails.
pub async fn prove_subtree_consistency(
    cur_tree_hash: Hash,
    cur_tree_size: u64,
    start: u64,
    end: u64,
    object: &impl ObjectBackend,
) -> Result<Proof, ProofError> {
    let m = &Subtree::new(start, end)?;
    // Fetch the tiles needed for the proof.
    let mut indexes = tlog_tiles::subtree_consistency_proof_indexes(cur_tree_size, m)?;

    // Fetch the subtree hash to verify the proof. These aren't
    // needed to construct the proof, but we want to fetch them now so they're
    // available in `tile_reader`.
    indexes.append(&mut tlog_tiles::subtree_hash_indexes(m));

    let tile_reader = tile_reader_for_indexes(cur_tree_size, &indexes, object).await?;
    let hash_reader = TileHashReader::new(cur_tree_size, cur_tree_hash, &tile_reader);

    // Construct the proof.
    let proof = tlog_tiles::subtree_consistency_proof(cur_tree_size, m, &hash_reader)?;

    // Verify the proof.
    let m_hash = tlog_tiles::subtree_hash(m, &hash_reader)?;
    tlog_tiles::verify_subtree_consistency_proof(&proof, cur_tree_size, cur_tree_hash, m, m_hash)?;

    Ok(proof)
}

/// Fetch the tree tiles containing the nodes at the requested indexes, as well
/// as all tiles needed to verify those nodes.
async fn tile_reader_for_indexes(
    tree_size: u64,
    indexes: &[u64],
    object: &impl ObjectBackend,
) -> Result<PreloadedTlogTileReader, anyhow::Error> {
    // Record the tiles that we'll need.
    let tiles_to_fetch = {
        let tile_reader = TlogTileRecorder::default();
        // Pass in a dummy tree hash since 'read_hashes' doesn't use it before
        // it short-circuits with `TlogError::RecordedTilesOnly`.
        let hash_reader = TileHashReader::new(tree_size, Hash::default(), &tile_reader);

        // `TileRecorder` is guaranteed to make `read_hashes` return a
        // `TlogError::RecordedTilesOnly` error. This is fine, because it
        // already collected the data we needed.
        match hash_reader.read_hashes(indexes) {
            Err(TlogError::RecordedTilesOnly) => {}
            _ => bail!("expected to get a RecordedTilesOnly error"),
        }

        tile_reader.0.into_inner()
    };

    // Fetch all the tiles needed to fetch and authenticate the nodes at the
    // requested indexes.
    let mut all_tile_data = HashMap::new();
    for tile in tiles_to_fetch {
        let Some(tile_data) = object.fetch(&tile.path()).await? else {
            bail!("tile not found in object backend: {}", tile.path());
        };
        all_tile_data.insert(tile, tile_data);
    }

    // Return a `PreloadedTlogTileReader` wrapping with the fetched tiles.
    Ok(PreloadedTlogTileReader(all_tile_data))
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
pub(crate) fn add_leaf_to_pool<E: PendingLogEntry>(
    state: &RefCell<PoolState<E>>,
    cache: &impl CacheRead,
    config: &SequencerConfig,
    entry: E,
) -> AddLeafResult {
    let hash = entry.lookup_key();
    let mut state = state.borrow_mut();

    if !config.enable_dedup {
        // Bypass deduplication and rate limit checks.
        state.add(hash, entry)
    } else if let Some(result) = state.check(&hash) {
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

/// Sequences the current pool of pending entries in the ephemeral state.
///
/// # Errors
///
/// Will return an error if sequencing fails with an error that requires the
/// sequencer to be re-initialized to get into a good state.
pub(crate) async fn sequence<L: LogEntry>(
    pool_state: &RefCell<PoolState<L::Pending>>,
    sequence_state: &RefCell<SequenceState>,
    config: &SequencerConfig,
    object: &impl ObjectBackend,
    lock: &impl LockBackend,
    cache: &impl CacheWrite,
    metrics: &SequencerMetrics,
) -> Result<(), anyhow::Error> {
    // Add the log's initial entry if needed.
    if sequence_state.borrow().tree.size() == 0 {
        if let Some(entry) = L::initial_entry() {
            pool_state.borrow_mut().add(entry.lookup_key(), entry);
        }
    }

    let Some(entries) = pool_state.borrow_mut().take(
        sequence_state.borrow().tree.size(),
        config.max_sequence_skips,
        config.sequence_skip_threshold_millis,
    ) else {
        // Skip this checkpoint. Nothing to sequence.
        metrics.seq_count.with_label_values(&["skip"]).inc();
        return Ok(());
    };

    metrics.seq_pool_size.observe(entries.len().as_f64());

    let result = match sequence_entries::<L>(
        sequence_state,
        config,
        object,
        lock,
        cache,
        entries,
        metrics,
    )
    .await
    {
        Ok(()) => {
            metrics.seq_count.with_label_values(&["none"]).inc();
            Ok(())
        }
        Err(SequenceError::Fatal(e)) => {
            // The ephemeral sequence state may no longer be valid. Return an
            // error so the caller can reload the log into a good state.
            metrics.seq_count.with_label_values(&["fatal"]).inc();
            error!("{}: Fatal sequencing error {e}", config.name);
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
    pool_state.borrow_mut().reset_in_sequencing_dedup();

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
async fn sequence_entries<L: LogEntry>(
    sequence_state: &RefCell<SequenceState>,
    config: &SequencerConfig,
    object: &impl ObjectBackend,
    lock: &impl LockBackend,
    cache: &impl CacheWrite,
    entries: Vec<(L::Pending, Sender<SequenceMetadata>)>,
    metrics: &SequencerMetrics,
) -> Result<(), SequenceError> {
    let name = &config.name;

    let SequenceState {
        tree: old_tree,
        checkpoint: old_checkpoint,
        mut edge_tiles,
    } = (*sequence_state.borrow()).clone();

    let old_size = old_tree.size();
    let old_time = old_tree.time();
    let timestamp = now_millis();

    // Load the current partial data tile, if any.
    let mut tile_uploads: Vec<UploadAction> = Vec::new();
    let mut data_tile = Vec::new();
    if let Some(t) = edge_tiles.get(&DATA_TILE_LEVEL_KEY) {
        if t.tile.width() < TlogTile::FULL_WIDTH {
            data_tile.clone_from(&t.b);
        }
    }

    // Load the current partial auxiliary tile, if configured.
    let mut aux_tile = Vec::new();
    if L::Pending::AUX_TILE_PATH.is_some() {
        if let Some(t) = edge_tiles.get(&AUX_TILE_LEVEL_KEY) {
            if t.tile.width() < TlogTile::FULL_WIDTH {
                aux_tile.clone_from(&t.b);
            }
        }
    }

    let mut overlay = HashMap::new();
    let mut n = old_size;
    let mut sequenced_metadata = Vec::with_capacity(entries.len());
    let mut cache_metadata = Vec::with_capacity(entries.len());

    for (entry, sender) in entries {
        // Add the entry and metadata to our lists of things sequenced
        let metadata = (n, timestamp);
        cache_metadata.push((entry.lookup_key(), metadata));
        sequenced_metadata.push((sender, metadata));

        // Write to the auxiliary tile, if configured.
        if L::Pending::AUX_TILE_PATH.is_some() {
            aux_tile.extend(entry.aux_entry());
        }

        let sequenced_entry = L::new(entry, metadata);
        let tile_leaf = sequenced_entry.to_data_tile_entry();
        let merkle_tree_leaf = sequenced_entry.merkle_tree_leaf();
        metrics.seq_leaf_size.observe(tile_leaf.len().as_f64());
        data_tile.extend(tile_leaf);

        // Compute the new tree hashes and add them to the hashReader overlay
        // (we will use them later to insert more leaves and finally to produce
        // the new tiles).
        let hashes = tlog_tiles::stored_hashes_for_record_hash(
            n,
            merkle_tree_leaf,
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
            metrics
                .seq_data_tile_size
                .with_label_values(&["full"])
                .observe(data_tile.len().as_f64());
            stage_data_tile::<L>(
                n,
                &mut edge_tiles,
                &mut tile_uploads,
                std::mem::take(&mut data_tile),
                std::mem::take(&mut aux_tile),
            );
        }
    }

    // Stage leftover partial data tile, if any.
    if n != old_size && n % u64::from(TlogTile::FULL_WIDTH) != 0 {
        metrics
            .seq_data_tile_size
            .with_label_values(&["partial"])
            .observe(data_tile.len().as_f64());
        stage_data_tile::<L>(
            n,
            &mut edge_tiles,
            &mut tile_uploads,
            std::mem::take(&mut data_tile),
            std::mem::take(&mut aux_tile),
        );
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

    // Construct the new sequence state.
    let new = {
        let tree = TreeWithTimestamp::from_hash_reader(
            n,
            &HashReaderWithOverlay {
                edge_tiles: &edge_tiles,
                overlay: &overlay,
            },
            timestamp,
        )
        .map_err(|e| SequenceError::NonFatal(format!("couldn't compute tree head: {e}")))?;
        let dyn_signers = config
            .checkpoint_signers
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>();
        let extensions = (config.checkpoint_extension)(timestamp);
        let checkpoint = tree
            .sign(
                config.origin.as_str(),
                &extensions.iter().map(String::as_str).collect::<Vec<_>>(),
                &dyn_signers,
                &mut rand::thread_rng(),
            )
            .map_err(|e| SequenceError::NonFatal(format!("couldn't sign checkpoint: {e}")))?;
        SequenceState {
            tree,
            checkpoint,
            edge_tiles,
        }
    };

    // Upload tiles to staging, where they can be recovered by [SequenceState::load] if we
    // crash right after updating DO storage.
    let staged_uploads = marshal_staged_uploads(&tile_uploads, new.tree.size(), new.tree.hash())
        .map_err(|e| SequenceError::NonFatal(format!("couldn't marshal staged uploads: {e}")))?;
    lock.put_multipart(STAGING_KEY, &staged_uploads)
        .await
        .map_err(|e| SequenceError::NonFatal(format!("couldn't upload staged tiles: {e}")))?;

    // This is a critical error, since we don't know the state of the
    // checkpoint in the database at this point. Bail and let [SequenceState::load] get us
    // to a good state after restart.
    lock.swap(CHECKPOINT_KEY, &old_checkpoint, new.checkpoint())
        .await
        .map_err(|e| {
            SequenceError::Fatal(format!("couldn't upload checkpoint to database: {e}"))
        })?;

    // At this point the pool is fully serialized: new entries were persisted to
    // durable storage (in staging) and the checkpoint was committed to the
    // database. If we were to crash after this, recovery would be clean from
    // database and object storage.
    *sequence_state.borrow_mut() = new.clone();

    // Use apply_staged_uploads instead of going over tile_uploads directly, to exercise the same
    // code path as LoadLog.
    // An error here is fatal, since we can't continue leaving behind missing tiles. The next
    // run of sequence would not upload them again, while LoadLog will retry uploading them
    // from the staging bundle.
    apply_staged_uploads(object, &staged_uploads, new.tree.size(), new.tree.hash())
        .await
        .map_err(|e| SequenceError::Fatal(format!("couldn't upload a tile: {e}")))?;

    // If we fail to upload, return an error so that we don't produce SCTs that, although
    // safely serialized, wouldn't be part of a publicly visible tree.
    object
        .upload(CHECKPOINT_KEY, new.checkpoint(), &OPTS_CHECKPOINT)
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
    if let Err(e) = cache.put_entries(&cache_metadata).await {
        warn!(
            "{name}: Cache put failed (entries={}): {e}",
            cache_metadata.len()
        );
    }

    // Call the checkpoint callback. This is a no-op for CT, but is used to
    // update landmark checkpoints for MTC.
    if let Err(e) = (config.checkpoint_callback)(n, old_time, timestamp).await {
        warn!("{name}: Checkpoint callback failed: {e}");
    }

    for tile in new.edge_tiles {
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
    metrics.tree_time.set(timestamp.as_f64() / 1000.0);

    Ok(())
}

// Stage a data tile, and if configured an auxiliary tile.
// This is used as a helper function for [`sequence_entries`].
fn stage_data_tile<L: LogEntry>(
    n: u64,
    edge_tiles: &mut HashMap<u8, TileWithBytes>,
    tile_uploads: &mut Vec<UploadAction>,
    data_tile: Vec<u8>,
    aux_tile: Vec<u8>,
) {
    let tile = TlogTile::from_index(tlog_tiles::stored_hash_index(0, n - 1))
        .with_data_path(L::Pending::DATA_TILE_PATH);
    edge_tiles.insert(
        DATA_TILE_LEVEL_KEY,
        TileWithBytes {
            tile,
            b: data_tile.clone(),
        },
    );
    tile_uploads.push(UploadAction {
        key: tile.path(),
        data: data_tile,
        opts: OPTS_DATA_TILE.clone(),
    });
    if let Some(path_elem) = L::Pending::AUX_TILE_PATH {
        let tile =
            TlogTile::from_index(tlog_tiles::stored_hash_index(0, n - 1)).with_data_path(path_elem);
        edge_tiles.insert(
            AUX_TILE_LEVEL_KEY,
            TileWithBytes {
                tile,
                b: aux_tile.clone(),
            },
        );
        tile_uploads.push(UploadAction {
            key: tile.path(),
            data: aux_tile,
            opts: OPTS_DATA_TILE.clone(),
        });
    }
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
    let uploads = bitcode::deserialize::<Vec<UploadAction>>(&staged_uploads[8 + HASH_SIZE..])?;
    let upload_futures = uploads
        .iter()
        .map(|u| object.upload(&u.key, u.data.clone(), &u.opts));
    try_join_all(upload_futures).await?;

    Ok(())
}

/// Read and verify the tiles on the right edge of the tree from the object backend.
async fn read_edge_tiles(
    object: &impl ObjectBackend,
    tree_size: u64,
    tree_hash: &Hash,
) -> Result<HashMap<u8, TileWithBytes>, anyhow::Error> {
    // Fetch the right-most edge tiles by reading the last leaf. TileHashReader
    // will fetch and verify the right tiles as a side-effect.
    let indexes = vec![tlog_tiles::stored_hash_index(0, tree_size - 1)];
    let tile_reader = tile_reader_for_indexes(tree_size, &indexes, object).await?;

    // Verify the leaf tile against the tree hash.
    let hash_reader = TileHashReader::new(tree_size, *tree_hash, &tile_reader);
    hash_reader.read_hashes(&indexes).map_err(|e| anyhow!(e))?;

    let mut edge_tiles: HashMap<u8, TileWithBytes> = HashMap::new();
    for (tile, b) in tile_reader.0 {
        if edge_tiles.get(&tile.level()).is_none_or(|t| {
            t.tile.level_index() < tile.level_index()
                || (t.tile.level_index() == tile.level_index() && t.tile.width() < tile.width())
        }) {
            edge_tiles.insert(tile.level(), TileWithBytes { tile, b });
        }
    }

    Ok(edge_tiles)
}

/// Read and verify a single log entry at `leaf_index`.
///
/// # Errors
///
/// Returns an error if the leaf is not successfully read or verified.
pub async fn read_leaf<L: LogEntry>(
    object: &impl ObjectBackend,
    leaf_index: u64,
    tree_size: u64,
    tree_hash: &Hash,
) -> Result<L, anyhow::Error> {
    let leaf_shx = tlog_tiles::stored_hash_index(0, leaf_index);
    let tile_reader = tile_reader_for_indexes(tree_size, &[leaf_shx], object).await?;

    // Verify the leaf tile against the tree hash.
    let hash_reader = TileHashReader::new(tree_size, *tree_hash, &tile_reader);
    let hashes = hash_reader
        .read_hashes(&[leaf_shx])
        .map_err(|e| anyhow!(e))?;
    let leaf_hash = hashes.first().ok_or(anyhow!("too many hashes read"))?;

    // Get the level-0 tile. There will be two level-0 tiles in the reader, so get the one matching the requested hash.
    let Some((level0_tile, level0_tile_bytes)) = tile_reader.0.into_iter().find(|(tile, b)| {
        tile.level() == 0
            && tile
                .hash_at_index(b, leaf_shx)
                .is_ok_and(|h| h == *leaf_hash)
    }) else {
        bail!("failed to get level-0 tile");
    };

    // Get the data tile.
    let data_tile = level0_tile.with_data_path(L::Pending::DATA_TILE_PATH);
    let data_tile_bytes = object
        .fetch(&data_tile.path())
        .await?
        .ok_or(anyhow!("no data tile in object storage"))?;

    // Verify the data tile against the level 0 tile.
    let start = u64::from(TlogTile::FULL_WIDTH) * data_tile.level_index();
    for (i, entry_res) in
        TileIterator::<L>::new(&data_tile_bytes, data_tile.width() as usize).enumerate()
    {
        let entry = entry_res?;
        let got = entry.merkle_tree_leaf();
        let exp = level0_tile.hash_at_index(
            &level0_tile_bytes,
            tlog_tiles::stored_hash_index(0, start + i as u64),
        )?;
        if got != exp {
            bail!(
                "tile leaf entry {} hashes to {got}, level 0 hash is {exp}",
                start + i as u64,
            );
        }
        if leaf_index == start + i as u64 {
            return Ok(entry);
        }
    }
    bail!("did not find leaf")
}

/// Returns hashes from `edge_tiles` or from the overlay cache.
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
        .chain(bitcode::serialize(uploads)?)
        .collect::<Vec<_>>())
}

/// [`UploadOptions`] are used as part of the [`ObjectBackend::upload`] method, and are
/// marshaled to JSON and stored in the staging bundles.
#[derive(Debug, Default, Serialize, Clone, Deserialize)]
pub struct UploadOptions {
    /// The MIME type of the data. If empty, defaults to
    /// "application/octet-stream".
    pub content_type: Option<String>,

    /// Immutable is true if the data is never updated after being uploaded.
    pub immutable: bool,
}

/// Options for uploading checkpoints.
static OPTS_CHECKPOINT: LazyLock<UploadOptions> = LazyLock::new(|| UploadOptions {
    content_type: Some("text/plain; charset=utf-8".to_string()),
    immutable: false,
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

/// Content-type header for issuer cert uploads
static OPTS_ISSUER: LazyLock<UploadOptions> = LazyLock::new(|| UploadOptions {
    content_type: Some("application/pkix-cert".to_string()),
    immutable: true,
});

/// Uploads any newly-observed issuers to the object backend, returning the
/// paths of those uploaded.
///
/// # Errors
///
/// Will return an error if an issuer already exists in the object backend, but
/// with invalid contents.
pub async fn upload_issuers(
    object: &impl ObjectBackend,
    issuers: &[&[u8]],
    name: &str,
) -> worker::Result<()> {
    let issuer_futures = issuers.iter().map(|issuer| async move {
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
            object.upload(&path, *issuer, &OPTS_ISSUER).await?;
            Ok(Some(path))
        }
    });

    for path in try_join_all(issuer_futures).await?.iter().flatten() {
        {
            info!("{name}: Observed new issuer; path={path}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{empty_checkpoint_callback, util};

    use anyhow::ensure;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use futures_executor::block_on;
    use itertools::Itertools;
    use p256::ecdsa::SigningKey as EcdsaSigningKey;
    use prometheus::Registry;
    use rand::{
        rngs::{OsRng, SmallRng},
        thread_rng, Rng, RngCore, SeedableRng,
    };
    use signed_note::{KeyName, Note};
    use static_ct_api::{
        PrecertData, StaticCTCheckpointSigner, StaticCTLogEntry, StaticCTPendingLogEntry,
    };
    use std::time::Duration;
    use tlog_tiles::{CheckpointSigner, CheckpointText, Ed25519CheckpointSigner, TlogTile};

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

        // For testing, keep the root hashes of all the intermediate trees we create
        let mut tree_hashes = vec![*log.sequence_state.borrow().tree.hash()];
        // Add n certs to the tree one by one
        for i in 0..n {
            let old_tree_hash = *log.sequence_state.borrow().tree.hash();

            let res = log.add_certificate();
            log.sequence().unwrap();
            // Wait until sequencing completes for this entry's pool.
            let (leaf_index, _) = block_on(res.resolve()).unwrap();
            assert_eq!(leaf_index, i);
            log.check(i + 1).unwrap();

            // Check we can make proofs
            let sequence_state = log.sequence_state.borrow();
            let new_tree_hash = *sequence_state.tree.hash();
            let tree_size = i + 1;
            let inc_proof = sequence_state.prove_inclusion_of_last_elem();
            // Verify the inclusion proof
            let last_hash: Hash = {
                // Get the rightmost leaf tile, then extract the last hash from it
                let leaf_edge = &sequence_state.edge_tiles.get(&0u8).unwrap().b;
                Hash(leaf_edge[leaf_edge.len() - HASH_SIZE..].try_into().unwrap())
            };
            tlog_tiles::verify_inclusion_proof(
                &inc_proof,
                tree_size,
                new_tree_hash,
                leaf_index,
                last_hash,
            )
            .unwrap();

            // Save the tree hash
            tree_hashes.push(new_tree_hash);

            // Make a consistency proof. Just can't do it with a size-0 subtree
            if i > 0 {
                let proof = sequence_state.prove_consistency_of_single_append().unwrap();
                // Verify the proof
                tlog_tiles::verify_consistency_proof(
                    &proof,
                    tree_size,
                    new_tree_hash,
                    tree_size - 1,
                    old_tree_hash,
                )
                .unwrap();
                // Check that the other way of constructing the consistency proof is the same
                let proof2 = block_on(prove_consistency(
                    new_tree_hash,
                    tree_size,
                    tree_size - 1,
                    &log.object,
                ))
                .unwrap();
                assert_eq!(proof, proof2);
            }
        }
        // Check that the static CT log is valid
        log.check(n).unwrap();

        // Check that we can make an inclusion proof for every leaf in the tree
        let sequence_state = log.sequence_state.borrow();
        let tree_hash = *sequence_state.tree.hash();
        for i in 0..n {
            // Compute the inclusion proof for leaf `leaf_index`.
            let proof = block_on(prove_inclusion(
                sequence_state.tree.size(),
                *sequence_state.tree.hash(),
                i,
                &log.object,
            ))
            .unwrap();
            // Verify the inclusion proof. We need the leaf hash.
            let leaf_hash = {
                // Get the tile the leaf belongs to, and correct the width by getting the 0th parent
                let leaf_tile = TlogTile::from_leaf_index(i).parent(0, n).unwrap();
                let leaf_tile_data = block_on(log.object.fetch(&leaf_tile.path()))
                    .unwrap()
                    .unwrap();
                // Extract the correct hash from the tile
                let leaf_tile_idx = usize::try_from(i % u64::from(TlogTile::FULL_WIDTH)).unwrap();
                Hash(
                    leaf_tile_data[HASH_SIZE * leaf_tile_idx..HASH_SIZE * (leaf_tile_idx + 1)]
                        .try_into()
                        .unwrap(),
                )
            };
            // Verify the inclusion proof
            tlog_tiles::verify_inclusion_proof(&proof, n, tree_hash, i, leaf_hash).unwrap();
        }

        // Check that we can make a consistency proof for random spans in the tree
        let mut rng = thread_rng();
        for _ in 0..100 {
            let prev_tree_size = rng.gen_range(1..n);
            let new_tree_size = rng.gen_range(prev_tree_size + 1..=n);
            let consistency_proof = block_on(prove_consistency(
                tree_hashes[usize::try_from(new_tree_size).unwrap()],
                new_tree_size,
                prev_tree_size,
                &log.object,
            ))
            .unwrap();
            tlog_tiles::verify_consistency_proof(
                &consistency_proof,
                new_tree_size,
                tree_hashes[usize::try_from(new_tree_size).unwrap()],
                prev_tree_size,
                tree_hashes[usize::try_from(prev_tree_size).unwrap()],
            )
            .unwrap();
        }
    }

    #[test]
    #[ignore] // This test is skipped as it takes a long time, but can be run with `cargo test -- --ignored`.
    fn test_sequence_large_log() {
        let mut log = TestLog::new();

        for _ in 0..5 {
            log.add_certificate();
        }
        log.sequence().unwrap();
        log.check(5).unwrap();

        for i in 0..500_u64 {
            for k in 0..3000_u64 {
                let certificate = (i * 3000 + k).to_be_bytes().to_vec();
                let leaf = StaticCTPendingLogEntry {
                    certificate,
                    precert_opt: None,
                    chain_fingerprints: vec![[0; 32], [1; 32], [2; 32]],
                };
                add_leaf_to_pool(&log.pool_state, &log.cache, &log.config, leaf);
            }
            log.sequence().unwrap();

            // Check we can make proofs
            log.sequence_state.borrow().prove_inclusion_of_last_elem();
            // We're batch-adding, so there's no chance tree_size - 1 is 0
            log.sequence_state
                .borrow()
                .prove_consistency_of_single_append()
                .unwrap();
            // It's annoying to verify these proofs right here. See
            // sequence_one_leaf() for the verifications
        }
        log.check(5 + 500 * 3000).unwrap();
    }

    #[test]
    fn test_sequence_empty_pool() {
        let mut log = TestLog::new();
        let sequence_twice = |log: &mut TestLog, size: u64| {
            log.sequence().unwrap();
            let t1 = log.check(size).unwrap();
            log.sequence().unwrap();
            let t2 = log.check(size).unwrap();
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

        log.check(u64::from(TlogTile::FULL_WIDTH) * 2 + 15).unwrap();

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
        log.check(6).unwrap();

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
        log.check(8).unwrap();
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
            log.check(i + 1).unwrap();

            *log.sequence_state.borrow_mut() = block_on(SequenceState::load::<StaticCTLogEntry>(
                &log.config,
                &log.object,
                &log.lock,
            ))
            .unwrap();
            log.sequence().unwrap();
            log.check(i + 1).unwrap();
        }
    }

    #[test]
    fn test_reload_wrong_origin() {
        let mut log = TestLog::new();
        *log.sequence_state.borrow_mut() = block_on(SequenceState::load::<StaticCTLogEntry>(
            &log.config,
            &log.object,
            &log.lock,
        ))
        .unwrap();

        log.config.origin = KeyName::new("wrong".to_string()).unwrap();
        block_on(SequenceState::load::<StaticCTLogEntry>(
            &log.config,
            &log.object,
            &log.lock,
        ))
        .unwrap_err();
    }

    #[test]
    fn test_reload_wrong_key() {
        let mut log = TestLog::new();
        *log.sequence_state.borrow_mut() = block_on(SequenceState::load::<StaticCTLogEntry>(
            &log.config,
            &log.object,
            &log.lock,
        ))
        .unwrap();

        // Try to load the checkpoint with two randomly generated checkpoint signers. These should fail
        let checkpoint_signer = StaticCTCheckpointSigner::new(
            log.config.origin.clone(),
            EcdsaSigningKey::random(&mut OsRng),
        )
        .unwrap();
        log.config.checkpoint_signers = vec![Box::new(checkpoint_signer)];
        block_on(SequenceState::load::<StaticCTLogEntry>(
            &log.config,
            &log.object,
            &log.lock,
        ))
        .unwrap_err();

        let checkpoint_signer = Ed25519CheckpointSigner::new(
            log.config.origin.clone(),
            Ed25519SigningKey::generate(&mut OsRng),
        )
        .unwrap();
        log.config.checkpoint_signers = vec![Box::new(checkpoint_signer)];
        block_on(SequenceState::load::<StaticCTLogEntry>(
            &log.config,
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
        log.check(1).unwrap();

        *log.lock.mode.borrow_mut() = StorageMode::Ok;
        *log.sequence_state.borrow_mut() = block_on(SequenceState::load::<StaticCTLogEntry>(
            &log.config,
            &log.object,
            &log.lock,
        ))
        .unwrap();
        log.check(1).unwrap();

        // First, cause the exact same staging bundle to be uploaded.

        log.add_certificate_with_seed('A' as u64);
        log.add_certificate_with_seed('B' as u64);
        log.sequence().unwrap();
        log.check(3).unwrap();

        // Again, but now due to a staging bundle upload error.

        util::set_global_time(now_millis() + 1);

        log.add_certificate_with_seed('C' as u64);
        log.add_certificate_with_seed('D' as u64);

        *log.lock.mode.borrow_mut() = StorageMode::Break {
            prefix: STAGING_KEY,
            persist: true,
        };
        log.sequence().unwrap();
        log.check(3).unwrap();

        *log.lock.mode.borrow_mut() = StorageMode::Ok;

        log.add_certificate_with_seed('C' as u64);
        log.add_certificate_with_seed('D' as u64);
        log.sequence().unwrap();
        log.check(5).unwrap();

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
        log.check(2).unwrap();

        *log.lock.mode.borrow_mut() = StorageMode::Ok;
        *log.sequence_state.borrow_mut() = block_on(SequenceState::load::<StaticCTLogEntry>(
            &log.config,
            &log.object,
            &log.lock,
        ))
        .unwrap();
        log.add_certificate();
        log.sequence().unwrap();
        log.check(3).unwrap();
    }

    #[test]
    fn test_sequence_holds() {
        let mut log = TestLog::new();

        let mut tree_size = 0;
        let mut pending = 0;

        // Hold entries at most one sequencing round.
        log.config.max_sequence_skips = 1;
        log.add_certificate();
        log.add_certificate();
        pending += 2;
        log.sequence().unwrap();
        // 2 pending entries are held
        log.check(0).unwrap();
        for _ in 0..TlogTile::FULL_WIDTH + 3 {
            log.add_certificate();
            pending += 1;
        }
        log.sequence().unwrap();
        // one full tile sequenced, and 5 pending entries held
        (tree_size, pending) = sequence_only_full_tiles(tree_size, pending);
        log.check(tree_size).unwrap();
        log.sequence().unwrap();
        // all pending entries sequenced
        (tree_size, pending) = sequence_everything(tree_size, pending);
        log.check(tree_size).unwrap();

        // Hold entries at most two sequencing rounds.
        log.config.max_sequence_skips = 2;
        log.add_certificate();
        log.add_certificate();
        pending += 2;
        log.sequence().unwrap();
        // 2 entries held
        log.check(tree_size).unwrap();
        log.add_certificate();
        pending += 1;
        log.sequence().unwrap();
        // 3 entries held
        log.check(tree_size).unwrap();
        log.sequence().unwrap();
        // all pending entries sequenced
        (tree_size, pending) = sequence_everything(tree_size, pending);
        log.check(tree_size).unwrap();

        for _ in 0..TlogTile::FULL_WIDTH * 2 {
            log.add_certificate();
            pending += 1;
        }
        log.sequence().unwrap();
        // two full tiles added, and 8 pending entries held
        (tree_size, pending) = sequence_only_full_tiles(tree_size, pending);
        log.sequence().unwrap(); // still held
        log.check(tree_size).unwrap();
        log.sequence().unwrap();
        // all pending entries sequenced
        tree_size += pending;
        pending = 0;
        (tree_size, pending) = sequence_everything(tree_size, pending);
        log.check(tree_size).unwrap();

        // Test holding entries only when under the sequence skip threshold.
        // For these tests, we need to control time.
        let _lock = util::TIME_MUX.lock();
        util::set_freeze_time(true);
        let old_time = now_millis();

        log.config.max_sequence_skips = 1;
        log.config.sequence_skip_threshold_millis = Some(250);
        log.add_certificate();
        pending += 1;
        util::set_global_time(now_millis() + 250);
        log.sequence().unwrap();
        // Entry is sequenced as it was pending longer than the sequence skip
        // threshold.
        (tree_size, pending) = sequence_everything(tree_size, pending);
        log.check(tree_size).unwrap();

        for _ in 0..TlogTile::FULL_WIDTH + 10 {
            log.add_certificate();
            pending += 1;
        }
        util::set_global_time(now_millis() + 100);
        log.sequence().unwrap();
        // Some entries held as they haven't yet expired.
        (tree_size, pending) = sequence_only_full_tiles(tree_size, pending);
        log.check(tree_size).unwrap();

        log.sequence().unwrap();
        (tree_size, _) = sequence_everything(tree_size, pending);
        log.check(tree_size).unwrap();

        // Reset time
        util::set_freeze_time(false);
        util::set_global_time(old_time);
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
                        log.check(*expected_size).unwrap();
                        if result.is_err() {
                            if broken {
                                *log.object.mode.borrow_mut() = StorageMode::Ok;
                                *log.lock.mode.borrow_mut() = StorageMode::Ok;
                            }
                            *log.sequence_state.borrow_mut() =
                                block_on(SequenceState::load::<StaticCTLogEntry>(
                                    &log.config,
                                    &log.object,
                                    &log.lock,
                                ))
                                .unwrap();
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
        async fn upload<S: AsRef<str>, D: Into<Vec<u8>>>(
            &self,
            key: S,
            data: D,
            _opts: &super::UploadOptions,
        ) -> worker::Result<()> {
            *self.uploads.borrow_mut() += 1;
            let (ok, persist) = self.mode.borrow().check(key.as_ref());
            if persist {
                self.objects
                    .borrow_mut()
                    .insert(key.as_ref().to_string(), data.into());
            }
            if ok {
                Ok(())
            } else {
                Err("upload failure".into())
            }
        }
        async fn fetch<S: AsRef<str>>(&self, key: S) -> worker::Result<Option<Vec<u8>>> {
            if let Some(data) = self.objects.borrow().get(key.as_ref()) {
                Ok(Some(data.clone()))
            } else {
                Ok(None)
            }
        }
    }

    struct TestCacheBackend(RefCell<HashMap<LookupKey, SequenceMetadata>>);

    impl CacheRead for TestCacheBackend {
        fn get_entry(&self, key: &LookupKey) -> Option<SequenceMetadata> {
            self.0.borrow().get(key).copied()
        }
    }

    impl CacheWrite for TestCacheBackend {
        async fn put_entries(
            &self,
            entries: &[(LookupKey, SequenceMetadata)],
        ) -> worker::Result<()> {
            let mut map = self.0.borrow_mut();
            for (key, value) in entries {
                if map.contains_key(key) {
                    continue;
                }
                map.insert(*key, *value);
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
        config: SequencerConfig,
        pool_state: RefCell<PoolState<StaticCTPendingLogEntry>>,
        sequence_state: RefCell<SequenceState>,
        lock: TestLockBackend,
        object: TestObjectBackend,
        cache: TestCacheBackend,
        metrics: SequencerMetrics,
    }

    impl TestLog {
        fn new() -> Self {
            let mut rng = OsRng;

            let cache = TestCacheBackend(RefCell::new(HashMap::new()));
            let object = TestObjectBackend::new();
            let lock = TestLockBackend::new();
            let origin = KeyName::new("example.com/TestLog".to_string()).unwrap();

            // Generate two signing keys
            let checkpoint_signers: Vec<Box<dyn CheckpointSigner>> = {
                let signer = StaticCTCheckpointSigner::new(
                    origin.clone(),
                    EcdsaSigningKey::random(&mut rng),
                )
                .unwrap();
                let witness = Ed25519CheckpointSigner::new(
                    origin.clone(),
                    Ed25519SigningKey::generate(&mut rng),
                )
                .unwrap();
                vec![Box::new(signer), Box::new(witness)]
            };
            // Don't use checkpoint extensions
            let checkpoint_extension = Box::new(|_| vec![]);

            let config = SequencerConfig {
                name: "TestLog".to_string(),
                origin,
                checkpoint_signers,
                checkpoint_extension,
                sequence_interval: Duration::from_secs(1),
                max_sequence_skips: 0,
                enable_dedup: true,
                sequence_skip_threshold_millis: None,
                location_hint: None,
                checkpoint_callback: empty_checkpoint_callback(),
            };
            let pool_state = RefCell::new(PoolState::default());
            block_on(create_log(&config, &object, &lock)).unwrap();
            let sequence_state = RefCell::new(
                block_on(SequenceState::load::<StaticCTLogEntry>(
                    &config, &object, &lock,
                ))
                .unwrap(),
            );
            let metrics = SequencerMetrics::new(&Registry::new());
            Self {
                config,
                pool_state,
                sequence_state,
                lock,
                object,
                cache,
                metrics,
            }
        }
        fn sequence(&mut self) -> Result<(), anyhow::Error> {
            block_on(sequence::<StaticCTLogEntry>(
                &self.pool_state,
                &self.sequence_state,
                &self.config,
                &self.object,
                &self.lock,
                &self.cache,
                &self.metrics,
            ))
        }
        fn sequence_start(&self) -> Vec<(StaticCTPendingLogEntry, Sender<SequenceMetadata>)> {
            self.pool_state
                .borrow_mut()
                .take(
                    self.sequence_state.borrow().tree.size(),
                    self.config.max_sequence_skips,
                    self.config.sequence_skip_threshold_millis,
                )
                .unwrap_or_default()
        }
        fn sequence_finish(
            &mut self,
            entries: Vec<(StaticCTPendingLogEntry, Sender<SequenceMetadata>)>,
        ) {
            block_on(sequence_entries::<StaticCTLogEntry>(
                &self.sequence_state,
                &self.config,
                &self.object,
                &self.lock,
                &self.cache,
                entries,
                &self.metrics,
            ))
            .unwrap();
            self.pool_state.borrow_mut().reset_in_sequencing_dedup();
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
            let precert_opt: Option<PrecertData> = if is_precert {
                let mut issuer_key_hash = [0; 32];
                rng.fill(&mut issuer_key_hash);
                let mut pre_certificate = vec![0; rng.gen_range(1..5)];
                rng.fill(&mut pre_certificate[..]);
                Some(PrecertData {
                    issuer_key_hash,
                    pre_certificate,
                })
            } else {
                None
            };
            let issuers = CHAINS[rng.gen_range(0..CHAINS.len())];
            let leaf = StaticCTPendingLogEntry {
                certificate,
                precert_opt,
                chain_fingerprints: issuers.iter().map(|&x| Sha256::digest(x).into()).collect(),
            };

            block_on(upload_issuers(&self.object, issuers, &self.config.name)).unwrap();

            add_leaf_to_pool(&self.pool_state, &self.cache, &self.config, leaf)
        }

        fn check(&self, size: u64) -> anyhow::Result<u64> {
            let sth = block_on(self.object.fetch(CHECKPOINT_KEY))?
                .ok_or(anyhow!("no checkpoint in object storage"))?;
            let first_signer = &self.config.checkpoint_signers[0];
            let n = Note::from_bytes(&sth).map_err(|e| anyhow!(e))?;
            let (verified_sigs, _) = n
                .verify(&VerifierList::new(vec![first_signer.verifier()]))
                .map_err(|e| anyhow!(e))?;
            assert_eq!(verified_sigs.len(), 1);
            let sth_timestamp = first_signer
                .verifier()
                .extract_timestamp_millis(verified_sigs[0].signature())
                .map_err(|e| anyhow!(e))?
                .unwrap();

            let c = CheckpointText::from_bytes(n.text()).map_err(|e| anyhow!(e))?;

            assert_eq!(c.origin(), "example.com/TestLog");
            assert_eq!(c.extension(), "");

            {
                let sth: Vec<u8> =
                    block_on(self.lock.get(CHECKPOINT_KEY)).map_err(|e| anyhow!(e))?;
                let first_signer = &self.config.checkpoint_signers[0];
                let n = Note::from_bytes(&sth).map_err(|e| anyhow!(e))?;
                let (verified_sigs, _) = n
                    .verify(&VerifierList::new(vec![first_signer.verifier()]))
                    .map_err(|e| anyhow!(e))?;
                assert_eq!(verified_sigs.len(), 1);
                let sth_timestamp1 = first_signer
                    .verifier()
                    .extract_timestamp_millis(verified_sigs[0].signature())
                    .map_err(|e| anyhow!(e))?
                    .unwrap();
                let c1 = CheckpointText::from_bytes(n.text()).map_err(|e| anyhow!(e))?;

                ensure!(c1.origin() == c.origin());
                ensure!(c1.extension() == c.extension());
                if c1.size() == c.size() {
                    ensure!(c1.hash() == c.hash());
                }
                ensure!(sth_timestamp1 >= sth_timestamp);
                ensure!(c1.size() >= c.size());
                ensure!(c1.size() == size);
            }

            if c.size() == 0 {
                let expected = Sha256::digest([]);
                ensure!(c.hash() == &Hash(expected.into()));
                return Ok(sth_timestamp);
            }

            let indexes: Vec<u64> = (0..c.size())
                .map(|n| tlog_tiles::stored_hash_index(0, n))
                .collect();
            // [read_tile_hashes] checks the inclusion of every hash in the provided tree,
            // so this checks the validity of the entire Merkle tree.
            let leaf_hashes = {
                let tile_reader =
                    block_on(tile_reader_for_indexes(c.size(), &indexes, &self.object))?;
                let hash_reader = TileHashReader::new(c.size(), *c.hash(), &tile_reader);
                hash_reader.read_hashes(&indexes)?
            };

            let last_tile = TlogTile::from_index(tlog_tiles::stored_hash_count(c.size() - 1))
                .with_data_path(StaticCTPendingLogEntry::DATA_TILE_PATH);

            for n in 0..last_tile.level_index() {
                let tile = if n == last_tile.level_index() {
                    last_tile
                } else {
                    TlogTile::new(
                        0,
                        n,
                        TlogTile::FULL_WIDTH,
                        Some(StaticCTPendingLogEntry::DATA_TILE_PATH),
                    )
                };
                for (i, entry) in TileIterator::<StaticCTLogEntry>::new(
                    &block_on(self.object.fetch(&tile.path()))
                        .map_err(|e| anyhow!(e))?
                        .unwrap(),
                    tile.width() as usize,
                )
                .enumerate()
                {
                    let entry = entry.map_err(|e| anyhow!(e))?;
                    let idx = n * u64::from(TlogTile::FULL_WIDTH) + i as u64;
                    ensure!(entry.leaf_index == idx);
                    ensure!(entry.timestamp <= sth_timestamp);
                    ensure!(
                        leaf_hashes[usize::try_from(idx).map_err(|e| anyhow!(e))?]
                            == entry.merkle_tree_leaf()
                    );

                    ensure!(!entry.inner.certificate.is_empty());
                    if let Some(precert_data) = entry.inner.precert_opt {
                        ensure!(!precert_data.pre_certificate.is_empty());
                        ensure!(precert_data.issuer_key_hash != [0; 32]);
                    }

                    for fp in entry.inner.chain_fingerprints {
                        let b = block_on(self.object.fetch(&format!("issuer/{}", hex::encode(fp))))
                            .map_err(|e| anyhow!(e))?
                            .unwrap();
                        ensure!(Sha256::digest(b).to_vec() == fp);
                    }
                }
            }

            Ok(sth_timestamp)
        }
    }

    fn sequence_only_full_tiles(old_size: u64, pending: u64) -> (u64, u64) {
        let new_size = ((old_size + pending) / u64::from(TlogTile::FULL_WIDTH))
            * u64::from(TlogTile::FULL_WIDTH);
        (new_size, old_size + pending - new_size)
    }
    fn sequence_everything(old_size: u64, pending: u64) -> (u64, u64) {
        (old_size + pending, 0)
    }
}
