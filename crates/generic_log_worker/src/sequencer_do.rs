// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use std::{collections::HashMap, time::Duration};

use crate::{
    log_ops::{self, CreateError, PoolState, SequenceState},
    metrics::{millis_diff_as_secs, ObjectMetrics, SequencerMetrics},
    util::now_millis,
    DedupCache, LookupKey, MemoryCache, ObjectBackend, ObjectBucket, SequenceMetadata,
    BATCH_ENDPOINT, ENTRY_ENDPOINT, METRICS_ENDPOINT, PROVE_INCLUSION_ENDPOINT,
};
use futures_util::future::join_all;
use log::{info, warn};
use prometheus::{Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use tlog_tiles::{
    prove_record, CheckpointSigner, LogEntry, PendingLogEntry, RecordProof, Tile, TileHashReader,
    TileReader, TlogError, TlogTile,
};
use tokio::sync::Mutex;
use worker::{Bucket, Error as WorkerError, Request, Response, State};

// The number of entries in the short-term deduplication cache.
// This cache provides a secondary deduplication layer to bridge the gap in KV's eventual consistency.
// It should hold at least <maximum-entries-per-second> x <kv-eventual-consistency-time (60s)> entries.
const MEMORY_CACHE_SIZE: usize = 300_000;

pub struct GenericSequencer<E: PendingLogEntry> {
    do_state: State,             // implements LockBackend
    public_bucket: ObjectBucket, // implements ObjectBackend
    cache: DedupCache,           // implements CacheRead, CacheWrite
    config: SequencerConfig,
    sequence_state: Option<SequenceState>,
    pool_state: PoolState<E>,
    initialized: bool,
    init_mux: Mutex<()>,
    registry: Registry,
    metrics: SequencerMetrics,
}

/// Configuration for a CT log.
pub struct SequencerConfig {
    pub name: String,
    pub origin: String,
    pub checkpoint_signers: Vec<Box<dyn CheckpointSigner>>,
    pub sequence_interval: Duration,
    pub max_sequence_skips: usize,
    pub sequence_skip_threshold_millis: Option<u64>,
    pub enable_dedup: bool,
}

/// GET query structure for the sequencer's /prove_inclusion endpoint
#[derive(Serialize, Deserialize)]
pub struct ProveInclusionQuery {
    pub leaf_index: u64,
}

/// GET response structure for the sequencer's /prove_inclusion endpoint
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ProveInclusionResponse {
    #[serde_as(as = "Vec<Base64>")]
    pub proof: Vec<Vec<u8>>,
}

impl<E: PendingLogEntry> GenericSequencer<E> {
    /// Return a new sequencer with the given config.
    pub fn new(config: SequencerConfig, state: State, bucket: Bucket, registry: Registry) -> Self {
        let metrics = SequencerMetrics::new(&registry);
        let public_bucket = ObjectBucket {
            bucket,
            metrics: Some(ObjectMetrics::new(&registry)),
        };
        let cache = DedupCache {
            memory: MemoryCache::new(MEMORY_CACHE_SIZE),
            storage: state.storage(),
        };

        Self {
            do_state: state,
            public_bucket,
            cache,
            config,
            sequence_state: None,
            pool_state: PoolState::default(),
            initialized: false,
            init_mux: Mutex::new(()),
            registry,
            metrics,
        }
    }

    /// Handles requests to add new entries to the sequencing pool, and returns
    /// a response with the sequencing result.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be parsed.
    pub async fn fetch(&mut self, mut req: Request) -> Result<Response, WorkerError> {
        if !self.initialized {
            info!("{}: Initializing log from fetch handler", self.config.name);
            self.initialize().await?;
        }

        let start = now_millis();
        self.metrics.req_in_flight.inc();

        let path = req.path();
        let mut endpoint = path.trim_start_matches('/');
        let resp = match path.as_str() {
            METRICS_ENDPOINT => self.fetch_metrics(),
            PROVE_INCLUSION_ENDPOINT => {
                let ProveInclusionQuery { leaf_index } = req.query()?;
                // Construct the proof and convert the hashes to Vec<u8>
                let proof = self
                    .prove_inclusion(leaf_index)
                    .await?
                    .into_iter()
                    .map(|h| h.0.to_vec())
                    .collect::<Vec<_>>();
                Response::from_json(&ProveInclusionResponse { proof })
            }
            ENTRY_ENDPOINT => {
                let pending_entry: E = req.json().await?;
                let lookup_key = pending_entry.lookup_key();
                let result = self.add_batch(vec![pending_entry]).await;
                if result.is_empty() || result[0].0 != lookup_key {
                    Response::error("rate limited", 429)
                } else {
                    Response::from_json(&result[0].1)
                }
            }
            BATCH_ENDPOINT => {
                let pending_entries: Vec<E> = req.json().await?;
                Response::from_json(&self.add_batch(pending_entries).await)
            }
            _ => {
                endpoint = "unknown";
                Response::error("unknown endpoint", 404)
            }
        };
        self.metrics.req_count.with_label_values(&[endpoint]).inc();
        self.metrics.req_in_flight.dec();
        self.metrics
            .req_duration
            .with_label_values(&[endpoint])
            .observe(millis_diff_as_secs(start, now_millis()));

        resp
    }

    /// Handles alarm events by sequencing the log.
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues scheduling the next alarm.
    pub async fn alarm<L: LogEntry<Pending = E>>(&mut self) -> Result<Response, WorkerError> {
        if !self.initialized {
            info!("{}: Initializing log from alarm handler", self.config.name);
            self.initialize().await?;
        }
        let name = &self.config.name;

        // Schedule the next sequencing.
        self.do_state
            .storage()
            .set_alarm(self.config.sequence_interval)
            .await?;

        if let Err(e) = log_ops::sequence::<L>(
            &mut self.pool_state,
            &mut self.sequence_state,
            &self.config,
            &self.public_bucket,
            &self.do_state,
            &mut self.cache,
            &self.metrics,
        )
        .await
        {
            warn!("{name}: Fatal sequencing error, log will be reloaded: {e}",);
        }

        Response::empty()
    }
}

/// A thin wrapper around a map of tlog tile ⇒ bytestring. Implements TileReader
/// so we can use it for producing inclusion proofs.
struct SimpleTlogTileReader(HashMap<TlogTile, Vec<u8>>);

impl TileReader for SimpleTlogTileReader {
    fn height(&self) -> u8 {
        8
    }

    /// Converts the given tiles into tlog tiles, then reads them from the
    /// internal hashmap.
    ///
    /// # Errors
    /// Errors if any of given tiles hash height != 8, or is a data tile. Also
    /// errors if the hash map is missing tiles from the input here.
    fn read_tiles(&self, tiles: &[Tile]) -> Result<Vec<Vec<u8>>, TlogError> {
        let mut buf = Vec::with_capacity(32 * (1 << self.height()));

        for tile in tiles {
            // Convert the tile to a tlog-tile, ie one where height=8 and data=false
            if tile.height() != 8 {
                return Err(TlogError::InvalidInput(
                    "SimpleTlogTileReader cannot read tiles of height not equal to 8".to_string(),
                ));
            }
            if tile.is_data() {
                return Err(TlogError::InvalidInput(
                    "SimpleTlogTileReader cannot read data tiles".to_string(),
                ));
            }
            let tlog_tile = TlogTile::new(tile.level(), tile.level_index(), tile.width(), None);

            // Record the tile's contents
            let Some(contents) = self.0.get(&tlog_tile) else {
                return Err(TlogError::InvalidInput(format!(
                    "SimpleTlogTileReader cannot find {}",
                    tlog_tile.path()
                )));
            };
            buf.push(contents.clone());
        }

        Ok(buf)
    }

    // Do nothing; we only use this struct to read tiles
    fn save_tiles(&self, _tiles: &[Tile], _data: &[Vec<u8>]) {}
}

impl<E: PendingLogEntry> GenericSequencer<E> {
    // Initialize the durable object when it is started on a new machine (e.g., after eviction or a deployment).
    async fn initialize(&mut self) -> Result<(), WorkerError> {
        // This can be triggered by the alarm() or fetch() handlers, so lock state to avoid a race condition.
        let _lock = self.init_mux.lock().await;
        let name = &self.config.name;

        if self.initialized {
            return Ok(());
        }

        if let Err(e) = self.cache.load().await {
            warn!("Failed to load short-term dedup cache from DO storage: {e}");
        };

        match log_ops::create_log(&self.config, &self.public_bucket, &self.do_state).await {
            Err(CreateError::LogExists) => info!("{name}: Log exists, not creating"),
            Err(CreateError::Other(msg)) => {
                return Err(format!("{name}: failed to create: {msg}").into())
            }
            Ok(()) => {}
        }

        // Start sequencing loop (OK if alarm is already scheduled).
        self.do_state
            .storage()
            .set_alarm(self.config.sequence_interval)
            .await?;

        self.initialized = true;

        Ok(())
    }

    // Add a batch of entries, returning metadata for successfully sequenced
    // entries. Entries that fail to be added (e.g., due to rate limiting) are
    // omitted.
    async fn add_batch(&mut self, pending_entries: Vec<E>) -> Vec<(LookupKey, SequenceMetadata)> {
        // Safe to unwrap config here as the log must be initialized.
        let mut futures = Vec::with_capacity(pending_entries.len());
        let mut lookup_keys = Vec::with_capacity(pending_entries.len());
        for pending_entry in pending_entries {
            lookup_keys.push(pending_entry.lookup_key());

            let add_leaf_result = log_ops::add_leaf_to_pool(
                &mut self.pool_state,
                &self.cache,
                &self.config,
                pending_entry,
            );

            self.metrics
                .entry_count
                .with_label_values(&[add_leaf_result.source()])
                .inc();

            futures.push(add_leaf_result.resolve());
        }
        let entries_metadata = join_all(futures).await;

        // Zip the cache keys with the cache values, filtering out entries that
        // were not sequenced (e.g., due to rate limiting).
        lookup_keys
            .into_iter()
            .zip(entries_metadata.iter())
            .filter_map(|(key, value_opt)| value_opt.map(|metadata| (key, metadata)))
            .collect::<Vec<_>>()
    }

    /// Returns the latest checkpoint. This may only be called after the
    /// sequencer state has been loaded, i.e., after the first `alarm()` has
    /// triggered.
    ///
    /// # Errors
    /// Errors when sequencer state has not been loaded
    pub fn checkpoint(&self) -> Result<&[u8], WorkerError> {
        if let Some(s) = self.sequence_state.as_ref() {
            Ok(s.checkpoint())
        } else {
            Err(WorkerError::RustError(
                "cannot get checkpoint of a sequencer with no sequence state".to_string(),
            ))
        }
    }

    /// Does a compare-and-swap of checkpoints. Useful for updating a checkpoint
    /// to include new cosignatures
    ///
    /// # Errors
    /// Errors when `old` doesn't match the current checkpoint, or if fetching
    /// or setting storage failed.
    pub async fn swap_checkpoint(&self, old: &[u8], new: &[u8]) -> Result<(), WorkerError> {
        log_ops::swap_checkpoint(&self.do_state, old, new).await
    }

    /// Returns an inclusion proof for the given leaf index
    ///
    /// # Errors
    /// Errors when sequencer state has not been loaded, or when the desired
    /// tiles do not exist as bucket objects.
    pub async fn prove_inclusion(&self, leaf_index: u64) -> Result<RecordProof, WorkerError> {
        // Get the size of the tree
        let (num_leaves, tree_hash) = if let Some(s) = self.sequence_state.as_ref() {
            (s.num_leaves(), *s.tree_hash())
        } else {
            return Err(WorkerError::RustError(
                "cannot prove inclusion in a sequencer with no sequence state".to_string(),
            ));
        };

        if leaf_index >= num_leaves {
            return Err(WorkerError::RustError(
                "leaf index exceeds number of leaves in the tree".to_string(),
            ));
        }

        let mut all_tile_data = HashMap::new();

        // Get the leaf tile
        let mut cur_tile = TlogTile::from_leaf_index(leaf_index);
        // Set the correct width. from_leaf_index returns the least width, but
        // our current tile might be larger if we've added more elements. This
        // subtraction is ok because we checked that num_leaves > leaf_index
        // above.
        if num_leaves - leaf_index < 128 {
            let last_partial_tile_width = (num_leaves % 128) as u32;
            cur_tile = TlogTile::new(
                cur_tile.level(),
                cur_tile.level_index(),
                last_partial_tile_width,
                None,
            );
        }
        // Collect the leaf tile
        let Some(tile_data) = self.public_bucket.fetch(&cur_tile.path()).await? else {
            return Err(WorkerError::RustError(format!(
                "missing tile for inclusion proof {}",
                cur_tile.path()
            )));
        };
        all_tile_data.insert(cur_tile, tile_data);

        // It suffices to grab all the tiles from the leaf to the root. This
        // will contain the copath necessary for the inclusion proof
        while let Some(parent) = cur_tile.parent(1, num_leaves) {
            let Some(tile_data) = self.public_bucket.fetch(&parent.path()).await? else {
                return Err(WorkerError::RustError(format!(
                    "missing tile for inclusion proof {}",
                    parent.path()
                )));
            };
            all_tile_data.insert(parent, tile_data);

            cur_tile = parent;
        }

        // Now make the proof
        let proof = {
            // Put the recorded tiles into the appropriate Reader structs for prove_record()
            let tile_reader = SimpleTlogTileReader(all_tile_data);
            let hash_reader = TileHashReader::new(num_leaves, tree_hash, &tile_reader);
            prove_record(num_leaves, leaf_index, &hash_reader)
                .map_err(|e| WorkerError::RustError(e.to_string()))?
        };
        Ok(proof)
    }

    /// Proves inclusion of the last leaf in the current tree. This may only be
    /// called after the sequencer state has been loaded, i.e., after the first
    /// `alarm()` has triggered.
    ///
    /// # Errors
    /// Errors when sequencer state has not been loaded
    pub fn prove_inclusion_of_last_elem(&self) -> Result<RecordProof, WorkerError> {
        if let Some(s) = self.sequence_state.as_ref() {
            Ok(s.prove_inclusion_of_last_elem())
        } else {
            Err(WorkerError::RustError(
                "cannot prove inclusion in a sequencer with no sequence state".to_string(),
            ))
        }
    }

    /// Proves that this tree of size n is compatible with the subtree of size
    /// n-1. In other words, prove that we appended 1 element to the tree.
    ///
    /// # Errors
    /// Errors when this sequencer has not been used to sequence anything yet.
    pub fn prove_consistency_of_single_append(&self) -> Result<RecordProof, WorkerError> {
        if let Some(s) = self.sequence_state.as_ref() {
            s.prove_consistency_of_single_append()
                .map_err(|e| WorkerError::RustError(format!("consistency proof failed: {e}")))
        } else {
            Err(WorkerError::RustError(
                "cannot prove inclusion in a sequencer with no sequence state".to_string(),
            ))
        }
    }

    fn fetch_metrics(&self) -> Result<Response, WorkerError> {
        let mut buffer = String::new();
        let encoder = TextEncoder::new();
        encoder
            .encode_utf8(&self.registry.gather(), &mut buffer)
            .unwrap();
        Response::ok(buffer)
    }
}
