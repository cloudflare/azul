// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use std::{cell::RefCell, time::Duration};

use crate::{
    deserialize,
    log_ops::{self, CreateError, PoolState, SequenceState},
    metrics::{millis_diff_as_secs, ObjectMetrics, SequencerMetrics},
    serialize,
    util::now_millis,
    DedupCache, LookupKey, MemoryCache, ObjectBucket, SequenceMetadata, BATCH_ENDPOINT,
    ENTRY_ENDPOINT, METRICS_ENDPOINT,
};
use futures_util::future::join_all;
use log::{info, warn};
use prometheus::{Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use signed_note::KeyName;
use tlog_tiles::{CheckpointSigner, LeafIndex, LogEntry, PendingLogEntryBlob, UnixTimestamp};
use tokio::sync::Mutex;
use worker::{Bucket, Error as WorkerError, Request, Response, State};

// The number of entries in the short-term deduplication cache.
// This cache provides a secondary deduplication layer to bridge the gap in KV's eventual consistency.
// It should hold at least <maximum-entries-per-second> x <kv-eventual-consistency-time (60s)> entries.
const MEMORY_CACHE_SIZE: usize = 300_000;

pub struct GenericSequencer<L: LogEntry> {
    do_state: State,             // implements LockBackend
    public_bucket: ObjectBucket, // implements ObjectBackend
    cache: DedupCache,           // implements CacheRead, CacheWrite
    config: SequencerConfig,
    sequence_state: RefCell<SequenceState>,
    pool_state: RefCell<PoolState<L::Pending>>,
    initialized: RefCell<bool>,
    init_mux: Mutex<()>,
    registry: Registry,
    metrics: SequencerMetrics,
}

/// Configuration for a CT log.
pub struct SequencerConfig {
    pub name: String,
    pub origin: KeyName,
    pub checkpoint_signers: Vec<Box<dyn CheckpointSigner>>,
    /// A function that takes a Unix timestamp in milliseconds and returns
    /// extension lines to be included in the checkpoint
    pub checkpoint_extension: Box<dyn Fn(UnixTimestamp) -> Vec<String>>,
    pub sequence_interval: Duration,
    pub max_sequence_skips: usize,
    pub sequence_skip_threshold_millis: Option<u64>,
    pub enable_dedup: bool,
}

/// GET query structure for the sequencer's `/prove_inclusion` endpoint
#[derive(Serialize, Deserialize)]
pub struct ProveInclusionQuery {
    pub leaf_index: LeafIndex,
}

/// GET response structure for the sequencer's `/prove_inclusion` endpoint
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ProveInclusionResponse {
    #[serde_as(as = "Vec<Base64>")]
    pub proof: Vec<Vec<u8>>,
}

impl<L: LogEntry> GenericSequencer<L> {
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
            sequence_state: RefCell::new(SequenceState::default()),
            pool_state: RefCell::new(PoolState::default()),
            initialized: RefCell::new(false),
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
    pub async fn fetch(&self, mut req: Request) -> Result<Response, WorkerError> {
        if !*self.initialized.borrow() {
            info!("{}: Initializing log from fetch handler", self.config.name);
            self.initialize().await?;
        }

        let start = now_millis();
        self.metrics.req_in_flight.inc();

        let path = req.path();
        let mut endpoint = path.trim_start_matches('/');
        let resp = match path.as_str() {
            METRICS_ENDPOINT => self.fetch_metrics(),
            ENTRY_ENDPOINT => {
                let pending_entry = deserialize::<PendingLogEntryBlob>(&req.bytes().await?)?;
                let lookup_key = pending_entry.lookup_key;
                let result = self.add_batch(vec![pending_entry]).await?;
                if result.is_empty() || result[0].0 != lookup_key {
                    Response::error("rate limited", 429)
                } else {
                    Response::from_bytes(serialize(&result[0].1)?)
                }
            }
            BATCH_ENDPOINT => {
                let pending_entries: Vec<PendingLogEntryBlob> = deserialize(&req.bytes().await?)?;
                Response::from_bytes(serialize(&self.add_batch(pending_entries).await?)?)
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
    pub async fn alarm(&self) -> Result<Response, WorkerError> {
        if !*self.initialized.borrow() {
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
            &self.pool_state,
            &self.sequence_state,
            &self.config,
            &self.public_bucket,
            &self.do_state,
            &self.cache,
            &self.metrics,
        )
        .await
        {
            warn!("{name}: Fatal sequencing error, log will be reloaded: {e}",);
        }

        Response::empty()
    }
}

impl<L: LogEntry> GenericSequencer<L> {
    // Initialize the durable object when it is started on a new machine (e.g., after eviction or a deployment).
    async fn initialize(&self) -> Result<(), WorkerError> {
        // This can be triggered by the alarm() or fetch() handlers, so lock state to avoid a race condition.
        let _lock = self.init_mux.lock().await;
        let name = &self.config.name;

        if *self.initialized.borrow() {
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

        // Load sequencing state.
        *self.sequence_state.borrow_mut() =
            SequenceState::load::<L>(&self.config, &self.public_bucket, &self.do_state)
                .await
                .map_err(|e| e.to_string())?;

        // Start sequencing loop (OK if alarm is already scheduled).
        self.do_state
            .storage()
            .set_alarm(self.config.sequence_interval)
            .await?;

        *self.initialized.borrow_mut() = true;

        Ok(())
    }

    // Add a batch of entries, returning metadata for successfully sequenced
    // entries. Entries that fail to be added (e.g., due to rate limiting) are
    // omitted.
    async fn add_batch(
        &self,
        pending_entries: Vec<PendingLogEntryBlob>,
    ) -> Result<Vec<(LookupKey, SequenceMetadata)>, WorkerError> {
        // Safe to unwrap config here as the log must be initialized.
        let mut futures = Vec::with_capacity(pending_entries.len());
        let mut lookup_keys = Vec::with_capacity(pending_entries.len());
        for pending_entry_blob in pending_entries {
            lookup_keys.push(pending_entry_blob.lookup_key);
            let pending_entry = deserialize(&pending_entry_blob.data)?;

            let add_leaf_result = log_ops::add_leaf_to_pool(
                &self.pool_state,
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
        Ok(lookup_keys
            .into_iter()
            .zip(entries_metadata.iter())
            .filter_map(|(key, value_opt)| value_opt.map(|metadata| (key, metadata)))
            .collect::<Vec<_>>())
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
