// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use crate::{
    config::AppConfig,
    ctlog, load_public_bucket,
    metrics::{millis_diff_as_secs, Metrics, ObjectMetrics},
    util::{get_durable_object_name, now_millis},
    DedupCache, LookupKey, MemoryCache, ObjectBucket, QueryParams, SequenceMetadata,
    BATCH_ENDPOINT, ENTRY_ENDPOINT, METRICS_ENDPOINT,
};
use anyhow::anyhow;
use ctlog::{CreateError, LogConfig, PoolState, SequenceState};
use futures_util::future::join_all;
use log::{info, warn};
use std::time::Duration;
use tlog_tiles::{CheckpointSigner, LogEntry, PendingLogEntry};
use tokio::sync::Mutex;
use worker::{Env, Error as WorkerError, Request, Response, State};

// The number of entries in the short-term deduplication cache.
// This cache provides a secondary deduplication layer to bridge the gap in KV's eventual consistency.
// It should hold at least <maximum-entries-per-second> x <kv-eventual-consistency-time (60s)> entries.
const MEMORY_CACHE_SIZE: usize = 300_000;

/// Function that takes env, name, origin, and loads the checkpoint signing objects
// We have to use Box dyn because we need to be able to monomorphize Sequencer, and making it
// generic over a function type doesn't let us write down the type
pub type CheckpointSignerLoader =
    Box<dyn Fn(&Env, &str, &str) -> Result<Vec<Box<dyn CheckpointSigner>>, WorkerError>>;

pub struct GenericSequencer<E: PendingLogEntry> {
    do_state: State, // implements LockBackend
    env: Env,
    public_bucket: Option<ObjectBucket>, // implements ObjectBackend
    cache: Option<DedupCache>,           // implements CacheRead, CacheWrite
    log_config: LogConfig,
    key_loader: CheckpointSignerLoader,
    sequence_state: Option<SequenceState>,
    pool_state: PoolState<E>,
    initialized: bool,
    init_mux: Mutex<()>,
    metrics: Metrics,
}

impl<E: PendingLogEntry> GenericSequencer<E> {
    /// Creates a new generic sequencer. Returns an error if it cannot extract
    /// the name of this Durable Object from `state`.
    pub fn new(
        app_config: &AppConfig,
        state: State,
        env: Env,
        key_loader: CheckpointSignerLoader,
    ) -> Result<Self, anyhow::Error> {
        let (state, dur_obj_name) = get_durable_object_name(state)?;

        let params = app_config
            .logs
            .get(&dur_obj_name)
            .ok_or_else(|| anyhow!("could not get log param with object name {dur_obj_name}",))?;

        // https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#checkpoints
        // The origin line MUST be the submission prefix of the log as a schema-less URL with no trailing slashes.
        let origin = params
            .submission_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');
        let sequence_interval = Duration::from_millis(params.sequence_interval_millis);
        let checkpoint_signers = (key_loader)(&env, &dur_obj_name, origin)?;

        let log_config = LogConfig {
            name: dur_obj_name.to_string(),
            origin: origin.to_string(),
            checkpoint_signers,
            sequence_interval,
            max_sequence_skips: params.max_sequence_skips,
            enable_dedup: params.enable_dedup,
            sequence_skip_threshold_millis: params.sequence_skip_threshold_millis,
        };

        Ok(Self {
            do_state: state,
            env,
            public_bucket: None,
            cache: None,
            log_config,
            key_loader,
            sequence_state: None,
            pool_state: PoolState::default(),
            initialized: false,
            init_mux: Mutex::new(()),
            metrics: Metrics::new(),
        })
    }

    pub async fn fetch(&mut self, mut req: Request) -> Result<Response, WorkerError> {
        let name = &req.query::<QueryParams>()?.name;
        if !self.initialized {
            info!("{name}: Initializing log from fetch handler");
            // TODO: Remove name from req params
            self.initialize().await?;
        }

        let start = now_millis();
        self.metrics.req_in_flight.inc();

        let path = req.path();
        let mut endpoint = path.trim_start_matches('/');
        let resp = match path.as_str() {
            METRICS_ENDPOINT => self.fetch_metrics(),
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

    pub async fn alarm<L: LogEntry<Pending = E>>(&mut self) -> Result<Response, WorkerError> {
        if !self.initialized {
            self.initialize().await?;
        }
        // Safe to unwrap here as the log must be initialized.
        let name = &self.log_config.name;

        // Schedule the next sequencing.
        self.do_state
            .storage()
            .set_alarm(self.log_config.sequence_interval)
            .await?;

        if let Err(e) = ctlog::sequence::<L>(
            &mut self.pool_state,
            &mut self.sequence_state,
            &self.log_config,
            self.public_bucket.as_ref().unwrap(),
            &self.do_state,
            self.cache.as_mut().unwrap(),
            &self.metrics,
        )
        .await
        {
            warn!("{name}: Fatal sequencing error, log will be reloaded: {e}",);
        }

        Response::empty()
    }
}

impl<E: PendingLogEntry> GenericSequencer<E> {
    // Initialize the durable object when it is started on a new machine (e.g., after eviction or a deployment).
    async fn initialize(&mut self) -> Result<(), WorkerError> {
        // This can be triggered by the alarm() or fetch() handlers, so lock state to avoid a race condition.
        let _lock = self.init_mux.lock().await;

        if self.initialized {
            return Ok(());
        }

        let LogConfig {
            ref name,
            sequence_interval,
            ..
        } = &self.log_config;

        self.public_bucket = Some(ObjectBucket {
            bucket: load_public_bucket(&self.env, name)?,
            metrics: Some(ObjectMetrics::new(&self.metrics.registry)),
        });
        self.cache = Some(DedupCache {
            memory: MemoryCache::new(MEMORY_CACHE_SIZE),
            storage: self.do_state.storage(),
        });

        if let Err(e) = self.cache.as_mut().unwrap().load().await {
            warn!("Failed to load short-term dedup cache from DO storage: {e}");
        };

        // Safe to unwrap here as the relevant fields were set above.
        match ctlog::create_log(
            &self.log_config,
            self.public_bucket.as_ref().unwrap(),
            &self.do_state,
        )
        .await
        {
            Err(CreateError::LogExists) => info!("{name}: Log exists, not creating"),
            Err(CreateError::Other(msg)) => {
                return Err(format!("{name}: failed to create: {msg}").into())
            }
            Ok(()) => {}
        }

        // Start sequencing loop (OK if alarm is already scheduled).
        self.do_state
            .storage()
            .set_alarm(*sequence_interval)
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
            let mut logging_labels = pending_entry.logging_labels();
            lookup_keys.push(pending_entry.lookup_key());

            let add_leaf_result = ctlog::add_leaf_to_pool(
                &mut self.pool_state,
                self.cache.as_ref().unwrap(),
                &self.log_config,
                pending_entry,
            );

            logging_labels.push(add_leaf_result.source().to_string());
            self.metrics
                .entry_count
                .with_label_values(&logging_labels)
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

    fn fetch_metrics(&self) -> Result<Response, WorkerError> {
        Response::ok(self.metrics.encode())
    }
}
