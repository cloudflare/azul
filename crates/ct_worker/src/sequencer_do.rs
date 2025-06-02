// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use crate::{
    ctlog, load_public_bucket, load_signing_key, load_witness_key,
    metrics::{millis_diff_as_secs, AsF64, Metrics, ObjectMetrics},
    util::{self, now_millis},
    DedupCache, MemoryCache, ObjectBucket, QueryParams, CONFIG, ROOTS,
};
use ctlog::{CreateError, LogConfig, PoolState, SequenceState};
use futures_util::future::join_all;
use log::{info, warn, Level};
use static_ct_api::{
    LogEntryTrait, PendingLogEntryTrait, StandardEd25519CheckpointSigner, StaticCTCheckpointSigner,
    StaticCTLogEntry, StaticCTPendingLogEntry,
};
use std::str::FromStr;
use std::time::Duration;
use tlog_tiles::CheckpointSigner;
use tokio::sync::Mutex;
#[allow(clippy::wildcard_imports)]
use worker::*;

// The number of entries in the short-term deduplication cache.
// This cache provides a secondary deduplication layer to bridge the gap in KV's eventual consistency.
// It should hold at least <maximum-entries-per-second> x <kv-eventual-consistency-time (60s)> entries.
const MEMORY_CACHE_SIZE: usize = 300_000;

/// Function that takes env, name, origin, and loads the checkpoint signing objects
// We have to use Box dyn because we need to be able to monomorphize Sequencer, and making it
// generic over a function type doesn't let us write down the type
pub type CheckpointSignerLoader =
    Box<dyn Fn(&Env, &str, &str) -> Result<Vec<Box<dyn CheckpointSigner>>>>;

#[durable_object]
struct StaticCTSequencer(Sequencer<StaticCTPendingLogEntry>);

#[durable_object]
impl DurableObject for StaticCTSequencer {
    fn new(state: State, env: Env) -> Self {
        // Need to define how we load our signing keys from the environment. This closure has type
        // CheckpointSignerLoader
        let load_signers = |e: &Env, name: &str, origin: &str| {
            let signing_key = load_signing_key(e, name)?.clone();
            let witness_key = load_witness_key(e, name)?.clone();

            // Make the checkpoint signers from the secret keys and put them in a vec
            let signer = StaticCTCheckpointSigner::new(&origin, signing_key).map_err(|e| {
                Error::RustError(format!("could not create static-ct checkpoint signer: {e}"))
            })?;
            let witness =
                StandardEd25519CheckpointSigner::new(&origin, witness_key).map_err(|e| {
                    Error::RustError(format!("could not create ed25519 checkpoint signer: {e}"))
                })?;

            let out: Vec<Box<dyn CheckpointSigner>> = vec![Box::new(signer), Box::new(witness)];
            Ok(out)
        };

        StaticCTSequencer(Sequencer::new(state, env, Box::new(load_signers)))
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }

    async fn alarm(&mut self) -> Result<Response> {
        self.0.alarm::<StaticCTLogEntry>().await
    }
}

struct Sequencer<E: PendingLogEntryTrait> {
    do_state: State, // implements LockBackend
    env: Env,
    public_bucket: Option<ObjectBucket>, // implements ObjectBackend
    cache: Option<DedupCache>,           // implements CacheRead, CacheWrite
    config: Option<LogConfig>,
    key_loader: CheckpointSignerLoader,
    sequence_state: Option<SequenceState>,
    pool_state: PoolState<E>,
    initialized: bool,
    init_mux: Mutex<()>,
    metrics: Metrics,
}

impl<E: PendingLogEntryTrait> Sequencer<E> {
    fn new(state: State, env: Env, key_loader: CheckpointSignerLoader) -> Self {
        let level = CONFIG
            .logging_level
            .as_ref()
            .and_then(|level| Level::from_str(level).ok())
            .unwrap_or(Level::Info);
        util::init_logging(level);
        console_error_panic_hook::set_once();
        Self {
            do_state: state,
            env,
            public_bucket: None,
            cache: None,
            config: None,
            key_loader,
            sequence_state: None,
            pool_state: PoolState::default(),
            initialized: false,
            init_mux: Mutex::new(()),
            metrics: Metrics::new(),
        }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        let name = &req.query::<QueryParams>()?.name;
        if !self.initialized {
            info!("{name}: Initializing log from fetch handler");
            self.initialize(name).await?;
        }

        let start = now_millis();
        self.metrics.req_in_flight.inc();

        let endpoint: &str;
        let resp = match req.path().as_str() {
            "/metrics" => {
                endpoint = "metrics";
                self.metrics.req_count.with_label_values(&["metrics"]).inc();
                self.fetch_metrics()
            }
            "/add_batch" => {
                endpoint = "add_batch";
                let pending_entries: Vec<E> = req.json().await?;
                self.add_batch(pending_entries).await
            }
            _ => {
                endpoint = "unknown";
                Response::error("Unknown endpoint", 404)
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

    async fn alarm<L: LogEntryTrait<Pending = E>>(&mut self) -> Result<Response> {
        if !self.initialized {
            let name = &self.do_state.storage().get::<String>("name").await?;
            info!("{name}: Initializing log from sequencing loop");
            self.initialize(name).await?;
        }
        // Safe to unwrap here as the log must be initialized.
        let config = self.config.as_ref().unwrap();
        let name = &config.name;

        // Schedule the next sequencing.
        self.do_state
            .storage()
            .set_alarm(config.sequence_interval)
            .await?;

        if let Err(e) = ctlog::sequence::<L>(
            &mut self.pool_state,
            &mut self.sequence_state,
            config,
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

impl<E: PendingLogEntryTrait> Sequencer<E> {
    // Initialize the durable object when it is started on a new machine (e.g., after eviction or a deployment).
    async fn initialize(&mut self, name: &str) -> Result<()> {
        let params = &CONFIG.logs[name];

        // This can be triggered by the alarm() or fetch() handlers, so lock state to avoid a race condition.
        let _lock = self.init_mux.lock().await;

        if self.initialized {
            return Ok(());
        }

        // https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#checkpoints
        // The origin line MUST be the submission prefix of the log as a schema-less URL with no trailing slashes.
        let origin = params
            .submission_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');

        let sequence_interval = Duration::from_secs(params.sequence_interval_seconds);
        let checkpoint_signers = (self.key_loader)(&self.env, name, origin)?;

        self.config = Some(LogConfig {
            name: name.to_string(),
            origin: origin.to_string(),
            checkpoint_signers,
            sequence_interval,
            max_pending_entry_holds: params.max_pending_entry_holds,
        });
        self.public_bucket = Some(ObjectBucket {
            sequence_interval_seconds: params.sequence_interval_seconds,
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
            self.config.as_ref().unwrap(),
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
        // Put log name in DO storage so we can trigger re-initialization
        // from the sequencing loop in the future.
        if self.do_state.storage().get::<String>("name").await.is_err() {
            self.do_state.storage().put("name", name).await?;
        }

        // Start sequencing loop (OK if alarm is already scheduled).
        self.do_state.storage().set_alarm(sequence_interval).await?;

        self.metrics.config_roots.set(ROOTS.certs.len().as_f64());
        self.metrics.config_start.set(
            params
                .temporal_interval
                .start_inclusive
                .timestamp()
                .as_f64(),
        );
        self.metrics
            .config_end
            .set(params.temporal_interval.end_exclusive.timestamp().as_f64());

        self.initialized = true;

        Ok(())
    }

    // Add a batch of entries, returning a Response with metadata for
    // successfully sequenced entries. Entries that fail to be added (e.g., due to rate limiting)
    // are omitted.
    async fn add_batch(&mut self, pending_entries: Vec<E>) -> Result<Response> {
        // Safe to unwrap config here as the log must be initialized.
        let mut futures = Vec::with_capacity(pending_entries.len());
        let mut lookup_keys = Vec::with_capacity(pending_entries.len());
        for pending_entry in pending_entries {
            let mut logging_labels = pending_entry.logging_labels();
            lookup_keys.push(pending_entry.lookup_key());

            let add_leaf_result = ctlog::add_leaf_to_pool(
                &mut self.pool_state,
                self.cache.as_ref().unwrap(),
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
        let result = lookup_keys
            .iter()
            .zip(entries_metadata.iter())
            .filter_map(|(key, value_opt)| value_opt.as_ref().map(|metadata| (key, metadata)))
            .collect::<Vec<_>>();

        Response::from_json(&result)
    }

    fn fetch_metrics(&self) -> Result<Response> {
        Response::ok(self.metrics.encode())
    }
}
