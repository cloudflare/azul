// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Batcher buffers entries to be sequenced, submits batches to the sequencer, and
//! waits until the entries are sequenced. Each time the Batcher gets an update with
//! new sequenced entry metadata, it writes to an in-memory cache and signals all waiting
//! requests to check if metadata for their entry is available.
//!
//! Entries are assigned to Batcher shards with consistent hashing on the cache key.

use crate::{ctlog, get_stub, util, CacheKey, CacheValue, MemoryCache, QueryParams, CONFIG};
use base64::prelude::*;
use futures::future::join_all;
use log::Level;
use static_ct_api::LogEntry;
use std::{collections::HashSet, str::FromStr, time::Duration};
use tokio::sync::watch::{self, Sender};
#[allow(clippy::wildcard_imports)]
use worker::*;

// How many in-flight requests to allow. Tune to prevent the DO from being overloaded.
const MAX_IN_FLIGHT: usize = 900;

// The maximum number of requests to submit together in a batch.
const MAX_BATCH_SIZE: usize = 100;

// The maximum amount of time to wait before submitting a batch.
const MAX_BATCH_TIMEOUT_MILLIS: u64 = 1_000;

// How many cached entries to keep in the in-memory FIFO cache.
const MEMORY_CACHE_SIZE: usize = 100_000;

#[durable_object]
struct Batcher {
    state: State,
    env: Env,
    name: Option<String>,
    memory: MemoryCache,
    batch: Batch,
    in_flight: usize,
}

// A batch of entries to be submitted to the Sequencer together.
struct Batch {
    pending_leaves: Vec<LogEntry>,
    by_hash: HashSet<CacheKey>,
    done: Sender<()>,
}

impl Default for Batch {
    /// Returns a batch initialized with a watch channel.
    fn default() -> Self {
        let (tx, _) = watch::channel(());
        Self {
            pending_leaves: Vec::new(),
            by_hash: HashSet::new(),
            done: tx,
        }
    }
}

#[durable_object]
impl DurableObject for Batcher {
    fn new(state: State, env: Env) -> Self {
        let level = CONFIG
            .logging_level
            .as_ref()
            .and_then(|level| Level::from_str(level).ok())
            .unwrap_or(Level::Info);
        util::init_logging(level);
        console_error_panic_hook::set_once();
        Self {
            state,
            env,
            name: None,
            memory: MemoryCache::new(MEMORY_CACHE_SIZE),
            batch: Batch::default(),
            in_flight: 0,
        }
    }
    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        if self.name.is_none() {
            self.name = Some(req.query::<QueryParams>()?.name);
        }
        match req.path().as_str() {
            "/add_leaf" => {
                let entry: LogEntry = req.json().await?;
                let key = ctlog::compute_cache_hash(
                    entry.is_precert,
                    &entry.certificate,
                    &entry.issuer_key_hash,
                );
                // First check if the entry is already in the cache.
                if let Some(value) = self.memory.get_entry(&key) {
                    return Response::from_json(&value);
                }

                if self.in_flight >= MAX_IN_FLIGHT {
                    return Response::error("too many requests in flight", 429);
                }
                self.in_flight += 1;

                // Set an alarm to flush the batch if it times out.
                if self.state.storage().get_alarm().await?.is_none() {
                    self.state
                        .storage()
                        .set_alarm(Duration::from_millis(MAX_BATCH_TIMEOUT_MILLIS))
                        .await?;
                }

                // Add entry to the current pending batch if it isn't already present.
                // If we maintained a cache of in-flight batches, we could also check
                // if the entry is present in one of those, but the Sequencer will already
                // deduplicate those.
                if !self.batch.by_hash.contains(&key) {
                    self.batch.by_hash.insert(key);
                    self.batch.pending_leaves.push(entry);
                }

                let mut recv = self.batch.done.subscribe();

                // Submit the current pending batch if it's full.
                if self.batch.pending_leaves.len() >= MAX_BATCH_SIZE {
                    // Delete the alarm as we're flushing the batch now.
                    self.state.storage().delete_alarm().await?;
                    // Take the current pending batch, replacing it with a new one.
                    let batch = std::mem::take(&mut self.batch);
                    if let Err(e) = self.submit_batch(batch).await {
                        log::warn!("failed to submit batch: {e}");
                    }
                }

                // Wait until the batch has been processed.
                if recv.changed().await.is_err() {
                    // If we see an error, the Sender for this channel was dropped, which
                    // could happen if the batch submission failed due to rate-limiting
                    // or other communication failures with the Sequencer.
                    // Proceed and check the in-memory cache before returning an error response.
                }
                let resp = if let Some(value) = self.memory.get_entry(&key) {
                    // The entry has been sequenced!
                    Response::from_json(&value)
                } else {
                    // Failed to sequence this entry, either due to an error
                    // submitting the batch or rate limiting at the Sequencer.
                    Response::error("rate limited", 429)
                };
                self.in_flight -= 1;

                resp
            }
            _ => Response::error("not found", 404),
        }
    }
    async fn alarm(&mut self) -> Result<Response> {
        // Ignore the alarm if it fired just after the DO was re-initialized.
        if self.name.is_none() {
            return Response::empty();
        }
        // Take the current pending batch, replacing it with a new one.
        let batch = std::mem::take(&mut self.batch);
        if let Err(e) = self.submit_batch(batch).await {
            log::warn!("failed to submit batch: {e}");
        }
        Response::empty()
    }
}

impl Batcher {
    // Submit the current pending batch to be sequenced.
    async fn submit_batch(&mut self, batch: Batch) -> Result<()> {
        let name = self.name.as_ref().unwrap();
        let params = CONFIG.params_or_err(name)?;
        let stub = get_stub(&self.env, name, None, "SEQUENCER")?;

        // Submit the batch, and wait for it to be sequenced.
        let sequenced_entries = stub
            .fetch_with_request(Request::new_with_init(
                &format!("http://fake_url.com/add_batch?name={name}"),
                &RequestInit {
                    method: Method::Post,
                    body: Some(serde_json::to_string(&batch.pending_leaves)?.into()),
                    ..Default::default()
                },
            )?)
            .await?
            .json::<Vec<(CacheKey, CacheValue)>>()
            .await?;

        // Put the sequenced entries into the in-memory store, where they can be retrieved
        // and returned to clients.
        self.memory.put_entries(&sequenced_entries);

        // We could wait until the batch's 'done' channel goes out of scope, but send an
        // explicit 'finished' signal here to allow waiting requests to respond faster.
        batch.done.send_modify(|()| {});

        // Write sequenced entries to the long-term deduplication cache in Workers KV.
        let kv = self.env.kv(&params.cache_kv).unwrap();
        let futures = sequenced_entries
            .into_iter()
            .map(|(k, v)| {
                kv.put(&BASE64_STANDARD.encode(k), "")
                    .unwrap()
                    .metadata::<CacheValue>(v)
                    .unwrap()
                    .execute()
            })
            .collect::<Vec<_>>();
        join_all(futures).await;
        Ok(())
    }
}
