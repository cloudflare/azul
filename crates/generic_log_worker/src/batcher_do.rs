// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Batcher buffers entries to be sequenced, submits batches to the sequencer, and
//! sends sequenced entry metadata to fetch tasks waiting on that batch.
//!
//! Entries are assigned to Batcher shards with consistent hashing on the cache key.

use crate::{
    config::AppConfig, get_stub, load_cache_kv, LookupKey, QueryParams, SequenceMetadata,
    BATCH_ENDPOINT, ENTRY_ENDPOINT,
};
use base64::prelude::*;
use futures_util::future::{join_all, select, Either};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tlog_tiles::PendingLogEntry;
use tokio::sync::watch::{self, Sender};
#[allow(clippy::wildcard_imports)]
use worker::*;

pub struct GenericBatcher<E: PendingLogEntry> {
    env: Env,
    app_config: AppConfig,
    batch: Batch<E>,
    in_flight: usize,
    processed: usize,
}

// A batch of entries to be submitted to the Sequencer together.
struct Batch<E: PendingLogEntry> {
    entries: Vec<E>,
    by_hash: HashSet<LookupKey>,
    done: Sender<HashMap<LookupKey, SequenceMetadata>>,
}

impl<E: PendingLogEntry> Default for Batch<E> {
    /// Returns a batch initialized with a watch channel.
    fn default() -> Self {
        let (done, _) = watch::channel(HashMap::new());
        Self {
            entries: Vec::new(),
            by_hash: HashSet::new(),
            done,
        }
    }
}

impl<E: PendingLogEntry> GenericBatcher<E> {
    pub fn new(app_config: AppConfig, env: Env) -> Self {
        Self {
            env,
            app_config,
            batch: Batch::default(),
            in_flight: 0,
            processed: 0,
        }
    }

    pub async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        match req.path().as_str() {
            ENTRY_ENDPOINT => {
                let name = &req.query::<QueryParams>()?.name;
                let params = &self.app_config.logs[name];
                let entry: E = req.json().await?;
                let key = entry.lookup_key();

                self.in_flight += 1;
                self.processed += 1;

                // Add entry to the current pending batch if it isn't already present.
                // Rely on the Sequencer to deduplicate entries across batches.
                if !self.batch.by_hash.contains(&key) {
                    self.batch.by_hash.insert(key);
                    self.batch.entries.push(entry);
                }

                let mut recv = self.batch.done.subscribe();

                // Submit the current pending batch if it's full.
                if self.batch.entries.len() >= params.max_batch_entries {
                    if let Err(e) = self.submit_batch(name).await {
                        log::warn!("{name} failed to submit full batch: {e}");
                    }
                } else {
                    let batch_done = recv.changed();
                    let timeout = Delay::from(Duration::from_millis(params.batch_timeout_millis));
                    futures_util::pin_mut!(batch_done);
                    match select(batch_done, timeout).await {
                        Either::Left((batch_done, _timeout)) => {
                            if batch_done.is_err() {
                                log::warn!("{name} failed to sequence: batch dropped");
                            }
                        }
                        Either::Right(((), batch_done)) => {
                            // Batch timeout reached; submit this entry's batch if no-one has already.
                            if self.batch.by_hash.contains(&key) {
                                if let Err(e) = self.submit_batch(name).await {
                                    log::warn!("{name} failed to submit timed-out batch: {e}");
                                }
                            } else {
                                // Someone else submitted the batch; wait for it to finish.
                                if batch_done.await.is_err() {
                                    log::warn!("{name} failed to sequence: batch dropped");
                                }
                            }
                        }
                    }
                }

                let resp = if let Some(value) = recv.borrow().get(&key) {
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
}

impl<E: PendingLogEntry> GenericBatcher<E> {
    // Submit the current pending batch to be sequenced.
    pub async fn submit_batch(&mut self, name: &str) -> Result<()> {
        let stub = get_stub(&self.app_config, &self.env, name, None, "SEQUENCER")?;

        // Take the current pending batch and replace it with a new one.
        let batch = std::mem::take(&mut self.batch);

        log::debug!(
            "{name} submitting batch: leaves={} inflight={} processed={}",
            batch.entries.len(),
            self.in_flight,
            self.processed,
        );

        // Submit the batch, and wait for it to be sequenced.
        let req = Request::new_with_init(
            &format!("http://fake_url.com{BATCH_ENDPOINT}?name={name}"),
            &RequestInit {
                method: Method::Post,
                body: Some(serde_json::to_string(&batch.entries)?.into()),
                ..Default::default()
            },
        )?;
        let sequenced_entries: HashMap<LookupKey, SequenceMetadata> = stub
            .fetch_with_request(req)
            .await?
            .json::<Vec<(LookupKey, SequenceMetadata)>>()
            .await?
            .into_iter()
            .collect();

        // Send the sequenced entries to channel subscribers.
        batch.done.send_modify(|v| v.clone_from(&sequenced_entries));

        // Write sequenced entries to the long-term deduplication cache in Workers KV.
        let kv = load_cache_kv(&self.env, name)?;
        let futures = sequenced_entries
            .into_iter()
            .map(|(k, v)| {
                kv.put(&BASE64_STANDARD.encode(k), "")
                    .unwrap()
                    .metadata::<SequenceMetadata>(v)
                    .unwrap()
                    .execute()
            })
            .collect::<Vec<_>>();
        join_all(futures).await;
        Ok(())
    }
}
