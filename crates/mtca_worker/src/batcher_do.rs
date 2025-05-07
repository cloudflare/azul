// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Batcher buffers entries to be sequenced, submits batches to the sequencer, and
//! sends sequenced entry metadata to fetch tasks waiting on that batch.
//!
//! Entries are assigned to Batcher shards with consistent hashing on the cache key.

use crate::{get_stub, LookupKey, QueryParams, SequenceMetadata};
use futures_util::future::{select, Either};
use mtc_api::{unmarshal_exact, LogEntry, Marshal};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tokio::sync::watch::{self, Sender};
#[allow(clippy::wildcard_imports)]
use worker::*;

// How many in-flight requests to allow. Tune to prevent the DO from being overloaded.
const MAX_IN_FLIGHT: usize = 900;

// The maximum number of requests to submit together in a batch.
const MAX_BATCH_SIZE: usize = 100;

// The maximum amount of time to wait before submitting a batch.
const MAX_BATCH_TIMEOUT_MILLIS: u64 = 1_000;

#[durable_object]
struct Batcher {
    env: Env,
    batch: Batch,
    in_flight: usize,
    processed: usize,
}

// A batch of entries to be submitted to the Sequencer together.
struct Batch {
    pending_leaves: Vec<LogEntry>,
    by_hash: HashSet<LookupKey>,
    done: Sender<HashMap<LookupKey, SequenceMetadata>>,
}

impl Default for Batch {
    /// Returns a batch initialized with a watch channel.
    fn default() -> Self {
        let (done, _) = watch::channel(HashMap::new());
        Self {
            pending_leaves: Vec::new(),
            by_hash: HashSet::new(),
            done,
        }
    }
}

#[durable_object]
impl DurableObject for Batcher {
    fn new(state: State, env: Env) -> Self {
        Self {
            env,
            batch: Batch::default(),
            in_flight: 0,
            processed: 0,
        }
    }
    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        match req.path().as_str() {
            "/add_leaf" => {
                let name = &req.query::<QueryParams>()?.name;
                let mut data: &[u8] = &req.bytes().await?;
                let entry: LogEntry = unmarshal_exact(&mut data).map_err(|e| e.to_string())?;
                let lookup_key = entry.lookup_key();

                if self.in_flight >= MAX_IN_FLIGHT {
                    return Response::error("too many requests in flight", 429);
                }
                self.in_flight += 1;
                self.processed += 1;

                // Add entry to the current pending batch if it isn't already present.
                // Rely on the Sequencer to deduplicate entries across batches.
                if !self.batch.by_hash.contains(&lookup_key) {
                    self.batch.by_hash.insert(lookup_key);
                    self.batch.pending_leaves.push(entry);
                }

                let mut recv = self.batch.done.subscribe();

                // Submit the current pending batch if it's full.
                if self.batch.pending_leaves.len() >= MAX_BATCH_SIZE {
                    if let Err(e) = self.submit_batch(name).await {
                        log::warn!("{name} failed to submit full batch: {e}");
                    }
                } else {
                    let batch_done = recv.changed();
                    let timeout = Delay::from(Duration::from_millis(MAX_BATCH_TIMEOUT_MILLIS));
                    futures_util::pin_mut!(batch_done);
                    match select(batch_done, timeout).await {
                        Either::Left((batch_done, _timeout)) => {
                            if batch_done.is_err() {
                                log::warn!("{name} failed to sequence: batch dropped");
                            }
                        }
                        Either::Right(((), batch_done)) => {
                            // Batch timeout reached; submit this entry's batch if no-one has already.
                            if self.batch.by_hash.contains(&lookup_key) {
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

                let resp = if let Some(value) = recv.borrow().get(&lookup_key) {
                    // The entry has been sequenced!
                    Response::from_json(&value)
                } else {
                    // Failed to sequence this entry, either due to an error
                    // submitting the batch or rate limiting at the Sequencer.
                    // The entry's batch could have also been dropped before
                    // this fetch task woke up and received the channel update.
                    Response::error("rate limited", 429)
                };
                self.in_flight -= 1;

                resp
            }
            _ => Response::error("not found", 404),
        }
    }
}

impl Batcher {
    // Submit the current pending batch to be sequenced.
    async fn submit_batch(&mut self, name: &str) -> Result<()> {
        let stub = get_stub(&self.env, name, None, "SEQUENCER")?;

        // Take the current pending batch and replace it with a new one.
        let batch = std::mem::take(&mut self.batch);

        log::debug!(
            "{name} submitting batch: leaves={} inflight={} processed={}",
            batch.pending_leaves.len(),
            self.in_flight,
            self.processed,
        );

        let mut data = Vec::new();
        for entry in batch.pending_leaves {
            entry.marshal(&mut data).map_err(|e| e.to_string())?;
        }

        // Submit the batch, and wait for it to be sequenced.
        let req = Request::new_with_init(
            &format!("http://fake_url.com/add_batch?name={name}"),
            &RequestInit {
                method: Method::Post,
                body: Some(data.into()),
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

        // TODO will the batch get dropped immediately before subscribers get their responses?
        Ok(())
    }
}
