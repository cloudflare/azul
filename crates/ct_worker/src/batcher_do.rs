// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Batcher buffers entries to be sequenced, submits batches to the sequencer, and
//! sends sequenced entry metadata to fetch tasks waiting on that batch.
//!
//! Entries are assigned to Batcher shards with consistent hashing on the cache key.

use crate::{get_stub, load_cache_kv, LookupKey, QueryParams, SequenceMetadata};
use base64::prelude::*;
use futures_util::future::{join_all, select, Either};
use static_ct_api::{JsonSerialize, PendingLogEntry, PendingLogEntryTrait};
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
struct Batcher<E: PendingLogEntryTrait> {
    env: Env,
    batch: Batch<E>,
    in_flight: usize,
    processed: usize,
}

// A batch of entries to be submitted to the Sequencer together.
struct Batch<E: PendingLogEntryTrait> {
    pending_leaves: Vec<E>,
    by_hash: HashSet<LookupKey>,
    done: Sender<HashMap<LookupKey, SequenceMetadata>>,
}

impl<E: PendingLogEntryTrait> Default for Batch<E> {
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
impl<E: PendingLogEntryTrait> DurableObject for Batcher<E> {
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
                let entry: PendingLogEntry = req.json().await?;
                let key = entry.lookup_key();

                if self.in_flight >= MAX_IN_FLIGHT {
                    return Response::error("too many requests in flight", 429);
                }
                self.in_flight += 1;
                self.processed += 1;

                // Add entry to the current pending batch if it isn't already present.
                // Rely on the Sequencer to deduplicate entries across batches.
                if !self.batch.by_hash.contains(&key) {
                    self.batch.by_hash.insert(key);
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

/// Serializes a slice of JsonSerializable items to a vec
fn to_json_array(items: &[impl JsonSerialize]) -> core::result::Result<String, serde_json::Error> {
    let mut buf = vec![b'['];

    for item in items {
        let mut writer = Vec::with_capacity(128);
        let mut ser = serde_json::Serializer::new(&mut writer);
        item.json_serialize(&mut ser)?;
        writer.push(b',');

        buf.extend(writer);
    }
    buf.push(b']');

    let out = unsafe {
        // serde_json does not emit invalid UTF-8.
        String::from_utf8_unchecked(buf)
    };
    Ok(out)
}

impl<E: PendingLogEntryTrait> Batcher<E> {
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

        // Submit the batch, and wait for it to be sequenced.
        let req = Request::new_with_init(
            &format!("http://fake_url.com/add_batch?name={name}"),
            &RequestInit {
                method: Method::Post,
                body: Some(to_json_array(&batch.pending_leaves)?.into()),
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
