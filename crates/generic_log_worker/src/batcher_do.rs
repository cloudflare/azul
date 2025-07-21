// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Batcher buffers entries to be sequenced, submits batches to the sequencer, and
//! sends sequenced entry metadata to fetch tasks waiting on that batch.
//!
//! Entries are assigned to Batcher shards with consistent hashing on the cache key.

use crate::{deserialize, serialize, LookupKey, SequenceMetadata, BATCH_ENDPOINT, ENTRY_ENDPOINT};
use base64::prelude::*;
use futures_util::future::{join_all, select, Either};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    time::Duration,
};
use tlog_tiles::PendingLogEntryBlob;
use tokio::sync::watch::{self, Sender};
use worker::kv::KvStore;
#[allow(clippy::wildcard_imports)]
use worker::*;

pub struct GenericBatcher {
    config: BatcherConfig,
    kv: Option<KvStore>,
    sequencer: Stub,
    batch: RefCell<Batch>,
    in_flight: RefCell<usize>,
    processed: RefCell<usize>,
}

pub struct BatcherConfig {
    pub name: String,
    pub max_batch_entries: usize,
    pub batch_timeout_millis: u64,
}

// A batch of entries to be submitted to the Sequencer together.
struct Batch {
    entries: Vec<PendingLogEntryBlob>,
    by_hash: HashSet<LookupKey>,
    done: Sender<HashMap<LookupKey, SequenceMetadata>>,
}

impl Default for Batch {
    /// Returns a batch initialized with a watch channel.
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            by_hash: HashSet::new(),
            done: watch::Sender::default(),
        }
    }
}

impl GenericBatcher {
    /// Returns a new batcher with the given config.
    pub fn new(config: BatcherConfig, kv: Option<KvStore>, sequencer: Stub) -> Self {
        Self {
            config,
            kv,
            sequencer,
            batch: RefCell::new(Batch::default()),
            in_flight: RefCell::new(0),
            processed: RefCell::new(0),
        }
    }

    /// Adds a request containing a log entry to the current batch. When the
    /// batch is full or timed-out, requests are sent to the sequencer and
    /// responses forwarded to the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be parsed or response cannot be
    /// constructed.
    pub async fn fetch(&self, mut req: Request) -> Result<Response> {
        match req.path().as_str() {
            ENTRY_ENDPOINT => {
                let entry: PendingLogEntryBlob = deserialize(&req.bytes().await?)?;
                let key = entry.lookup_key;

                *self.in_flight.borrow_mut() += 1;
                *self.processed.borrow_mut() += 1;

                // Add entry to the current pending batch if it isn't already present.
                // Rely on the Sequencer to deduplicate entries across batches.
                if !self.batch.borrow().by_hash.contains(&key) {
                    self.batch.borrow_mut().by_hash.insert(key);
                    self.batch.borrow_mut().entries.push(entry);
                }

                let mut recv = self.batch.borrow().done.subscribe();

                // Submit the current pending batch if it's full.
                if self.batch.borrow().entries.len() >= self.config.max_batch_entries {
                    if let Err(e) = self.submit_batch().await {
                        log::warn!("{} failed to submit full batch: {e}", self.config.name);
                    }
                } else {
                    let batch_done = recv.changed();
                    let timeout =
                        Delay::from(Duration::from_millis(self.config.batch_timeout_millis));
                    futures_util::pin_mut!(batch_done);
                    match select(batch_done, timeout).await {
                        Either::Left((batch_done, _timeout)) => {
                            if batch_done.is_err() {
                                log::warn!(
                                    "{} failed to sequence: batch dropped",
                                    self.config.name
                                );
                            }
                        }
                        Either::Right(((), batch_done)) => {
                            // Batch timeout reached; submit this entry's batch if no-one has already.
                            if self.batch.borrow().by_hash.contains(&key) {
                                if let Err(e) = self.submit_batch().await {
                                    log::warn!(
                                        "{} failed to submit timed-out batch: {e}",
                                        self.config.name
                                    );
                                }
                            } else {
                                // Someone else submitted the batch; wait for it to finish.
                                if batch_done.await.is_err() {
                                    log::warn!(
                                        "{} failed to sequence: batch dropped",
                                        self.config.name
                                    );
                                }
                            }
                        }
                    }
                }

                let resp = if let Some(value) = recv.borrow().get(&key) {
                    // The entry has been sequenced!
                    Response::from_bytes(serialize(&value)?)
                } else {
                    // Failed to sequence this entry, either due to an error
                    // submitting the batch or rate limiting at the Sequencer.
                    Response::error("rate limited", 429)
                };
                *self.in_flight.borrow_mut() -= 1;

                resp
            }
            _ => Response::error("not found", 404),
        }
    }
}

impl GenericBatcher {
    /// Submit the current pending batch to be sequenced.
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues constructing or sending requests to
    /// the sequencer or deduplication cache.
    pub async fn submit_batch(&self) -> Result<()> {
        // Take the current pending batch and replace it with a new one.
        let batch = std::mem::take(&mut *self.batch.borrow_mut());

        log::debug!(
            "{} submitting batch: leaves={} inflight={} processed={}",
            self.config.name,
            batch.entries.len(),
            self.in_flight.borrow(),
            self.processed.borrow(),
        );

        // Submit the batch, and wait for it to be sequenced.
        let req = Request::new_with_init(
            &format!("http://fake_url.com{BATCH_ENDPOINT}"),
            &RequestInit {
                method: Method::Post,
                body: Some(serialize(&batch.entries)?.into()),
                ..Default::default()
            },
        )?;
        let sequenced_entries: HashMap<LookupKey, SequenceMetadata> =
            deserialize::<Vec<(LookupKey, SequenceMetadata)>>(
                &self
                    .sequencer
                    .fetch_with_request(req)
                    .await?
                    .bytes()
                    .await?,
            )?
            .into_iter()
            .collect();

        // Send the sequenced entries to channel subscribers.
        batch.done.send_modify(|v| v.clone_from(&sequenced_entries));

        // Write sequenced entries to the long-term deduplication cache in Workers KV.
        if let Some(kv) = &self.kv {
            let futures = sequenced_entries
                .into_iter()
                .map(|(k, v)| {
                    Ok(kv
                        .put(&BASE64_STANDARD.encode(k), "")?
                        .metadata::<SequenceMetadata>(v)?
                        .execute())
                })
                .collect::<Result<Vec<_>>>()?;
            join_all(futures).await;
        }
        Ok(())
    }
}

/// Return a batcher ID to which the provided entry should be assigned.
pub fn batcher_id_from_lookup_key(key: &LookupKey, num_batchers: u8) -> Option<u8> {
    if num_batchers > 0 {
        Some(key[0] % num_batchers)
    } else {
        None
    }
}
