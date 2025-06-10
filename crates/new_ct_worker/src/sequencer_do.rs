// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use crate::{load_signing_key, load_witness_key};
use ct_worker::sequencer_do::GenericSequencer;
use static_ct_api::{StaticCTCheckpointSigner, StaticCTLogEntry, StaticCTPendingLogEntry};
use tlog_tiles::{CheckpointSigner, Ed25519CheckpointSigner};
#[allow(clippy::wildcard_imports)]
use worker::*;

// The number of entries in the short-term deduplication cache.
// This cache provides a secondary deduplication layer to bridge the gap in KV's eventual consistency.
// It should hold at least <maximum-entries-per-second> x <kv-eventual-consistency-time (60s)> entries.
const MEMORY_CACHE_SIZE: usize = 300_000;

#[durable_object]
struct Sequencer(GenericSequencer<StaticCTPendingLogEntry>);

#[durable_object]
impl DurableObject for Sequencer {
    fn new(state: State, env: Env) -> Self {
        // Need to define how we load our signing keys from the environment. This closure has type
        // CheckpointSignerLoader
        let load_signers = |e: &Env, name: &str, origin: &str| {
            let signing_key = load_signing_key(e, name)?.clone();
            let witness_key = load_witness_key(e, name)?.clone();

            // Make the checkpoint signers from the secret keys and put them in a vec
            let signer = StaticCTCheckpointSigner::new(origin, signing_key).map_err(|e| {
                Error::RustError(format!("could not create static-ct checkpoint signer: {e}"))
            })?;
            let witness = Ed25519CheckpointSigner::new(origin, witness_key).map_err(|e| {
                Error::RustError(format!("could not create ed25519 checkpoint signer: {e}"))
            })?;

            let out: Vec<Box<dyn CheckpointSigner>> = vec![Box::new(signer), Box::new(witness)];
            Ok(out)
        };

        Sequencer(GenericSequencer::new(state, env, Box::new(load_signers)))
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }

    async fn alarm(&mut self) -> Result<Response> {
        self.0.alarm::<StaticCTLogEntry>().await
    }
}
