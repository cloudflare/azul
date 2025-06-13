// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use std::time::Duration;

use crate::{load_signing_key, load_witness_key, CONFIG};
use generic_log_worker::{
    get_durable_object_name, load_public_bucket, GenericSequencer, SequencerConfig,
};
use prometheus::Registry;
use static_ct_api::{StaticCTCheckpointSigner, StaticCTLogEntry, StaticCTPendingLogEntry};
use tlog_tiles::{CheckpointSigner, Ed25519CheckpointSigner};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object]
struct Sequencer(GenericSequencer<StaticCTPendingLogEntry>);

#[durable_object]
impl DurableObject for Sequencer {
    fn new(state: State, env: Env) -> Self {
        let (state, name) = get_durable_object_name(state).unwrap();
        let params = &CONFIG.logs[&name];

        // https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#checkpoints
        // The origin line MUST be the submission prefix of the log as a schema-less URL with no trailing slashes.
        let origin = params
            .submission_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');
        let sequence_interval = Duration::from_millis(params.sequence_interval_millis);

        let checkpoint_signers: Vec<Box<dyn CheckpointSigner>> = {
            let signing_key = load_signing_key(&env, &name).unwrap().clone();
            let witness_key = load_witness_key(&env, &name).unwrap().clone();

            // Make the checkpoint signers from the secret keys and put them in a vec
            let signer = StaticCTCheckpointSigner::new(origin, signing_key)
                .map_err(|e| {
                    Error::RustError(format!("could not create static-ct checkpoint signer: {e}"))
                })
                .unwrap();
            let witness = Ed25519CheckpointSigner::new(origin, witness_key)
                .map_err(|e| {
                    Error::RustError(format!("could not create ed25519 checkpoint signer: {e}"))
                })
                .unwrap();

            vec![Box::new(signer), Box::new(witness)]
        };
        let bucket = load_public_bucket(&env, &name).unwrap();
        let registry = Registry::new();

        let config = SequencerConfig {
            name,
            origin: origin.to_string(),
            checkpoint_signers,
            sequence_interval,
            max_sequence_skips: params.max_sequence_skips,
            enable_dedup: params.enable_dedup,
            sequence_skip_threshold_millis: params.sequence_skip_threshold_millis,
        };

        Sequencer(GenericSequencer::new(config, state, bucket, registry))
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }

    async fn alarm(&mut self) -> Result<Response> {
        self.0.alarm::<StaticCTLogEntry>().await
    }
}
