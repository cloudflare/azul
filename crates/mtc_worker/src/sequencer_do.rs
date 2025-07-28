// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use std::time::Duration;

use crate::{load_checkpoint_signers, load_origin, CONFIG};
use generic_log_worker::{
    get_durable_object_name, GenericSequencer, SequencerConfig, SEQUENCER_BINDING,
};
use mtc_api::BootstrapMtcLogEntry;
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(alarm)]
struct Sequencer(GenericSequencer<BootstrapMtcLogEntry>);

impl DurableObject for Sequencer {
    fn new(state: State, env: Env) -> Self {
        let name = get_durable_object_name(
            &env,
            &state,
            SEQUENCER_BINDING,
            &mut CONFIG.logs.keys().map(|name| (name.as_str(), 0)),
        );
        let params = &CONFIG.logs[name];

        let config = SequencerConfig {
            name: name.to_string(),
            origin: load_origin(name),
            checkpoint_signers: load_checkpoint_signers(&env, name),
            checkpoint_extension: Box::new(|_| vec![]), // no checkpoint extension for MTC
            sequence_interval: Duration::from_millis(params.sequence_interval_millis),
            max_sequence_skips: params.max_sequence_skips,
            enable_dedup: params.enable_dedup,
            sequence_skip_threshold_millis: params.sequence_skip_threshold_millis,
            location_hint: params.location_hint.clone(),
        };

        Sequencer(GenericSequencer::new(state, env, config))
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.0.alarm().await
    }
}
