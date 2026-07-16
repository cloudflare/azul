// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use std::time::Duration;

use crate::{CONFIG, StaticCTSequenceMetadata, init_sentry, load_checkpoint_signers, load_origin};
use generic_log_worker::{GenericSequencer, SequencerConfig, empty_checkpoint_callback};
use static_ct_api::StaticCTLogEntry;
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(alarm)]
struct Sequencer(GenericSequencer<StaticCTLogEntry, StaticCTSequenceMetadata>);

// SAFETY: Durable Objects are single-threaded; the `RefUnwindSafe` bound
// is required by `wasm-bindgen` when building with `panic=unwind`.
impl std::panic::RefUnwindSafe for Sequencer {}

impl DurableObject for Sequencer {
    fn new(state: State, env: Env) -> Self {
        let name = state
            .id()
            .name()
            .expect("durable object name not provided by runtime");
        let params = &CONFIG.logs[&name];

        let config = SequencerConfig {
            origin: load_origin(&name),
            checkpoint_signers: load_checkpoint_signers(&env, &name),
            checkpoint_extension: Box::new(|_| vec![]), // no checkpoint extensions for CT
            sequence_interval: Duration::from_millis(params.sequence_interval_millis),
            max_sequence_skips: params.max_sequence_skips,
            enable_dedup: params.enable_dedup,
            sequence_skip_threshold_millis: params.sequence_skip_threshold_millis,
            location_hint: params.location_hint.clone(),
            checkpoint_callback: empty_checkpoint_callback(),
            name,
        };

        init_sentry(&env);
        Sequencer(GenericSequencer::new(state, env, config))
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_fetch"), ("do_type", "sequencer")],
            self.0.fetch(req),
        )
        .await
    }

    async fn alarm(&self) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_alarm"), ("do_type", "sequencer")],
            self.0.alarm(),
        )
        .await
    }
}
