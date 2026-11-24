// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use std::time::Duration;

use crate::{CONFIG, StaticCTSequenceMetadata, init_sentry, load_checkpoint_signers, load_origin};
use generic_log_worker::key_service::Keyring;
use generic_log_worker::{
    CheckpointSource, GenericSequencer, SequencerConfig, empty_checkpoint_callback,
};
use signed_note::{NoteSignature, VerifierList};
use static_ct_api::StaticCTLogEntry;
use tlog_checkpoint::{CheckpointSigner, CheckpointText, UnixTimestampMillis};
#[allow(clippy::wildcard_imports)]
use worker::*;

enum ShardCheckpointSource {
    Local(Vec<Box<dyn CheckpointSigner>>),
    Service(crate::key_service::ShardCheckpointSigner),
}

impl CheckpointSource for ShardCheckpointSource {
    async fn sign(
        &self,
        timestamp: UnixTimestampMillis,
        checkpoint: &CheckpointText,
    ) -> std::result::Result<Vec<NoteSignature>, String> {
        match self {
            Self::Local(signers) => signers.sign(timestamp, checkpoint).await,
            Self::Service(signer) => signer.sign(timestamp, checkpoint).await,
        }
    }

    async fn verifiers(&self) -> std::result::Result<VerifierList, String> {
        match self {
            Self::Local(signers) => signers.verifiers().await,
            Self::Service(signer) => signer.verifiers().await,
        }
    }
}

#[durable_object(alarm)]
struct Sequencer(
    GenericSequencer<StaticCTLogEntry, StaticCTSequenceMetadata, ShardCheckpointSource>,
);

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
            checkpoint_source: if let Some(ring) = Keyring::new(&env) {
                ShardCheckpointSource::Service(crate::key_service::ShardCheckpointSigner::new(
                    ring, &name,
                ))
            } else {
                ShardCheckpointSource::Local(load_checkpoint_signers(&env, &name))
            },
            origin: load_origin(&name),
            checkpoint_extension: Box::new(|_| vec![]), // no checkpoint extensions for CT
            sequence_interval: Duration::from_millis(params.sequence_interval_millis),
            max_sequence_skips: params.max_sequence_skips,
            enable_dedup: params.enable_dedup,
            max_tree_size: None,
            sequence_skip_threshold_millis: params.sequence_skip_threshold_millis,
            location_hint: params.location_hint.clone(),
            checkpoint_callback: empty_checkpoint_callback(),
            durable_checkpoint_callback: false,
            checkpoint_callback_on_idle: false,
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
