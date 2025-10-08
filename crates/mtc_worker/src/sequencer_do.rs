// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use std::{future::Future, pin::Pin, time::Duration};

use crate::{load_checkpoint_signers, load_origin, CONFIG};
use generic_log_worker::{
    get_durable_object_name, load_public_bucket, CheckpointCallbacker, GenericSequencer,
    SequencerConfig, SEQUENCER_BINDING,
};
use mtc_api::{BootstrapMtcLogEntry, LandmarkSequence, LANDMARK_KEY};
use tlog_tiles::UnixTimestamp;
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
            enable_dedup: false, // deduplication is not currently supported
            sequence_skip_threshold_millis: params.sequence_skip_threshold_millis,
            location_hint: params.location_hint.clone(),
            checkpoint_callback: checkpoint_callback(&env, name),
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

/// Return a callback function that gets passed into the generic sequencer and
/// called each time a new checkpoint is created. For MTC, this is used to
/// periodically update the landmark checkpoint sequence.
fn checkpoint_callback(env: &Env, name: &str) -> CheckpointCallbacker {
    let params = &CONFIG.logs[name];
    let bucket = load_public_bucket(env, name).unwrap();
    Box::new(
        move |tree_size: u64, old_time: UnixTimestamp, new_time: UnixTimestamp| {
            Box::pin({
                // We have to clone each time since the bucket gets moved into
                // the async function.
                let bucket_clone = bucket.clone();
                async move {
                    if old_time > new_time {
                        return Err("condition not met: `old_time <= new_time`".into());
                    }
                    // Check if we crossed a landmark epoch between the old and
                    // new checkpoints. (Ideally `old_time` would be the time
                    // that the last landmark was added, but we don't have that
                    // handy so can use the previous checkpoint time instead.)
                    if new_time / (1000 * params.landmark_interval_secs as u64)
                        == old_time / (1000 * params.landmark_interval_secs as u64)
                    {
                        // Not yet time to add a new landmark.
                        return Ok(());
                    }

                    // Time to add a new landmark.
                    let max_landmarks = params
                        .max_certificate_lifetime_secs
                        .div_ceil(params.landmark_interval_secs)
                        + 1;

                    // Load current landmark sequence.
                    let mut seq =
                        if let Some(obj) = bucket_clone.get(LANDMARK_KEY).execute().await? {
                            let bytes = obj.body().ok_or("missing object body")?.bytes().await?;
                            LandmarkSequence::from_bytes(&bytes, max_landmarks)
                                .map_err(|e| e.to_string())?
                        } else {
                            LandmarkSequence::create(max_landmarks)
                        };
                    // Add the new landmark.
                    if seq.add(tree_size).map_err(|e| e.to_string())? {
                        // The landmark sequence was updated. Publish the result.
                        bucket_clone
                            .put(LANDMARK_KEY, seq.to_bytes().map_err(|e| e.to_string())?)
                            .execute()
                            .await?;
                    }
                    Ok(())
                }
            }) as Pin<Box<dyn Future<Output = Result<()>>>>
        },
    )
}
