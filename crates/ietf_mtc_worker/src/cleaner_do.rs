use std::time::Duration;

use crate::{CONFIG, SUBTREE_SIG_KEY_PREFIX, init_sentry, load_checkpoint_cosigner, load_origin};
use generic_log_worker::{
    CleanerConfig, GenericCleaner, ObjectBackend, ObjectBucket, load_public_bucket,
};
use ietf_mtc_api::{IetfMtcPendingLogEntry, LANDMARK_KEY, LandmarkSequence};
use signed_note::VerifierList;
use tlog_checkpoint::CheckpointSigner;
use tlog_entry::PendingLogEntry;
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(alarm)]
struct Cleaner(GenericCleaner, Env, String);

// SAFETY: Durable Objects are single-threaded; this is required by wasm-bindgen
// when building with panic unwinding.
impl std::panic::RefUnwindSafe for Cleaner {}

impl DurableObject for Cleaner {
    fn new(state: State, env: Env) -> Self {
        let name = state
            .id()
            .name()
            .expect("durable object name not provided by runtime");
        let params = &CONFIG.logs[&name];

        let config = CleanerConfig {
            origin: load_origin(&name),
            data_path: IetfMtcPendingLogEntry::DATA_TILE_PATH,
            aux_path: IetfMtcPendingLogEntry::AUX_TILE_PATH,
            verifiers: VerifierList::new(vec![load_checkpoint_cosigner(&env, &name).verifier()]),
            clean_interval: Duration::from_secs(params.clean_interval_secs),
            name: name.clone(),
        };

        init_sentry(&env);
        Cleaner(GenericCleaner::new(state, &env, config), env, name)
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_fetch"), ("do_type", "cleaner")],
            self.0.fetch(req),
        )
        .await
    }

    async fn alarm(&self) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_alarm"), ("do_type", "cleaner")],
            async {
                let response = self.0.alarm().await?;
                if let Err(e) = self.clean_subtree_sigs().await {
                    log::warn!("{}: subtree sig cleanup failed: {e}", self.2);
                }
                Ok(response)
            },
        )
        .await
    }
}

impl Cleaner {
    /// Delete subtree signature entries whose covered interval ends at or
    /// before the oldest landmark in the sequence.
    ///
    /// Any entry with `hi <= oldest_landmark` is guaranteed to be covered by
    /// an expired landmark and will never be needed for a new certificate.
    async fn clean_subtree_sigs(&self) -> Result<()> {
        let env = &self.1;
        let name = &self.2;
        let params = &CONFIG.logs[name.as_str()];
        let object_bucket = ObjectBucket::new(load_public_bucket(env, name)?);
        let raw_bucket = load_public_bucket(env, name)?;

        // Load the landmark sequence to determine the oldest active landmark.
        let Some(seq_bytes) = object_bucket.fetch(LANDMARK_KEY).await? else {
            return Ok(()); // no landmarks yet, nothing to clean
        };
        let seq = LandmarkSequence::from_bytes(&seq_bytes, params.max_active_landmarks())
            .map_err(|e| e.to_string())?;
        let Some(&oldest_landmark) = seq.landmarks.front() else {
            return Ok(());
        };

        // List all subtree signature keys and delete those with hi <= oldest_landmark.
        let mut cursor = None;
        loop {
            let mut list_req = raw_bucket.list().prefix(SUBTREE_SIG_KEY_PREFIX);
            if let Some(ref c) = cursor {
                list_req = list_req.cursor(c);
            }
            let listed = list_req.execute().await?;

            let to_delete: Vec<String> = listed
                .objects()
                .into_iter()
                .filter_map(|obj| {
                    let key = obj.key();
                    parse_subtree_sig_hi(&key)
                        .filter(|&hi| hi <= oldest_landmark)
                        .map(|_| key)
                })
                .collect();

            if !to_delete.is_empty() {
                log::info!("{name}: deleting {} expired subtree sigs", to_delete.len());
                raw_bucket.delete_multiple(to_delete).await?;
            }

            if listed.truncated() {
                cursor = listed.cursor();
            } else {
                break;
            }
        }

        Ok(())
    }
}

/// Parse the `hi` endpoint from a subtree signature R2 key.
/// Key format: `{prefix}/{lo:020}-{hi:020}`
fn parse_subtree_sig_hi(key: &str) -> Option<u64> {
    let suffix = key
        .strip_prefix(SUBTREE_SIG_KEY_PREFIX)?
        .strip_prefix('/')?;
    let hi_str = suffix.split('-').nth(1)?;
    hi_str.parse().ok()
}
