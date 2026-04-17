use std::time::Duration;

use crate::{load_checkpoint_cosigner, load_origin, CONFIG};
use generic_log_worker::{
    get_durable_object_name, load_public_bucket, CleanerConfig, GenericCleaner, ObjectBackend,
    ObjectBucket, CLEANER_BINDING,
};
use ietf_mtc_api::{
    IetfMtcPendingLogEntry, LandmarkSequence, LANDMARK_KEY, SUBTREE_SIG_KEY_PREFIX,
};
use signed_note::VerifierList;
use tlog_tiles::{CheckpointSigner, PendingLogEntry};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(alarm)]
struct Cleaner(GenericCleaner, Env, String);

impl DurableObject for Cleaner {
    fn new(state: State, env: Env) -> Self {
        let name = get_durable_object_name(
            &env,
            &state,
            CLEANER_BINDING,
            &mut CONFIG.logs.keys().map(|name| (name.as_str(), 0)),
        );
        let params = &CONFIG.logs[name];

        let config = CleanerConfig {
            name: name.to_string(),
            origin: load_origin(name),
            data_path: IetfMtcPendingLogEntry::DATA_TILE_PATH,
            aux_path: IetfMtcPendingLogEntry::AUX_TILE_PATH,
            verifiers: VerifierList::new(vec![load_checkpoint_cosigner(&env, name).verifier()]),
            clean_interval: Duration::from_secs(params.clean_interval_secs),
        };

        let name = name.to_string();
        Cleaner(GenericCleaner::new(state, &env, config), env, name)
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.0.fetch(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        // Run the generic log cleaner first.
        let response = self.0.alarm().await?;

        // Then clean up expired subtree signatures.
        if let Err(e) = self.clean_subtree_sigs().await {
            log::warn!("{}: subtree sig cleanup failed: {e}", self.2);
        }

        Ok(response)
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
