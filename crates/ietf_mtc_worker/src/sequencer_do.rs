// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use std::{collections::VecDeque, time::Duration};

use crate::{
    load_checkpoint_cosigner, load_key_pair, load_origin, IetfMtcSequenceMetadata, CONFIG,
};
use generic_log_worker::{
    get_durable_object_name, load_public_bucket,
    log_ops::{prove_subtree_consistency, ProofError},
    CachedRoObjectBucket, CheckpointCallbacker, GenericSequencer, ObjectBucket, SequencerConfig,
    SEQUENCER_BINDING,
};
use ietf_mtc_api::{
    subtree_sig_key, IetfMtcLogEntry, LandmarkSequence, SignedSubtree, TrustAnchorID,
    LANDMARK_BUNDLE_KEY, LANDMARK_CHECKPOINT_KEY, LANDMARK_KEY,
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use signed_note::Note;
use std::str::FromStr;
use tlog_tiles::{CheckpointText, Hash, Subtree, UnixTimestamp};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(alarm)]
struct Sequencer(GenericSequencer<IetfMtcLogEntry, IetfMtcSequenceMetadata>);

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
            checkpoint_signers: vec![Box::new(load_checkpoint_cosigner(&env, name))],
            checkpoint_extension: Box::new(|_| vec![]), // no checkpoint extension for MTC
            sequence_interval: Duration::from_millis(params.sequence_interval_millis),
            max_sequence_skips: params.max_sequence_skips,
            enable_dedup: false, // deduplication is not currently supported
            sequence_skip_threshold_millis: params.sequence_skip_threshold_millis,
            location_hint: params.location_hint.clone(),
            checkpoint_callback: checkpoint_callback(&env, name),
            env_label: env!("DEPLOY_ENV").to_string(),
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

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SubtreeWithConsistencyProof {
    #[serde_as(as = "Base64")]
    pub hash: [u8; 32],
    #[serde_as(as = "Vec<Base64>")]
    pub consistency_proof: Vec<[u8; 32]>,
}

/// GET response structure for the `/get-landmark-bundle` endpoint
#[derive(Serialize, Deserialize)]
pub struct LandmarkBundle {
    pub checkpoint: String,
    pub subtrees: Vec<SubtreeWithConsistencyProof>,
    pub landmarks: VecDeque<u64>,
}

/// Return a callback function that gets passed into the generic sequencer and
/// called each time a new checkpoint is created. For MTC, this is used to
/// periodically update the landmark checkpoint sequence.
fn checkpoint_callback(env: &Env, name: &str) -> CheckpointCallbacker {
    let params = &CONFIG.logs[name];
    let bucket = load_public_bucket(env, name).unwrap();
    // Capture the signing key parts so the cosigner can be reconstructed
    // on each callback invocation (MtcCosigner is not Clone).
    let (sk, vk) = load_key_pair(env, name).unwrap();
    let log_id = TrustAnchorID::from_str(&CONFIG.logs[name].log_id).unwrap();
    let cosigner_id_str = CONFIG.logs[name].cosigner_id.clone();
    Box::new(
        move |old_time: UnixTimestamp,
              new_time: UnixTimestamp,
              old_tree_size: u64,
              new_tree_size: u64,
              new_checkpoint_bytes: &[u8]| {
            let new_checkpoint = {
                // TODO: Make more efficient. There are two unnecessary allocations here.

                // We can unwrap because the checkpoint provided is the checkpoint that the
                // sequencer just created, so it must be well formed.
                let note = Note::from_bytes(new_checkpoint_bytes)
                    .expect("freshly created checkpoint is not a note");
                CheckpointText::from_bytes(note.text())
                    .expect("freshly created checkpoint is not a checkpoint")
            };
            let tree_size = new_checkpoint.size();
            let root_hash = *new_checkpoint.hash();
            // We can unwrap here for the same reason as above
            let new_checkpoint_str = String::from_utf8(new_checkpoint_bytes.to_vec())
                .expect("freshly created checkpoint is not UTF-8");

            Box::pin({
                // We have to clone each time since the bucket gets moved into
                // the async function.
                let bucket_clone = bucket.clone();
                let sk_clone = sk.clone();
                let vk_clone = vk.clone();
                let log_id_clone = log_id.clone();
                let cosigner_id_clone = TrustAnchorID::from_str(&cosigner_id_str).unwrap();
                async move {
                    if old_time > new_time {
                        return Err("condition not met: `old_time <= new_time`".into());
                    }

                    // Sign and cache the subtree(s) covering entries added in
                    // this batch (§4.5).  This enables the add-entry endpoint to
                    // return a standalone certificate immediately after sequencing.
                    Box::pin(sign_and_cache_batch_subtrees(
                        old_tree_size,
                        new_tree_size,
                        tree_size,
                        root_hash,
                        &cosigner_id_clone,
                        &log_id_clone,
                        &sk_clone,
                        &vk_clone,
                        &bucket_clone,
                    ))
                    .await?;

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
                    let max_active_landmarks = params.max_active_landmarks();

                    // TODO: the put operations below should all be done as part of the same
                    // transaction. Otherwise an error that occurs after this point might put us in
                    // a state where the objects are not in sync with one another, e.g., the
                    // landmark bundle and checkpoint might have the same value. We need an
                    // all-or-nothing multi-put operation. Tracking issue here
                    // https://github.com/cloudflare/workers-rs/issues/876

                    // Load current landmark sequence.
                    let mut seq =
                        if let Some(obj) = bucket_clone.get(LANDMARK_KEY).execute().await? {
                            let bytes = obj.body().ok_or("missing object body")?.bytes().await?;
                            LandmarkSequence::from_bytes(&bytes, max_active_landmarks)
                                .map_err(|e| e.to_string())?
                        } else {
                            LandmarkSequence::create(max_active_landmarks)
                        };
                    // Add the new landmark.
                    if seq.add(tree_size).map_err(|e| e.to_string())? {
                        // The landmark sequence was updated. Publish the result.
                        bucket_clone
                            .put(LANDMARK_KEY, seq.to_bytes().map_err(|e| e.to_string())?)
                            .execute()
                            .await?;
                    }

                    // Update the landmark checkpoint.
                    bucket_clone
                        .put(LANDMARK_CHECKPOINT_KEY, new_checkpoint_str.clone())
                        .execute()
                        .await?;

                    // Compute the landmark bundle and save it
                    let landmark_subtrees =
                        get_landmark_subtrees(&seq, root_hash, tree_size, bucket_clone.clone())
                            .await?;

                    // Sign and cache each active landmark subtree so that
                    // build_standalone_cert can serve certificates for entries
                    // from older batches, not just the current one.
                    Box::pin(sign_and_cache_landmark_subtrees(
                        &seq,
                        root_hash,
                        tree_size,
                        &cosigner_id_clone,
                        &log_id_clone,
                        &sk_clone,
                        &vk_clone,
                        &landmark_subtrees,
                        &bucket_clone,
                    ))
                    .await?;

                    let bundle = LandmarkBundle {
                        checkpoint: new_checkpoint_str,
                        subtrees: landmark_subtrees,
                        landmarks: seq.landmarks,
                    };
                    bucket_clone
                        // Can unwrap here because we use the autoderived Serialize impl for LandmarkBundle
                        .put(LANDMARK_BUNDLE_KEY, serde_json::to_vec(&bundle).unwrap())
                        .execute()
                        .await?;

                    Ok(())
                }
            })
        },
    )
}

// Computes the sequence of landmark subtrees and, for each subtree, a proof of consistency with the
// checkpoint. Each landmark-relative MTC certificate includes an inclusion proof in one of these subtrees.
async fn get_landmark_subtrees(
    landmark_sequence: &LandmarkSequence,
    checkpoint_hash: Hash,
    checkpoint_size: u64,
    bucket: Bucket,
) -> Result<Vec<SubtreeWithConsistencyProof>> {
    let cached_object_backend = CachedRoObjectBucket::new(ObjectBucket::new(bucket));
    let mut subtrees = Vec::new();
    for landmark_subtree in landmark_sequence.subtrees() {
        let (consistency_proof, landmark_subtree_hash) = match prove_subtree_consistency(
            checkpoint_hash,
            checkpoint_size,
            landmark_subtree.lo(),
            landmark_subtree.hi(),
            &cached_object_backend,
        )
        .await
        {
            Ok(p) => p,
            Err(ProofError::Tlog(s)) => return Err(s.to_string().into()),
            Err(ProofError::Other(e)) => return Err(e.to_string().into()),
        };

        subtrees.push(SubtreeWithConsistencyProof {
            hash: landmark_subtree_hash.0,
            consistency_proof: consistency_proof.iter().map(|h| h.0).collect(),
        });
    }

    Ok(subtrees)
}

/// Sign the subtree(s) covering `[old_tree_size, new_tree_size)` and store
/// each signature in R2.  Called from the checkpoint callback.
///
/// The subtree root hash is computed from the checkpoint tiles via
/// `prove_subtree_consistency` so that the signature covers the actual
/// subtree head, not the full checkpoint hash.
#[allow(clippy::too_many_arguments)]
async fn sign_and_cache_batch_subtrees(
    old_tree_size: u64,
    new_tree_size: u64,
    checkpoint_size: u64,
    checkpoint_hash: Hash,
    cosigner_id: &TrustAnchorID,
    log_id: &TrustAnchorID,
    sk: &ietf_mtc_api::MtcSigningKey,
    vk: &ietf_mtc_api::MtcVerifyingKey,
    bucket: &Bucket,
) -> Result<()> {
    if old_tree_size >= new_tree_size {
        return Ok(());
    }
    let cosigner = ietf_mtc_api::MtcCosigner::new_checkpoint(
        cosigner_id.clone(),
        log_id.clone(),
        sk.clone(),
        vk.clone(),
    );
    let object_bucket = CachedRoObjectBucket::new(ObjectBucket::new(bucket.clone()));
    let (left, right) =
        Subtree::split_interval(old_tree_size, new_tree_size).map_err(|e| e.to_string())?;
    for subtree in [Some(left), right].into_iter().flatten() {
        // Compute the actual subtree root hash from the checkpoint tiles.
        let (_, subtree_hash) = match prove_subtree_consistency(
            checkpoint_hash,
            checkpoint_size,
            subtree.lo(),
            subtree.hi(),
            &object_bucket,
        )
        .await
        {
            Ok(p) => p,
            Err(ProofError::Tlog(s)) => return Err(s.to_string().into()),
            Err(ProofError::Other(e)) => return Err(e.to_string().into()),
        };
        let sig = cosigner
            .sign_subtree(subtree.lo(), subtree.hi(), &subtree_hash)
            .map_err(|e| e.to_string())?;
        let signed = SignedSubtree {
            lo: subtree.lo(),
            hi: subtree.hi(),
            hash: subtree_hash.0,
            checkpoint_hash: checkpoint_hash.0,
            checkpoint_size,
            signature: sig,
            cosigner_id: cosigner_id.to_string(),
        };
        bucket
            .put(
                subtree_sig_key(subtree.lo(), subtree.hi()),
                serde_json::to_vec(&signed).map_err(|e| e.to_string())?,
            )
            .execute()
            .await?;
    }
    Ok(())
}

/// Sign and cache each active landmark subtree so that `build_standalone_cert`
/// can serve certificates for entries from prior batches.
///
/// Like batch subtrees, landmark subtrees are signed with their own Merkle
/// root hash (obtained from `get_landmark_subtrees` via `prove_subtree_consistency`)
/// rather than the full checkpoint hash.
#[allow(clippy::too_many_arguments)]
async fn sign_and_cache_landmark_subtrees(
    seq: &LandmarkSequence,
    checkpoint_hash: Hash,
    checkpoint_size: u64,
    cosigner_id: &TrustAnchorID,
    log_id: &TrustAnchorID,
    sk: &ietf_mtc_api::MtcSigningKey,
    vk: &ietf_mtc_api::MtcVerifyingKey,
    landmark_subtrees: &[SubtreeWithConsistencyProof],
    bucket: &Bucket,
) -> Result<()> {
    let cosigner = ietf_mtc_api::MtcCosigner::new_checkpoint(
        cosigner_id.clone(),
        log_id.clone(),
        sk.clone(),
        vk.clone(),
    );
    for (subtree, proof) in seq.subtrees().zip(landmark_subtrees.iter()) {
        let subtree_hash = Hash(proof.hash);
        let sig = cosigner
            .sign_subtree(subtree.lo(), subtree.hi(), &subtree_hash)
            .map_err(|e| e.to_string())?;
        let signed = SignedSubtree {
            lo: subtree.lo(),
            hi: subtree.hi(),
            hash: proof.hash,
            checkpoint_hash: checkpoint_hash.0,
            checkpoint_size,
            signature: sig,
            cosigner_id: cosigner_id.to_string(),
        };
        bucket
            .put(
                subtree_sig_key(subtree.lo(), subtree.hi()),
                serde_json::to_vec(&signed).map_err(|e| e.to_string())?,
            )
            .execute()
            .await?;
    }
    Ok(())
}
