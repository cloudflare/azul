// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Sequencer is the 'brain' of the CT log, responsible for sequencing entries and maintaining log state.

use std::{
    cell::Cell, collections::VecDeque, future::Future, rc::Rc, str::FromStr, time::Duration,
};

use crate::{
    CONFIG, CachedSubtreeSignature, IetfMtcSequenceMetadata, SignedSubtree, init_sentry,
    load_checkpoint_cosigner, load_key_pair, load_origin, subtree_sig_key,
};
use config::CosignerParams;
use generic_log_worker::{
    CachedRoObjectBucket, CheckpointCallbacker, GenericSequencer, ObjectBucket, SequencerConfig,
    load_public_bucket,
    log_ops::{ProofError, prove_consistency, prove_subtree_consistency, read_leaf_range},
};
use ietf_mtc_api::{
    IetfMtcLogEntry, LANDMARK_BUNDLE_KEY, LANDMARK_CHECKPOINT_KEY, LANDMARK_KEY, LandmarkSequence,
    TrustAnchorID, UINT48_MAX,
};
use ml_dsa::{MlDsa44, VerifyingKey as MlDsaVerifyingKey};
use pkcs8::DecodePublicKey as _;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use signed_note::{KeyName, Note, NoteVerifier};
use tlog_checkpoint::{CheckpointText, UnixTimestampMillis};
use tlog_core::{Hash, Subtree};
use tlog_cosignature::SubtreeV1NoteVerifier;
use tlog_mirror::{AddEntriesRequestHeader, EntryPackage, MirrorInfo, package_ranges};
use tlog_witness::{
    parse_add_checkpoint_response, parse_sign_subtree_response, serialize_add_checkpoint_request,
    serialize_sign_subtree_request,
};
#[allow(clippy::wildcard_imports)]
use worker::*;

#[durable_object(alarm)]
struct Sequencer(GenericSequencer<IetfMtcLogEntry, IetfMtcSequenceMetadata>);

// SAFETY: Durable Objects are single-threaded; this is required by wasm-bindgen
// when building with panic unwinding.
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
            checkpoint_signers: vec![Box::new(load_checkpoint_cosigner(&env, &name))],
            checkpoint_extension: Box::new(|_| vec![]), // no checkpoint extension for MTC
            sequence_interval: Duration::from_millis(params.sequence_interval_millis),
            max_sequence_skips: params.max_sequence_skips,
            enable_dedup: true,
            max_tree_size: Some(UINT48_MAX),
            sequence_skip_threshold_millis: params.sequence_skip_threshold_millis,
            location_hint: params.location_hint.clone(),
            checkpoint_callback: checkpoint_callback(&env, &name),
            durable_checkpoint_callback: true,
            checkpoint_callback_on_idle: true,
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

const MAX_PACKAGES_PER_MIRROR_REQUEST: usize = 1;
const MAX_MIRROR_UPLOAD_REQUESTS: usize = 32;

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

struct MirrorSession {
    id: TrustAnchorID,
    submission_url: String,
    verifier: SubtreeV1NoteVerifier,
    checkpoint: Note,
}

/// Return a callback function that gets passed into the generic sequencer and
/// called each time a new checkpoint is created. For MTC, this is used to
/// periodically update the landmark checkpoint sequence.
#[allow(clippy::too_many_lines)]
fn checkpoint_callback(env: &Env, name: &str) -> CheckpointCallbacker {
    let params = &CONFIG.logs[name];
    let bucket = load_public_bucket(env, name).unwrap();
    // Capture the signing key parts so the cosigner can be reconstructed
    // on each callback invocation (MtcCosigner is not Clone).
    let (sk, vk) = load_key_pair(env, name).unwrap();
    let ca_id = TrustAnchorID::from_str(&params.ca_id).unwrap();
    let log_number = params.log_number;
    let last_idle_landmark = Rc::new(Cell::new(None));
    Box::new(
        move |old_time: UnixTimestampMillis,
              new_time: UnixTimestampMillis,
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
            let checkpoint_note = Note::from_bytes(new_checkpoint_bytes)
                .expect("freshly created checkpoint is not a note");

            Box::pin({
                // We have to clone each time since the bucket gets moved into
                // the async function.
                let bucket_clone = bucket.clone();
                let sk_clone = sk.clone();
                let vk_clone = vk.clone();
                let ca_id_clone = ca_id.clone();
                let last_idle_landmark = last_idle_landmark.clone();
                async move {
                    if old_time > new_time {
                        return Err("condition not met: `old_time <= new_time`".into());
                    }

                    let landmark_due = new_time / (1000 * params.landmark_interval_secs as u64)
                        != old_time / (1000 * params.landmark_interval_secs as u64);
                    let idle = old_tree_size == new_tree_size;
                    if idle && !landmark_due {
                        return Ok(());
                    }

                    let max_active_landmarks = params.max_active_landmarks();
                    let mut landmark_sequence = None;
                    if idle {
                        if last_idle_landmark.get() == Some(tree_size) {
                            return Ok(());
                        }
                        let mut sequence =
                            load_landmark_sequence(&bucket_clone, max_active_landmarks).await?;
                        if !sequence.add(tree_size).map_err(|e| e.to_string())? {
                            last_idle_landmark.set(Some(tree_size));
                            return Ok(());
                        }
                        landmark_sequence = Some(sequence);
                    }

                    let mirrors = advance_mirrors(
                        &params.cosigners,
                        old_tree_size,
                        tree_size,
                        root_hash,
                        &checkpoint_note,
                        &bucket_clone,
                    )
                    .await?;

                    // Sign and cache the subtree(s) covering entries added in
                    // this batch (§4.5).  This enables the add-entry endpoint to
                    // return a standalone certificate immediately after sequencing.
                    Box::pin(sign_and_cache_batch_subtrees(
                        old_tree_size,
                        new_tree_size,
                        tree_size,
                        root_hash,
                        &ca_id_clone,
                        log_number,
                        &sk_clone,
                        &vk_clone,
                        &mirrors,
                        &bucket_clone,
                    ))
                    .await?;

                    // Check if we crossed a landmark epoch between the old and
                    // new checkpoints. (Ideally `old_time` would be the time
                    // that the last landmark was added, but we don't have that
                    // handy so can use the previous checkpoint time instead.)
                    if !landmark_due {
                        // Not yet time to add a new landmark.
                        return Ok(());
                    }

                    // Time to add a new landmark.
                    let seq = if let Some(sequence) = landmark_sequence {
                        sequence
                    } else {
                        let mut sequence =
                            load_landmark_sequence(&bucket_clone, max_active_landmarks).await?;
                        if !sequence.add(tree_size).map_err(|e| e.to_string())? {
                            return Ok(());
                        }
                        sequence
                    };

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
                        &ca_id_clone,
                        log_number,
                        &sk_clone,
                        &vk_clone,
                        &mirrors,
                        &landmark_subtrees,
                        &bucket_clone,
                    ))
                    .await?;

                    let bundle = LandmarkBundle {
                        checkpoint: new_checkpoint_str,
                        subtrees: landmark_subtrees,
                        landmarks: seq.landmarks.clone(),
                    };
                    bucket_clone
                        // Can unwrap here because we use the autoderived Serialize impl for LandmarkBundle
                        .put(LANDMARK_BUNDLE_KEY, serde_json::to_vec(&bundle).unwrap())
                        .execute()
                        .await?;

                    bucket_clone
                        .put(LANDMARK_CHECKPOINT_KEY, bundle.checkpoint)
                        .execute()
                        .await?;

                    // The sequence is the commit marker for all landmark-dependent objects.
                    put_landmark_sequence(&bucket_clone, &seq).await?;
                    last_idle_landmark.set(Some(tree_size));

                    Ok(())
                }
            })
        },
    )
}

async fn load_landmark_sequence(
    bucket: &Bucket,
    max_active_landmarks: usize,
) -> Result<LandmarkSequence> {
    if let Some(object) = bucket.get(LANDMARK_KEY).execute().await? {
        let bytes = object.body().ok_or("missing object body")?.bytes().await?;
        LandmarkSequence::from_bytes(&bytes, max_active_landmarks)
            .map_err(|error| error.to_string().into())
    } else {
        Ok(LandmarkSequence::create(max_active_landmarks))
    }
}

async fn advance_mirrors(
    params: &[CosignerParams],
    old_tree_size: u64,
    tree_size: u64,
    root_hash: Hash,
    checkpoint: &Note,
    bucket: &Bucket,
) -> Result<Vec<MirrorSession>> {
    if params.is_empty() {
        return Ok(Vec::new());
    }
    let origin = CheckpointText::from_bytes(checkpoint.text())
        .map_err(|error| error.to_string())?
        .origin()
        .to_owned();
    let mut sessions = Vec::with_capacity(params.len());
    for params in params {
        let id = TrustAnchorID::from_str(&params.id).map_err(|error| error.to_string())?;
        let name = KeyName::new(id.oid_name()).map_err(|error| format!("{error:?}"))?;
        let key = MlDsaVerifyingKey::<MlDsa44>::from_public_key_der(&params.public_key)
            .map_err(|error| error.to_string())?;
        let verifier = SubtreeV1NoteVerifier::new(name, key);

        let upload_start = post_add_checkpoint(
            &params.submission_url,
            checkpoint,
            old_tree_size,
            tree_size,
            root_hash,
            bucket,
        )
        .await?;
        let response = upload_entries(
            &params.submission_url,
            &origin,
            upload_start,
            tree_size,
            root_hash,
            bucket,
        )
        .await?;
        let signatures =
            parse_add_checkpoint_response(&response).map_err(|error| error.to_string())?;
        let signature = require_signature(&signatures, &verifier)?;
        if !verifier.verify(checkpoint.text(), signature.signature()) {
            return Err(format!(
                "mirror {} returned an invalid checkpoint signature",
                params.id
            )
            .into());
        }
        let mut checkpoint_signatures = checkpoint.signatures().to_vec();
        checkpoint_signatures.push(signature.clone());
        let checkpoint = Note::new(checkpoint.text(), &checkpoint_signatures)
            .map_err(|error| format!("{error:?}"))?;
        sessions.push(MirrorSession {
            id,
            submission_url: params.submission_url.clone(),
            verifier,
            checkpoint,
        });
    }
    Ok(sessions)
}

async fn build_add_entries_body(
    origin: &str,
    upload_start: u64,
    upload_end: u64,
    ticket: Vec<u8>,
    checkpoint_hash: Hash,
    bucket: &CachedRoObjectBucket,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    AddEntriesRequestHeader {
        log_origin: origin.to_owned(),
        upload_start,
        upload_end,
        ticket,
    }
    .write_to(&mut body)
    .map_err(|error| error.to_string())?;
    for (start, end) in
        package_ranges(upload_start, upload_end).take(MAX_PACKAGES_PER_MIRROR_REQUEST)
    {
        let subtree_start = start / 256 * 256;
        let (proof, _) =
            prove_subtree_consistency(checkpoint_hash, upload_end, subtree_start, end, bucket)
                .await
                .map_err(proof_error)?;
        let entries =
            read_leaf_range::<IetfMtcLogEntry>(bucket, start, end, upload_end, &checkpoint_hash)
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|entry| entry.data().to_vec())
                .collect();
        EntryPackage { entries, proof }
            .write_to(&mut body)
            .map_err(|error| error.to_string())?;
    }
    Ok(body)
}

async fn upload_entries(
    prefix: &str,
    origin: &str,
    upload_start: u64,
    upload_end: u64,
    checkpoint_hash: Hash,
    bucket: &Bucket,
) -> Result<Vec<u8>> {
    continue_upload(
        upload_start,
        upload_end,
        |upload_start, ticket| async move {
            let object_bucket = CachedRoObjectBucket::new(ObjectBucket::new(bucket.clone()));
            let body = build_add_entries_body(
                origin,
                upload_start,
                upload_end,
                ticket,
                checkpoint_hash,
                &object_bucket,
            )
            .await?;
            post_mirror_response(prefix, "add-entries", "application/octet-stream", body).await
        },
    )
    .await
}

async fn continue_upload<F, Fut>(
    mut upload_start: u64,
    upload_end: u64,
    mut request: F,
) -> Result<Vec<u8>>
where
    F: FnMut(u64, Vec<u8>) -> Fut,
    Fut: Future<Output = Result<(u16, Vec<u8>)>>,
{
    let mut ticket = Vec::new();
    for _ in 0..MAX_MIRROR_UPLOAD_REQUESTS {
        let minimum_next = package_ranges(upload_start, upload_end)
            .next()
            .map_or(upload_end, |(_, end)| end);
        let (status, response) = request(upload_start, ticket).await?;
        match status {
            200 => return Ok(response),
            202 => {
                let (next_entry, next_ticket) =
                    mirror_upload_progress(status, &response, minimum_next, upload_end)?;
                if next_entry <= upload_start {
                    return Err(format!(
                        "mirror add-entries returned 202 without advancing from {upload_start}"
                    )
                    .into());
                }
                upload_start = next_entry;
                ticket = next_ticket;
            }
            409 => {
                let (next_entry, next_ticket) =
                    mirror_upload_progress(status, &response, 0, upload_end)?;
                if next_entry == upload_start {
                    return Err(format!(
                        "mirror add-entries returned 409 without changing upload start {upload_start}"
                    )
                    .into());
                }
                upload_start = next_entry;
                ticket = next_ticket;
            }
            _ => {
                return Err(format!(
                    "mirror add-entries returned {status}: {}",
                    String::from_utf8_lossy(&response)
                )
                .into());
            }
        }
    }
    Err(format!(
        "mirror add-entries exceeded {MAX_MIRROR_UPLOAD_REQUESTS} requests before reaching {upload_end}"
    )
    .into())
}

fn mirror_upload_progress(
    status: u16,
    body: &[u8],
    minimum_next: u64,
    upload_end: u64,
) -> Result<(u64, Vec<u8>)> {
    let info = MirrorInfo::parse(body)
        .map_err(|error| format!("mirror add-entries returned malformed {status}: {error}"))?;
    if info.tree_size != upload_end {
        return Err(format!(
            "mirror add-entries returned {status} for tree size {}, expected {upload_end}",
            info.tree_size
        )
        .into());
    }
    if info.next_entry < minimum_next || info.next_entry > upload_end {
        return Err(format!(
            "mirror add-entries returned {status} with invalid next entry {} for [{minimum_next}, {upload_end}]",
            info.next_entry
        )
        .into());
    }
    Ok((info.next_entry, info.ticket))
}

async fn post_mirror(
    prefix: &str,
    endpoint: &str,
    content_type: &str,
    body: &[u8],
) -> Result<Vec<u8>> {
    let (status, bytes) =
        post_mirror_response(prefix, endpoint, content_type, body.to_vec()).await?;
    if status != 200 {
        return Err(format!(
            "mirror {endpoint} returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        )
        .into());
    }
    Ok(bytes)
}

async fn post_add_checkpoint(
    prefix: &str,
    checkpoint: &Note,
    old_tree_size: u64,
    tree_size: u64,
    root_hash: Hash,
    bucket: &Bucket,
) -> Result<u64> {
    let object_bucket = ObjectBucket::new(bucket.clone());
    let mut submitted_old_size = old_tree_size;
    for attempt in 0..2 {
        let consistency_proof =
            prove_consistency(root_hash, tree_size, submitted_old_size, &object_bucket)
                .await
                .map_err(proof_error)?;
        let body =
            serialize_add_checkpoint_request(submitted_old_size, &consistency_proof, checkpoint)
                .map_err(|error| error.to_string())?;
        let (status, bytes) =
            post_mirror_response(prefix, "add-checkpoint", "text/plain; charset=utf-8", body)
                .await?;
        if add_checkpoint_succeeded(status, &bytes, tree_size) {
            return Ok(submitted_old_size);
        }
        if attempt == 0
            && let Some(mirror_size) =
                checkpoint_reconciliation_size(status, &bytes, submitted_old_size, tree_size)
        {
            submitted_old_size = mirror_size;
            continue;
        }
        return Err(format!(
            "mirror add-checkpoint returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        )
        .into());
    }
    unreachable!()
}

fn add_checkpoint_succeeded(status: u16, body: &[u8], tree_size: u64) -> bool {
    status == 200 || status == 409 && parse_tlog_size(body) == Some(tree_size)
}

fn checkpoint_reconciliation_size(
    status: u16,
    body: &[u8],
    submitted_old_size: u64,
    tree_size: u64,
) -> Option<u64> {
    let mirror_size = (status == 409).then(|| parse_tlog_size(body)).flatten()?;
    (mirror_size < tree_size && mirror_size != submitted_old_size).then_some(mirror_size)
}

fn parse_tlog_size(body: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(body).ok()?.strip_suffix('\n')?;
    if text.is_empty()
        || text.len() > 1 && text.starts_with('0')
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
}

async fn post_mirror_response(
    prefix: &str,
    endpoint: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>)> {
    let headers = Headers::new();
    headers.set("content-type", content_type)?;
    let request = Request::new_with_init(
        &format!("{prefix}{endpoint}"),
        &RequestInit {
            method: Method::Post,
            headers,
            body: Some(body.into()),
            ..Default::default()
        },
    )?;
    let mut response = Fetch::Request(request).send().await?;
    let status = response.status_code();
    let bytes = response.bytes().await?;
    Ok((status, bytes))
}

fn require_signature<'a>(
    signatures: &'a [signed_note::NoteSignature],
    verifier: &SubtreeV1NoteVerifier,
) -> Result<&'a signed_note::NoteSignature> {
    signatures
        .iter()
        .find(|signature| {
            signature.name() == verifier.name() && signature.id() == verifier.key_id()
        })
        .ok_or_else(|| "mirror response omitted its configured signature".into())
}

fn proof_error(error: ProofError) -> Error {
    match error {
        ProofError::Tlog(error) => error.to_string().into(),
        ProofError::Other(error) => error.to_string().into(),
    }
}

async fn mirror_subtree_signatures(
    mirrors: &[MirrorSession],
    origin: &str,
    subtree: &Subtree,
    hash: &Hash,
    consistency_proof: &[Hash],
) -> Result<Vec<CachedSubtreeSignature>> {
    let mut signatures = Vec::with_capacity(mirrors.len());
    for mirror in mirrors {
        let body = serialize_sign_subtree_request(
            subtree.lo(),
            subtree.hi(),
            hash,
            &[],
            consistency_proof,
            &mirror.checkpoint,
        )
        .map_err(|error| error.to_string())?;
        let response = post_mirror(
            &mirror.submission_url,
            "sign-subtree",
            "text/plain; charset=utf-8",
            &body,
        )
        .await?;
        let response = parse_sign_subtree_response(&response).map_err(|error| error.to_string())?;
        let signature = require_signature(&response, &mirror.verifier)?;
        if !mirror
            .verifier
            .verify_subtree(origin, subtree, hash, signature.signature())
        {
            return Err(
                format!("mirror {} returned an invalid subtree signature", mirror.id).into(),
            );
        }
        signatures.push(CachedSubtreeSignature {
            cosigner_id: mirror.id.to_string(),
            signature: signature.signature().to_vec(),
        });
    }
    Ok(signatures)
}

async fn put_landmark_sequence(bucket: &Bucket, sequence: &LandmarkSequence) -> Result<()> {
    bucket
        .put(
            LANDMARK_KEY,
            sequence.to_bytes().map_err(|e| e.to_string())?,
        )
        .http_metadata(HttpMetadata {
            content_type: Some("text/plain; charset=utf-8".to_owned()),
            ..Default::default()
        })
        .execute()
        .await?;
    Ok(())
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
    ca_id: &TrustAnchorID,
    log_number: u16,
    sk: &ietf_mtc_api::MtcSigningKey,
    vk: &ietf_mtc_api::MtcVerifyingKey,
    mirrors: &[MirrorSession],
    bucket: &Bucket,
) -> Result<()> {
    if old_tree_size >= new_tree_size {
        return Ok(());
    }
    let cosigner = ietf_mtc_api::MtcCosigner::new_checkpoint(
        ca_id.clone(),
        ca_id,
        log_number,
        sk.clone(),
        vk.clone(),
    )
    .map_err(|e| e.to_string())?;
    let origin = cosigner.log_id().oid_name();
    let object_bucket = CachedRoObjectBucket::new(ObjectBucket::new(bucket.clone()));
    let (left, right) =
        Subtree::split_interval(old_tree_size, new_tree_size).map_err(|e| e.to_string())?;
    for subtree in [left, right]
        .into_iter()
        .filter(|subtree| subtree.lo() < subtree.hi())
    {
        // Compute the actual subtree root hash from the checkpoint tiles.
        let (consistency_proof, subtree_hash) = match prove_subtree_consistency(
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
        let mut signatures = vec![CachedSubtreeSignature {
            signature: sig,
            cosigner_id: ca_id.to_string(),
        }];
        signatures.extend(
            mirror_subtree_signatures(
                mirrors,
                &origin,
                &subtree,
                &subtree_hash,
                &consistency_proof,
            )
            .await?,
        );
        let signed = SignedSubtree {
            lo: subtree.lo(),
            hi: subtree.hi(),
            hash: subtree_hash.0,
            checkpoint_hash: checkpoint_hash.0,
            checkpoint_size,
            signatures,
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
    ca_id: &TrustAnchorID,
    log_number: u16,
    sk: &ietf_mtc_api::MtcSigningKey,
    vk: &ietf_mtc_api::MtcVerifyingKey,
    mirrors: &[MirrorSession],
    landmark_subtrees: &[SubtreeWithConsistencyProof],
    bucket: &Bucket,
) -> Result<()> {
    let cosigner = ietf_mtc_api::MtcCosigner::new_checkpoint(
        ca_id.clone(),
        ca_id,
        log_number,
        sk.clone(),
        vk.clone(),
    )
    .map_err(|e| e.to_string())?;
    let origin = cosigner.log_id().oid_name();
    for (subtree, proof) in seq.subtrees().zip(landmark_subtrees.iter()) {
        let subtree_hash = Hash(proof.hash);
        let sig = cosigner
            .sign_subtree(subtree.lo(), subtree.hi(), &subtree_hash)
            .map_err(|e| e.to_string())?;
        let mut signatures = vec![CachedSubtreeSignature {
            signature: sig,
            cosigner_id: ca_id.to_string(),
        }];
        let consistency_proof = proof
            .consistency_proof
            .iter()
            .copied()
            .map(Hash)
            .collect::<Vec<_>>();
        signatures.extend(
            mirror_subtree_signatures(
                mirrors,
                &origin,
                &subtree,
                &subtree_hash,
                &consistency_proof,
            )
            .await?,
        );
        let signed = SignedSubtree {
            lo: subtree.lo(),
            hi: subtree.hi(),
            hash: proof.hash,
            checkpoint_hash: checkpoint_hash.0,
            checkpoint_size,
            signatures,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_checkpoint_accepts_completed_retry() {
        assert!(add_checkpoint_succeeded(200, b"", 7));
        assert!(add_checkpoint_succeeded(409, b"7\n", 7));
        assert!(!add_checkpoint_succeeded(409, b"7\n", 8));
        assert!(!add_checkpoint_succeeded(409, b"07\n", 7));
        assert!(!add_checkpoint_succeeded(409, b"7", 7));
    }

    #[test]
    fn add_checkpoint_reconciles_behind_mirror() {
        assert_eq!(
            checkpoint_reconciliation_size(409, b"0\n", 256, 600),
            Some(0)
        );
        assert_eq!(
            checkpoint_reconciliation_size(409, b"128\n", 256, 600),
            Some(128)
        );
        assert_eq!(
            checkpoint_reconciliation_size(409, b"256\n", 256, 600),
            None
        );
        assert_eq!(
            checkpoint_reconciliation_size(409, b"600\n", 256, 600),
            None
        );
        assert_eq!(checkpoint_reconciliation_size(200, b"0\n", 256, 600), None);
    }

    #[test]
    fn mirror_upload_resumes_with_ticket() {
        let body = MirrorInfo {
            tree_size: 7,
            next_entry: 4,
            ticket: vec![1, 2, 3],
        }
        .to_body();

        assert_eq!(
            mirror_upload_progress(202, &body, 4, 7).unwrap(),
            (4, vec![1, 2, 3])
        );
        assert_eq!(
            mirror_upload_progress(409, &body, 4, 7).unwrap(),
            (4, vec![1, 2, 3])
        );
    }

    #[test]
    fn mirror_upload_rejects_invalid_progress() {
        let body = |tree_size, next_entry| {
            MirrorInfo {
                tree_size,
                next_entry,
                ticket: Vec::new(),
            }
            .to_body()
        };

        assert!(mirror_upload_progress(202, &body(8, 4), 4, 7).is_err());
        assert!(mirror_upload_progress(202, &body(7, 3), 4, 7).is_err());
        assert!(mirror_upload_progress(202, &body(7, 8), 4, 7).is_err());
        assert!(mirror_upload_progress(202, b"invalid", 4, 7).is_err());
    }

    #[test]
    fn upload_continues_with_returned_tickets() {
        let mirror_info = |next_entry, ticket| {
            MirrorInfo {
                tree_size: 600,
                next_entry,
                ticket,
            }
            .to_body()
        };
        let mut responses = VecDeque::from([
            (202, mirror_info(256, vec![1])),
            (202, mirror_info(512, vec![2])),
            (200, b"signature".to_vec()),
        ]);
        let mut requests = Vec::new();

        let response =
            futures_executor::block_on(continue_upload(0, 600, |upload_start, ticket| {
                requests.push((upload_start, ticket));
                std::future::ready(Ok(responses.pop_front().unwrap()))
            }))
            .unwrap();

        assert_eq!(response, b"signature");
        assert_eq!(requests, vec![(0, vec![]), (256, vec![1]), (512, vec![2])]);
    }

    #[test]
    fn upload_resynchronizes_to_mirror_frontier() {
        let mirror_info = |next_entry, ticket| {
            MirrorInfo {
                tree_size: 600,
                next_entry,
                ticket,
            }
            .to_body()
        };
        let mut responses = VecDeque::from([
            (409, mirror_info(0, vec![9])),
            (202, mirror_info(256, vec![1])),
            (202, mirror_info(512, vec![2])),
            (200, b"signature".to_vec()),
        ]);
        let mut requests = Vec::new();

        let response =
            futures_executor::block_on(continue_upload(256, 600, |upload_start, ticket| {
                requests.push((upload_start, ticket));
                std::future::ready(Ok(responses.pop_front().unwrap()))
            }))
            .unwrap();

        assert_eq!(response, b"signature");
        assert_eq!(
            requests,
            vec![(256, vec![]), (0, vec![9]), (256, vec![1]), (512, vec![2])]
        );
    }

    #[test]
    fn upload_rejects_terminal_202() {
        let body = MirrorInfo {
            tree_size: 600,
            next_entry: 600,
            ticket: vec![1],
        }
        .to_body();

        let result = futures_executor::block_on(continue_upload(600, 600, |_, _| {
            std::future::ready(Ok((202, body.clone())))
        }));

        assert!(result.is_err());
    }
}
