// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Entrypoint for the IETF MTC interoperability APIs.

use crate::{
    CONFIG, IetfMtcSequenceMetadata, SignedSubtree, init_sentry, load_checkpoint_cosigner,
    load_origin, subtree_sig_key,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{StatusCode, header},
    middleware,
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
};
use der::{Decode, asn1::UtcTime};
use generic_log_worker::{
    ENTRY_ENDPOINT, ObjectBackend, ObjectBucket, batcher_id_from_lookup_key, deserialize,
    frontend::request_metrics,
    get_durable_object_stub, init_logging, load_public_bucket,
    log_ops::{CHECKPOINT_KEY, ProofError, prove_subtree_inclusion, read_leaf},
    obs::{Wshim, metrics},
    serialize,
    util::now_millis,
};
use ietf_mtc_api::{
    AddEntryRequest, AddEntryResponse, IetfMtcLogEntry, LANDMARK_BUNDLE_KEY, LANDMARK_KEY,
    LandmarkSequence, TrustAnchorID, UINT48_MAX, build_pending_entry, serialize_mtc_cert,
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use signed_note::VerifierList;
use std::{str::FromStr, time::Duration};
use tlog_checkpoint::{CheckpointSigner, CheckpointText, open_checkpoint};
use tlog_core::{LeafIndex, Subtree};
use tlog_entry::{PendingLogEntry, PendingLogEntryBlob};
use tower_service::Service;
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_cert::{
    name::RdnSequence,
    time::{Time, Validity},
};

#[serde_as]
#[derive(Serialize)]
struct MetadataResponse<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: &'a Option<String>,
    ca_id: &'a str,
    log_number: u16,
    log_id: String,
    cosigner_id: String,
    #[serde_as(as = "Base64")]
    cosigner_public_key: Vec<u8>,
    submission_url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    monitoring_url: Option<&'a str>,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct GetCertificateRequest {
    pub leaf_index: LeafIndex,
    #[serde_as(as = "Base64")]
    pub spki_der: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct GetCertificateResponse {
    #[serde_as(as = "Base64")]
    pub data: Vec<u8>,
    pub landmark_id: usize,
}

#[event(start)]
fn start() {
    init_logging(CONFIG.logging_level.as_deref());
}

#[event(fetch, respond_with_errors)]
async fn main(
    req: HttpRequest,
    env: Env,
    ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    init_sentry(&env);
    let wshim = Wshim::from_env(&env);
    let registry = metrics::registry();
    let response = generic_log_worker::obs::sentry::catch_unwind_and_flush(async {
        Router::new()
            .route("/logs/{log}/add-entry", post(add_entry))
            .route("/logs/{log}/get-certificate", post(get_certificate))
            .route("/logs/{log}/get-landmark-bundle", get(get_landmark_bundle))
            .route("/logs/{log}/landmark", get(get_landmark))
            .route("/logs/{log}/metadata", get(metadata))
            .route("/logs/{log}/sequencer_id", get(sequencer_id))
            .layer(middleware::from_fn_with_state(
                (env.clone(), metrics::FrontendWorkerMetrics::new(&registry)),
                request_metrics,
            ))
            .with_state(env)
            .call(req)
            .await
    })
    .await?;
    generic_log_worker::obs::sentry::flush().await;
    if let Ok(wshim) = wshim {
        ctx.wait_until(async move {
            wshim.flush(&generic_log_worker::obs::logs::LOGGER).await;
            wshim.flush(&registry).await;
        });
    }
    Ok(response)
}

#[derive(Deserialize)]
struct PathParams {
    log: String,
}

impl axum::extract::FromRequestParts<Env> for PathParams {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Env,
    ) -> Result<Self, Self::Rejection> {
        let Path(params) = Path::<PathParams>::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                AppError::InternalServerError("path param does not have log field".into())
            })?;
        if CONFIG.logs.contains_key(&params.log) {
            Ok(params)
        } else {
            Err(AppError::UnknownLog)
        }
    }
}

type ApiResult<T> = std::result::Result<T, AppError>;

enum AppError {
    InternalServerError(String),
    BadRequest(String),
    UnknownLog,
    FailedToSerializeCertificate(ietf_mtc_api::MtcError),
    SubtreeInclusionProofFailed(tlog_core::TlogError),
    LeafIndexBeforeFirstActiveLandmark,
    LeafIndexNotInLog,
    LeafIndexPendingLandmark { retry_after: u64 },
    SubtreeSignaturePending,
    LogFull,
}

impl From<Error> for AppError {
    fn from(err: Error) -> Self {
        Self::InternalServerError(err.to_string())
    }
}

impl From<String> for AppError {
    fn from(msg: String) -> Self {
        Self::InternalServerError(msg)
    }
}

impl From<&str> for AppError {
    fn from(msg: &str) -> Self {
        Self::InternalServerError(msg.to_owned())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::InternalServerError(msg) => {
                log::error!("Internal error: {msg}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
            }
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            Self::UnknownLog => (StatusCode::BAD_REQUEST, "Unknown log").into_response(),
            Self::FailedToSerializeCertificate(error) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Failed to serialize MTC certificate: {error}"),
            )
                .into_response(),
            Self::SubtreeInclusionProofFailed(error) => {
                (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response()
            }
            Self::LeafIndexBeforeFirstActiveLandmark => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Leaf index is before first active landmark",
            )
                .into_response(),
            Self::LeafIndexNotInLog => {
                (StatusCode::UNPROCESSABLE_ENTITY, "Leaf index is not in log").into_response()
            }
            Self::LeafIndexPendingLandmark { retry_after } => (
                StatusCode::SERVICE_UNAVAILABLE,
                AppendHeaders([(header::RETRY_AFTER, retry_after.to_string())]),
                "Leaf index will be covered by next landmark",
            )
                .into_response(),
            Self::SubtreeSignaturePending => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Service unavailable: subtree signature not yet available",
            )
                .into_response(),
            Self::LogFull => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Service unavailable: log has reached its maximum tree size",
            )
                .into_response(),
        }
    }
}

#[worker::send]
/// Unauthenticated interoperability endpoint. This does not implement ACME
/// authorization or production certificate issuance policy.
async fn add_entry(
    State(env): State<Env>,
    PathParams { log }: PathParams,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let params = &CONFIG.logs[&log];
    let req: AddEntryRequest =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    ensure_log_has_capacity(&env, &log).await?;
    let issuer = build_issuer_rdn(&params.ca_id).map_err(AppError::BadRequest)?;
    let validity = build_validity(now_millis(), params.max_certificate_lifetime_secs as u64)
        .map_err(AppError::BadRequest)?;
    let pending_entry = build_pending_entry(&req, &issuer, validity).map_err(|error| {
        log::warn!("{log}: Bad request: {error}");
        AppError::BadRequest("Bad request".into())
    })?;
    let lookup_key = pending_entry.lookup_key();
    let shard_id = batcher_id_from_lookup_key(&lookup_key, params.num_batchers);
    let stub = get_durable_object_stub(
        &env,
        &log,
        shard_id,
        if shard_id.is_some() {
            "BATCHER"
        } else {
            "SEQUENCER"
        },
        params.location_hint.as_deref(),
    )?;
    let serialized = serialize(&PendingLogEntryBlob {
        lookup_key,
        data: serialize(&pending_entry)?,
    })?;
    let mut response = stub
        .fetch_with_request(Request::new_with_init(
            &format!("http://fake_url.com{ENTRY_ENDPOINT}"),
            &RequestInit {
                method: Method::Post,
                body: Some(serialized.into()),
                ..Default::default()
            },
        )?)
        .await?;
    if response.status_code() != 200 {
        return Ok(response.into());
    }
    let sequence_metadata = deserialize::<IetfMtcSequenceMetadata>(&response.bytes().await?)?;
    let Some(certificate) = build_standalone_cert(&env, &log, &sequence_metadata, &req).await
    else {
        log::warn!(
            "{log}: subtree sig not found for leaf {} after sequencing",
            sequence_metadata.leaf_index
        );
        return Err(AppError::SubtreeSignaturePending);
    };
    Ok((StatusCode::OK, Json(AddEntryResponse { certificate })).into_response())
}

#[worker::send]
async fn get_certificate(
    State(env): State<Env>,
    PathParams { log }: PathParams,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let params = &CONFIG.logs[&log];
    let GetCertificateRequest {
        leaf_index,
        spki_der,
    } = serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let object_backend = ObjectBucket::new(load_public_bucket(&env, &log)?);
    let checkpoint = get_current_checkpoint(&env, &log, &object_backend).await?;
    if leaf_index >= checkpoint.size() {
        return Err(AppError::LeafIndexNotInLog);
    }
    let Some(sequence) = get_landmark_sequence(&log, &object_backend).await? else {
        let interval = params.landmark_interval_secs as u64;
        return Err(AppError::LeafIndexPendingLandmark {
            retry_after: interval - (now_millis() / 1000) % interval,
        });
    };
    if leaf_index < sequence.first_index() {
        return Err(AppError::LeafIndexBeforeFirstActiveLandmark);
    }
    let Some((landmark_id, landmark_subtree)) = sequence.subtree_for_index(leaf_index) else {
        let interval = params.landmark_interval_secs as u64;
        return Err(AppError::LeafIndexPendingLandmark {
            retry_after: interval - (now_millis() / 1000) % interval,
        });
    };
    let log_entry = read_leaf::<IetfMtcLogEntry>(
        &object_backend,
        leaf_index,
        checkpoint.size(),
        checkpoint.hash(),
    )
    .await
    .map_err(|e| AppError::BadRequest(e.to_string()))?;
    let proof = match prove_subtree_inclusion(
        checkpoint.size(),
        *checkpoint.hash(),
        landmark_subtree.lo(),
        landmark_subtree.hi(),
        leaf_index,
        &object_backend,
    )
    .await
    {
        Ok(proof) => proof,
        Err(ProofError::Tlog(error)) => {
            return Err(AppError::SubtreeInclusionProofFailed(error));
        }
        Err(ProofError::Other(error)) => {
            return Err(AppError::InternalServerError(error.to_string()));
        }
    };
    let data = serialize_mtc_cert(
        &log_entry,
        params.log_number,
        leaf_index,
        &spki_der,
        &landmark_subtree,
        proof,
        &[],
    )
    .map_err(AppError::FailedToSerializeCertificate)?;
    Ok((
        StatusCode::OK,
        Json(GetCertificateResponse { data, landmark_id }),
    ))
}

#[worker::send]
async fn get_landmark_bundle(
    State(env): State<Env>,
    PathParams { log }: PathParams,
) -> ApiResult<impl IntoResponse> {
    let object_backend = ObjectBucket::new(load_public_bucket(&env, &log)?);
    let bytes = object_backend
        .fetch(LANDMARK_BUNDLE_KEY)
        .await?
        .ok_or_else(|| AppError::InternalServerError("failed to get landmark bundle".into()))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    ))
}

#[worker::send]
async fn get_landmark(
    State(env): State<Env>,
    PathParams { log }: PathParams,
) -> ApiResult<impl IntoResponse> {
    let object_backend = ObjectBucket::new(load_public_bucket(&env, &log)?);
    let bytes = object_backend
        .fetch(LANDMARK_KEY)
        .await?
        .ok_or_else(|| AppError::InternalServerError("failed to get landmark sequence".into()))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        bytes,
    ))
}

#[worker::send]
async fn metadata(
    State(env): State<Env>,
    PathParams { log }: PathParams,
) -> ApiResult<impl IntoResponse> {
    let params = &CONFIG.logs[&log];
    let ca_id = TrustAnchorID::from_str(&params.ca_id)
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;
    let cosigner = load_checkpoint_cosigner(&env, &log);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&MetadataResponse {
            description: &params.description,
            ca_id: &params.ca_id,
            log_number: params.log_number,
            log_id: ca_id
                .log_id(params.log_number)
                .map_err(|e| AppError::InternalServerError(e.to_string()))?
                .to_string(),
            cosigner_id: cosigner.cosigner_id().to_string(),
            cosigner_public_key: cosigner.verifying_key(),
            submission_url: &params.submission_url,
            monitoring_url: params.monitoring_url.as_deref(),
        })
        .unwrap(),
    ))
}

#[worker::send]
async fn sequencer_id(
    State(env): State<Env>,
    PathParams { log }: PathParams,
) -> ApiResult<impl IntoResponse> {
    let namespace = env.durable_object("SEQUENCER")?;
    let object_id = namespace.id_from_name(&log)?;
    Ok((StatusCode::OK, object_id.to_string()))
}

fn build_issuer_rdn(ca_id: &str) -> std::result::Result<RdnSequence, String> {
    TrustAnchorID::from_str(ca_id)
        .and_then(|id| id.to_rdn_sequence())
        .map_err(|e| e.to_string())
}

async fn ensure_log_has_capacity(env: &Env, name: &str) -> ApiResult<()> {
    let object_backend = ObjectBucket::new(load_public_bucket(env, name)?);
    let Some(checkpoint_bytes) = object_backend.fetch(CHECKPOINT_KEY).await? else {
        return Ok(());
    };
    let origin = load_origin(name);
    let verifiers = VerifierList::new(vec![load_checkpoint_cosigner(env, name).verifier()]);
    let (checkpoint, _) =
        open_checkpoint(origin.as_str(), &verifiers, now_millis(), &checkpoint_bytes)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
    if !tree_has_capacity(checkpoint.size()) {
        return Err(AppError::LogFull);
    }
    Ok(())
}

fn tree_has_capacity(tree_size: u64) -> bool {
    tree_size < UINT48_MAX
}

fn build_validity(
    now_millis: u64,
    max_lifetime_secs: u64,
) -> std::result::Result<Validity, String> {
    let now = Duration::from_millis(now_millis);
    let validity_span_secs = max_lifetime_secs
        .checked_sub(1)
        .ok_or_else(|| "maximum certificate lifetime must be at least one second".to_string())?;
    let not_before = UtcTime::from_unix_duration(now).map_err(|e| e.to_string())?;
    let not_after = UtcTime::from_unix_duration(now + Duration::from_secs(validity_span_secs))
        .map_err(|e| e.to_string())?;
    Ok(Validity::new(
        Time::UtcTime(not_before),
        Time::UtcTime(not_after),
    ))
}

const MAX_SIG_RETRIES: u32 = 6;
const SIG_RETRY_DELAY_MS: u64 = 250;

fn subtree_key_for_leaf(metadata: &IetfMtcSequenceMetadata) -> Option<String> {
    let (left, right) =
        Subtree::split_interval(metadata.old_tree_size, metadata.new_tree_size).ok()?;
    [left, right]
        .into_iter()
        .find(|subtree| subtree.contains(metadata.leaf_index))
        .map(|subtree| subtree_sig_key(subtree.lo(), subtree.hi()))
}

async fn build_standalone_cert(
    env: &Env,
    name: &str,
    metadata: &IetfMtcSequenceMetadata,
    req: &AddEntryRequest,
) -> Option<Vec<u8>> {
    let params = &CONFIG.logs[name];
    let object_bucket = ObjectBucket::new(load_public_bucket(env, name).ok()?);
    let leaf_index = metadata.leaf_index;
    let key = subtree_key_for_leaf(metadata)?;
    let mut signed = None;
    for _ in 0..MAX_SIG_RETRIES {
        if let Some(raw) = object_bucket.fetch(&key).await.ok().flatten()
            && let Ok(value) = serde_json::from_slice::<SignedSubtree>(&raw)
            && value.has_signatures_for(
                std::iter::once(params.ca_id.as_str())
                    .chain(params.cosigners.iter().map(|cosigner| cosigner.id.as_str())),
            )
        {
            signed = Some(value);
            break;
        }
        Delay::from(Duration::from_millis(SIG_RETRY_DELAY_MS)).await;
    }
    let signed = signed?;
    let subtree = signed.as_subtree().ok()?;
    let checkpoint_hash = tlog_core::Hash(signed.checkpoint_hash);
    let csr = x509_cert::request::CertReq::from_der(&req.csr).ok()?;
    let spki_der = der::Encode::to_der(&csr.info.public_key).ok()?;
    let log_entry = read_leaf::<IetfMtcLogEntry>(
        &object_bucket,
        leaf_index,
        signed.checkpoint_size,
        &checkpoint_hash,
    )
    .await
    .ok()?;
    let proof = prove_subtree_inclusion(
        signed.checkpoint_size,
        checkpoint_hash,
        subtree.lo(),
        subtree.hi(),
        leaf_index,
        &object_bucket,
    )
    .await
    .map_err(|error| {
        log::warn!("{name}: subtree inclusion proof failed for leaf {leaf_index}: {error:?}");
    })
    .ok()?;
    let signatures = signed
        .signatures
        .into_iter()
        .map(|signature| {
            Some((
                TrustAnchorID::from_str(&signature.cosigner_id).ok()?,
                signature.signature,
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    serialize_mtc_cert(
        &log_entry,
        params.log_number,
        leaf_index,
        &spki_der,
        &subtree,
        proof,
        &signatures,
    )
    .ok()
}

async fn get_current_checkpoint(
    env: &Env,
    name: &str,
    object_backend: &ObjectBucket,
) -> ApiResult<CheckpointText> {
    let checkpoint_bytes = object_backend
        .fetch(CHECKPOINT_KEY)
        .await?
        .ok_or_else(|| AppError::InternalServerError("no checkpoint in object storage".into()))?;
    let origin = load_origin(name);
    let verifiers = VerifierList::new(vec![load_checkpoint_cosigner(env, name).verifier()]);
    let (checkpoint, _) =
        open_checkpoint(origin.as_str(), &verifiers, now_millis(), &checkpoint_bytes)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
    Ok(checkpoint)
}

async fn get_landmark_sequence(
    name: &str,
    object_backend: &ObjectBucket,
) -> ApiResult<Option<LandmarkSequence>> {
    let Some(bytes) = object_backend.fetch(LANDMARK_KEY).await? else {
        return Ok(None);
    };
    LandmarkSequence::from_bytes(&bytes, CONFIG.logs[name].max_active_landmarks())
        .map(Some)
        .map_err(|e| AppError::InternalServerError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    #[test]
    fn test_build_issuer_rdn() {
        let ca_id = TrustAnchorID::from_str("44363.48.3").unwrap();
        let rdn = build_issuer_rdn(&ca_id.to_string()).unwrap();
        let attr = rdn.as_ref()[0].as_ref().iter().next().unwrap();
        assert_eq!(attr.oid, ietf_mtc_api::ID_RDNA_TRUSTANCHOR_ID);
        assert_eq!(attr.value.to_der().unwrap()[0], 0x0d);
        assert_eq!(TrustAnchorID::from_rdn_sequence(&rdn).unwrap(), ca_id);
    }

    #[test]
    fn test_build_validity_respects_inclusive_lifetime() {
        let now_ms = 1_700_000_000_500_u64;
        let lifetime_secs = 7 * 24 * 60 * 60;
        let validity = build_validity(now_ms, lifetime_secs).unwrap();
        let not_before = validity.not_before.to_unix_duration().as_secs();
        let not_after = validity.not_after.to_unix_duration().as_secs();
        assert_eq!(not_before, now_ms / 1000);
        assert_eq!(not_after - not_before + 1, lifetime_secs);
    }

    #[test]
    fn test_build_validity_rejects_zero_lifetime() {
        assert!(build_validity(1_700_000_000_000, 0).is_err());
    }

    #[test]
    fn test_uint48_tree_size_limit() {
        assert!(tree_has_capacity(UINT48_MAX - 1));
        assert!(!tree_has_capacity(UINT48_MAX));
    }
}
