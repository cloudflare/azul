// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Entrypoint for the static CT submission APIs.

use crate::{
    load_checkpoint_cosigner, load_origin, load_roots, BootstrapMtcSequenceMetadata, CONFIG,
};
use bootstrap_mtc_api::{
    serialize_signatureless_cert, AddEntryRequest, AddEntryResponse, BootstrapMtcLogEntry,
    GetRootsResponse, LandmarkSequence, ID_RDNA_TRUSTANCHOR_ID, LANDMARK_BUNDLE_KEY, LANDMARK_KEY,
};
use der::{
    asn1::{UtcTime, Utf8StringRef},
    Any, Encode, Tag,
};
use generic_log_worker::{
    batcher_id_from_lookup_key, deserialize, get_durable_object_stub, init_logging,
    load_public_bucket,
    log_ops::{prove_subtree_inclusion, read_leaf, ProofError, CHECKPOINT_KEY},
    obs::Wshim,
    serialize,
    util::{now_millis, WorkerByteStream},
    ObjectBackend, ObjectBucket, ENTRY_ENDPOINT,
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use signed_note::VerifierList;
use std::time::Duration;
use tlog_checkpoint::{open_checkpoint, CheckpointSigner, CheckpointText};
use tlog_core::LeafIndex;
use tlog_entry::{PendingLogEntry, PendingLogEntryBlob};
#[allow(clippy::wildcard_imports)]
use worker::*;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use tower_service::Service;
use x509_cert::{
    attr::AttributeTypeAndValue,
    name::{RdnSequence, RelativeDistinguishedName},
    time::{Time, Validity},
};

#[serde_as]
#[derive(Serialize)]
struct MetadataResponse<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: &'a Option<String>,
    log_id: String,
    cosigner_id: String,
    #[serde_as(as = "Base64")]
    cosigner_public_key: &'a [u8],
    submission_url: &'a str,
    monitoring_url: &'a str,
}

// POST body structure for the `/get-certificate` endpoint
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct GetCertificateRequest {
    pub leaf_index: LeafIndex,

    #[serde_as(as = "Base64")]
    pub spki_der: Vec<u8>,
}

/// GET response structure for the `/get-certificate` endpoint
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct GetCertificateResponse {
    #[serde_as(as = "Base64")]
    pub data: Vec<u8>,
    pub landmark_id: usize,
}

/// Start is the first code run when the Wasm module is loaded.
#[event(start)]
fn start() {
    init_logging(CONFIG.logging_level.as_deref());
}

/// Worker entrypoint.
///
/// # Errors
///
/// Returns an error if any unhandled internal error occurs while processing the
/// request.
#[event(fetch, respond_with_errors)]
async fn main(
    req: HttpRequest,
    env: Env,
    ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    let wshim = Wshim::from_env(&env);
    let response = Router::new()
        .route("/logs/{log}/get-roots", get(get_roots))
        .route("/logs/{log}/add-entry", post(add_entry))
        .route("/logs/{log}/get-certificate", post(get_certificate))
        .route("/logs/{log}/get-landmark-bundle", get(get_landmark_bundle))
        .route("/logs/{log}/metadata", get(metadata))
        .route("/logs/{log}/sequencer_id", get(sequencer_id))
        .route("/logs/{log}/{*key}", get(get_object))
        .with_state(env)
        .call(req)
        .await?;
    if let Ok(wshim) = wshim {
        ctx.wait_until(async move { wshim.flush(&generic_log_worker::obs::logs::LOGGER).await });
    }
    Ok(response)
}

#[derive(serde::Deserialize)]
struct PathParams<Rest> {
    log: String,
    #[serde(flatten)]
    rest: Rest,
}

#[derive(serde::Deserialize)]
struct Key {
    key: String,
}

impl<T> axum::extract::FromRequestParts<Env> for PathParams<T>
where
    T: serde::de::DeserializeOwned + Send,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Env,
    ) -> Result<Self, Self::Rejection> {
        let Path(params) = Path::<PathParams<T>>::from_request_parts(parts, state)
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

/// Result type for the route handlers: each builds a [`worker::Response`] which
/// is converted into an axum response at the boundary via the worker crate's
/// `axum` feature.
type ApiResult<T> = std::result::Result<T, AppError>;

enum AppError {
    InternalServerError(String),
    NotFound,
    BadRequest(String),
    UnknownLog,
    FailedToSerializeSignaturelessCert(bootstrap_mtc_api::MtcError),
    SubtreeInclusionProofFailed(tlog_core::TlogError),
    LeafIndexBeforeFirstActiveLandmark,
    LeafIndexNotInLog,
    RedirectToMonitorApi(&'static str),
    LeafIndexPendingLandmark { retry_after: u64 },
}

impl From<Error> for AppError {
    fn from(err: Error) -> Self {
        Self::InternalServerError(err.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::InternalServerError(msg) => {
                log::error!("Internal error: {msg}");
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error",
                )
                    .into_response()
            }
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not Found").into_response(),
            Self::BadRequest(e) => (
                StatusCode::BAD_REQUEST,
                format!("Bad request{}{e}", if e.is_empty() { "" } else { ": " }),
            )
                .into_response(),
            Self::UnknownLog => {
                (axum::http::StatusCode::BAD_REQUEST, "Unknown log").into_response()
            }
            Self::FailedToSerializeSignaturelessCert(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Failed to serialize signatureless cert: {e}"),
            )
                .into_response(),
            Self::SubtreeInclusionProofFailed(e) => {
                (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response()
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
            Self::RedirectToMonitorApi(url) => (
                StatusCode::NOT_FOUND,
                format!("Use {url} for monitoring API"),
            )
                .into_response(),
        }
    }
}

/// `GET /logs/{log}/get-roots`
#[worker::send]
async fn get_roots(
    State(env): State<Env>,
    PathParams { log, .. }: PathParams<()>,
) -> ApiResult<impl IntoResponse> {
    Ok((
        StatusCode::OK,
        Json(GetRootsResponse {
            certificates: x509_util::certs_to_bytes(&load_roots(&env, &log).await?.certs).unwrap(),
        }),
    ))
}

/// `POST /logs/{log}/add-entry`
#[worker::send]
async fn add_entry(
    State(env): State<Env>,
    PathParams { log, .. }: PathParams<()>,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let params = &CONFIG.logs[&log];
    let req: AddEntryRequest =
        serde_json::from_slice(&body).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let issuer = build_issuer_rdn(&params.log_id).map_err(AppError::BadRequest)?;
    let mut validity = build_validity(now_millis(), params.max_certificate_lifetime_secs as u64)
        .map_err(AppError::BadRequest)?;

    let roots = load_roots(&env, &log).await?;
    let (pending_entry, found_root_idx) =
        match bootstrap_mtc_api::validate_chain(&req.chain, roots, &issuer, &mut validity) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("{log}: Bad request: {e}");
                return Err(AppError::BadRequest(String::new()));
            }
        };

    // SCT validation (if enabled for this log shard)
    if params.enable_sct_validation {
        use crate::ct_logs_cron::load_ct_logs;
        use sct_validator::{SctValidationResult, SctValidator};

        // Load the CT log list from KV
        let ct_logs = load_ct_logs(&env).await?;
        let validator = SctValidator::new(ct_logs);

        // Get leaf and issuer DER for SCT validation
        let leaf_der = req
            .chain
            .first()
            .ok_or_else(|| AppError::BadRequest("Chain is empty".into()))?;
        let issuer_der = resolve_issuer_for_sct(&req.chain, roots).map_err(AppError::BadRequest)?;

        let validation_time_secs = now_millis() / 1000;

        match validator.validate_embedded_scts(leaf_der, &issuer_der, validation_time_secs) {
            Ok(SctValidationResult::Valid) => {
                log::info!("{log}: SCT validation passed");
            }
            Ok(SctValidationResult::ValidWithWarnings(warnings)) => {
                log::info!(
                    "{log}: SCT validation passed with {} warnings",
                    warnings.len()
                );
                for warning in &warnings {
                    log::debug!("{log}: SCT warning: {warning:?}");
                }
            }
            Ok(SctValidationResult::StaleLogList) => {
                log::warn!("{log}: SCT validation skipped (stale log list)");
            }
            Err(e) => {
                log::warn!("{log}: SCT validation failed: {e}");
                return Err(AppError::BadRequest(format!("SCT validation failed: {e}")));
            }
        }
    }

    // Retrieve the sequenced entry for this pending log entry by sending a request to the DO to
    // sequence the entry.
    let lookup_key = pending_entry.lookup_key();

    // First persist issuers. Use a block so memory is deallocated sooner.
    {
        let public_bucket = ObjectBucket::new(load_public_bucket(&env, &log)?);
        let mut issuers = req.chain[1..]
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<&[u8]>>();

        // Make sure the found root is persisted as well, if the add-chain
        // request did not include the root.
        let root_bytes;
        if let Some(idx) = found_root_idx {
            root_bytes = roots.certs[idx]
                .to_der()
                .map_err(|e| AppError::BadRequest(e.to_string()))?;
            issuers.push(&root_bytes);
        }

        generic_log_worker::upload_issuers(&public_bucket, &issuers, &log).await?;
    }

    // Submit entry to be sequenced, either via a batcher or directly to the
    // sequencer.
    let stub = {
        let shard_id = batcher_id_from_lookup_key(&lookup_key, params.num_batchers);
        get_durable_object_stub(
            &env,
            &log,
            shard_id,
            if shard_id.is_some() {
                "BATCHER"
            } else {
                "SEQUENCER"
            },
            params.location_hint.as_deref(),
        )?
    };
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
        // Return the response from the sequencing directly to the client.
        return Ok(response.into());
    }
    let metadata = deserialize::<BootstrapMtcSequenceMetadata>(&response.bytes().await?)?;
    Ok((
        StatusCode::OK,
        Json(AddEntryResponse {
            leaf_index: metadata.leaf_index(),
            timestamp: metadata.timestamp(),
            not_before: validity.not_before.to_unix_duration().as_secs(),
            not_after: validity.not_after.to_unix_duration().as_secs(),
        }),
    )
        .into_response())
}

/// `POST /logs/{log}/get-certificate`
#[worker::send]
async fn get_certificate(
    State(env): State<Env>,
    PathParams { log, .. }: PathParams<()>,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let params = &CONFIG.logs[&log];
    let Ok(GetCertificateRequest {
        leaf_index,
        spki_der,
    }) = serde_json::from_slice(&body)
    else {
        return Err(AppError::BadRequest("Unexpected input".into()));
    };
    let object_backend = ObjectBucket::new(load_public_bucket(&env, &log)?);
    // Fetch the current checkpoint to know which tiles to fetch
    // (full or partials).
    let (checkpoint, _checkpoint_bytes) =
        get_current_checkpoint(&env, &log, &object_backend).await?;
    if leaf_index >= checkpoint.size() {
        return Err(AppError::LeafIndexNotInLog);
    }

    let seq = get_landmark_sequence(&log, &object_backend).await?;
    if leaf_index < seq.first_index() {
        return Err(AppError::LeafIndexBeforeFirstActiveLandmark);
    }
    let Some((landmark_id, landmark_subtree)) = seq.subtree_for_index(leaf_index) else {
        // The leaf index might be between the latest landmark and the current
        // tree size. Set Retry-After to the expected time for the next landmark
        // so the client can try again later.
        let i = params.landmark_interval_secs as u64;
        return Err(AppError::LeafIndexPendingLandmark {
            retry_after: i - (now_millis() / 1000) % i,
        });
    };

    // Fetch the log entry for the leaf index.
    let log_entry = read_leaf::<BootstrapMtcLogEntry>(
        &object_backend,
        leaf_index,
        checkpoint.size(),
        checkpoint.hash(),
    )
    .await
    .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Get the inclusion proof.
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
        Ok(p) => p,
        Err(ProofError::Tlog(s)) => return Err(AppError::SubtreeInclusionProofFailed(s)),
        Err(ProofError::Other(e)) => return Err(AppError::BadRequest(e.to_string())),
    };

    // Construct the signatureless certificate.
    let data = match serialize_signatureless_cert(
        &log_entry,
        leaf_index,
        &spki_der,
        &landmark_subtree,
        proof,
    ) {
        Ok(data) => data,
        Err(e) => return Err(AppError::FailedToSerializeSignaturelessCert(e)),
    };

    Ok((
        StatusCode::OK,
        Json(GetCertificateResponse { data, landmark_id }),
    ))
}

/// `GET /logs/{log}/get-landmark-bundle`
#[worker::send]
async fn get_landmark_bundle(
    State(env): State<Env>,
    PathParams { log, .. }: PathParams<()>,
) -> ApiResult<impl IntoResponse> {
    let object_backend = ObjectBucket::new(load_public_bucket(&env, &log)?);

    // Fetch the current landmark bundle from R2 (already encoded in JSON) and return it
    let Some(landmark_bundle_bytes) = object_backend.fetch(LANDMARK_BUNDLE_KEY).await? else {
        return Err(AppError::InternalServerError(
            "failed to get landmark bundle".into(),
        ));
    };

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        landmark_bundle_bytes,
    ))
}

/// `GET /logs/{log}/metadata`
#[worker::send]
async fn metadata(
    State(env): State<Env>,
    PathParams { log, .. }: PathParams<()>,
) -> ApiResult<impl IntoResponse> {
    let params = &CONFIG.logs[&log];
    let cosigner = load_checkpoint_cosigner(&env, &log);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&MetadataResponse {
            description: &params.description,
            log_id: cosigner.log_id().to_string(),
            cosigner_id: cosigner.cosigner_id().to_string(),
            cosigner_public_key: cosigner.verifying_key(),
            submission_url: &params.submission_url,
            monitoring_url: if params.monitoring_url.is_empty() {
                &params.submission_url
            } else {
                &params.monitoring_url
            },
        })
        .unwrap(),
    ))
}

/// `GET /logs/{log}/sequencer_id`
#[worker::send]
async fn sequencer_id(
    State(env): State<Env>,
    PathParams { log, .. }: PathParams<()>,
) -> ApiResult<impl IntoResponse> {
    // Print out the Durable Object ID of the sequencer to allow looking it up
    // in internal Cloudflare dashboards. This value does not need to be secret.
    let namespace = env.durable_object("SEQUENCER")?;
    let object_id = namespace.id_from_name(&log)?;
    Ok((StatusCode::OK, object_id.to_string()))
}

/// `GET /logs/{log}/{*key}` — direct read-through to the public R2 bucket when
/// the log's `monitoring_url` is unspecified.
#[worker::send]
async fn get_object(
    State(env): State<Env>,
    PathParams {
        log,
        rest: Key { key },
    }: PathParams<Key>,
) -> ApiResult<impl IntoResponse> {
    // Enable direct access to the bucket via the Worker if monitoring_url is
    // unspecified.
    if CONFIG.logs[&log].monitoring_url.is_empty() {
        let bucket = load_public_bucket(&env, &log)?;
        if let Some(obj) = bucket.get(key).execute().await? {
            let body = obj
                .body()
                .ok_or_else(|| AppError::InternalServerError("R2 object missing body".into()))?
                .stream()?;
            Ok((
                StatusCode::OK,
                headers_from_http_metadata(obj.http_metadata()),
                axum::body::Body::from_stream(WorkerByteStream::new(body)),
            ))
        } else {
            Err(AppError::NotFound)
        }
    } else {
        // TODO: should this be an HTTP redirect instead of a 404?
        Err(AppError::RedirectToMonitorApi(
            &CONFIG.logs[&log].monitoring_url,
        ))
    }
}

/// Builds the issuer RDN with the trust anchor ID.
fn build_issuer_rdn(log_id: &str) -> std::result::Result<RdnSequence, String> {
    let utf8_value = Utf8StringRef::new(log_id).map_err(|e| e.to_string())?;
    let any_value = Any::new(Tag::Utf8String, utf8_value.as_bytes()).map_err(|e| e.to_string())?;

    let attr = AttributeTypeAndValue {
        oid: ID_RDNA_TRUSTANCHOR_ID,
        value: any_value,
    };

    let rdn = RelativeDistinguishedName::try_from(vec![attr])
        .expect("single attribute should always succeed");

    Ok(RdnSequence::from(vec![rdn]))
}

fn build_validity(
    now_millis: u64,
    max_lifetime_secs: u64,
) -> std::result::Result<Validity, String> {
    let now = Duration::from_millis(now_millis);
    let not_before = UtcTime::from_unix_duration(now).map_err(|e| e.to_string())?;
    let not_after = UtcTime::from_unix_duration(now + Duration::from_secs(max_lifetime_secs))
        .map_err(|e| e.to_string())?;

    Ok(Validity::new(
        Time::UtcTime(not_before),
        Time::UtcTime(not_after),
    ))
}

/// Returns the issuer cert for SCT validation. For multi-cert chains, that's
/// chain[1]. For single-cert chains, we look it up from the roots pool.
fn resolve_issuer_for_sct(
    chain: &[Vec<u8>],
    roots: &x509_util::CertPool,
) -> std::result::Result<Vec<u8>, String> {
    use der::{Decode, Encode};
    use x509_cert::Certificate;

    if chain.is_empty() {
        return Err("chain is empty".into());
    }

    if chain.len() > 1 {
        return Ok(chain[1].clone());
    }

    // Single-cert chain: look up issuer from roots pool
    let leaf =
        Certificate::from_der(&chain[0]).map_err(|e| format!("failed to parse leaf: {e}"))?;
    let issuer_dn = leaf.tbs_certificate().issuer();

    roots
        .find_by_subject(issuer_dn)
        .ok_or_else(|| format!("issuer not found in roots pool: {issuer_dn}"))?
        .to_der()
        .map_err(|e| format!("failed to encode issuer: {e}"))
}

async fn get_current_checkpoint(
    env: &Env,
    name: &str,
    object_backend: &ObjectBucket,
) -> Result<(CheckpointText, Vec<u8>)> {
    let checkpoint_bytes = object_backend
        .fetch(CHECKPOINT_KEY)
        .await?
        .ok_or("no checkpoint in object storage".to_string())?;

    let origin = &load_origin(name);
    let verifiers = &VerifierList::new(vec![load_checkpoint_cosigner(env, name).verifier()]);
    let (checkpoint, _timestamp) =
        open_checkpoint(origin.as_str(), verifiers, now_millis(), &checkpoint_bytes)
            .map_err(|e| e.to_string())?;
    Ok((checkpoint, checkpoint_bytes))
}

async fn get_landmark_sequence(
    name: &str,
    object_backend: &ObjectBucket,
) -> Result<LandmarkSequence> {
    let params = &CONFIG.logs[name];

    let Some(landmark_sequence_bytes) = object_backend.fetch(LANDMARK_KEY).await? else {
        return Err("failed to get landmark sequence".into());
    };

    let landmark_sequence =
        LandmarkSequence::from_bytes(&landmark_sequence_bytes, params.max_active_landmarks())
            .map_err(|e| e.to_string())?;

    Ok(landmark_sequence)
}

fn headers_from_http_metadata(meta: HttpMetadata) -> HeaderMap {
    let mut h = HeaderMap::new();
    if let Some(hdr) = meta.cache_control {
        h.append("Cache-Control", hdr.try_into().unwrap());
    }
    if let Some(hdr) = meta.content_encoding {
        h.append("Content-Encoding", hdr.try_into().unwrap());
    }
    if let Some(hdr) = meta.content_type {
        h.append("Content-Type", hdr.try_into().unwrap());
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    #[test]
    fn test_build_issuer_rdn() {
        let rdn = build_issuer_rdn("test-log-id").unwrap();
        assert_eq!(rdn.as_ref().len(), 1);

        let attr = rdn.as_ref()[0].as_ref().iter().next().unwrap();
        assert_eq!(attr.oid, ID_RDNA_TRUSTANCHOR_ID);

        let encoded = attr.value.to_der().unwrap();
        assert_eq!(encoded[0], 0x0C); // UTF8String tag
    }

    #[test]
    fn test_build_validity() {
        let now_ms = 1_700_000_000_000_u64; // Nov 2023
        let lifetime_secs = 86400_u64; // 1 day

        let validity = build_validity(now_ms, lifetime_secs).unwrap();

        assert_eq!(
            validity.not_before.to_unix_duration().as_secs(),
            now_ms / 1000
        );
        assert_eq!(
            validity.not_after.to_unix_duration().as_secs(),
            now_ms / 1000 + lifetime_secs
        );
    }

    #[test]
    fn test_resolve_issuer_empty_chain() {
        let chain: Vec<Vec<u8>> = vec![];
        let roots = x509_util::CertPool::new(vec![]).unwrap();
        assert!(resolve_issuer_for_sct(&chain, &roots).is_err());
    }

    #[test]
    fn test_resolve_issuer_multi_cert_chain() {
        let leaf = vec![1, 2, 3];
        let issuer = vec![4, 5, 6];
        let chain = vec![leaf, issuer.clone()];
        let roots = x509_util::CertPool::new(vec![]).unwrap();

        assert_eq!(resolve_issuer_for_sct(&chain, &roots).unwrap(), issuer);
    }

    #[test]
    fn test_resolve_issuer_invalid_der() {
        let chain = vec![vec![0xFF, 0xFF, 0xFF]];
        let roots = x509_util::CertPool::new(vec![]).unwrap();
        assert!(resolve_issuer_for_sct(&chain, &roots).is_err());
    }
}
