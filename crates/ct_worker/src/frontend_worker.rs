// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Entrypoint for the static CT submission APIs.

use crate::{load_roots, load_signing_key, StaticCTSequenceMetadata, CONFIG};
use config::TemporalInterval;
use generic_log_worker::{
    batcher_id_from_lookup_key, deserialize,
    frontend::request_metrics,
    get_cached_metadata, get_durable_object_stub, init_logging, load_cache_kv, load_public_bucket,
    obs::{metrics, Wshim},
    put_cache_entry_metadata, serialize,
    util::WorkerByteStream,
    ObjectBucket, ENTRY_ENDPOINT,
};
use p256::pkcs8::EncodePublicKey;
use serde::Serialize;
use serde_with::{base64::Base64, serde_as};
use static_ct_api::{AddChainRequest, GetRootsResponse, StaticCTLogEntry};
use tlog_entry::{LogEntry, PendingLogEntry, PendingLogEntryBlob};
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_cert::der::Encode;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use tower_service::Service;

// The Maximum Merge Delay (MMD) of a log indicates the maximum period of time
// between when a SCT is issued and the corresponding entry is sequenced in the
// log. For Azul-based logs, this is effectively zero since SCT issuance happens
// only once the entry is sequenced. However, we can leave this value as the
// maximum allowed in Chrome's policy, 60 seconds, to allow future flexibility.
// For details, see https://github.com/C2SP/C2SP/issues/79.
const MAX_MERGE_DELAY_SECS: usize = 60;

#[serde_as]
#[derive(Serialize)]
struct LogV3JsonResponse<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_type: &'a Option<String>,
    #[serde_as(as = "Base64")]
    log_id: &'a [u8],
    #[serde_as(as = "Base64")]
    key: &'a [u8],
    mmd: usize,
    submission_url: &'a str,
    monitoring_url: &'a str,
    temporal_interval: &'a TemporalInterval,
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
    let registry = metrics::registry();
    let response = Router::new()
        .route("/logs/{log}/ct/v1/get-roots", get(get_roots))
        .route("/logs/{log}/ct/v1/add-chain", post(add_chain))
        .route("/logs/{log}/ct/v1/add-pre-chain", post(add_pre_chain))
        .route("/logs/{log}/log.v3.json", get(log_v3_json))
        .route("/logs/{log}/sequencer_id", get(sequencer_id))
        .route("/logs/{log}/{*key}", get(get_object))
        .layer(middleware::from_fn_with_state(
            (env.clone(), metrics::FrontendWorkerMetrics::new(&registry)),
            request_metrics,
        ))
        .with_state(env)
        .call(req)
        .await?;
    if let Ok(wshim) = wshim {
        ctx.wait_until(async move {
            wshim.flush(&generic_log_worker::obs::logs::LOGGER).await;
            wshim.flush(&registry).await;
        });
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
    ReadonlyLog,
    RedirectToMonitorApi(&'static str),
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
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error",
                )
                    .into_response()
            }
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not Found").into_response(),
            Self::BadRequest(e) => {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Bad request{}{e}", if e.is_empty() { "" } else { ": " })
                ).into_response()
            }
            Self::UnknownLog => {
                (StatusCode::BAD_REQUEST, "Unknown log").into_response()
            }
            Self::ReadonlyLog => {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "300")],
                    "The log is temporarily in read-only mode during maintenance. Please try again after 5 minutes."
                ).into_response()
            }
            Self::RedirectToMonitorApi(url) => (
                StatusCode::NOT_FOUND,
                format!("Use {url} for monitoring API"),
            )
                .into_response(),
        }
    }
}

/// `GET /logs/{log}/ct/v1/get-roots`
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

/// `POST /logs/{log}/ct/v1/add-chain`
#[worker::send]
async fn add_chain(
    State(env): State<Env>,
    PathParams { log, .. }: PathParams<()>,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    add_chain_or_pre_chain(body, &env, &log, false).await
}

/// `POST /logs/{log}/ct/v1/add-pre-chain`
#[worker::send]
async fn add_pre_chain(
    State(env): State<Env>,
    PathParams { log, .. }: PathParams<()>,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    add_chain_or_pre_chain(body, &env, &log, true).await
}

/// `GET /logs/{log}/log.v3.json`
#[worker::send]
async fn log_v3_json(
    State(env): State<Env>,
    PathParams { log, .. }: PathParams<()>,
) -> ApiResult<impl IntoResponse> {
    let params = &CONFIG.logs[&log];
    let verifying_key = load_signing_key(&env, &log)?.verifying_key();
    let log_id = &static_ct_api::log_id_from_key(verifying_key).map_err(|e| e.to_string())?;
    let key = verifying_key
        .to_public_key_der()
        .map_err(|e| e.to_string())?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&LogV3JsonResponse {
            description: &params.description,
            log_type: &params.log_type,
            log_id,
            key: key.as_bytes(),
            submission_url: &params.submission_url,
            monitoring_url: if params.monitoring_url.is_empty() {
                &params.submission_url
            } else {
                &params.monitoring_url
            },
            mmd: MAX_MERGE_DELAY_SECS,
            temporal_interval: &params.temporal_interval,
        })
        .unwrap(),
    )
        .into_response())
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

#[allow(clippy::too_many_lines)]
async fn add_chain_or_pre_chain(
    body: Bytes,
    env: &Env,
    log: &str,
    expect_precert: bool,
) -> ApiResult<impl IntoResponse> {
    let params = &CONFIG.logs[log];
    if params.read_only {
        return Err(AppError::ReadonlyLog);
    }
    let req: AddChainRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            log::debug!("{log}: Invalid add-(pre)chain request: {e}");
            return Err(AppError::BadRequest(
                "Invalid add-[pre-]chain request".into(),
            ));
        }
    };

    // Temporal interval dates prior to the Unix epoch are treated as the Unix epoch.
    let roots = load_roots(env, log).await?;
    let (pending_entry, found_root_idx) = match static_ct_api::partially_validate_chain(
        &req.chain,
        &roots,
        Some(
            u64::try_from(params.temporal_interval.start_inclusive.timestamp_millis())
                .unwrap_or_default(),
        ),
        Some(
            u64::try_from(params.temporal_interval.end_exclusive.timestamp_millis())
                .unwrap_or_default(),
        ),
        expect_precert,
        true,
    ) {
        Ok(v) => v,
        Err(e) => {
            log::debug!("{log}: Bad request: {e}");
            return Err(AppError::BadRequest(String::new()));
        }
    };

    // Retrieve the sequenced entry for this pending log entry by first checking the
    // deduplication cache and then sending a request to the DO to sequence the entry.
    let lookup_key = pending_entry.lookup_key();
    let signing_key = load_signing_key(env, log)?;

    // Check if entry is cached and return right away if so.
    if params.enable_dedup {
        if let Some(metadata) =
            get_cached_metadata::<StaticCTSequenceMetadata>(&load_cache_kv(env, log)?, &lookup_key)
                .await?
        {
            log::debug!("{log}: Entry is cached");
            let entry =
                StaticCTLogEntry::new(pending_entry, metadata.leaf_index(), metadata.timestamp());
            let sct = static_ct_api::signed_certificate_timestamp(signing_key, &entry)
                .map_err(|e| e.to_string())?;
            return Ok((StatusCode::OK, Json(sct)).into_response());
        }
    }

    // Entry is not cached, so we need to sequence it.

    // First persist issuers. Use a block so memory is deallocated sooner.
    {
        let public_bucket = ObjectBucket::new(load_public_bucket(env, log)?);
        let mut issuers = req.chain[1..]
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<&[u8]>>();

        // Make sure the found root is persisted as well, if the add-chain
        // request did not include the root.
        let root_bytes;
        if let Some(idx) = found_root_idx {
            root_bytes = roots.certs[idx].to_der().map_err(|e| e.to_string())?;
            issuers.push(&root_bytes);
        }

        generic_log_worker::upload_issuers(&public_bucket, &issuers, log).await?;
    }

    // Submit entry to be sequenced, either via a batcher or directly to the
    // sequencer.
    let stub = {
        let shard_id = batcher_id_from_lookup_key(&lookup_key, params.num_batchers);
        get_durable_object_stub(
            env,
            log,
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
    let metadata = deserialize::<StaticCTSequenceMetadata>(&response.bytes().await?)?;
    if params.num_batchers == 0 && params.enable_dedup {
        // Write sequenced entry to the long-term deduplication cache in Workers
        // KV as there are no batchers configured to do it for us.
        if put_cache_entry_metadata(&load_cache_kv(env, log)?, &pending_entry, metadata)
            .await
            .is_err()
        {
            log::warn!("{log}: Failed to write entry to deduplication cache");
        }
    }
    let entry = StaticCTLogEntry {
        inner: pending_entry,
        leaf_index: metadata.leaf_index(),
        timestamp: metadata.timestamp(),
    };
    let sct = static_ct_api::signed_certificate_timestamp(signing_key, &entry)
        .map_err(|e| e.to_string())?;
    Ok((StatusCode::OK, Json(sct)).into_response())
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
