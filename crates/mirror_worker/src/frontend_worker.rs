// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! HTTP entry point + handlers for the mirror worker.
//!
//! Routes:
//!
//! - `POST /add-checkpoint`: [c2sp.org/tlog-mirror#add-checkpoint][add-cp].
//!   Updates the pending checkpoint for an origin. Wire format and
//!   response semantics are identical to the witness's `add-checkpoint`,
//!   with one spec-mandated exception: the mirror MUST NOT cosign in
//!   this process. Successful responses have an empty body and HTTP
//!   status 200.
//! - `GET /metadata`: mirror identity, ML-DSA-44 SPKI,
//!   `mirror_algorithm`, prefixes, and the per-log configuration.
//! - `GET /`: root status string.
//!
//! The mirror's per-origin persistent state lives in a [`MirrorState`]
//! Durable Object; see [`crate::mirror_state_do`] for details.
//!
//! [add-cp]: https://c2sp.org/tlog-mirror#add-checkpoint
//! [`MirrorState`]: crate::mirror_state_do

use crate::{
    CONFIG, load_mirror_public_key_der, load_mirror_signer, log_verifiers,
    mirror_state_do::{PendingCheckpoint, UpdatePendingRequest, state_stub},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use serde::Serialize;
use serde_with::{base64::Base64 as Base64As, serde_as};
use signed_note::NoteError;
use tlog_checkpoint::CheckpointText;
use tlog_witness::{AddCheckpointRequest, CONTENT_TYPE_TLOG_SIZE, parse_add_checkpoint_request};
use tower_service::Service as _;
#[allow(clippy::wildcard_imports)]
use worker::*;

/// Entry point: initialize logging.
#[event(start)]
fn start() {
    let level = match CONFIG.logging_level.as_deref().unwrap_or("info") {
        "trace" => log::Level::Trace,
        "debug" => log::Level::Debug,
        "warn" => log::Level::Warn,
        "error" => log::Level::Error,
        _ => log::Level::Info,
    };
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(level);
}

/// Top-level `#[event(fetch)]` handler. Delegates to the axum router;
/// unmatched routes return 404.
#[event(fetch, respond_with_errors)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    crate::init_sentry(&env);
    // Wrap the router in the sentry catch/flush guard so a panic in any
    // handler is captured and shipped before the WASM isolate is torn
    // down. `Router`'s `Service::Error` is `Infallible`; the `?` below
    // performs the trivial conversion into `worker::Error`.
    let response = generic_log_worker::obs::sentry::catch_unwind_and_flush(async {
        Router::new()
            .route(
                "/add-checkpoint",
                post(add_checkpoint).layer(DefaultBodyLimit::max(MAX_ADD_CHECKPOINT_BODY_SIZE)),
            )
            .route("/metadata", get(metadata))
            .route("/", get(root))
            .with_state(env)
            .call(req)
            .await
    })
    .await?;
    generic_log_worker::obs::sentry::flush().await;
    Ok(response)
}

/// `GET /` -- mirror identity string. Convenience only; not part of the
/// spec.
async fn root() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{} - c2sp.org/tlog-mirror mirror\n", CONFIG.mirror_name),
    )
}

/// Error type for the mirror's axum handlers, mapped to an HTTP status by
/// [`IntoResponse`].
enum AppError {
    InternalServerError(String),
    BadRequest(String),
    UnknownLogOrigin,
    NoValidSignatures,
}

/// Result type for the mirror's axum handlers.
type ApiResult<T> = std::result::Result<T, AppError>;

impl From<worker::Error> for AppError {
    fn from(err: worker::Error) -> Self {
        Self::InternalServerError(err.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AppError::InternalServerError(error) => {
                log::error!("unhandled error: {error}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            AppError::BadRequest(e) => {
                (StatusCode::BAD_REQUEST, format!("Bad request: {e}")).into_response()
            }
            AppError::UnknownLogOrigin => {
                (StatusCode::NOT_FOUND, "Unknown log origin").into_response()
            }
            AppError::NoValidSignatures => (
                StatusCode::FORBIDDEN,
                "No valid signatures from trusted log keys",
            )
                .into_response(),
        }
    }
}

/// Response body for the `/metadata` endpoint: the mirror's identity,
/// URL prefixes, and per-log configuration. The `mirror_algorithm` field
/// tells clients whether to expect `cosignature/v1` or `subtree/v1`
/// cosignatures.
#[serde_as]
#[derive(Serialize)]
struct MetadataResponse<'a> {
    mirror_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    /// DER-encoded `SubjectPublicKeyInfo` for the mirror's verifying
    /// key. Algorithm is identified by `mirror_algorithm`.
    #[serde_as(as = "Base64As")]
    mirror_public_key: &'a [u8],
    /// Always `"subtree/v1"` (ML-DSA-44); the mirror's cosigner is an MTC
    /// cosigner. See
    /// [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature).
    mirror_algorithm: &'a str,
    submission_prefix: &'a str,
    monitoring_prefix: &'a str,
    logs: Vec<LogMetadata<'a>>,
}

#[serde_as]
#[derive(Serialize)]
struct LogMetadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    /// The note-signature name the log's trusted checkpoints carry (for
    /// MTC, the CA cosigner ID). The concrete origins served for this
    /// key are `<log_key_name>.0.<N>` for each `N` in
    /// `[min_log_number, max_log_number]`, each addressable at
    /// `<monitoring_prefix>/<SHA-256(origin), hex>/`.
    log_key_name: &'a str,
    /// Lowest MTC log number served for this key (inclusive). For a plain
    /// (non-MTC) log this equals `max_log_number`.
    min_log_number: u64,
    /// Highest MTC log number served for this key (inclusive).
    max_log_number: u64,
    /// DER-encoded `SubjectPublicKeyInfo` blobs for the log's trusted
    /// keys.
    #[serde_as(as = "Vec<Base64As>")]
    log_public_keys: Vec<&'a [u8]>,
}

/// Build the per-log metadata entries, one per configured key, sorted by
/// `log_key_name` so the response is deterministic regardless of
/// `HashMap` iteration order (it may be diffed or hashed by monitors).
///
/// MTC log-number windows are published as `[min_log_number,
/// max_log_number]` bounds; a client derives the concrete origins as
/// `<log_key_name>.0.<N>`.
fn metadata_logs(
    logs: &std::collections::HashMap<String, config::LogParams>,
) -> Vec<LogMetadata<'_>> {
    let mut out: Vec<LogMetadata> = logs
        .iter()
        .map(|(log_key_name, p)| LogMetadata {
            description: p.description.as_deref(),
            log_key_name,
            min_log_number: p.min_log_number,
            max_log_number: p.max_log_number,
            log_public_keys: p.log_public_keys.iter().map(Vec::as_slice).collect(),
        })
        .collect();
    out.sort_by(|a, b| a.log_key_name.cmp(b.log_key_name));
    out
}

/// `GET /metadata` handler.
#[worker::send]
async fn metadata(State(env): State<Env>) -> ApiResult<impl IntoResponse> {
    let mirror_public_key = load_mirror_public_key_der(&env)?;
    let mirror_algorithm = load_mirror_signer(&env)?.algorithm();
    let logs = metadata_logs(&CONFIG.logs);
    let body = MetadataResponse {
        mirror_name: &CONFIG.mirror_name,
        description: CONFIG.description.as_deref(),
        mirror_public_key,
        mirror_algorithm,
        submission_prefix: &CONFIG.submission_prefix,
        monitoring_prefix: CONFIG
            .monitoring_prefix
            .as_deref()
            .unwrap_or(&CONFIG.submission_prefix),
        logs,
    };
    Ok((StatusCode::OK, Json(body)))
}

/// Handle `POST /add-checkpoint`, updating the pending checkpoint for a
/// log. Handled like a witness's `add-checkpoint`, but the mirror does
/// not cosign and returns an empty body ([spec][add-cp]).
///
/// After validating the request (parse, log lookup, signature, and size
/// range), the check-proof-and-update against persisted pending state is
/// delegated to the per-origin [`MirrorState`] DO so it happens
/// atomically; see [`dispatch_update_pending`] for the status-code
/// mapping.
///
/// [add-cp]: https://c2sp.org/tlog-mirror#add-checkpoint
/// [`MirrorState`]: crate::mirror_state_do
#[worker::send]
async fn add_checkpoint(
    State(env): State<Env>,
    body: Bytes,
) -> ApiResult<axum::response::Response> {
    // The body size is capped by the `DefaultBodyLimit` layer on this
    // route, which rejects oversized payloads (413) before they are fully
    // buffered, so by here `body` is already within bounds.
    let AddCheckpointRequest {
        old_size,
        consistency_proof,
        checkpoint,
    } = match parse_add_checkpoint_request(&body) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("add-checkpoint: malformed request: {e}");
            return Err(AppError::BadRequest(e.to_string()));
        }
    };

    // Parse the checkpoint and look up the log by its origin. Using the
    // validated `CheckpointText` origin (not a looser re-parse) keeps the
    // lookup consistent with the size/hash used below.
    let cp_text = match CheckpointText::from_bytes(checkpoint.text()) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("add-checkpoint: malformed checkpoint text: {e:?}");
            return Err(AppError::BadRequest(e.to_string()));
        }
    };
    let origin = cp_text.origin();
    let Some(verifiers) = log_verifiers(origin) else {
        return Err(AppError::UnknownLogOrigin);
    };

    // Accept the checkpoint if at least one trusted log key signed it;
    // unknown-key signatures are ignored (witness semantics). No valid
    // trusted signature -> 403; a malformed signature line -> 400.
    if let Err(e) = checkpoint.verify(&verifiers) {
        match e {
            NoteError::UnverifiedNote | NoteError::InvalidSignature { .. } => {
                log::info!("add-checkpoint: rejecting note: {e:?}");
                return Err(AppError::NoValidSignatures);
            }
            _ => {
                log::warn!("add-checkpoint: verify failed: {e:?}");
                return Err(AppError::BadRequest(e.to_string()));
            }
        }
    }

    if old_size > cp_text.size() {
        return Err(AppError::BadRequest(format!(
            "old_size {old_size} > checkpoint size {}",
            cp_text.size()
        )));
    }

    // Atomic check-proof-and-update in the per-origin DO. Pass the whole
    // signed note (via `to_bytes()`) so the DO retains the log's
    // signature alongside size+hash, per spec.
    let update = UpdatePendingRequest {
        old_size,
        new_size: cp_text.size(),
        new_hash: *cp_text.hash(),
        proof: consistency_proof,
        signed_note_bytes: checkpoint.to_bytes(),
    };
    if let Some(resp) = dispatch_update_pending(&env, origin, &update).await? {
        return Ok(resp);
    }

    // Empty body; the mirror cosigner MUST NOT sign here.
    Ok(StatusCode::OK.into_response())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maximum `add-checkpoint` request body, enforced by the route's
/// [`DefaultBodyLimit`] layer. A well-formed request is an `old <N>`
/// line, up to 63 base64 hash lines, and a checkpoint note of up to
/// `signed_note::MAX_NOTE_SIZE` (1 MiB); 1 MiB plus 16 KiB of headroom
/// covers that.
const MAX_ADD_CHECKPOINT_BODY_SIZE: usize = 1_024 * 1_024 + 16 * 1_024;

/// POST the [`UpdatePendingRequest`] to the per-origin DO, translating
/// the DO's status code into either:
///
///   * `Ok(None)`: success (200); the caller should return an empty
///     `Response`.
///   * `Ok(Some(resp))`: the DO responded with a non-200 status that
///     maps directly to the `add-checkpoint` HTTP response (409 with
///     `text/x.tlog.size` body, 422, or a forwarded 400).
///   * `Err(_)`: transport-level failure.
async fn dispatch_update_pending(
    env: &Env,
    origin: &str,
    update: &UpdatePendingRequest,
) -> Result<Option<axum::response::Response>> {
    let stub = state_stub(env, origin)?;
    let mut resp = stub
        .fetch_with_request(Request::new_with_init(
            "http://do/update-pending",
            &RequestInit {
                method: Method::Post,
                body: Some(serde_json::to_string(update)?.into()),
                headers: {
                    let h = Headers::new();
                    h.set("content-type", "application/json")?;
                    h
                },
                ..Default::default()
            },
        )?)
        .await?;
    match resp.status_code() {
        // Drop `resp`; its destructor releases the body (no explicit read).
        200 => Ok(None),
        409 => {
            let current: PendingCheckpoint = resp.json().await?;
            Ok(Some(tlog_size_conflict(&current)))
        }
        422 => Ok(Some(
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Entity: consistency proof failed",
            )
                .into_response(),
        )),
        400 => {
            // Forward the DO's message verbatim; it already describes the
            // specific violation (e.g. non-empty proof for a first pending).
            let msg = resp.text().await.unwrap_or_else(|_| "Bad request".into());
            Ok(Some((StatusCode::BAD_REQUEST, msg).into_response()))
        }
        status => Ok(Some(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal error: DO returned {status}"),
            )
                .into_response(),
        )),
    }
}

/// Build the 409 response body per the witness/mirror spec:
/// `text/x.tlog.size` content type, decimal latest size followed by a
/// newline.
fn tlog_size_conflict(current: &PendingCheckpoint) -> axum::response::Response {
    let body = format!("{}\n", current.size);
    (
        StatusCode::CONFLICT,
        [(header::CONTENT_TYPE, CONTENT_TYPE_TLOG_SIZE)],
        body,
    )
        .into_response()
}
