// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! HTTP entry point and protocol handlers.

use crate::{
    CONFIG, IdentitySigner, enabled_roles, load_mirror_signer, load_witness_signer, log_verifiers,
    mirror_state_do::{PendingCheckpoint, UpdatePendingRequest, state_stub},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use generic_log_worker::{
    frontend::request_metrics,
    init_logging,
    obs::{Wshim, metrics},
    util::now_millis,
};
use serde::Serialize;
use serde_with::{base64::Base64 as Base64As, serde_as};
use signed_note::{NoteSignature, VerifierList};
use tlog_checkpoint::CheckpointSigner as _;
use tlog_witness::{
    CONTENT_TYPE_TLOG_SIZE, MAX_REQUEST_BODY_SIZE, TrustedSignatureError,
    serialize_add_checkpoint_response, serialize_sign_subtree_response,
    validate_add_checkpoint_request, validate_sign_subtree_proof, validate_sign_subtree_request,
    verify_trusted_checkpoint_signature,
};
use tower_service::Service as _;
#[allow(clippy::wildcard_imports)]
use worker::*;

const MAX_ADD_CHECKPOINT_BODY_SIZE: usize = 1_024 * 1_024 + 16 * 1_024;

#[event(start)]
fn start() {
    init_logging(CONFIG.logging_level.as_deref());
}

async fn add_accept_encoding(
    mut response: axum::http::Response<axum::body::Body>,
) -> axum::http::Response<axum::body::Body> {
    if enabled_roles(CONFIG.mode).mirror() {
        response
            .headers_mut()
            .insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    }
    response
}

#[event(fetch, respond_with_errors)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    crate::init_sentry(&env);
    crate::validate_identity_keys(&env)?;
    let wshim = Wshim::from_env(&env);
    let registry = metrics::registry();
    let response = generic_log_worker::obs::sentry::catch_unwind_and_flush(async {
        let mut router = Router::new()
            .route(
                "/add-checkpoint",
                post(add_checkpoint).layer(DefaultBodyLimit::max(MAX_ADD_CHECKPOINT_BODY_SIZE)),
            )
            .route(
                "/sign-subtree",
                post(sign_subtree).layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_SIZE)),
            )
            .route("/metadata", get(metadata))
            .route("/", get(root));
        if enabled_roles(CONFIG.mode).mirror() {
            router = router.route("/add-entries", post(crate::add_entries::add_entries));
        }
        router
            .layer(axum::middleware::map_response(add_accept_encoding))
            .layer(axum::middleware::from_fn_with_state(
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

async fn root() -> impl IntoResponse {
    let roles = match CONFIG.mode {
        config::Mode::Witness => "witness",
        config::Mode::Mirror => "mirror",
        config::Mode::WitnessAndMirror => "witness and mirror",
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("mirror worker: {roles}\n"),
    )
}

pub(crate) enum AppError {
    InternalServerError(String),
    BadRequest(String),
    UnsupportedMediaType(String),
    UnprocessableEntity(String),
    UnknownLogOrigin,
    NoValidSignatures,
    ReferenceCheckpointNotCosigned,
}

pub(crate) type ApiResult<T> = std::result::Result<T, AppError>;

impl From<worker::Error> for AppError {
    fn from(err: worker::Error) -> Self {
        Self::InternalServerError(err.to_string())
    }
}

impl From<crate::body::BodyError> for AppError {
    fn from(err: crate::body::BodyError) -> Self {
        match err {
            crate::body::BodyError::Decode(msg) => Self::BadRequest(msg),
            crate::body::BodyError::Transport(error) => {
                Self::InternalServerError(error.to_string())
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::InternalServerError(error) => {
                log::error!("unhandled error: {error}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            Self::BadRequest(error) => {
                (StatusCode::BAD_REQUEST, format!("Bad request: {error}")).into_response()
            }
            Self::UnsupportedMediaType(error) => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, error).into_response()
            }
            Self::UnprocessableEntity(error) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Unprocessable Entity: {error}"),
            )
                .into_response(),
            Self::UnknownLogOrigin => (StatusCode::NOT_FOUND, "Unknown log origin").into_response(),
            Self::NoValidSignatures => (
                StatusCode::FORBIDDEN,
                "No valid signatures from trusted log keys",
            )
                .into_response(),
            Self::ReferenceCheckpointNotCosigned => (
                StatusCode::FORBIDDEN,
                "Reference checkpoint not cosigned by an enabled identity",
            )
                .into_response(),
        }
    }
}

#[serde_as]
#[derive(Serialize)]
struct MetadataResponse<'a> {
    mode: &'a str,
    submission_prefix: &'a str,
    monitoring_prefix: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness: Option<IdentityMetadata<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mirror: Option<IdentityMetadata<'a>>,
    logs: Vec<LogMetadata<'a>>,
}

#[serde_as]
#[derive(Serialize)]
struct IdentityMetadata<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    #[serde_as(as = "Base64As")]
    public_key: &'a [u8],
    algorithm: &'a str,
    supports_sign_subtree: bool,
}

#[derive(Serialize)]
struct LogMetadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    origin: &'a str,
    checkpoint_signers: Vec<CheckpointSignerMetadata<'a>>,
}

#[serde_as]
#[derive(Serialize)]
struct CheckpointSignerMetadata<'a> {
    name: &'a str,
    algorithm: &'a str,
    #[serde_as(as = "Base64As")]
    public_key: &'a [u8],
}

fn metadata_logs() -> Vec<LogMetadata<'static>> {
    let mut logs = CONFIG
        .logs
        .iter()
        .map(|(origin, log)| LogMetadata {
            description: log.description.as_deref(),
            origin,
            checkpoint_signers: log
                .checkpoint_signers
                .iter()
                .map(|signer| CheckpointSignerMetadata {
                    name: &signer.name,
                    algorithm: signer.algorithm.as_str(),
                    public_key: &signer.public_key,
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    logs.sort_by(|a, b| a.origin.cmp(b.origin));
    logs
}

#[worker::send]
async fn metadata(State(env): State<Env>) -> ApiResult<impl IntoResponse> {
    let roles = enabled_roles(CONFIG.mode);
    let witness = if roles.witness() {
        let identity = CONFIG
            .witness
            .as_ref()
            .expect("validated witness mode has witness config");
        let signer = load_witness_signer(&env)?;
        Some(identity_metadata(identity, signer))
    } else {
        None
    };
    let mirror = if roles.mirror() {
        let identity = CONFIG
            .mirror
            .as_ref()
            .expect("validated mirror mode has mirror config");
        let signer = load_mirror_signer(&env)?;
        Some(IdentityMetadata {
            name: &identity.name,
            description: identity.description.as_deref(),
            public_key: signer.public_key_der(),
            algorithm: signer.algorithm(),
            supports_sign_subtree: signer.supports_sign_subtree(),
        })
    } else {
        None
    };
    Ok((
        StatusCode::OK,
        Json(MetadataResponse {
            mode: CONFIG.mode.as_str(),
            submission_prefix: &CONFIG.submission_prefix,
            monitoring_prefix: CONFIG
                .monitoring_prefix
                .as_deref()
                .unwrap_or(&CONFIG.submission_prefix),
            witness,
            mirror,
            logs: metadata_logs(),
        }),
    ))
}

fn identity_metadata<'a>(
    identity: &'a config::IdentityConfig,
    signer: &'a IdentitySigner,
) -> IdentityMetadata<'a> {
    IdentityMetadata {
        name: &identity.name,
        description: identity.description.as_deref(),
        public_key: signer.public_key_der(),
        algorithm: signer.algorithm(),
        supports_sign_subtree: signer.supports_sign_subtree(),
    }
}

#[worker::send]
async fn add_checkpoint(
    State(env): State<Env>,
    body: Bytes,
) -> ApiResult<axum::response::Response> {
    let validated = validate_add_checkpoint_request(&body).map_err(|error| {
        log::warn!("add-checkpoint: malformed request: {error}");
        AppError::BadRequest(error.to_string())
    })?;
    let (old_size, consistency_proof, checkpoint, checkpoint_text) = validated.into_parts();
    let origin = checkpoint_text.origin();
    let Some(verifiers) = log_verifiers(origin) else {
        return Err(AppError::UnknownLogOrigin);
    };
    verify_source_checkpoint(&checkpoint, &verifiers, "add-checkpoint")?;

    let witness_signature = if enabled_roles(CONFIG.mode).witness() {
        Some(
            load_witness_signer(&env)?
                .as_checkpoint_signer()
                .sign(now_millis(), &checkpoint_text)
                .map_err(|error| Error::from(format!("witness signing: {error:?}")))?,
        )
    } else {
        None
    };

    let update = UpdatePendingRequest {
        old_size,
        new_size: checkpoint_text.size(),
        new_hash: *checkpoint_text.hash(),
        proof: consistency_proof,
        signed_note_bytes: checkpoint.to_bytes(),
    };
    if let Some(response) = dispatch_update_pending(&env, origin, &update).await? {
        return Ok(response);
    }

    let Some(signature) = witness_signature else {
        return Ok(StatusCode::OK.into_response());
    };
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        serialize_add_checkpoint_response(std::slice::from_ref(&signature)),
    )
        .into_response())
}

fn verify_source_checkpoint(
    checkpoint: &signed_note::Note,
    verifiers: &VerifierList,
    handler: &str,
) -> ApiResult<()> {
    verify_trusted_checkpoint_signature(checkpoint, verifiers).map_err(|error| match error {
        TrustedSignatureError::NoValidSignature(error) => {
            log::info!("{handler}: rejecting note: {error:?}");
            AppError::NoValidSignatures
        }
        TrustedSignatureError::VerifierInvariant(error) => {
            AppError::InternalServerError(format!("{handler} verifier invariant: {error:?}"))
        }
    })
}

#[worker::send]
async fn sign_subtree(State(env): State<Env>, body: Bytes) -> ApiResult<axum::response::Response> {
    let mut signers = Vec::with_capacity(2);
    let roles = enabled_roles(CONFIG.mode);
    if roles.witness()
        && let Some(signer) = load_witness_signer(&env)?.as_subtree_signer()
    {
        signers.push(signer);
    }
    if roles.mirror()
        && let Some(signer) = load_mirror_signer(&env)?.as_subtree_signer()
    {
        signers.push(signer);
    }
    if signers.is_empty() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    let validated = validate_sign_subtree_request(&body).map_err(|error| {
        log::warn!("sign-subtree: malformed request: {error}");
        AppError::BadRequest(error.to_string())
    })?;
    let origin = validated.checkpoint_text().origin();
    if log_verifiers(origin).is_none() {
        return Err(AppError::UnknownLogOrigin);
    }
    validate_sign_subtree_proof(&validated).map_err(|_| {
        AppError::UnprocessableEntity("subtree consistency proof failed".to_owned())
    })?;

    let mut signatures: Vec<NoteSignature> = Vec::with_capacity(signers.len());
    for signer in signers {
        let verifiers = VerifierList::new(vec![signer.verifier()]);
        match verify_trusted_checkpoint_signature(validated.checkpoint(), &verifiers) {
            Ok(()) => signatures.push(signer.sign_subtree(
                0,
                origin,
                validated.subtree(),
                validated.subtree_hash(),
            )),
            Err(TrustedSignatureError::NoValidSignature(_)) => {}
            Err(TrustedSignatureError::VerifierInvariant(error)) => {
                return Err(AppError::InternalServerError(format!(
                    "sign-subtree verifier invariant: {error:?}"
                )));
            }
        }
    }
    if signatures.is_empty() {
        return Err(AppError::ReferenceCheckpointNotCosigned);
    }
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        serialize_sign_subtree_response(&signatures),
    )
        .into_response())
}

async fn dispatch_update_pending(
    env: &Env,
    origin: &str,
    update: &UpdatePendingRequest,
) -> Result<Option<axum::response::Response>> {
    let stub = state_stub(env, origin)?;
    let mut response = stub
        .fetch_with_request(Request::new_with_init(
            "http://do/update-pending",
            &RequestInit {
                method: Method::Post,
                body: Some(serde_json::to_string(update)?.into()),
                headers: {
                    let headers = Headers::new();
                    headers.set("content-type", "application/json")?;
                    headers
                },
                ..Default::default()
            },
        )?)
        .await?;
    match response.status_code() {
        200 => Ok(None),
        409 => {
            let current: PendingCheckpoint = response.json().await?;
            Ok(Some(tlog_size_conflict(current.size)))
        }
        422 => Ok(Some(
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Entity: consistency proof failed",
            )
                .into_response(),
        )),
        400 => {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Bad request".into());
            Ok(Some((StatusCode::BAD_REQUEST, message).into_response()))
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

fn tlog_size_conflict(size: u64) -> axum::response::Response {
    (
        StatusCode::CONFLICT,
        [(header::CONTENT_TYPE, CONTENT_TYPE_TLOG_SIZE)],
        format!("{size}\n"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::add_accept_encoding;
    use axum::http::header::ACCEPT_ENCODING;

    #[tokio::test]
    async fn combined_mode_advertises_gzip() {
        let response = axum::http::Response::new(axum::body::Body::empty());
        let response = add_accept_encoding(response).await;
        assert_eq!(response.headers()[ACCEPT_ENCODING], "gzip");
    }
}
