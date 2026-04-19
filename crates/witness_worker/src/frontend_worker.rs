// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! HTTP entry point + handler for the witness worker.
//!
//! Routes:
//!
//! - `POST /add-checkpoint` — [c2sp.org/tlog-witness#add-checkpoint][add].
//!
//! The witness's per-origin persistent state lives in a [`WitnessState`]
//! Durable Object; see [`crate::witness_state_do`] for details. Atomicity of
//! the "check old-size, verify proof, update latest, return cosignature"
//! sequence follows from the DO's single-threaded fetch handler.
//!
//! [add]: https://c2sp.org/tlog-witness#add-checkpoint
//! [`WitnessState`]: crate::witness_state_do

use config::LogParams;
use generic_log_worker::util::now_millis;
use pkcs8::DecodePublicKey as _;
use signed_note::{Ed25519NoteVerifier, KeyName, Note, NoteVerifier, VerifierList};
use tlog_tiles::{
    open_checkpoint, verify_consistency_proof, CheckpointSigner, TlogError, ValidationMode,
};
use tlog_witness::{
    parse_add_checkpoint_request, serialize_add_checkpoint_response, AddCheckpointRequest,
    CONTENT_TYPE_TLOG_SIZE,
};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::{
    load_witness_cosigner, load_witness_public_key_der,
    witness_state_do::{state_stub, CheckAndUpdateRequest, LatestCheckpoint},
    CONFIG,
};
use serde::Serialize;
use serde_with::{base64::Base64 as Base64As, serde_as};

/// Entry point: initialize logging and dispatch to the router.
#[event(start)]
fn start() {
    let level = match CONFIG.logging_level.as_deref().unwrap_or("info") {
        "trace" => log::Level::Trace,
        "debug" => log::Level::Debug,
        "info" => log::Level::Info,
        "warn" => log::Level::Warn,
        "error" => log::Level::Error,
        _ => log::Level::Info,
    };
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(level);
}

/// Top-level `#[event(fetch)]` handler.
#[event(fetch, respond_with_errors)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .post_async("/add-checkpoint", |req, ctx| async move {
            add_checkpoint(req, ctx.env).await
        })
        .get("/metadata", |_req, ctx| metadata(&ctx.env))
        .get("/", |_req, _ctx| {
            Response::ok(format!(
                "{} — c2sp.org/tlog-witness witness\n",
                CONFIG.witness_name
            ))
        })
        .run(req, env)
        .await
}

/// Response body for the `/metadata` endpoint.
///
/// Publishes the witness's identity and the per-log configuration so clients
/// can learn what logs this witness cosigns and what URL prefixes to use.
#[serde_as]
#[derive(Serialize)]
struct MetadataResponse<'a> {
    witness_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: &'a Option<String>,
    /// DER-encoded `SubjectPublicKeyInfo` for the witness's Ed25519 key.
    #[serde_as(as = "Base64As")]
    witness_public_key: Vec<u8>,
    submission_prefix: &'a str,
    monitoring_prefix: &'a str,
    logs: Vec<LogMetadata<'a>>,
}

#[serde_as]
#[derive(Serialize)]
struct LogMetadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: &'a Option<String>,
    origin: &'a str,
    /// DER-encoded `SubjectPublicKeyInfo` blobs for the log's trusted keys.
    #[serde_as(as = "Vec<Base64As>")]
    log_public_keys: Vec<&'a [u8]>,
}

/// `GET /metadata` handler.
fn metadata(env: &Env) -> Result<Response> {
    let witness_public_key = load_witness_public_key_der(env)?;
    let logs: Vec<LogMetadata> = CONFIG
        .logs
        .values()
        .map(|p| LogMetadata {
            description: &p.description,
            origin: &p.origin,
            log_public_keys: p.log_public_keys.iter().map(Vec::as_slice).collect(),
        })
        .collect();
    let body = MetadataResponse {
        witness_name: &CONFIG.witness_name,
        description: &CONFIG.description,
        witness_public_key,
        submission_prefix: &CONFIG.submission_prefix,
        monitoring_prefix: if CONFIG.monitoring_prefix.is_empty() {
            &CONFIG.submission_prefix
        } else {
            &CONFIG.monitoring_prefix
        },
        logs,
    };
    Response::from_json(&body)
}

/// Handle `POST /add-checkpoint`.
///
/// The flow mirrors the MUSTs listed in the spec, in order:
///
/// 1. Parse the request body (malformed → 400).
/// 2. Look up the log by origin; if unknown → 404.
/// 3. Verify the checkpoint carries at least one signature from a trusted
///    log key; if none → 403. Unknown signatures are silently ignored.
/// 4. Range check: `old_size <= checkpoint.size` → else 400.
/// 5. Atomic check-and-update against persisted state (via the
///    [`WitnessState`] DO): if `old_size` doesn't match the stored size →
///    409 with the current size in a `text/x.tlog.size` body.
/// 6. If `old_size == checkpoint.size`, the stored root hash must equal the
///    incoming root hash — otherwise → 409 (same body).
/// 7. Verify the consistency proof; on failure → 422.
/// 8. Persist the new state atomically, then produce a `cosignature/v1`
///    signature and return the signature line as the response body.
///
/// Steps 5 and 6 are combined inside the DO's `/check-and-update` RPC so the
/// "check then write" pair is atomic per origin.
///
/// [`WitnessState`]: crate::witness_state_do
async fn add_checkpoint(mut req: Request, env: Env) -> Result<Response> {
    // (1) Parse.
    let body = req.bytes().await?;
    let AddCheckpointRequest {
        old_size,
        consistency_proof,
        checkpoint,
    } = match parse_add_checkpoint_request(&body) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("add-checkpoint: malformed request: {e}");
            return Response::error(format!("Bad request: {e}"), 400);
        }
    };

    // (2) Look up the log by origin.
    //
    // `checkpoint.text()` is the checkpoint note body; its first line is the
    // origin per c2sp.org/tlog-checkpoint.
    let origin = match checkpoint_origin(&checkpoint) {
        Some(o) => o,
        None => {
            return Response::error("Bad request: checkpoint note has no origin", 400);
        }
    };
    let Some(log) = CONFIG.log_by_origin(origin) else {
        return Response::error("Unknown log origin", 404);
    };

    // (3) Verify the checkpoint signature against trusted log keys.
    //
    // Per c2sp.org/tlog-witness, the witness accepts the checkpoint as soon
    // as AT LEAST ONE of the trusted log keys has signed it; signatures from
    // unknown keys are silently ignored. This is `ValidationMode::Any`,
    // distinct from the full-coverage `ValidationMode::All` mode used by
    // issuers and monitors.
    let now = now_millis();
    let verifiers = log_verifier_list(log)?;
    let cp_bytes = checkpoint.to_bytes();
    let (cp_text, _timestamp) =
        match open_checkpoint(origin, &verifiers, ValidationMode::Any, now, &cp_bytes) {
            Ok(v) => v,
            Err(TlogError::MissingVerifierSignature) => {
                return Response::error("No valid signatures from trusted log keys", 403);
            }
            Err(e) => {
                log::warn!("add-checkpoint: open_checkpoint failed: {e:?}");
                return Response::error("Bad request: malformed checkpoint", 400);
            }
        };

    // (4) Range check.
    if old_size > cp_text.size() {
        return Response::error(
            format!("Bad request: old_size {old_size} > checkpoint size {}", cp_text.size()),
            400,
        );
    }

    // (7) Verify the consistency proof before touching DO state. The spec
    // allows verifying in either order; verifying first means we don't churn
    // DO storage on a bad proof, and aligns with the spec's advice that the
    // witness MAY log the request even if the proof doesn't verify (but
    // MUST NOT cosign).
    if old_size > 0 && old_size < cp_text.size() {
        // Consistency proof required.
        if consistency_proof.is_empty() {
            return Response::error("Unprocessable Entity: consistency proof required", 422);
        }
        // We don't have the old root hash on hand — the spec check is:
        // verify_consistency_proof(proof, old_size, old_hash, new_size, new_hash).
        // The old_hash is whatever the DO previously recorded. We fetch it
        // from the DO; if nothing is recorded, old_size must be zero (checked
        // above).
        let recorded = fetch_latest(&env, origin).await?;
        if recorded.size != old_size {
            // Size mismatch → we short-circuit to the 409 path without
            // consistency-proof verification (it would be meaningless).
            return tlog_size_conflict(&recorded);
        }
        if verify_consistency_proof(
            &consistency_proof,
            cp_text.size(),
            *cp_text.hash(),
            old_size,
            recorded.hash,
        )
        .is_err()
        {
            return Response::error("Unprocessable Entity: consistency proof failed", 422);
        }
    } else if old_size > 0 && old_size == cp_text.size() {
        // No proof needed; identical-size case requires identical hashes,
        // which is enforced atomically by the DO below.
        if !consistency_proof.is_empty() {
            return Response::error(
                "Bad request: consistency proof must be empty when old_size == checkpoint size",
                400,
            );
        }
    } else {
        // old_size == 0: no proof expected, no recorded state needed. Any
        // proof lines the client sent are treated as malformed per the spec.
        if !consistency_proof.is_empty() {
            return Response::error(
                "Bad request: consistency proof must be empty when old size is 0",
                400,
            );
        }
    }

    // (5, 6, 8) Atomic check-and-update. The DO returns 409 with the current
    // LatestCheckpoint body on size/hash mismatch, 200 on success.
    let update = CheckAndUpdateRequest {
        old_size,
        new_size: cp_text.size(),
        new_hash: *cp_text.hash(),
    };
    let stub = state_stub(&env, origin)?;
    let mut resp = stub
        .fetch_with_request(Request::new_with_init(
            "http://do/check-and-update",
            &RequestInit {
                method: Method::Post,
                body: Some(serde_json::to_string(&update)?.into()),
                headers: {
                    let h = Headers::new();
                    h.set("content-type", "application/json")?;
                    h
                },
                ..Default::default()
            },
        )?)
        .await?;
    if resp.status_code() == 409 {
        let current: LatestCheckpoint = resp.json().await?;
        return tlog_size_conflict(&current);
    }
    if resp.status_code() != 200 {
        return Response::error(
            format!("Internal error: DO returned {}", resp.status_code()),
            500,
        );
    }
    // Drain the body so we can drop the response.
    let _ = resp.bytes().await?;

    // (8) Produce and return the cosignature.
    let cosigner = load_witness_cosigner(&env)?;
    let note_sig = cosigner
        .sign(now, &cp_text)
        .map_err(|e| Error::from(format!("signing: {e:?}")))?;
    let body = serialize_add_checkpoint_response(std::slice::from_ref(&note_sig));
    let headers = Headers::new();
    headers.set("content-type", "text/plain; charset=utf-8")?;
    Ok(Response::from_body(ResponseBody::Body(body))?.with_headers(headers))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `VerifierList` from a log's configured trusted public keys.
///
/// Each `log_public_keys` entry is a DER-encoded SPKI; we parse it
/// as Ed25519 (the only algorithm supported by `cosignature/v1` and therefore
/// by this witness). Unknown-algorithm keys in the config result in an error
/// at request-handling time — but `build.rs` validates the overall config
/// shape, and a future improvement would validate the SPKI algorithm there
/// too.
fn log_verifier_list(log: &LogParams) -> Result<VerifierList> {
    let mut verifiers: Vec<Box<dyn NoteVerifier>> = Vec::with_capacity(log.log_public_keys.len());
    let origin_name = KeyName::new(log.origin.clone()).map_err(|e| {
        Error::from(format!(
            "invalid origin '{}' as KeyName: {:?}",
            log.origin, e
        ))
    })?;
    for spki in &log.log_public_keys {
        let vk = ed25519_dalek::VerifyingKey::from_public_key_der(spki)
            .map_err(|e| Error::from(format!("log SPKI is not Ed25519: {e}")))?;
        verifiers.push(Box::new(Ed25519NoteVerifier::new(origin_name.clone(), vk)));
    }
    Ok(VerifierList::new(verifiers))
}

/// Return the first line of a checkpoint note's text — the origin.
fn checkpoint_origin(note: &Note) -> Option<&str> {
    let text = std::str::from_utf8(note.text()).ok()?;
    text.lines().next()
}

/// Fetch the DO-held latest cosigned checkpoint for an origin.
async fn fetch_latest(env: &Env, origin: &str) -> Result<LatestCheckpoint> {
    let stub = state_stub(env, origin)?;
    let mut resp = stub
        .fetch_with_request(Request::new_with_init(
            "http://do/get",
            &RequestInit {
                method: Method::Get,
                ..Default::default()
            },
        )?)
        .await?;
    if resp.status_code() != 200 {
        return Err(Error::from(format!(
            "DO /get returned {}",
            resp.status_code()
        )));
    }
    resp.json().await
}

/// Build the 409 response body per the spec:
/// `text/x.tlog.size` content type, decimal latest size followed by a newline.
fn tlog_size_conflict(current: &LatestCheckpoint) -> Result<Response> {
    let body = format!("{}\n", current.size);
    let headers = Headers::new();
    headers.set("content-type", CONTENT_TYPE_TLOG_SIZE)?;
    Ok(Response::from_body(ResponseBody::Body(body.into_bytes()))?
        .with_status(409)
        .with_headers(headers))
}

