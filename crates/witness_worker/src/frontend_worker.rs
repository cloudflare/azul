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

use generic_log_worker::util::now_millis;
use signed_note::NoteError;
use tlog_tiles::{CheckpointSigner, CheckpointText};
use tlog_witness::{
    parse_add_checkpoint_request, serialize_add_checkpoint_response, AddCheckpointRequest,
    CONTENT_TYPE_TLOG_SIZE,
};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::{
    load_witness_cosigner, load_witness_public_key_der, log_verifiers,
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
    description: Option<&'a str>,
    /// DER-encoded `SubjectPublicKeyInfo` for the witness's Ed25519 key.
    #[serde_as(as = "Base64As")]
    witness_public_key: &'a [u8],
    submission_prefix: &'a str,
    monitoring_prefix: &'a str,
    logs: Vec<LogMetadata<'a>>,
}

#[serde_as]
#[derive(Serialize)]
struct LogMetadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
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
            description: p.description.as_deref(),
            origin: &p.origin,
            log_public_keys: p.log_public_keys.iter().map(Vec::as_slice).collect(),
        })
        .collect();
    let body = MetadataResponse {
        witness_name: &CONFIG.witness_name,
        description: CONFIG.description.as_deref(),
        witness_public_key,
        submission_prefix: &CONFIG.submission_prefix,
        monitoring_prefix: CONFIG
            .monitoring_prefix
            .as_deref()
            .unwrap_or(&CONFIG.submission_prefix),
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
    //
    // Cap the request body at `MAX_ADD_CHECKPOINT_BODY_SIZE` so a
    // malicious or misconfigured client can't make the worker buffer
    // arbitrary data in memory. A well-formed request is an `old <N>`
    // line + up to 63 base64 hash lines + a blank line + a checkpoint
    // note (capped at `signed_note::MAX_NOTE_SIZE = 1 MiB`); anything
    // larger is guaranteed to be rejected downstream and we avoid the
    // allocation by rejecting it here.
    let body = req.bytes().await?;
    if body.len() > MAX_ADD_CHECKPOINT_BODY_SIZE {
        return Response::error(
            format!("Bad request: body exceeds {MAX_ADD_CHECKPOINT_BODY_SIZE} bytes"),
            400,
        );
    }
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

    // (2) Parse the checkpoint body and look up the log by its origin.
    //
    // `CheckpointText::from_bytes` validates the full checkpoint shape
    // (origin, decimal size, base64 root hash, extensions) and exposes
    // the parsed origin; we use that — rather than a second, looser
    // parse of `checkpoint.text().lines().next()` — for the log lookup
    // so the two views cannot disagree.
    let cp_text = match CheckpointText::from_bytes(checkpoint.text()) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("add-checkpoint: malformed checkpoint text: {e:?}");
            return Response::error(format!("Bad request: {e}"), 400);
        }
    };
    let origin = cp_text.origin();
    let Some(verifiers) = log_verifiers(origin) else {
        return Response::error("Unknown log origin", 404);
    };

    // (3) Verify the checkpoint signature against trusted log keys.
    //
    // Per c2sp.org/tlog-witness, the witness accepts the checkpoint as
    // soon as at least one of the trusted log keys has signed it;
    // signatures from unknown keys are silently ignored. Both
    // `UnverifiedNote` (no signature line matches a trusted key at all)
    // and `InvalidSignature` (a signature line matches a trusted `(name,
    // id)` but the signature bytes fail to verify — a malformed note per
    // c2sp.org/signed-note) are surfaced as `403 Forbidden`, matching the
    // behavior of sunlight's and sigsum-go's reference witnesses. Other
    // `NoteError` variants indicate a syntactically malformed signature
    // line and are surfaced as `400 Bad Request`.
    //
    // `tlog_tiles::open_checkpoint` is deliberately not used here because
    // it additionally requires *every* configured verifier to sign — the
    // full-coverage semantics an issuer or monitor wants, but not a
    // witness: a log rotating keys may have multiple trusted public keys
    // of which any single one signing is sufficient.
    let now = now_millis();
    if let Err(e) = checkpoint.verify(&verifiers) {
        match e {
            NoteError::UnverifiedNote | NoteError::InvalidSignature { .. } => {
                log::info!("add-checkpoint: rejecting note: {e:?}");
                return Response::error("No valid signatures from trusted log keys", 403);
            }
            _ => {
                log::warn!("add-checkpoint: verify failed: {e:?}");
                return Response::error(format!("Bad request: {e}"), 400);
            }
        }
    }

    // (4) Range check.
    if old_size > cp_text.size() {
        return Response::error(
            format!(
                "Bad request: old_size {old_size} > checkpoint size {}",
                cp_text.size()
            ),
            400,
        );
    }

    // (5, 6, 7) Atomic check-proof-and-update against the per-origin DO.
    // See [`dispatch_check_and_update`] for the status-code mapping.
    let update = CheckAndUpdateRequest {
        old_size,
        new_size: cp_text.size(),
        new_hash: *cp_text.hash(),
        proof: consistency_proof,
    };
    if let Some(resp) = dispatch_check_and_update(&env, origin, &update).await? {
        return Ok(resp);
    }

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

/// Maximum size we are willing to buffer from an incoming `add-checkpoint`
/// request body. A well-formed request is an `old <N>` line + up to
/// [`tlog_witness::MAX_CONSISTENCY_PROOF_LINES`] (63) base64 hash lines +
/// a blank line + a checkpoint note of up to `signed_note::MAX_NOTE_SIZE`
/// (1 MiB); 1 MiB + 16 KiB of envelope headroom comfortably covers that
/// and rejects anything obviously too large before it is allocated.
const MAX_ADD_CHECKPOINT_BODY_SIZE: usize = 1_024 * 1_024 + 16 * 1_024;

/// POST the `CheckAndUpdateRequest` to the per-origin DO, translating the
/// DO's status code into either:
///   * `Ok(None)` — success (200); the caller should proceed to cosign.
///   * `Ok(Some(resp))` — the DO responded with a non-200 status that maps
///     directly to the `add-checkpoint` HTTP response (409 with
///     `text/x.tlog.size` body, 422, or a forwarded 400).
///   * `Err(_)` — transport-level failure.
async fn dispatch_check_and_update(
    env: &Env,
    origin: &str,
    update: &CheckAndUpdateRequest,
) -> Result<Option<Response>> {
    let stub = state_stub(env, origin)?;
    let mut resp = stub
        .fetch_with_request(Request::new_with_init(
            "http://do/check-and-update",
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
        200 => {
            // Drain the body so we can drop the response.
            let _ = resp.bytes().await?;
            Ok(None)
        }
        409 => {
            let current: LatestCheckpoint = resp.json().await?;
            Ok(Some(tlog_size_conflict(&current)?))
        }
        422 => Ok(Some(Response::error(
            "Unprocessable Entity: consistency proof failed",
            422,
        )?)),
        400 => {
            let msg = resp.text().await.unwrap_or_else(|_| "Bad request".into());
            Ok(Some(Response::error(format!("Bad request: {msg}"), 400)?))
        }
        status => Ok(Some(Response::error(
            format!("Internal error: DO returned {status}"),
            500,
        )?)),
    }
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

#[cfg(test)]
mod tests {
    use super::{LogMetadata, MetadataResponse};

    /// `description` is optional in the `/metadata` response. When absent
    /// it MUST be omitted from the JSON body (not serialized as `null`)
    /// so the wire shape matches the c2sp.org/tlog-witness expectation.
    #[test]
    fn metadata_description_omitted_when_none() {
        let log = LogMetadata {
            description: None,
            origin: "example.com/log",
            log_public_keys: vec![b"spki".as_slice()],
        };
        let body = MetadataResponse {
            witness_name: "example.com/witness",
            description: None,
            witness_public_key: b"witness-spki",
            submission_prefix: "https://witness.example.com/",
            monitoring_prefix: "https://witness.example.com/",
            logs: vec![log],
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(
            !json.contains("\"description\""),
            "description should be omitted when None, got: {json}"
        );
    }

    #[test]
    fn metadata_description_present_when_some() {
        let log = LogMetadata {
            description: Some("a log"),
            origin: "example.com/log",
            log_public_keys: vec![b"spki".as_slice()],
        };
        let body = MetadataResponse {
            witness_name: "example.com/witness",
            description: Some("a witness"),
            witness_public_key: b"witness-spki",
            submission_prefix: "https://witness.example.com/",
            monitoring_prefix: "https://witness.example.com/",
            logs: vec![log],
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"description\":\"a witness\""), "{json}");
        assert!(json.contains("\"description\":\"a log\""), "{json}");
    }
}
