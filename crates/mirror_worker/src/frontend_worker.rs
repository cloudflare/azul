// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! HTTP entry point + handler for the mirror worker.
//!
//! Routes:
//!
//! - `POST /add-checkpoint` — [c2sp.org/tlog-mirror#add-checkpoint][add-cp].
//!   Updates the *pending* checkpoint for an origin. Wire format and
//!   response semantics are identical to the witness's `add-checkpoint`,
//!   with one spec-mandated exception: the mirror MUST NOT cosign in
//!   this process. Successful responses have an empty body and HTTP
//!   status 200.
//! - `POST /add-entries` — [c2sp.org/tlog-mirror#add-entries][add-e].
//!   Ingests entries against a known pending checkpoint. Currently a
//!   parse-and-verify only implementation (slice C4a; see
//!   [`crate::add_entries`]). Persistence and cosignature emission
//!   land in C4b/C4c.
//! - `GET /metadata` — mirror identity, ML-DSA-44 SPKI,
//!   `mirror_algorithm`, prefixes, and the per-log configuration.
//! - `GET /` — root status string. Convenience only; not part of the
//!   spec.
//!
//! The mirror's per-origin persistent state lives in a [`MirrorState`]
//! Durable Object; see [`crate::mirror_state_do`] for details. Atomicity
//! of the "check old-pending-size, verify proof, update pending"
//! sequence follows from the DO's single-threaded fetch handler.
//!
//! Future slices will add the [tlog-tiles][tiles] read interface
//! served at `<monitoring_prefix>/<encoded origin>/...`.
//!
//! [add-cp]: https://c2sp.org/tlog-mirror#add-checkpoint
//! [add-e]: https://c2sp.org/tlog-mirror#add-entries
//! [`MirrorState`]: crate::mirror_state_do
//! [tiles]: https://c2sp.org/tlog-tiles

use serde::Serialize;
use serde_with::{base64::Base64 as Base64As, serde_as};
use signed_note::NoteError;
use tlog_checkpoint::CheckpointText;
use tlog_witness::{parse_add_checkpoint_request, AddCheckpointRequest, CONTENT_TYPE_TLOG_SIZE};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::{
    load_mirror_public_key_der, load_mirror_signer, log_verifiers,
    mirror_state_do::{state_stub, PendingCheckpoint, UpdatePendingRequest},
    CONFIG,
};

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

/// Top-level `#[event(fetch)]` handler.
#[event(fetch, respond_with_errors)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .post_async("/add-checkpoint", |req, ctx| async move {
            add_checkpoint(req, ctx.env).await
        })
        .post_async("/add-entries", |req, ctx| async move {
            crate::add_entries::add_entries(req, ctx.env).await
        })
        .get("/metadata", |_req, ctx| metadata(&ctx.env))
        .get("/", |_req, _ctx| {
            Response::ok(format!(
                "{} — c2sp.org/tlog-mirror mirror\n",
                CONFIG.mirror_name
            ))
        })
        .run(req, env)
        .await
}

/// Response body for the `/metadata` endpoint.
///
/// Publishes the mirror's identity and the per-log configuration so
/// clients can learn what logs this mirror mirrors and what URL
/// prefixes to use. Symmetric with the witness's `/metadata` shape,
/// with a `mirror_algorithm` field added so clients know whether to
/// expect `cosignature/v1` or `subtree/v1` cosignatures.
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
    /// `"cosignature/v1"` (Ed25519) or `"subtree/v1"` (ML-DSA-44).
    /// See [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature).
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
    origin: &'a str,
    /// DER-encoded `SubjectPublicKeyInfo` blobs for the log's trusted
    /// keys.
    #[serde_as(as = "Vec<Base64As>")]
    log_public_keys: Vec<&'a [u8]>,
}

/// Build the per-log metadata entries from the worker's `CONFIG`
/// `logs` map, sorted by origin so the result has a deterministic
/// order regardless of `HashMap` iteration order. The deterministic
/// order matters for diff-based monitoring of `/metadata` and for any
/// client that hashes the response (cache keys, etc.).
///
/// Split out from [`metadata`] so the sort can be unit-tested without
/// a `worker::Env`.
fn metadata_logs(
    logs: &std::collections::HashMap<String, config::LogParams>,
) -> Vec<LogMetadata<'_>> {
    let mut out: Vec<LogMetadata> = logs
        .iter()
        .map(|(origin, p)| LogMetadata {
            description: p.description.as_deref(),
            origin,
            log_public_keys: p.log_public_keys.iter().map(Vec::as_slice).collect(),
        })
        .collect();
    out.sort_by_key(|l| l.origin);
    out
}

/// `GET /metadata` handler.
fn metadata(env: &Env) -> Result<Response> {
    let mirror_public_key = load_mirror_public_key_der(env)?;
    let mirror_algorithm = load_mirror_signer(env)?.algorithm();
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
    Response::from_json(&body)
}

/// Handle `POST /add-checkpoint`.
///
/// Per [spec][add-cp]: "The request is handled identically to that of a
/// witness, updating the pending checkpoint (but not the mirror
/// checkpoint), with the exception that it does not need to generate
/// and respond with any cosignatures. The mirror MAY handle the request
/// by internally updating the pending checkpoint and responding with an
/// empty response body. The mirror MUST retain the log's signature in
/// the pending checkpoint."
///
/// The flow:
///
/// 1. Parse the request body (malformed → 400).
/// 2. Look up the log by origin; if unknown → 404.
/// 3. Verify the checkpoint carries at least one signature from a
///    trusted log key; if none → 403. Unknown signatures are silently
///    ignored.
/// 4. Range check: `old_size <= checkpoint.size` → else 400.
/// 5. Atomic check-and-update against persisted *pending* state (via the
///    [`MirrorState`] DO): if `old_size` doesn't match the stored
///    pending size → 409 with the current size in a `text/x.tlog.size`
///    body.
/// 6. If `old_size == checkpoint.size`, the stored root hash must equal
///    the incoming root hash — otherwise → 409 (same body).
/// 7. Verify the consistency proof from the stored pending hash; on
///    failure → 422.
/// 8. Persist the new pending state atomically. The full signed-note
///    bytes are stored alongside size+hash so the mirror can later
///    serve them back to `add-entries` clients (per spec) — this also
///    satisfies the MUST-retain-the-signature requirement.
/// 9. Return 200 with an empty body. The mirror cosigner MUST NOT sign
///    here; cosignatures are emitted only by `add-entries` once entries
///    catch up to the pending tree size (a future slice).
///
/// Steps 5, 6, and 7 are combined inside the DO's `/update-pending` RPC
/// so the "check then verify proof then write" sequence is atomic per
/// origin.
///
/// [add-cp]: https://c2sp.org/tlog-mirror#add-checkpoint
/// [`MirrorState`]: crate::mirror_state_do
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
    // Per c2sp.org/tlog-witness (whose semantics the mirror inherits
    // here), the verifier accepts the checkpoint as soon as at least
    // one of the trusted log keys has signed it; signatures from
    // unknown keys are silently ignored. Both `UnverifiedNote` (no
    // signature line matches a trusted key at all) and
    // `InvalidSignature` (a signature line matches a trusted `(name,
    // id)` but the signature bytes fail to verify — a malformed note
    // per c2sp.org/signed-note) are surfaced as `403 Forbidden`,
    // matching the behavior of the witness implementation. Other
    // `NoteError` variants indicate a syntactically malformed
    // signature line and are surfaced as `400 Bad Request`.
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

    // (5, 6, 7, 8) Atomic check-proof-and-update against the per-origin
    // DO. See [`dispatch_update_pending`] for the status-code mapping.
    // The full signed-note bytes are passed in so the DO can persist
    // them alongside size+hash.
    let update = UpdatePendingRequest {
        old_size,
        new_size: cp_text.size(),
        new_hash: *cp_text.hash(),
        proof: consistency_proof,
        signed_note_bytes: checkpoint.text().to_vec(),
    };
    if let Some(resp) = dispatch_update_pending(&env, origin, &update).await? {
        return Ok(resp);
    }

    // (9) Spec: respond with an empty body. The mirror cosigner MUST
    // NOT sign here.
    Response::empty()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maximum size we are willing to buffer from an incoming
/// `add-checkpoint` request body. A well-formed request is an `old <N>`
/// line + up to [`tlog_witness::MAX_CONSISTENCY_PROOF_LINES`] (63)
/// base64 hash lines + a blank line + a checkpoint note of up to
/// `signed_note::MAX_NOTE_SIZE` (1 MiB); 1 MiB + 16 KiB of envelope
/// headroom comfortably covers that and rejects anything obviously too
/// large before it is allocated.
const MAX_ADD_CHECKPOINT_BODY_SIZE: usize = 1_024 * 1_024 + 16 * 1_024;

/// POST the [`UpdatePendingRequest`] to the per-origin DO, translating
/// the DO's status code into either:
///
///   * `Ok(None)` — success (200); the caller should return an empty
///     `Response`.
///   * `Ok(Some(resp))` — the DO responded with a non-200 status that
///     maps directly to the `add-checkpoint` HTTP response (409 with
///     `text/x.tlog.size` body, 422, or a forwarded 400).
///   * `Err(_)` — transport-level failure.
async fn dispatch_update_pending(
    env: &Env,
    origin: &str,
    update: &UpdatePendingRequest,
) -> Result<Option<Response>> {
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
        200 => {
            // Drain the body so we can drop the response.
            let _ = resp.bytes().await?;
            Ok(None)
        }
        409 => {
            let current: PendingCheckpoint = resp.json().await?;
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

/// Build the 409 response body per the witness/mirror spec:
/// `text/x.tlog.size` content type, decimal latest size followed by a
/// newline.
fn tlog_size_conflict(current: &PendingCheckpoint) -> Result<Response> {
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

    /// `description` is optional in the `/metadata` response. When
    /// absent it MUST be omitted from the JSON body (not serialized as
    /// `null`) so the wire shape matches what clients expect.
    #[test]
    fn metadata_description_omitted_when_none() {
        let log = LogMetadata {
            description: None,
            origin: "example.com/log",
            log_public_keys: vec![b"spki".as_slice()],
        };
        let body = MetadataResponse {
            mirror_name: "example.com/mirror",
            description: None,
            mirror_public_key: b"mirror-spki",
            mirror_algorithm: "subtree/v1",
            submission_prefix: "https://mirror.example.com/",
            monitoring_prefix: "https://mirror.example.com/",
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
            mirror_name: "example.com/mirror",
            description: Some("a mirror"),
            mirror_public_key: b"mirror-spki",
            mirror_algorithm: "subtree/v1",
            submission_prefix: "https://mirror.example.com/",
            monitoring_prefix: "https://mirror.example.com/",
            logs: vec![log],
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"description\":\"a mirror\""), "{json}");
        assert!(json.contains("\"description\":\"a log\""), "{json}");
    }

    /// Pin the `mirror_algorithm` field shape — it's a stable string
    /// that clients use to pick a verifier. Must be exactly
    /// `cosignature/v1` or `subtree/v1`.
    #[test]
    fn metadata_includes_mirror_algorithm() {
        let body = MetadataResponse {
            mirror_name: "example.com/mirror",
            description: None,
            mirror_public_key: b"k",
            mirror_algorithm: "subtree/v1",
            submission_prefix: "https://m.example/",
            monitoring_prefix: "https://m.example/",
            logs: vec![],
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(
            json.contains("\"mirror_algorithm\":\"subtree/v1\""),
            "missing or misnamed mirror_algorithm: {json}"
        );
    }

    /// `metadata_logs` returns entries sorted by origin so the
    /// `/metadata` response body is deterministic across worker
    /// isolates (regardless of `HashMap` iteration order).
    #[test]
    fn metadata_logs_sorted_by_origin() {
        use std::collections::HashMap;
        let mut logs = HashMap::new();
        logs.insert(
            "z.example/log".to_owned(),
            config::LogParams {
                description: None,
                log_public_keys: vec![b"z-spki".to_vec()],
            },
        );
        logs.insert(
            "a.example/log".to_owned(),
            config::LogParams {
                description: None,
                log_public_keys: vec![b"a-spki".to_vec()],
            },
        );
        logs.insert(
            "m.example/log".to_owned(),
            config::LogParams {
                description: None,
                log_public_keys: vec![b"m-spki".to_vec()],
            },
        );
        let out = super::metadata_logs(&logs);
        let origins: Vec<&str> = out.iter().map(|l| l.origin).collect();
        assert_eq!(
            origins,
            vec!["a.example/log", "m.example/log", "z.example/log"]
        );
    }
}
