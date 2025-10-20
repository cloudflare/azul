// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Entrypoint for the static CT submission APIs.

use crate::{
    load_checkpoint_signers, load_origin, load_roots, load_signing_key, SequenceMetadata, CONFIG,
};
use der::{
    asn1::{SetOfVec, UtcTime, Utf8StringRef},
    Any, Encode, Tag,
};
use generic_log_worker::{
    batcher_id_from_lookup_key, deserialize, get_durable_object_stub, init_logging,
    load_public_bucket,
    log_ops::{
        prove_subtree_consistency, prove_subtree_inclusion, read_leaf, ProofError, CHECKPOINT_KEY,
    },
    serialize,
    util::now_millis,
    ObjectBackend, ObjectBucket, ENTRY_ENDPOINT, METRICS_ENDPOINT,
};
use mtc_api::{
    serialize_signatureless_cert, AddEntryRequest, AddEntryResponse, BootstrapMtcLogEntry,
    GetRootsResponse, LandmarkSequence, ID_RDNA_TRUSTANCHOR_ID, LANDMARK_KEY,
};
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use signed_note::{NoteVerifier, VerifierList};
use std::time::Duration;
use tlog_tiles::{
    open_checkpoint, CheckpointText, LeafIndex, PendingLogEntry, PendingLogEntryBlob,
};
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_cert::{
    attr::AttributeTypeAndValue,
    name::{RdnSequence, RelativeDistinguishedName},
    time::{Time, Validity},
};

const UNKNOWN_LOG_MSG: &str = "unknown log";

#[serde_as]
#[derive(Serialize)]
struct MetadataResponse<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: &'a Option<String>,
    #[serde_as(as = "Base64")]
    key: &'a [u8],
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

/// GET response structure for the `/get-landmark-bundle` endpoint
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct GetLandmarkBundleResponse {
    #[serde_as(as = "Base64")]
    pub checkpoint: Vec<u8>,
    pub subtrees: Vec<SubtreeWithConsistencyProof>,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SubtreeWithConsistencyProof {
    pub start: u64,
    pub end: u64,
    #[serde_as(as = "Vec<Base64>")]
    pub consistency_proof: Vec<Vec<u8>>,
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
/// Returns an error if any unhandled internal errors occur while processing the request.
///
/// # Panics
///
/// Panics if there are issues parsing route parameters, which should never happen.
#[event(fetch, respond_with_errors)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Use an outer router as middleware to check that the log name is valid.
    Router::new()
        .or_else_any_method_async("/logs/:log/*route", |req, ctx| async move {
            let name = if let Some(name) = ctx.param("log") {
                if CONFIG.logs.contains_key(name) {
                    &name.clone()
                } else {
                    return Err(UNKNOWN_LOG_MSG.into());
                }
            } else {
                return Err("missing 'log' route param".into());
            };

            // Now that we've validated the log name, use an inner router to
            // handle the request.
            Router::with_data(name)
                .get_async("/logs/:log/get-roots", |_req, ctx| async move {
                    Response::from_json(&GetRootsResponse {
                        certificates: x509_util::certs_to_bytes(
                            &load_roots(&ctx.env, ctx.data).await?.certs,
                        )
                        .unwrap(),
                    })
                })
                .post_async("/logs/:log/add-entry", |req, ctx| async move {
                    add_entry(req, &ctx.env, ctx.data).await
                })
                .post_async("/logs/:log/get-certificate", |mut req, ctx| async move {
                    let name = ctx.data;
                    let params = &CONFIG.logs[name];
                    let Ok(GetCertificateRequest {
                        leaf_index,
                        spki_der,
                    }) = req.json().await
                    else {
                        return Response::error("Unexpected input", 400);
                    };
                    let object_backend = ObjectBucket::new(load_public_bucket(&ctx.env, name)?);
                    // Fetch the current checkpoint to know which tiles to fetch
                    // (full or partials).
                    let (checkpoint, _checkpoint_bytes) =
                        get_current_checkpoint(&ctx.env, name, &object_backend).await?;
                    if leaf_index >= checkpoint.size() {
                        return Response::error("Leaf index is not in log", 422);
                    }

                    let seq = get_landmark_sequence(name, &object_backend).await?;
                    if leaf_index < seq.first_index() {
                        return Response::error("Leaf index is before first active landmark", 422);
                    }
                    let Some((landmark_id, landmark_subtree)) = seq.subtree_for_index(leaf_index)
                    else {
                        // The leaf index might be between the latest landmark
                        // and the current tree size. Set Retry-After to the
                        // expected time for the next landmark so the client can
                        // try again later.
                        let headers = Headers::new();
                        let i = params.landmark_interval_secs as u64;
                        headers
                            .set("Retry-After", &format!("{}", i - (now_millis() / 1000) % i))?;
                        return Response::error("Leaf index will be covered by next landmark", 503)
                            .map(|r| r.with_headers(headers));
                    };

                    // Fetch the log entry for the leaf index.
                    let log_entry = read_leaf::<BootstrapMtcLogEntry>(
                        &object_backend,
                        leaf_index,
                        checkpoint.size(),
                        checkpoint.hash(),
                    )
                    .await
                    .map_err(|e| e.to_string())?;

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
                        Err(ProofError::Tlog(s)) => return Response::error(s.to_string(), 422),
                        Err(ProofError::Other(e)) => return Err(e.to_string().into()),
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
                        Err(e) => {
                            return Response::error(
                                format!("Failed to serialize signatureless cert: {e}"),
                                422,
                            )
                        }
                    };

                    Response::from_json(&GetCertificateResponse { data, landmark_id })
                })
                .get_async("/logs/:log/get-landmark-bundle", |_req, ctx| async move {
                    get_landmark_bundle(&ctx.env, ctx.data).await
                })
                .get("/logs/:log/metadata", |_req, ctx| {
                    let name = ctx.data;
                    let params = &CONFIG.logs[name];
                    let verifying_key = load_signing_key(&ctx.env, name)?.verifying_key();
                    let key = verifying_key
                        .to_public_key_der()
                        .map_err(|e| e.to_string())?;
                    Response::from_json(&MetadataResponse {
                        description: &params.description,
                        key: key.as_bytes(),
                        submission_url: &params.submission_url,
                        monitoring_url: if params.monitoring_url.is_empty() {
                            &params.submission_url
                        } else {
                            &params.monitoring_url
                        },
                    })
                })
                .get_async("/logs/:log/metrics", |_req, ctx| async move {
                    let name = ctx.data;
                    let stub = get_durable_object_stub(
                        &ctx.env,
                        name,
                        None,
                        "SEQUENCER",
                        CONFIG.logs[name].location_hint.as_deref(),
                    )?;
                    stub.fetch_with_str(&format!("http://fake_url.com{METRICS_ENDPOINT}"))
                        .await
                })
                .get("/logs/:log/sequencer_id", |_req, ctx| {
                    // Print out the Durable Object ID of the sequencer to allow
                    // looking it up in internal Cloudflare dashboards. This
                    // value does not need to be kept secret.
                    let name = ctx.data;
                    let namespace = ctx.env.durable_object("SEQUENCER")?;
                    let object_id = namespace.id_from_name(name)?;
                    Response::ok(object_id.to_string())
                })
                .get_async("/logs/:log/*key", |_req, ctx| async move {
                    let name = ctx.data;
                    let key = ctx.param("key").unwrap();

                    // Enable direct access to the bucket via the Worker if
                    // monitoring_url is unspecified.
                    if CONFIG.logs[name].monitoring_url.is_empty() {
                        let bucket = load_public_bucket(&ctx.env, name)?;
                        if let Some(obj) = bucket.get(key).execute().await? {
                            Response::from_body(
                                obj.body()
                                    .ok_or("R2 object missing body")?
                                    .response_body()?,
                            )
                            .map(|r| {
                                r.with_headers(headers_from_http_metadata(obj.http_metadata()))
                            })
                        } else {
                            Response::error("Not found", 404)
                        }
                    } else {
                        Response::error(
                            format!(
                                "Use {} for monitoring API",
                                CONFIG.logs[name].monitoring_url
                            ),
                            404,
                        )
                    }
                })
                .run(req, ctx.env)
                .await
        })
        .run(req, env)
        .await
        .or_else(|e| match e {
            Error::RustError(ref msg) if msg == UNKNOWN_LOG_MSG => {
                Response::error("Unknown log", 400)
            }
            _ => {
                log::warn!("Internal error: {e}");
                Response::error("Internal error", 500)
            }
        })
}

#[allow(clippy::too_many_lines)]
async fn add_entry(mut req: Request, env: &Env, name: &str) -> Result<Response> {
    let params = &CONFIG.logs[name];
    let req: AddEntryRequest = req.json().await?;

    let issuer = RdnSequence::from(vec![RelativeDistinguishedName(
        SetOfVec::from_iter([AttributeTypeAndValue {
            oid: ID_RDNA_TRUSTANCHOR_ID,
            value: Any::new(
                Tag::Utf8String,
                Utf8StringRef::new(&params.log_id)
                    .map_err(|e| e.to_string())?
                    .as_bytes(),
            )
            .map_err(|e| e.to_string())?,
        }])
        .unwrap(),
    )]);

    let now = Duration::from_millis(now_millis());
    let mut validity = Validity {
        not_before: Time::UtcTime(UtcTime::from_unix_duration(now).map_err(|e| e.to_string())?),
        not_after: Time::UtcTime(
            UtcTime::from_unix_duration(
                now + Duration::from_secs(params.max_certificate_lifetime_secs as u64),
            )
            .map_err(|e| e.to_string())?,
        ),
    };

    let roots = load_roots(env, name).await?;
    let (pending_entry, found_root_idx) =
        match mtc_api::validate_chain(&req.chain, roots, issuer, &mut validity) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("{name}: Bad request: {e}");
                return Response::error("Bad request", 400);
            }
        };

    // Retrieve the sequenced entry for this pending log entry by sending a request to the DO to
    // sequence the entry.
    let lookup_key = pending_entry.lookup_key();

    // First persist issuers. Use a block so memory is deallocated sooner.
    {
        let public_bucket = ObjectBucket::new(load_public_bucket(env, name)?);
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

        generic_log_worker::upload_issuers(&public_bucket, &issuers, name).await?;
    }

    // Submit entry to be sequenced, either via a batcher or directly to the
    // sequencer.
    let stub = {
        let shard_id = batcher_id_from_lookup_key(&lookup_key, params.num_batchers);
        get_durable_object_stub(
            env,
            name,
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
        return Ok(response);
    }
    let metadata = deserialize::<SequenceMetadata>(&response.bytes().await?)?;
    Response::from_json(&AddEntryResponse {
        leaf_index: metadata.0,
        timestamp: metadata.1,
        not_before: validity.not_before.to_unix_duration().as_secs(),
        not_after: validity.not_after.to_unix_duration().as_secs(),
    })
}

async fn get_landmark_bundle(env: &Env, name: &str) -> Result<Response> {
    let object_backend = ObjectBucket::new(load_public_bucket(env, name)?);

    // Fetch the current checkpoint.
    let (checkpoint, checkpoint_bytes) = get_current_checkpoint(env, name, &object_backend).await?;

    // Fetch the current landmark sequence.
    let landmark_sequence = get_landmark_sequence(name, &object_backend).await?;

    // Compute the sequence of landmark subtrees and, for each subtree, a proof of consistency with
    // the checkpoint. Each signatureless MTC includes an inclusion proof in one of these subtrees.
    let mut subtrees = Vec::new();
    for landmark_subtree in landmark_sequence.subtrees() {
        let consistency_proof = match prove_subtree_consistency(
            *checkpoint.hash(),
            checkpoint.size(),
            landmark_subtree.lo(),
            landmark_subtree.hi(),
            &object_backend,
        )
        .await
        {
            Ok(p) => p,
            Err(ProofError::Tlog(s)) => return Response::error(s.to_string(), 422),
            Err(ProofError::Other(e)) => return Err(e.to_string().into()),
        };

        subtrees.push(SubtreeWithConsistencyProof {
            start: landmark_subtree.lo(),
            end: landmark_subtree.hi(),
            consistency_proof: consistency_proof.iter().map(|h| h.0.to_vec()).collect(),
        });
    }

    Response::from_json(&GetLandmarkBundleResponse {
        checkpoint: checkpoint_bytes,
        subtrees,
    })
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
    let verifiers = &VerifierList::new(
        load_checkpoint_signers(env, name)
            .iter()
            .map(|s| s.verifier())
            .collect::<Vec<Box<dyn NoteVerifier>>>(),
    );
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

    let max_landmarks = params
        .max_certificate_lifetime_secs
        .div_ceil(params.landmark_interval_secs)
        + 1;

    let landmark_sequence = LandmarkSequence::from_bytes(&landmark_sequence_bytes, max_landmarks)
        .map_err(|e| e.to_string())?;

    Ok(landmark_sequence)
}

fn headers_from_http_metadata(meta: HttpMetadata) -> Headers {
    let h = Headers::new();
    if let Some(hdr) = meta.cache_control {
        h.append("Cache-Control", &hdr).unwrap();
    }
    if let Some(hdr) = meta.content_encoding {
        h.append("Content-Encoding", &hdr).unwrap();
    }
    if let Some(hdr) = meta.content_type {
        h.append("Content-Type", &hdr).unwrap();
    }
    h
}
