// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Entrypoint for the static CT submission APIs.

use crate::{load_checkpoint_cosigner, load_origin, load_roots, SequenceMetadata, CONFIG};
use der::{
    asn1::{SetOfVec, UtcTime, Utf8StringRef},
    Any, Encode, Tag,
};
use generic_log_worker::{
    batcher_id_from_lookup_key, deserialize, get_durable_object_stub, init_logging,
    load_public_bucket,
    log_ops::{prove_subtree_inclusion, read_leaf, ProofError, CHECKPOINT_KEY},
    obs::Wshim,
    serialize,
    util::now_millis,
    ObjectBackend, ObjectBucket, ENTRY_ENDPOINT,
};
use mtc_api::{
    serialize_signatureless_cert, AddEntryRequest, AddEntryResponse, BootstrapMtcLogEntry,
    GetRootsResponse, LandmarkSequence, ID_RDNA_TRUSTANCHOR_ID, LANDMARK_BUNDLE_KEY, LANDMARK_KEY,
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use signed_note::VerifierList;
use std::time::Duration;
use tlog_tiles::{
    open_checkpoint, CheckpointSigner, CheckpointText, LeafIndex, PendingLogEntry,
    PendingLogEntryBlob,
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
/// Returns an error if any unhandled internal errors occur while processing the request.
///
/// # Panics
///
/// Panics if there are issues parsing route parameters, which should never happen.
#[event(fetch, respond_with_errors)]
async fn main(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let wshim = Wshim::from_env(&env);
    // Use an outer router as middleware to check that the log name is valid.
    let response = Router::new()
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
                    let cosigner = load_checkpoint_cosigner(&ctx.env, name);
                    Response::from_json(&MetadataResponse {
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
        });
    if let Ok(wshim) = wshim {
        ctx.wait_until(async move { wshim.flush(&generic_log_worker::obs::logs::LOGGER).await });
    }
    response
}

/// Builds the issuer RDN with the trust anchor ID.
fn build_issuer_rdn(log_id: &str) -> std::result::Result<RdnSequence, String> {
    let utf8_value = Utf8StringRef::new(log_id).map_err(|e| e.to_string())?;
    let any_value = Any::new(Tag::Utf8String, utf8_value.as_bytes()).map_err(|e| e.to_string())?;

    let attr = AttributeTypeAndValue {
        oid: ID_RDNA_TRUSTANCHOR_ID,
        value: any_value,
    };

    let rdn = RelativeDistinguishedName(
        SetOfVec::from_iter([attr]).expect("single attribute should always succeed"),
    );

    Ok(RdnSequence::from(vec![rdn]))
}

fn build_validity(now_millis: u64, max_lifetime_secs: u64) -> std::result::Result<Validity, String> {
    let now = Duration::from_millis(now_millis);
    let not_before = UtcTime::from_unix_duration(now).map_err(|e| e.to_string())?;
    let not_after =
        UtcTime::from_unix_duration(now + Duration::from_secs(max_lifetime_secs)).map_err(|e| e.to_string())?;

    Ok(Validity {
        not_before: Time::UtcTime(not_before),
        not_after: Time::UtcTime(not_after),
    })
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
    let leaf = Certificate::from_der(&chain[0]).map_err(|e| format!("failed to parse leaf: {e}"))?;
    let issuer_dn = &leaf.tbs_certificate.issuer;

    roots
        .find_by_subject(issuer_dn)
        .ok_or_else(|| format!("issuer not found in roots pool: {issuer_dn}"))?
        .to_der()
        .map_err(|e| format!("failed to encode issuer: {e}"))
}

#[allow(clippy::too_many_lines)]
async fn add_entry(mut req: Request, env: &Env, name: &str) -> Result<Response> {
    let params = &CONFIG.logs[name];
    let req: AddEntryRequest = req.json().await?;

    let issuer = build_issuer_rdn(&params.log_id).map_err(|e| e.to_string())?;
    let mut validity =
        build_validity(now_millis(), params.max_certificate_lifetime_secs as u64).map_err(|e| e.to_string())?;

    let roots = load_roots(env, name).await?;
    let (pending_entry, found_root_idx) =
        match mtc_api::validate_chain(&req.chain, roots, issuer, &mut validity) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("{name}: Bad request: {e}");
                return Response::error("Bad request", 400);
            }
        };

    // SCT validation (if enabled for this log shard)
    if params.enable_sct_validation {
        use crate::ct_logs_cron::load_ct_logs;
        use sct_validator::{SctValidationResult, SctValidator};

        // Load the CT log list from KV
        let ct_logs = load_ct_logs(env).await?;
        let validator = SctValidator::new(ct_logs);

        // Get leaf and issuer DER for SCT validation
        let leaf_der = req.chain.first().ok_or("Chain is empty")?;
        let issuer_der = resolve_issuer_for_sct(&req.chain, roots).map_err(|e| e.to_string())?;

        let validation_time_secs = now_millis() / 1000;

        match validator.validate_embedded_scts(leaf_der, &issuer_der, validation_time_secs) {
            Ok(SctValidationResult::Valid) => {
                log::info!("{name}: SCT validation passed");
            }
            Ok(SctValidationResult::ValidWithWarnings(warnings)) => {
                log::info!(
                    "{name}: SCT validation passed with {} warnings",
                    warnings.len()
                );
                for warning in &warnings {
                    log::debug!("{name}: SCT warning: {:?}", warning);
                }
            }
            Ok(SctValidationResult::StaleLogList) => {
                log::warn!("{name}: SCT validation skipped (stale log list)");
            }
            Err(e) => {
                log::warn!("{name}: SCT validation failed: {e}");
                return Response::error(format!("SCT validation failed: {e}"), 400);
            }
        }
    }

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

    // Fetch the current landmark bundle from R2 (already encoded in JSON) and return it
    let Some(landmark_bundle_bytes) = object_backend.fetch(LANDMARK_BUNDLE_KEY).await? else {
        return Err("failed to get landmark bundle".into());
    };

    Ok(ResponseBuilder::new()
        .with_header("content-type", "application/json")?
        .body(ResponseBody::Body(landmark_bundle_bytes)))
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
        LandmarkSequence::from_bytes(&landmark_sequence_bytes, params.max_landmarks())
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

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    #[test]
    fn test_build_issuer_rdn() {
        let rdn = build_issuer_rdn("test-log-id").unwrap();
        assert_eq!(rdn.0.len(), 1);

        let attr = rdn.0[0].0.iter().next().unwrap();
        assert_eq!(attr.oid, ID_RDNA_TRUSTANCHOR_ID);

        let encoded = attr.value.to_der().unwrap();
        assert_eq!(encoded[0], 0x0C); // UTF8String tag
    }

    #[test]
    fn test_build_validity() {
        let now_ms = 1_700_000_000_000_u64; // Nov 2023
        let lifetime_secs = 86400_u64; // 1 day

        let validity = build_validity(now_ms, lifetime_secs).unwrap();

        assert_eq!(validity.not_before.to_unix_duration().as_secs(), now_ms / 1000);
        assert_eq!(validity.not_after.to_unix_duration().as_secs(), now_ms / 1000 + lifetime_secs);
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
