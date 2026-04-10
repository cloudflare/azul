// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Frontend worker for the IETF MTC submission API.

use crate::{load_checkpoint_cosigner, load_origin, CONFIG};
use ietf_mtc_api::IetfSequenceMetadata;
use der::{
    asn1::{UtcTime, Utf8StringRef},
    Any, Decode, Tag,
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
use ietf_mtc_api::{
    build_pending_entry, serialize_mtc_cert, AddEntryRequest, AddEntryResponse, IetfMtcLogEntry,
    LandmarkSequence, SignedSubtree, TrustAnchorID, ID_RDNA_TRUSTANCHOR_ID, LANDMARK_BUNDLE_KEY,
    LANDMARK_KEY,
};
use std::str::FromStr;
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
    /// DER-encoded `SubjectPublicKeyInfo` of the cosigner's verifying key,
    /// base64-encoded. Includes the algorithm identifier so clients can
    /// determine the signing algorithm without out-of-band information.
    #[serde_as(as = "Base64")]
    cosigner_public_key: Vec<u8>,
    submission_url: &'a str,
    monitoring_url: &'a str,
}

/// POST body for the `/get-certificate` endpoint.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct GetCertificateRequest {
    pub leaf_index: LeafIndex,

    #[serde_as(as = "Base64")]
    pub spki_der: Vec<u8>,
}

/// GET response for the `/get-certificate` endpoint.
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

            Router::with_data(name)
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
                        let headers = Headers::new();
                        let i = params.landmark_interval_secs as u64;
                        headers
                            .set("Retry-After", &format!("{}", i - (now_millis() / 1000) % i))?;
                        return Response::error("Leaf index will be covered by next landmark", 503)
                            .map(|r| r.with_headers(headers));
                    };

                    let log_entry = read_leaf::<IetfMtcLogEntry>(
                        &object_backend,
                        leaf_index,
                        checkpoint.size(),
                        checkpoint.hash(),
                    )
                    .await
                    .map_err(|e| e.to_string())?;

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

                    let data = match serialize_mtc_cert(
                        &log_entry,
                        leaf_index,
                        &spki_der,
                        &landmark_subtree,
                        proof,
                        &[], // landmark-relative: no cosignatures
                    ) {
                        Ok(data) => data,
                        Err(e) => {
                            return Response::error(
                                format!("Failed to serialize landmark-relative cert: {e}"),
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
                    let name = ctx.data;
                    let namespace = ctx.env.durable_object("SEQUENCER")?;
                    let object_id = namespace.id_from_name(name)?;
                    Response::ok(object_id.to_string())
                })
                .get_async("/logs/:log/*key", |_req, ctx| async move {
                    let name = ctx.data;
                    let key = ctx.param("key").unwrap();
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

/// Builds the issuer RDN containing the log's Trust Anchor ID.
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

/// Compute the validity window for a new entry.
///
/// `not_before` is the current time; `not_after` is `not_before +
/// max_lifetime_secs`.
///
/// ACME order `notBefore`/`notAfter` fields are not currently supported;
/// the validity window is always determined by the server's policy.
fn build_validity(
    now_millis: u64,
    max_lifetime_secs: u64,
) -> std::result::Result<Validity, String> {
    let not_before = Duration::from_millis(now_millis);
    let not_after = not_before + Duration::from_secs(max_lifetime_secs);

    Ok(Validity::new(
        Time::UtcTime(UtcTime::from_unix_duration(not_before).map_err(|e| e.to_string())?),
        Time::UtcTime(UtcTime::from_unix_duration(not_after).map_err(|e| e.to_string())?),
    ))
}

async fn add_entry(mut req: Request, env: &Env, name: &str) -> Result<Response> {
    let params = &CONFIG.logs[name];
    let req: AddEntryRequest = match req.json().await {
        Ok(r) => r,
        Err(e) => {
            log::warn!("{name}: Bad request: {e}");
            return Response::error("Bad request", 400);
        }
    };

    let issuer = build_issuer_rdn(&params.log_id)?;
    let validity = match build_validity(
        now_millis(),
        params.max_certificate_lifetime_secs as u64,
    ) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("{name}: Bad request: {e}");
            return Response::error("Bad request", 400);
        }
    };

    let pending_entry = match build_pending_entry(&req, &issuer, validity) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("{name}: Bad request: {e}");
            return Response::error("Bad request", 400);
        }
    };

    let lookup_key = pending_entry.lookup_key();

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
        return Ok(response);
    }
    let metadata = deserialize::<IetfSequenceMetadata>(&response.bytes().await?)?;
    let leaf_index = metadata.leaf_index;

    // Build the standalone certificate from the subtree signature cached by
    // the sequencer.  The checkpoint_callback runs before the sequencer
    // returns, so the signature should always be present at this point.
    let Some(certificate) = build_standalone_cert(env, name, leaf_index, metadata.old_tree_size, metadata.new_tree_size, &req).await else {
        log::warn!("{name}: subtree sig not found for leaf {leaf_index} after sequencing");
        return Response::error("Service unavailable: subtree signature not yet available", 503);
    };

    Response::from_json(&AddEntryResponse { certificate })
}

/// Try to build a standalone certificate for `leaf_index` using a cached
/// subtree signature.  Returns `None` if no matching signature is available
/// yet (the client should retry); logs warnings on unexpected errors.
/// Maximum number of retries waiting for a subtree signature to appear in R2.
const MAX_SIG_RETRIES: u32 = 6;
/// Delay between retries in milliseconds.
const SIG_RETRY_DELAY_MS: u64 = 250;

async fn build_standalone_cert(
    env: &Env,
    name: &str,
    leaf_index: LeafIndex,
    old_tree_size: u64,
    new_tree_size: u64,
    req: &AddEntryRequest,
) -> Option<Vec<u8>> {
    use ietf_mtc_api::subtree_sig_key;

    let object_bucket = ObjectBucket::new(load_public_bucket(env, name).ok()?);

    // Compute the exact subtree containing leaf_index using the batch tree
    // size range from IetfSequenceMetadata.
    let (left, right) = tlog_tiles::Subtree::split_interval(old_tree_size, new_tree_size).ok()?;
    let subtree = [Some(left), right]
        .into_iter()
        .flatten()
        .find(|s| s.lo() <= leaf_index && leaf_index < s.hi())?;
    let key = subtree_sig_key(subtree.lo(), subtree.hi());

    let mut signed: Option<SignedSubtree> = None;
    for _ in 0..MAX_SIG_RETRIES {
        let Some(raw) = object_bucket.fetch(&key).await.ok().flatten() else {
            worker::Delay::from(std::time::Duration::from_millis(SIG_RETRY_DELAY_MS)).await;
            continue;
        };
        if let Ok(s) = serde_json::from_slice::<SignedSubtree>(&raw) {
            signed = Some(s);
            break;
        }
        worker::Delay::from(std::time::Duration::from_millis(SIG_RETRY_DELAY_MS)).await;
    }
    let signed = signed?;

    let subtree = signed.as_subtree().ok()?;
    let cosigner_id = TrustAnchorID::from_str(&signed.cosigner_id).ok()?;
    let checkpoint_hash = tlog_tiles::Hash(signed.checkpoint_hash);

    // Parse the CSR to extract the SPKI.
    let csr = x509_cert::request::CertReq::from_der(&req.csr).ok()?;
    let spki_der = der::Encode::to_der(&csr.info.public_key).ok()?;

    // Read the sequenced log entry from the data tile.
    let log_entry = generic_log_worker::log_ops::read_leaf::<IetfMtcLogEntry>(
        &object_bucket,
        leaf_index,
        signed.checkpoint_size,
        &checkpoint_hash,
    )
    .await
    .ok()?;

    // Compute an inclusion proof of leaf_index into the subtree.
    let proof = match generic_log_worker::log_ops::prove_subtree_inclusion(
        signed.checkpoint_size,
        checkpoint_hash,
        subtree.lo(),
        subtree.hi(),
        leaf_index,
        &object_bucket,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            log::warn!("{name}: subtree inclusion proof failed for leaf {leaf_index}: {e:?}");
            return None;
        }
    };

    serialize_mtc_cert(
        &log_entry,
        leaf_index,
        &spki_der,
        &subtree,
        proof,
        &[(cosigner_id, signed.signature)],
    )
    .ok()
}

async fn get_landmark_bundle(env: &Env, name: &str) -> Result<Response> {
    let object_backend = ObjectBucket::new(load_public_bucket(env, name)?);
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
        LandmarkSequence::from_bytes(&landmark_sequence_bytes, params.max_active_landmarks())
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
        assert_eq!(rdn.as_ref().len(), 1);
        let attr = rdn.as_ref()[0].as_ref().iter().next().unwrap();
        assert_eq!(attr.oid, ID_RDNA_TRUSTANCHOR_ID);
        let encoded = attr.value.to_der().unwrap();
        assert_eq!(encoded[0], 0x0C); // UTF8String tag
    }

    #[test]
    fn test_build_validity() {
        let now_ms = 1_700_000_000_000_u64; // milliseconds
        let max_lifetime = 86400_u64; // 1 day

        let validity = build_validity(now_ms, max_lifetime).unwrap();
        assert_eq!(
            validity.not_before.to_unix_duration().as_secs(),
            now_ms / 1000
        );
        assert_eq!(
            validity.not_after.to_unix_duration().as_secs(),
            now_ms / 1000 + max_lifetime
        );
    }
}
