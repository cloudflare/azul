// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Entrypoint for the static CT submission APIs.

use crate::{
    ctlog, get_stub, load_cache_kv, load_public_bucket, load_signing_key, load_witness_key, util,
    CacheKey, CacheValue, ObjectBucket, CONFIG, ROOTS,
};
use base64::prelude::*;
use config::TemporalInterval;
use log::{debug, warn, Level};
use p256::pkcs8::EncodePublicKey;
use serde::Serialize;
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use static_ct_api::{AddChainRequest, GetRootsResponse, LogEntry, UnixTimestamp};
use std::str::FromStr;
#[allow(clippy::wildcard_imports)]
use worker::*;

// The Maximum Merge Delay (MMD) of a log indicates the maximum period of time
// between when a SCT is issued and the corresponding entry is sequenced
// in the log. For static CT logs, this is effectively zero since SCT issuance
// happens only once the entry is sequenced. However, we can leave this value
// in the metadata as the default (1 day).
const MAX_MERGE_DELAY: usize = 86_400;

// Number of Batchers to use to proxy requests to the Sequencer.
// Setting this too high could result in a high number of requests
// to the Sequencer, which may slow down the sequencing loop.
// Setting this too low could cause individual Batchers to hit the
// Durable Objects rate limits.
const NUM_BATCHER_PROXIES: u8 = 8;

const UNKNOWN_LOG_MSG: &str = "unknown log";

#[serde_as]
#[derive(Serialize)]
struct MetadataResponse<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_type: &'a Option<String>,
    #[serde_as(as = "Base64")]
    log_id: &'a [u8],
    #[serde_as(as = "Base64")]
    key: &'a [u8],
    #[serde_as(as = "Base64")]
    witness_key: &'a [u8],
    mmd: usize,
    submission_url: &'a str,
    monitoring_url: &'a str,
    temporal_interval: &'a TemporalInterval,
}

#[event(start)]
fn start() {
    let level = CONFIG
        .logging_level
        .as_ref()
        .and_then(|level| Level::from_str(level).ok())
        .unwrap_or(Level::Info);
    util::init_logging(level);
    console_error_panic_hook::set_once();
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
    let router = Router::new();
    router
        .get("/logs/:log/ct/v1/get-roots", |_req, ctx| {
            let _name = valid_log_name(&ctx)?;
            Response::from_json(&GetRootsResponse {
                certificates: static_ct_api::certs_to_bytes(&ROOTS.certs).unwrap(),
            })
        })
        .post_async("/logs/:log/ct/v1/add-chain", |req, ctx| async move {
            add_chain_or_pre_chain(req, &ctx.env, valid_log_name(&ctx)?, false).await
        })
        .post_async("/logs/:log/ct/v1/add-pre-chain", |req, ctx| async move {
            add_chain_or_pre_chain(req, &ctx.env, valid_log_name(&ctx)?, true).await
        })
        .get("/logs/:log/metadata", |_req, ctx| {
            let name = valid_log_name(&ctx)?;
            let params = &CONFIG.logs[name];
            let verifying_key = load_signing_key(&ctx.env, name)?.verifying_key();
            let log_id = &static_ct_api::log_id_from_key(verifying_key)
                .map_err(|e| e.to_string())?
                .to_vec();
            let key = verifying_key
                .to_public_key_der()
                .map_err(|e| e.to_string())?;
            let witness_key = load_witness_key(&ctx.env, name)?;
            let witness_key = witness_key
                .verifying_key()
                .to_public_key_der()
                .map_err(|e| e.to_string())?;
            Response::from_json(&MetadataResponse {
                description: &params.description,
                log_type: &params.log_type,
                log_id,
                key: key.as_bytes(),
                witness_key: witness_key.as_bytes(),
                submission_url: &params.submission_url,
                monitoring_url: if params.monitoring_url.is_empty() {
                    &params.submission_url
                } else {
                    &params.monitoring_url
                },
                mmd: MAX_MERGE_DELAY,
                temporal_interval: &params.temporal_interval,
            })
        })
        .get_async("/logs/:log/metrics", |_req, ctx| async move {
            let name = valid_log_name(&ctx)?;
            let stub = get_stub(&ctx.env, name, None, "SEQUENCER")?;
            stub.fetch_with_str(&format!("http://fake_url.com/metrics?name={name}"))
                .await
        })
        .get_async("/logs/:log/*key", |_req, ctx| async move {
            let name = valid_log_name(&ctx)?;
            let key = ctx.param("key").unwrap();

            let bucket = load_public_bucket(&ctx.env, name)?;
            if let Some(obj) = bucket.get(key).execute().await? {
                Response::from_body(
                    obj.body()
                        .ok_or("R2 object missing body")?
                        .response_body()?,
                )
                .map(|r| r.with_headers(headers_from_http_metadata(obj.http_metadata())))
            } else {
                Response::error("Not found", 404)
            }
        })
        .run(req, env)
        .await
        .or_else(|e| match e {
            Error::RustError(ref msg) if msg == UNKNOWN_LOG_MSG => {
                Response::error("Unknown log", 400)
            }
            _ => {
                warn!("Internal error: {e}");
                Response::error("Internal error", 500)
            }
        })
}

#[allow(clippy::too_many_lines)]
async fn add_chain_or_pre_chain(
    mut req: Request,
    env: &Env,
    name: &str,
    expect_precert: bool,
) -> Result<Response> {
    let params = &CONFIG.logs[name];
    let req: AddChainRequest = req.json().await?;

    // Temporal interval dates prior to the Unix epoch are treated as the Unix epoch.
    let chain = match static_ct_api::validate_chain(
        &req.chain,
        &ROOTS,
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
            debug!("{name}: Bad request: {e}");
            return Response::error("Bad request", 400);
        }
    };

    // Retrieve the sequenced entry for this pending log entry by first checking the
    // deduplication cache and then sending a request to the DO to sequence the entry.

    // Convert chain to a pending log entry.
    let mut entry = LogEntry {
        certificate: chain.certificate,
        is_precert: chain.is_precert,
        issuer_key_hash: chain.issuer_key_hash,
        chain_fingerprints: chain
            .issuers
            .iter()
            .map(|issuer| Sha256::digest(issuer).into())
            .collect(),
        pre_certificate: chain.pre_certificate,
        leaf_index: 0,
        timestamp: 0,
    };
    let hash =
        ctlog::compute_cache_hash(entry.is_precert, &entry.certificate, &entry.issuer_key_hash);
    let signing_key = load_signing_key(env, name)?;

    // Check if entry is cached and return right away if so.
    let kv = load_cache_kv(env, name)?;
    if let Some(v) = kv
        .get(&BASE64_STANDARD.encode(hash))
        .bytes_with_metadata::<CacheValue>()
        .await?
        .1
    {
        debug!("{name}: Entry is cached");
        (entry.leaf_index, entry.timestamp) = v;
        return Response::from_json(&static_ct_api::signed_certificate_timestamp(
            signing_key,
            &entry,
        ));
    }

    // Entry is not cached, so we need to sequence it.

    // First persist issuers.
    let public_bucket = ObjectBucket {
        sequence_interval: params.sequence_interval,
        bucket: load_public_bucket(env, name)?,
        metrics: None,
    };
    ctlog::upload_issuers(
        &public_bucket,
        &chain
            .issuers
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<&[u8]>>(),
        name,
    )
    .await?;

    // Add leaf to the Batcher, which will submit the entry to the Sequencer,
    // wait for the entry to be sequenced, and return the response.
    let shard_id = shard_id_from_cache_key(&hash);
    let batcher_stub = get_stub(env, name, Some(shard_id), "BATCHER")?;
    let mut response = batcher_stub
        .fetch_with_request(Request::new_with_init(
            &format!("http://fake_url.com/add_leaf?name={name}"),
            &RequestInit {
                method: Method::Post,
                body: Some(serde_json::to_string(&entry)?.into()),
                ..Default::default()
            },
        )?)
        .await?;
    if response.status_code() != 200 {
        // Return the response from the Batcher directly to the client.
        return Ok(response);
    }
    let (leaf_index, timestamp) = response.json::<(u64, UnixTimestamp)>().await?;
    entry.leaf_index = leaf_index;
    entry.timestamp = timestamp;
    Response::from_json(&static_ct_api::signed_certificate_timestamp(
        signing_key,
        &entry,
    ))
}

fn valid_log_name(ctx: &RouteContext<()>) -> Result<&str> {
    if let Some(name) = ctx.param("log") {
        if CONFIG.logs.contains_key(name) {
            Ok(name)
        } else {
            Err(UNKNOWN_LOG_MSG.into())
        }
    } else {
        Err("missing 'log' route param".into())
    }
}

fn shard_id_from_cache_key(key: &CacheKey) -> u8 {
    key[0] % NUM_BATCHER_PROXIES
}

fn headers_from_http_metadata(meta: HttpMetadata) -> Headers {
    let mut h = Headers::new();
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
