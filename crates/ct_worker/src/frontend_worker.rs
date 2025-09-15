// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Entrypoint for the static CT submission APIs.

use crate::{load_roots, load_signing_key, SequenceMetadata, CONFIG};
use config::TemporalInterval;
use generic_log_worker::{
    batcher_id_from_lookup_key, deserialize, get_cached_metadata, get_durable_object_stub,
    init_logging, load_cache_kv, load_public_bucket, put_cache_entry_metadata, serialize,
    ObjectBucket, ENTRY_ENDPOINT, METRICS_ENDPOINT,
};
use p256::pkcs8::EncodePublicKey;
use serde::Serialize;
use serde_with::{base64::Base64, serde_as};
use static_ct_api::{AddChainRequest, GetRootsResponse, StaticCTLogEntry};
use tlog_tiles::{LogEntry, PendingLogEntry, PendingLogEntryBlob};
#[allow(clippy::wildcard_imports)]
use worker::*;
use x509_cert::der::Encode;

// The Maximum Merge Delay (MMD) of a log indicates the maximum period of time
// between when a SCT is issued and the corresponding entry is sequenced in the
// log. For Azul-based logs, this is effectively zero since SCT issuance happens
// only once the entry is sequenced. However, we can leave this value as the
// maximum allowed in Chrome's policy, 60 seconds, to allow future flexibility.
// For details, see https://github.com/C2SP/C2SP/issues/79.
const MAX_MERGE_DELAY_SECS: usize = 60;

const UNKNOWN_LOG_MSG: &str = "unknown log";

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
                .get_async("/logs/:log/ct/v1/get-roots", |_req, ctx| async move {
                    Response::from_json(&GetRootsResponse {
                        certificates: x509_util::certs_to_bytes(
                            &load_roots(&ctx.env, ctx.data).await?.certs,
                        )
                        .unwrap(),
                    })
                })
                .post_async("/logs/:log/ct/v1/add-chain", |req, ctx| async move {
                    add_chain_or_pre_chain(req, &ctx.env, ctx.data, false).await
                })
                .post_async("/logs/:log/ct/v1/add-pre-chain", |req, ctx| async move {
                    add_chain_or_pre_chain(req, &ctx.env, ctx.data, true).await
                })
                .get("/logs/:log/log.v3.json", |_req, ctx| {
                    let name = ctx.data;
                    let params = &CONFIG.logs[name];
                    let verifying_key = load_signing_key(&ctx.env, name)?.verifying_key();
                    let log_id = &static_ct_api::log_id_from_key(verifying_key)
                        .map_err(|e| e.to_string())?;
                    let key = verifying_key
                        .to_public_key_der()
                        .map_err(|e| e.to_string())?;
                    Response::from_json(&LogV3JsonResponse {
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
async fn add_chain_or_pre_chain(
    mut req: Request,
    env: &Env,
    name: &str,
    expect_precert: bool,
) -> Result<Response> {
    let params = &CONFIG.logs[name];
    if params.read_only {
        return Response::error(
            "The log is temporarily in read-only mode during maintenance. Please try again after 5 minutes.",
            503,
        )
        .map(|r| {
            let h = Headers::new();
            h.set("Retry-After", "300").unwrap();
            r.with_headers(h)
        });
    }
    let req: AddChainRequest = match req.json().await {
        Ok(req) => req,
        Err(e) => {
            log::debug!("{name}: Invalid JSON in add-(pre)chain request: {e}");
            return Response::error("Invalid JSON in add-[pre-]chain request", 400);
        }
    };

    // Temporal interval dates prior to the Unix epoch are treated as the Unix epoch.
    let roots = load_roots(env, name).await?;
    let (pending_entry, found_root_idx) = match static_ct_api::partially_validate_chain(
        &req.chain,
        roots,
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
            log::debug!("{name}: Bad request: {e}");
            return Response::error("Bad request", 400);
        }
    };

    // Retrieve the sequenced entry for this pending log entry by first checking the
    // deduplication cache and then sending a request to the DO to sequence the entry.
    let lookup_key = pending_entry.lookup_key();
    let signing_key = load_signing_key(env, name)?;

    // Check if entry is cached and return right away if so.
    if params.enable_dedup {
        if let Some(metadata) = get_cached_metadata(&load_cache_kv(env, name)?, &lookup_key).await?
        {
            log::debug!("{name}: Entry is cached");
            let entry = StaticCTLogEntry::new(pending_entry, metadata);
            let sct = static_ct_api::signed_certificate_timestamp(signing_key, &entry)
                .map_err(|e| e.to_string())?;
            return Response::from_json(&sct);
        }
    }

    // Entry is not cached, so we need to sequence it.

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
    if params.num_batchers == 0 && params.enable_dedup {
        // Write sequenced entry to the long-term deduplication cache in Workers
        // KV as there are no batchers configured to do it for us.
        if put_cache_entry_metadata(&load_cache_kv(env, name)?, &pending_entry, metadata)
            .await
            .is_err()
        {
            log::warn!("{name}: Failed to write entry to deduplication cache");
        }
    }
    let entry = StaticCTLogEntry {
        inner: pending_entry,
        leaf_index: metadata.0,
        timestamp: metadata.1,
    };
    let sct = static_ct_api::signed_certificate_timestamp(signing_key, &entry)
        .map_err(|e| e.to_string())?;
    Response::from_json(&sct)
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
