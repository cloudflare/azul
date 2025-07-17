// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Entrypoint for the static CT submission APIs.

use std::{str::FromStr, sync::LazyLock, time::Duration};

use crate::{load_signing_key, load_witness_key, LookupKey, SequenceMetadata, CONFIG, ROOTS};
use der::{
    asn1::{SetOfVec, UtcTime},
    Any, Tag,
};
use futures_util::future::try_join_all;
use generic_log_worker::{
    get_cached_metadata, get_durable_object_stub, init_logging, load_cache_kv, load_public_bucket,
    log_ops::UploadOptions, put_cache_entry_metadata, util::now_millis, ObjectBackend,
    ObjectBucket, ProveInclusionQuery, ENTRY_ENDPOINT, METRICS_ENDPOINT, PROVE_INCLUSION_ENDPOINT,
};
use log::{debug, info, warn};
use mtc_api::{AddEntryRequest, AddEntryResponse, RelativeOid, ID_RDNA_TRUSTANCHOR_ID};
use p256::pkcs8::EncodePublicKey;
use serde::Serialize;
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest, Sha256};
use tlog_tiles::PendingLogEntry;
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
    #[serde_as(as = "Base64")]
    witness_key: &'a [u8],
    submission_url: &'a str,
    monitoring_url: &'a str,
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
    let router = Router::new();
    router
        .post_async("/logs/:log/add-entry", |req, ctx| async move {
            add_entry(req, &ctx.env, valid_log_name(&ctx)?).await
        })
        .get_async("/logs/:log/prove-inclusion", |req, ctx| async move {
            let name = valid_log_name(&ctx)?;
            let stub = get_durable_object_stub(
                &ctx.env,
                name,
                None,
                "SEQUENCER",
                CONFIG.logs[name].location_hint.as_deref(),
            )?;
            let ProveInclusionQuery { leaf_index } = req.query()?;
            stub.fetch_with_str(&format!(
                "http://fake_url.com{PROVE_INCLUSION_ENDPOINT}?leaf_index={leaf_index}"
            ))
            .await
        })
        .get("/logs/:log/metadata", |_req, ctx| {
            let name = valid_log_name(&ctx)?;
            let params = &CONFIG.logs[name];
            let verifying_key = load_signing_key(&ctx.env, name)?.verifying_key();
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
                key: key.as_bytes(),
                witness_key: witness_key.as_bytes(),
                submission_url: &params.submission_url,
                monitoring_url: if params.monitoring_url.is_empty() {
                    &params.submission_url
                } else {
                    &params.monitoring_url
                },
            })
        })
        .get_async("/logs/:log/metrics", |_req, ctx| async move {
            let name = valid_log_name(&ctx)?;
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

async fn add_entry(mut req: Request, env: &Env, name: &str) -> Result<Response> {
    let params = &CONFIG.logs[name];
    let req: AddEntryRequest = req.json().await?;

    let issuer = RdnSequence::from(vec![RelativeDistinguishedName(
        SetOfVec::from_iter([AttributeTypeAndValue {
            oid: ID_RDNA_TRUSTANCHOR_ID,
            value: Any::new(
                Tag::RelativeOid,
                RelativeOid::from_str(&params.log_id).unwrap().as_bytes(),
            )
            .map_err(|e| e.to_string())?,
        }])
        .unwrap(),
    )]);

    let now = Duration::from_millis(now_millis());
    let validity = Validity {
        not_before: Time::UtcTime(UtcTime::from_unix_duration(now).map_err(|e| e.to_string())?),
        not_after: Time::UtcTime(
            UtcTime::from_unix_duration(
                now + Duration::from_secs(params.validity_interval_seconds),
            )
            .map_err(|e| e.to_string())?,
        ),
    };

    let pending_entry = match mtc_api::validate_chain(&req.chain, &ROOTS, issuer, validity) {
        Ok(v) => v,
        Err(e) => {
            debug!("{name}: Bad request: {e}");
            return Response::error("Bad request", 400);
        }
    };

    // Retrieve the sequenced entry for this pending log entry by first checking the
    // deduplication cache and then sending a request to the DO to sequence the entry.
    let lookup_key = pending_entry.lookup_key();

    // Check if entry is cached and return right away if so.
    if params.enable_dedup {
        if let Some(metadata) =
            get_cached_metadata(&load_cache_kv(env, name)?, &pending_entry).await?
        {
            debug!("{name}: Entry is cached");
            let resp = AddEntryResponse {
                leaf_index: metadata.0,
                timestamp: metadata.1,
            };
            return Response::from_json(&resp);
        }
    }

    // Entry is not cached, so we need to sequence it.

    // First persist issuers.
    let public_bucket = ObjectBucket::new(load_public_bucket(env, name)?);
    upload_issuers(
        &public_bucket,
        &req.chain[1..]
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<&[u8]>>(),
        name,
    )
    .await?;

    // Submit entry to be sequenced, either via a batcher or directly to the
    // sequencer.
    let stub = if params.num_batchers > 0 {
        let batcher_id = batcher_id_from_lookup_key(&lookup_key, params.num_batchers);
        get_durable_object_stub(
            env,
            name,
            Some(batcher_id),
            "BATCHER",
            params.location_hint.as_deref(),
        )?
    } else {
        get_durable_object_stub(
            env,
            name,
            None,
            "SEQUENCER",
            params.location_hint.as_deref(),
        )?
    };
    let mut response = stub
        .fetch_with_request(Request::new_with_init(
            &format!("http://fake_url.com{ENTRY_ENDPOINT}"),
            &RequestInit {
                method: Method::Post,
                body: Some(serde_json::to_string(&pending_entry)?.into()),
                ..Default::default()
            },
        )?)
        .await?;
    if response.status_code() != 200 {
        // Return the response from the sequencing directly to the client.
        return Ok(response);
    }
    let metadata = response.json::<SequenceMetadata>().await?;
    if params.num_batchers == 0 && params.enable_dedup {
        // Write sequenced entry to the long-term deduplication cache in Workers
        // KV as there are no batchers configured to do it for us.
        if put_cache_entry_metadata(&load_cache_kv(env, name)?, &pending_entry, metadata)
            .await
            .is_err()
        {
            warn!("{name}: Failed to write entry to deduplication cache");
        }
    }
    let resp = AddEntryResponse {
        leaf_index: metadata.0,
        timestamp: metadata.1,
    };
    Response::from_json(&resp)
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

fn batcher_id_from_lookup_key(key: &LookupKey, num_batchers: u8) -> u8 {
    key[0] % num_batchers
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

/// Options for uploading issuers.
static OPTS_ISSUER: LazyLock<UploadOptions> = LazyLock::new(|| UploadOptions {
    content_type: Some("application/pkix-cert".to_string()),
    immutable: true,
});

/// Uploads any newly-observed issuers to the object backend, returning the paths of those uploaded.
pub(crate) async fn upload_issuers(
    object: &ObjectBucket,
    issuers: &[&[u8]],
    name: &str,
) -> worker::Result<()> {
    let issuer_futures: Vec<_> = issuers
        .iter()
        .map(|issuer| async move {
            let fingerprint: [u8; 32] = Sha256::digest(issuer).into();
            let path = format!("issuer/{}", hex::encode(fingerprint));

            if let Some(old) = object.fetch(&path).await? {
                if old != *issuer {
                    return Err(worker::Error::RustError(format!(
                        "invalid existing issuer: {}",
                        hex::encode(old)
                    )));
                }
                Ok(None)
            } else {
                object.upload(&path, issuer, &OPTS_ISSUER).await?;
                Ok(Some(path))
            }
        })
        .collect();

    for path in try_join_all(issuer_futures)
        .await?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
    {
        {
            info!("{name}: Observed new issuer; path={path}");
        }
    }

    Ok(())
}
