// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Entrypoint for the static CT submission APIs.

use crate::{
    get_stub, load_public_bucket, load_signing_key, load_witness_key, mtcalog, now_millis, util,
    LookupKey, ObjectBucket, CONFIG, ROOTS,
};
use log::{warn, Level};
use mtc_api::{
    check_claims_valid_for_x509, unmarshal_exact, AbridgedSubject, AssertionRequest, Evidence,
    EvidencePolicy, GetUmbilicalRootsResponse, LogEntry, Marshal, UnixTimestamp,
};
use p256::pkcs8::EncodePublicKey;
use serde::Serialize;
use serde_with::{base64::Base64, serde_as};
use std::str::FromStr;
#[allow(clippy::wildcard_imports)]
use worker::*;

// Number of Batchers to use to proxy requests to the Sequencer.
// Setting this too high could result in a high number of requests
// to the Sequencer, which may slow down the sequencing loop.
// Setting this too low could cause individual Batchers to hit the
// Durable Objects rate limits.
const NUM_BATCHER_PROXIES: u8 = 8;

const UNKNOWN_CA_MSG: &str = "unknown CA";

#[serde_as]
#[derive(Serialize)]
struct MetadataResponse<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_policy: &'a Option<String>,
    #[serde_as(as = "Base64")]
    ca_id: &'a [u8],
    #[serde_as(as = "Base64")]
    key: &'a [u8],
    #[serde_as(as = "Base64")]
    witness_key: &'a [u8],
    submission_url: &'a str,
    monitoring_url: &'a str,
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
        .get("/logs/:ca/umbilical-roots", |_req, ctx| {
            let _name = valid_ca_name(&ctx)?;
            Response::from_json(&GetUmbilicalRootsResponse {
                certificates: mtc_api::certs_to_bytes(&ROOTS.certs).unwrap(),
            })
        })
        .post_async("/logs/:ca/add-assertion", |req, ctx| async move {
            add_assertion(req, &ctx.env, valid_ca_name(&ctx)?).await
        })
        .get("/logs/:ca/metadata", |_req, ctx| {
            let name = valid_ca_name(&ctx)?;
            let params = &CONFIG.cas[name];
            let verifying_key = load_signing_key(&ctx.env, name)?.verifying_key();
            let ca_id = &mtc_api::log_id_from_key(verifying_key)
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
                evidence_policy: &params.evidence_policy,
                ca_id,
                key: key.as_bytes(),
                witness_key: witness_key.as_bytes(),
                submission_url: &params.origin_url,
                monitoring_url: if params.monitoring_url.is_empty() {
                    &params.origin_url
                } else {
                    &params.monitoring_url
                },
            })
        })
        .get_async("/logs/:ca/metrics", |_req, ctx| async move {
            let name = valid_ca_name(&ctx)?;
            let stub = get_stub(&ctx.env, name, None, "SEQUENCER")?;
            stub.fetch_with_str(&format!("http://fake_url.com/metrics?name={name}"))
                .await
        })
        .get_async("/logs/:ca/*key", |_req, ctx| async move {
            let name = valid_ca_name(&ctx)?;
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
            Error::RustError(ref msg) if msg == UNKNOWN_CA_MSG => {
                Response::error("Unknown log", 400)
            }
            _ => {
                warn!("Internal error: {e}");
                Response::error("Internal error", 500)
            }
        })
}

#[allow(clippy::too_many_lines)]
async fn add_assertion(mut req: Request, env: &Env, name: &str) -> Result<Response> {
    let params = &CONFIG.cas[name];
    let mut body: &[u8] = &req.bytes().await?;
    let req: AssertionRequest =
        unmarshal_exact(&mut body).map_err(|e| format!("failed to unmarshal: {e}"))?;

    let abridged_subject = req.assertion.subject.abridge().map_err(|e| e.to_string())?;
    let not_before = now_millis();
    let mut not_after = std::cmp::min(req.not_after, not_before + params.cert_lifetime);

    let mut extra_data = Vec::new();
    if let Some(policy) = &params.evidence_policy {
        if let Ok(p) = EvidencePolicy::try_from(policy.as_str()) {
            match p {
                EvidencePolicy::Unset | EvidencePolicy::Empty => {}
                EvidencePolicy::Umbilical => {
                    let tls_subj = match &abridged_subject {
                        AbridgedSubject::TLS(s) => s,
                        AbridgedSubject::Unknown(_) => return Response::error("Bad request", 400),
                    };

                    let Some(umbilical) = req.evidence.0.iter().find_map(|evidence| {
                        if let Evidence::Umbilical(umbilical) = evidence {
                            Some(umbilical)
                        } else {
                            None
                        }
                    }) else {
                        return Response::error("Bad request", 400);
                    };
                    let raw_chain = umbilical.raw_chain().map_err(|e| e.to_string())?;

                    not_after = check_claims_valid_for_x509(
                        &req.assertion.claims,
                        tls_subj,
                        not_before,
                        not_after,
                        &raw_chain,
                        &ROOTS,
                    )
                    .map_err(|e| e.to_string())?;

                    extra_data = umbilical.compress().map_err(|e| e.to_string())?;

                    // Persist evidence issuers.
                    let public_bucket = ObjectBucket {
                        sequence_interval: params.sequence_interval,
                        bucket: load_public_bucket(env, name)?,
                        metrics: None,
                    };
                    mtcalog::upload_issuers(
                        &public_bucket,
                        &umbilical.raw_chain().unwrap()[1..],
                        name,
                    )
                    .await?;
                }
            }
        }
    }

    let leaf = LogEntry {
        abridged_subject,
        claims: req.assertion.claims,
        not_after,
        extra_data,
    };

    // Add leaf to the Batcher, which will submit the entry to the Sequencer,
    // wait for the entry to be sequenced, and return the response.
    let hash = leaf.lookup_key();
    let shard_id = shard_id_from_lookup_key(&hash);
    let batcher_stub = get_stub(env, name, Some(shard_id), "BATCHER")?;
    let mut body = Vec::new();
    leaf.marshal(&mut body).map_err(|e| e.to_string())?;
    let mut response = batcher_stub
        .fetch_with_request(Request::new_with_init(
            &format!("http://fake_url.com/add_leaf?name={name}"),
            &RequestInit {
                method: Method::Post,
                body: Some(body.into()),
                ..Default::default()
            },
        )?)
        .await?;
    if response.status_code() != 200 {
        // Return the response from the Batcher directly to the client.
        return Ok(response);
    }
    let (leaf_index, _timestamp) = response.json::<(u64, UnixTimestamp)>().await?;
    Response::from_json(&mtc_api::AssertionResponse { leaf_index })
}

fn valid_ca_name(ctx: &RouteContext<()>) -> Result<&str> {
    if let Some(name) = ctx.param("ca") {
        if CONFIG.cas.contains_key(name) {
            Ok(name)
        } else {
            Err(UNKNOWN_CA_MSG.into())
        }
    } else {
        Err("missing 'log' route param".into())
    }
}

fn shard_id_from_lookup_key(key: &LookupKey) -> u8 {
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
