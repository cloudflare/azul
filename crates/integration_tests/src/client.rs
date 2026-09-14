// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! HTTP client wrappers around `reqwest` for the static CT API endpoints.

// These are test helpers, not public library API — doc exhaustiveness is not required.
#![allow(clippy::missing_errors_doc)]

use anyhow::{Context, Result, bail};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

use crate::local_r2;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Base URL of the Worker under test.  Defaults to `http://localhost:8787`.
#[must_use]
pub fn base_url() -> String {
    std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8787".to_string())
}

/// Log shard name to test against.  Defaults to `dev2026h1a`.
#[must_use]
pub fn log_name() -> String {
    std::env::var("LOG_NAME").unwrap_or_else(|_| "dev2026h1a".to_string())
}

/// Full URL prefix for a given log: `{base_url}/logs/{log_name}`.
#[must_use]
pub fn log_url(log: &str) -> String {
    format!("{}/logs/{log}", base_url())
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response body from `GET /logs/:log/ct/v1/get-roots`.
#[serde_as]
#[derive(Deserialize, Debug)]
pub struct GetRootsResponse {
    #[serde_as(as = "Vec<Base64>")]
    pub certificates: Vec<Vec<u8>>,
}

/// Response body from `GET /logs/:log/log.v3.json`.
#[serde_as]
#[derive(Deserialize, Debug)]
pub struct LogV3JsonResponse {
    pub description: Option<String>,
    pub log_type: Option<String>,
    #[serde_as(as = "Base64")]
    pub log_id: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub key: Vec<u8>,
    pub mmd: u64,
    pub submission_url: String,
    pub monitoring_url: Option<String>,
    pub temporal_interval: TemporalInterval,
}

/// Temporal interval within a `LogV3JsonResponse`.
#[derive(Deserialize, Debug)]
pub struct TemporalInterval {
    pub start_inclusive: String,
    pub end_exclusive: String,
}

/// Response body from `POST /logs/:log/ct/v1/add-[pre-]chain`.
#[serde_as]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AddChainResponse {
    pub sct_version: u8,
    #[serde_as(as = "Base64")]
    pub id: Vec<u8>,
    pub timestamp: u64,
    #[serde_as(as = "Base64")]
    pub extensions: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub signature: Vec<u8>,
}

/// Request body for `POST /logs/:log/ct/v1/add-[pre-]chain`.
#[serde_as]
#[derive(Serialize)]
pub struct AddChainRequest {
    #[serde_as(as = "Vec<Base64>")]
    pub chain: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// HTTP client bound to a particular log shard.
pub struct CtClient {
    client: reqwest::Client,
    pub log: String,
}

impl CtClient {
    /// Creates a new client targeting the given log shard name.
    pub fn new(log: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            log: log.into(),
        }
    }

    /// Creates a client for the default log (from `LOG_NAME` env / `dev2026h1a`).
    #[must_use]
    pub fn default_log() -> Self {
        Self::new(log_name())
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", log_url(&self.log), path)
    }

    /// `GET /logs/:log/ct/v1/get-roots`
    pub async fn get_roots(&self) -> Result<GetRootsResponse> {
        let resp = self
            .client
            .get(self.url("ct/v1/get-roots"))
            .send()
            .await
            .context("GET get-roots")?;
        let status = resp.status();
        if !status.is_success() {
            bail!("GET get-roots returned {status}");
        }
        resp.json().await.context("parsing get-roots response")
    }

    /// `GET /logs/:log/log.v3.json`
    pub async fn get_log_v3_json(&self) -> Result<LogV3JsonResponse> {
        let resp = self
            .client
            .get(self.url("log.v3.json"))
            .send()
            .await
            .context("GET log.v3.json")?;
        let status = resp.status();
        if !status.is_success() {
            bail!("GET log.v3.json returned {status}");
        }
        resp.json().await.context("parsing log.v3.json response")
    }

    /// `POST /logs/:log/ct/v1/add-chain`
    pub async fn add_chain(&self, chain: Vec<Vec<u8>>) -> Result<(u16, Option<AddChainResponse>)> {
        self.post_chain("ct/v1/add-chain", chain).await
    }

    /// `POST /logs/:log/ct/v1/add-pre-chain`
    pub async fn add_pre_chain(
        &self,
        chain: Vec<Vec<u8>>,
    ) -> Result<(u16, Option<AddChainResponse>)> {
        self.post_chain("ct/v1/add-pre-chain", chain).await
    }

    async fn post_chain(
        &self,
        path: &str,
        chain: Vec<Vec<u8>>,
    ) -> Result<(u16, Option<AddChainResponse>)> {
        let body = AddChainRequest { chain };
        let resp = self
            .client
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {path}"))?;
        let status = resp.status().as_u16();
        if status == 200 {
            let body: AddChainResponse = resp
                .json()
                .await
                .with_context(|| format!("parsing {path} response"))?;
            Ok((status, Some(body)))
        } else {
            Ok((status, None))
        }
    }

    /// `GET /logs/:log/checkpoint`
    pub async fn get_checkpoint(&self) -> Result<Vec<u8>> {
        self.get_raw("checkpoint").await
    }

    /// Reads raw log data (tiles, checkpoint, etc.).
    pub async fn get_raw(&self, path: &str) -> Result<Vec<u8>> {
        if local_r2::is_loopback_base_url(&base_url()) {
            return local_r2::get("ct_worker", &format!("static-ct-public-{}", self.log), path)
                .await?
                .with_context(|| format!("R2 object missing: {path}"));
        }

        let metadata = self.get_log_v3_json().await?;
        get_raw_http(&self.client, metadata.monitoring_url.as_deref(), path).await
    }

    /// `GET /logs/:log/{path}` — returns the HTTP status code (does not fail on 4xx/5xx).
    pub async fn get_status(&self, path: &str) -> Result<u16> {
        let resp = self
            .client
            .get(self.url(path))
            .send()
            .await
            .with_context(|| format!("GET {path} (status probe)"))?;
        Ok(resp.status().as_u16())
    }
}

async fn get_raw_http(
    client: &reqwest::Client,
    monitoring_url: Option<&str>,
    path: &str,
) -> Result<Vec<u8>> {
    let monitoring_url = monitoring_url.context("log does not advertise a monitoring URL")?;
    let url = format!("{}/{path}", monitoring_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("GET {url} returned {status}");
    }
    resp.bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .with_context(|| format!("reading body for {url}"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a `{"chain": [...base64...]}` fixture JSON into raw DER byte vectors.
pub fn parse_chain_fixture(json: &str) -> Result<Vec<Vec<u8>>> {
    #[derive(Deserialize)]
    struct Fixture {
        chain: Vec<String>,
    }
    let fixture: Fixture = serde_json::from_str(json).context("parsing chain fixture")?;
    fixture
        .chain
        .iter()
        .map(|b64| {
            BASE64_STANDARD
                .decode(b64)
                .context("base64-decoding chain entry")
        })
        .collect()
}
