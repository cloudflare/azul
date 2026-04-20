// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! HTTP client wrappers around `reqwest` for the static CT API and MTC API endpoints.

// These are test helpers, not public library API — doc exhaustiveness is not required.
#![allow(clippy::missing_errors_doc)]

use anyhow::{bail, Context, Result};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

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
    pub monitoring_url: String,
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

    /// `GET /logs/:log/{path}` — raw bytes (tiles, checkpoint, etc.)
    pub async fn get_raw(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(self.url(path))
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        let status = resp.status();
        if !status.is_success() {
            bail!("GET {path} returned {status}");
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .with_context(|| format!("reading body for {path}"))
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

// ===========================================================================
// MTC client
// ===========================================================================

/// Log shard name to use for MTC tests.  Defaults to `dev2` (the fast-interval
/// shard with `landmark_interval_secs: 10`).
#[must_use]
pub fn bootstrap_mtc_log_name() -> String {
    std::env::var("BOOTSTRAP_MTC_LOG_NAME").unwrap_or_else(|_| "dev2".to_string())
}

/// Response body from `GET /logs/:log/metadata`.
#[serde_as]
#[derive(Deserialize, Debug)]
pub struct BootstrapMtcMetadataResponse {
    pub description: Option<String>,
    pub log_id: String,
    pub cosigner_id: String,
    #[serde_as(as = "Base64")]
    pub cosigner_public_key: Vec<u8>,
    pub submission_url: String,
    pub monitoring_url: String,
}

/// Response body from `POST /logs/:log/add-entry`.
#[derive(Deserialize, Debug, Clone)]
pub struct BootstrapMtcAddEntryResponse {
    pub leaf_index: u64,
    pub timestamp: u64,
    pub not_before: u64,
    pub not_after: u64,
}

/// Response body from `POST /logs/:log/get-certificate`.
#[serde_as]
#[derive(Deserialize, Debug)]
pub struct BootstrapMtcGetCertificateResponse {
    #[serde_as(as = "Base64")]
    pub data: Vec<u8>,
    pub landmark_id: usize,
}

/// HTTP client bound to a particular MTC log shard.
pub struct BootstrapMtcClient {
    client: reqwest::Client,
    pub log: String,
}

impl BootstrapMtcClient {
    /// Creates a new client targeting the given MTC log shard name.
    #[must_use]
    pub fn new(log: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            log: log.into(),
        }
    }

    /// Creates a client for the default MTC log (from `BOOTSTRAP_MTC_LOG_NAME` env / `dev2`).
    #[must_use]
    pub fn default_log() -> Self {
        Self::new(bootstrap_mtc_log_name())
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", log_url(&self.log), path)
    }

    /// `GET /logs/:log/get-roots`
    pub async fn get_roots(&self) -> Result<GetRootsResponse> {
        let resp = self
            .client
            .get(self.url("get-roots"))
            .send()
            .await
            .context("GET get-roots")?;
        let status = resp.status();
        if !status.is_success() {
            bail!("GET get-roots returned {status}");
        }
        resp.json().await.context("parsing get-roots response")
    }

    /// `GET /logs/:log/metadata`
    pub async fn get_metadata(&self) -> Result<BootstrapMtcMetadataResponse> {
        let resp = self
            .client
            .get(self.url("metadata"))
            .send()
            .await
            .context("GET metadata")?;
        let status = resp.status();
        if !status.is_success() {
            bail!("GET metadata returned {status}");
        }
        resp.json().await.context("parsing metadata response")
    }

    /// `POST /logs/:log/add-entry`
    pub async fn add_entry(
        &self,
        chain: Vec<Vec<u8>>,
    ) -> Result<(u16, Option<BootstrapMtcAddEntryResponse>)> {
        let body = AddChainRequest { chain };
        let resp = self
            .client
            .post(self.url("add-entry"))
            .json(&body)
            .send()
            .await
            .context("POST add-entry")?;
        let status = resp.status().as_u16();
        if status == 200 {
            let body: BootstrapMtcAddEntryResponse =
                resp.json().await.context("parsing add-entry response")?;
            Ok((status, Some(body)))
        } else {
            Ok((status, None))
        }
    }

    /// `POST /logs/:log/get-certificate`
    pub async fn get_certificate(
        &self,
        leaf_index: u64,
        spki_der: Vec<u8>,
    ) -> Result<(u16, Option<BootstrapMtcGetCertificateResponse>)> {
        #[serde_as]
        #[derive(serde::Serialize)]
        struct Req {
            leaf_index: u64,
            #[serde_as(as = "Base64")]
            spki_der: Vec<u8>,
        }
        let resp = self
            .client
            .post(self.url("get-certificate"))
            .json(&Req {
                leaf_index,
                spki_der,
            })
            .send()
            .await
            .context("POST get-certificate")?;
        let status = resp.status().as_u16();
        if status == 200 {
            let body: BootstrapMtcGetCertificateResponse = resp
                .json()
                .await
                .context("parsing get-certificate response")?;
            Ok((status, Some(body)))
        } else {
            Ok((status, None))
        }
    }

    /// `GET /logs/:log/checkpoint` — raw bytes.
    pub async fn get_checkpoint(&self) -> Result<Vec<u8>> {
        self.get_raw("checkpoint").await
    }

    /// `GET /logs/:log/{path}` — raw bytes.
    pub async fn get_raw(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(self.url(path))
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        let status = resp.status();
        if !status.is_success() {
            bail!("GET {path} returned {status}");
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .with_context(|| format!("reading body for {path}"))
    }

    /// `GET /logs/:log/{path}` — returns the HTTP status code without failing on 4xx/5xx.
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
