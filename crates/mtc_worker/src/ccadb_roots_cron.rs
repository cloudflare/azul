// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Cron job to fetch the CCADB-maintained list of certificates trusted by root programs.

use base64ct::LineEnding;
use chrono::DateTime;
use generic_log_worker::util::now_millis;
use std::fmt::Write;
use worker::{
    event, kv::KvStore, Env, Fetch, Headers, Method, Request, RequestInit, Result, ScheduleContext,
    ScheduledEvent,
};
use x509_cert::{
    der::{DecodePem, EncodePem},
    Certificate,
};
use x509_util::CertPool;

// A KV namespace with this binding must be configured in 'wrangler.jsonc' if
// any log shards have 'enable_ccadb_roots=true'.
pub(crate) const CCADB_ROOTS_NAMESPACE: &str = "ccadb_roots";
pub(crate) const CCADB_ROOTS_FILENAME: &str = "mtc_bootstrap_roots.pem";

#[event(scheduled)]
async fn main(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // Update CCADB roots
    log::info!("Updating CCADB roots");
    match env.kv(CCADB_ROOTS_NAMESPACE) {
        Ok(kv) => {
            if let Err(e) = update_ccadb_roots(&kv).await {
                log::warn!("Failed to update CCADB roots: {e}");
            } else {
                log::info!("Successfully updated CCADB roots");
            }
        }
        Err(e) => log::warn!("Failed to get KV namespace '{CCADB_ROOTS_NAMESPACE}': {e}"),
    }

    // Update CT logs for SCT validation
    log::info!("Updating CT logs");
    match env.kv(crate::ct_logs_cron::CT_LOGS_NAMESPACE) {
        Ok(kv) => match crate::ct_logs_cron::update_ct_logs(&kv).await {
            Ok(()) => log::info!("Successfully updated CT logs"),
            Err(e) => log::warn!("Failed to update CT logs: {e}"),
        },
        Err(e) => log::warn!(
            "Failed to get KV namespace '{}': {e}",
            crate::ct_logs_cron::CT_LOGS_NAMESPACE
        ),
    }
}

/// Update CCADB roots at each of the provided keys. Roots are pruned to match
/// the current CCADB list, since we want the trust store to always be a subset
/// of Chrome's trust store.
///
/// SAFETY: In theory it's possible for multiple instances of this job to be
/// running concurrently. Since they're pulling from the same data source, it
/// shouldn't be problematic. Further, the chance of this job running
/// concurrently is slim given that the cron job runs only once per day. If this
/// turns out to be an issue we can add a lock.
///
/// # Errors
/// Will return an error if the latest CCADB roots cannot be fetched or if there
/// are issues getting or putting records into the KV store.
pub(crate) async fn update_ccadb_roots(kv: &KvStore) -> Result<()> {
    let ccadb_roots = ccadb_roots().await?;
    log::info!("Fetched {} CCADB roots", ccadb_roots.len());

    let mut buf = String::new();
    let mut pool = CertPool::default();

    for cert in &ccadb_roots {
        if pool.includes(cert).map_err(|e| e.to_string())? {
            continue;
        }
        write!(
            &mut buf,
            "\n# {}\n# added on {} from CCADB\n{}\n",
            cert.tbs_certificate.subject,
            DateTime::from_timestamp_millis(
                now_millis()
                    .try_into()
                    .or(Err("failed to convert time to i64"))?
            )
            .ok_or("failed to get current time")?
            .to_rfc3339(),
            cert.to_pem(LineEnding::LF).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;

        pool.add_cert(cert.clone()).map_err(|e| e.to_string())?;
    }
    kv.put(CCADB_ROOTS_FILENAME, buf)?.execute().await?;

    Ok(())
}

/// Fetch roots from the CCADB list.
///
/// # Errors
/// Will return an error if there are issues fetching or parsing the CSV, or if
/// the CSV does not contain any valid certificates.
async fn ccadb_roots() -> Result<Vec<Certificate>> {
    let headers = Headers::new();
    headers.set("User-Agent", "Cloudflare ct-logs (ct-logs@cloudflare.com)")?;
    let req = Request::new_with_init(
        "https://ccadb.my.salesforce-sites.com/ccadb/RootCACertificatesIncludedByRSReportCSV",
        &RequestInit {
            method: Method::Get,
            headers,
            ..Default::default()
        },
    )?;
    let resp_bytes = Fetch::Request(req).send().await?.bytes().await?;
    let mut rdr = csv::Reader::from_reader(resp_bytes.as_slice());
    let hdr = rdr
        .headers()
        .map_err(|e| format!("failed to read CCADB CSV header: {e}"))?;
    let pem_idx = hdr
        .iter()
        .position(|hdr| hdr == "X.509 Certificate (PEM)")
        .ok_or("CCADB CSV header does not contain 'X.509 Certificate (PEM)'")?;
    let uses_idx = hdr
        .iter()
        .position(|hdr| hdr == "Intended Use Case(s) Served")
        .ok_or("CCADB CSV header does not contain 'Intended Use Case(s) Served'")?;
    let chrome_status_idx = hdr
        .iter()
        .position(|hdr| hdr == "Google Chrome Status")
        .ok_or("CCADB CSV header does not contain 'Google Chrome Status'")?;
    let mozilla_status_idx = hdr
        .iter()
        .position(|hdr| hdr == "Mozilla Status")
        .ok_or("CCADB CSV header does not contain 'Mozilla Status'")?;
    let mut certificates = Vec::new();
    for result in rdr.records() {
        let record = result.map_err(|e| format!("failed to read CCADB CSV row: {e}"))?;
        let pem = record.get(pem_idx).ok_or("CCADB CSV row is too short")?;
        // There is an "Example CA" row with an empty PEM column.
        if pem.is_empty() {
            continue;
        }
        let uses = record.get(uses_idx).ok_or("CCADB CSV row is too short")?;
        if !uses.contains("Server Authentication (TLS) 1.3.6.1.5.5.7.3.1") {
            continue;
        }

        // Filter to the intersection of the Chrome and Mozilla root stores.
        // Chrome must be able to validate bootstrap certificate chains, and
        // Mozilla's CRLite filters to check for revocation.
        let chrome_status = record
            .get(chrome_status_idx)
            .ok_or("CCADB CSV row is too short")?;
        let mozilla_status = record
            .get(mozilla_status_idx)
            .ok_or("CCADB CSV row is too short")?;
        if !(chrome_status == "Included" && mozilla_status == "Included") {
            continue;
        }

        match Certificate::from_pem(pem) {
            Ok(cert) => certificates.push(cert),
            Err(e) => log::warn!("failed to parse CCADB certificate: {e}:\n{record:?}"),
        }
    }
    if certificates.is_empty() {
        return Err("no certificates found in CCADB CSV".into());
    }

    Ok(certificates)
}
