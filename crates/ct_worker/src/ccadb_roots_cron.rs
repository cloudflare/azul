// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Cron job to fetch the CCADB-maintained list of certificates trusted by root programs.

use base64ct::LineEnding;
use chrono::DateTime;
use generic_log_worker::util::now_millis;
use worker::{
    event, kv::KvStore, Env, Fetch, Headers, Method, Request, RequestInit, Result, ScheduleContext,
    ScheduledEvent,
};
use x509_cert::{
    der::{DecodePem, EncodePem},
    Certificate,
};
use x509_util::CertPool;

use crate::{ccadb_roots_filename, CCADB_ROOTS_NAMESPACE, CONFIG};

#[event(scheduled)]
async fn main(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let mut keys = Vec::new();
    for (name, params) in &CONFIG.logs {
        if params.enable_ccadb_roots {
            keys.push(ccadb_roots_filename(name));
        }
    }
    log::info!("Updating CCADB roots for keys: {keys:?}");
    let kv = match env.kv(CCADB_ROOTS_NAMESPACE) {
        Ok(kv) => kv,
        Err(e) => {
            log::warn!("Failed to get KV namespace '{CCADB_ROOTS_NAMESPACE}': {e}");
            return;
        }
    };
    if let Err(e) = update_ccadb_roots(&keys, &kv).await {
        log::warn!("Failed to update CCADB roots: {e}");
    } else {
        log::info!("Successfully updated CCADB roots");
    }
}

/// Update CCADB roots at each of the provided keys. Roots are never removed
/// once added.
///
/// SAFETY: In theory it's possible for multiple instances of this job to be
/// running concurrently, such that the result written by one job is overwritten
/// by the other, possibly removing roots that were just added to the list. This
/// isn't an integrity violation for the log (it's fine to have entries chaining
/// to roots that aren't currently served by get-roots, since each entry stores
/// the `chain_fingerprints` for its chain). Further, the chance of this job
/// running concurrently is slim given that the cron job runs only once per day.
/// If this turns out to be an issue we can add a lock.
///
/// # Errors
/// Will return an error if the latest CCADB roots cannot be fetched or if there
/// are issues getting or putting records into the KV store.
pub(crate) async fn update_ccadb_roots<T: AsRef<str>>(keys: &[T], kv: &KvStore) -> Result<()> {
    let ccadb_roots = ccadb_roots().await?;
    log::info!("Fetched {} CCADB roots", ccadb_roots.len());

    for key in keys {
        let old = kv.get(key.as_ref()).text().await?;
        let mut new_roots = 0;
        let mut buf = String::new();
        let mut pool = CertPool::default();
        if let Some(old) = old {
            pool.append_certs_from_pem(old.as_bytes())
                .map_err(|e| e.to_string())?;
            buf = old;
        }
        for cert in &ccadb_roots {
            if pool.included(cert).map_err(|e| e.to_string())? {
                continue;
            }
            new_roots += 1;
            buf.push_str(&format!(
                "\n# {}\n# added on {} from {}\n{}\n",
                cert.tbs_certificate.subject,
                DateTime::from_timestamp_millis(
                    now_millis()
                        .try_into()
                        .or(Err("failed to convert time to i64"))?
                )
                .ok_or("failed to get current time")?
                .to_rfc3339(),
                "CCADB",
                cert.to_pem(LineEnding::LF).map_err(|e| e.to_string())?,
            ));

            pool.add_cert(cert.clone()).map_err(|e| e.to_string())?;
        }
        if new_roots > 0 {
            log::info!("Added {new_roots} new roots to {}", key.as_ref());
            kv.put(key.as_ref(), buf)?.execute().await?;
        }
    }
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
    let mut certificates = Vec::new();
    for result in rdr.records() {
        let record = result.map_err(|e| format!("failed to read CCADB CSV row: {e}"))?;
        let pem = record.get(pem_idx).ok_or("CCADB CSV row is too short")?;
        // There is an "Example CA" row with an empty PEM column.
        if pem.is_empty() {
            continue;
        }
        let uses = record.get(uses_idx).ok_or("CCADB CSV row is too short")?;
        if !(uses.contains("Server Authentication (TLS) 1.3.6.1.5.5.7.3.1")
            || uses.contains("CT Monitoring"))
        {
            continue;
        }

        // One certificate (CN=Baltimore CyberTrust Root; OU=CyberTrust;
        // O=Baltimore; C=IE) has extra trailing spaces after each of the PEM
        // lines, which causes the `der` crate's PEM decoding to fail.
        match Certificate::from_pem(pem.replace(" \n", "\n")) {
            Ok(cert) => certificates.push(cert),
            Err(e) => log::warn!("failed to parse CCADB certificate: {e}:\n{record:?}"),
        }
    }
    if certificates.is_empty() {
        return Err("no certificates found in CCADB CSV".into());
    }

    Ok(certificates)
}
