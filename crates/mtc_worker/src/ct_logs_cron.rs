// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Cron job to fetch CT log list from Google. Same pattern as ccadb_roots_cron.

use sct_validator::CtLogList;
use worker::{kv::KvStore, Env, Fetch, Headers, Method, Request, RequestInit, Result};

pub(crate) const CT_LOGS_NAMESPACE: &str = "ct_logs";
pub(crate) const CT_LOGS_FILENAME: &str = "ct_log_list.json";
const CT_LOG_LIST_URL: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

pub(crate) async fn update_ct_logs(kv: &KvStore) -> Result<()> {
    log::info!("Fetching CT log list from Google");

    let headers = Headers::new();
    headers.set("User-Agent", "Cloudflare MTCA (ct-logs@cloudflare.com)")?;

    let req = Request::new_with_init(
        CT_LOG_LIST_URL,
        &RequestInit {
            method: Method::Get,
            headers,
            ..Default::default()
        },
    )?;

    let resp_bytes = Fetch::Request(req).send().await?.bytes().await?;

    // Validate before storing
    let log_list = CtLogList::from_chrome_log_list(&resp_bytes)
        .map_err(|e| format!("Failed to parse CT log list: {e}"))?;

    log::info!(
        "Parsed {} CT logs (timestamp: {})",
        log_list.logs.len(),
        log_list.log_list_timestamp
    );

    kv.put_bytes(CT_LOGS_FILENAME, &resp_bytes)?.execute().await?;
    Ok(())
}

pub(crate) async fn load_ct_logs(env: &Env) -> Result<CtLogList> {
    let kv = env.kv(CT_LOGS_NAMESPACE)?;

    let json_bytes = if let Some(bytes) = kv.get(CT_LOGS_FILENAME).bytes().await? {
        bytes
    } else {
        log::info!("CT log list not found in KV, fetching...");
        update_ct_logs(&kv).await?;
        kv.get(CT_LOGS_FILENAME)
            .bytes()
            .await?
            .ok_or("CT log list not found after update")?
    };

    CtLogList::from_chrome_log_list(&json_bytes)
        .map_err(|e| format!("Failed to parse CT log list from KV: {e}").into())
}
