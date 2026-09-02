// Copyright (c) 2025-2026 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

use anyhow::{Context, Result, bail};
use std::{path::PathBuf, time::Duration};

#[must_use]
pub fn is_loopback_base_url(base_url: &str) -> bool {
    base_url.starts_with("http://localhost:") || base_url.starts_with("http://127.0.0.1:")
}

/// Reads an object from a Worker's persisted local R2 state.
///
/// # Errors
///
/// Returns an error for non-loopback test URLs or if Wrangler fails.
pub async fn get(worker: &str, bucket: &str, key: &str) -> Result<Option<Vec<u8>>> {
    let base_url =
        std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8787".to_string());
    if !is_loopback_base_url(&base_url) {
        bail!("local R2 inspection requires a loopback BASE_URL");
    }

    let worker_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../{worker}"));
    let object = format!("{bucket}/{key}");
    let mut command = tokio::process::Command::new("wrangler");
    command.current_dir(worker_dir).args([
        "r2",
        "object",
        "get",
        &object,
        "--local",
        "--persist-to",
        ".wrangler/state",
        "--pipe",
    ]);
    command.kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .context("wrangler r2 object get timed out")?
        .context("running wrangler r2 object get")?;
    if output.status.success() {
        return Ok(Some(output.stdout));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("specified key does not exist") {
        return Ok(None);
    }
    bail!("wrangler r2 object get failed for {key}: {stderr}");
}
