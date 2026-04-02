// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Integration tests for the MTC API (`mtc_worker`).
//!
//! These tests require a running `wrangler dev` instance built with the
//! `dev-bootstrap-roots` feature (already configured in `wrangler.jsonc`).
//! Set `BASE_URL` to point at the server; defaults to `http://localhost:8787`.
//! Set `MTC_LOG_NAME` to choose which log shard; defaults to `dev2`.
//!
//! `dev2` is preferred because its `landmark_interval_secs: 10` makes the
//! landmark-dependent `get_certificate` test feasible without a long wait.
//!
//! # Running
//!
//! ```text
//! # From crates/mtc_worker/:
//! npx wrangler -e=dev dev &
//!
//! # From workspace root:
//! cargo test -p integration_tests --test mtc_api
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use integration_tests::{
    client::MtcClient,
    fixtures::{garbage_chain, make_mtc_chain},
};
use tokio::sync::OnceCell;
use x509_cert::{der::Decode, Certificate};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Initialization guard
// ---------------------------------------------------------------------------

/// Ensures the MTC worker is fully live and has sequenced at least one entry
/// before any test that depends on sequencer state runs.
static INITIALIZED: OnceCell<()> = OnceCell::const_new();

async fn ensure_initialized() {
    INITIALIZED
        .get_or_init(|| async {
            const MAX_ATTEMPTS: u32 = 30;
            const RETRY_DELAY: Duration = Duration::from_secs(1);

            let log_name = integration_tests::client::mtc_log_name();
            let client = MtcClient::new(&log_name);
            let mtc_chain = make_mtc_chain(&log_name).expect("make_mtc_chain for warmup");

            // Wait until get-roots succeeds before attempting add-entry.
            // get-roots triggers the CCADB fetch that populates the ROOTS
            // OnceCell.  If add-entry races with that fetch in-flight from
            // another request, the Workers runtime cancels it with a 500.
            let mut roots_ready = false;
            for _ in 0..MAX_ATTEMPTS {
                match client.get_roots().await {
                    Ok(_) => { roots_ready = true; break; }
                    Err(_) => tokio::time::sleep(RETRY_DELAY).await,
                }
            }
            if !roots_ready {
                panic!("mtc_worker get-roots never succeeded after {MAX_ATTEMPTS}s");
            }

            for attempt in 0..MAX_ATTEMPTS {
                // Submit an entry to trigger full initialization (DO startup,
                // sequencer first run).  Treat any non-200 as "not yet ready".
                match client.add_entry(mtc_chain.chain.clone()).await {
                    Ok((200, _)) => return,
                    Ok((status, _)) => {
                        eprintln!(
                            "ensure_initialized: add-entry returned {status} \
                             (attempt {}/{MAX_ATTEMPTS}), retrying…",
                            attempt + 1
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "ensure_initialized: add-entry error: {e} \
                             (attempt {}/{MAX_ATTEMPTS}), retrying…",
                            attempt + 1
                        );
                    }
                }

                tokio::time::sleep(RETRY_DELAY).await;
            }

            panic!("mtc_worker failed to initialize after {MAX_ATTEMPTS}s");
        })
        .await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `GET /logs/:log/get-roots` returns 200 with a non-empty list of valid
/// DER-encoded X.509 certificates.
#[tokio::test]
async fn get_roots_returns_valid_certs() {
    ensure_initialized().await;
    let client = MtcClient::default_log();
    let roots = client.get_roots().await.expect("get-roots failed");

    assert!(
        !roots.certificates.is_empty(),
        "expected at least one root certificate"
    );

    for (i, cert_der) in roots.certificates.iter().enumerate() {
        Certificate::from_der(cert_der)
            .unwrap_or_else(|e| panic!("certificate[{i}] is not valid DER: {e}"));
    }
}

/// `GET /logs/:log/metadata` returns 200 with all required fields.
#[tokio::test]
async fn metadata_returns_valid_fields() {
    let client = MtcClient::default_log();
    let meta = client.get_metadata().await.expect("metadata failed");

    // log_id and cosigner_id are dotted-decimal relative OIDs.
    assert!(
        !meta.log_id.is_empty(),
        "log_id must be non-empty"
    );
    assert!(
        meta.log_id.contains('.'),
        "log_id must be a dotted-decimal OID, got: {}",
        meta.log_id
    );
    assert!(
        !meta.cosigner_id.is_empty(),
        "cosigner_id must be non-empty"
    );

    // cosigner_public_key must be a raw 32-byte Ed25519 public key.
    assert_eq!(
        meta.cosigner_public_key.len(),
        32,
        "cosigner_public_key must be 32 bytes"
    );
    ed25519_dalek::VerifyingKey::from_bytes(
        meta.cosigner_public_key
            .as_slice()
            .try_into()
            .expect("already checked 32 bytes"),
    )
    .expect("cosigner_public_key must be a valid Ed25519 public key");

    assert!(
        !meta.submission_url.is_empty(),
        "submission_url must be non-empty"
    );
}

/// `POST /logs/:log/add-entry` with a valid bootstrap chain returns 200 with
/// a structurally valid `AddEntryResponse`.
#[tokio::test]
async fn add_entry_returns_valid_response() {
    ensure_initialized().await;
    let client = MtcClient::default_log();
    let mtc_chain = make_mtc_chain(&client.log).expect("generating MTC chain");

    let (status, resp) = client
        .add_entry(mtc_chain.chain)
        .await
        .expect("add-entry request");
    assert_eq!(status, 200, "expected 200 from add-entry");
    let resp = resp.unwrap();

    // timestamp is in milliseconds; not_before/not_after in seconds.
    assert!(resp.timestamp > 0, "timestamp must be positive");
    assert!(
        resp.not_before < resp.not_after,
        "not_before ({}) must be less than not_after ({})",
        resp.not_before,
        resp.not_after
    );
    // Sanity check: not_after should be no more than 7 days in the future.
    let now_secs = now_millis() / 1000;
    assert!(
        resp.not_after <= now_secs + 604_800,
        "not_after is suspiciously far in the future"
    );
}

/// `POST` with a garbage chain returns 400.
#[tokio::test]
async fn add_entry_with_garbage_chain_returns_400() {
    ensure_initialized().await;
    let client = MtcClient::default_log();
    let (status, _) = client
        .add_entry(garbage_chain())
        .await
        .expect("add-entry request");
    assert_eq!(status, 400, "expected 400 for garbage chain");
}

/// Requesting an unknown log name returns 400.
#[tokio::test]
async fn unknown_log_returns_400() {
    let client = MtcClient::new("this-log-does-not-exist");
    let status = client
        .get_status("get-roots")
        .await
        .expect("GET request");
    assert_eq!(status, 400, "expected 400 for unknown log");
}

/// After `add-entry`, the checkpoint tree size covers the returned `leaf_index`.
#[tokio::test]
async fn add_entry_appears_in_checkpoint() {
    ensure_initialized().await;
    let client = MtcClient::default_log();
    let mtc_chain = make_mtc_chain(&client.log).expect("generating MTC chain");

    let (status, resp) = client
        .add_entry(mtc_chain.chain)
        .await
        .expect("add-entry request");
    assert_eq!(status, 200, "expected 200 from add-entry");
    let resp = resp.unwrap();

    let min_size = resp.leaf_index + 1;

    // Retry until checkpoint covers the leaf or we time out.
    const MAX_RETRIES: u32 = 12;
    const RETRY_DELAY_MS: u64 = 500;
    let mut last_size = 0u64;

    for attempt in 0..MAX_RETRIES {
        let checkpoint_bytes = client
            .get_checkpoint()
            .await
            .expect("fetching checkpoint");
        // Parse tree size from the checkpoint text (second line).
        let text = String::from_utf8_lossy(&checkpoint_bytes);
        if let Some(size_str) = text.lines().nth(1) {
            if let Ok(size) = size_str.trim().parse::<u64>() {
                last_size = size;
                if size >= min_size {
                    return;
                }
            }
        }
        if attempt + 1 < MAX_RETRIES {
            tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
        }
    }

    panic!(
        "checkpoint size {last_size} never reached {min_size} after {MAX_RETRIES} retries"
    );
}

/// After `add-entry`, `get-certificate` returns a parseable signatureless DER
/// certificate once a landmark has been produced.
///
/// This test uses `dev2` (10s landmark interval) and retries for up to 30s.
/// It is skipped if `MTC_LOG_NAME` is set to a log with a longer interval.
#[tokio::test]
async fn get_certificate_returns_valid_cert() {
    ensure_initialized().await;
    // This test only makes sense against a fast-landmark shard (dev2).
    // If someone overrides to a slow shard, skip rather than timeout.
    let log_name = integration_tests::client::mtc_log_name();
    if log_name != "dev2" {
        eprintln!("Skipping get_certificate test: MTC_LOG_NAME={log_name} (not dev2)");
        return;
    }

    let client = MtcClient::new(&log_name);
    let mtc_chain = make_mtc_chain(&log_name).expect("generating MTC chain");
    let leaf_spki_der = mtc_chain.leaf_spki_der.clone();

    let (status, resp) = client
        .add_entry(mtc_chain.chain)
        .await
        .expect("add-entry request");
    assert_eq!(status, 200, "expected 200 from add-entry");
    let resp = resp.unwrap();

    let leaf_index = resp.leaf_index;

    // Wait for a landmark to be produced (dev2 landmark_interval_secs = 10).
    // Retry get-certificate until it returns 200 (not 503 Retry-After).
    const MAX_RETRIES: u32 = 30;
    const RETRY_DELAY_MS: u64 = 1_000;

    let mut last_status = 0u16;
    for attempt in 0..MAX_RETRIES {
        let (s, cert_resp) = client
            .get_certificate(leaf_index, leaf_spki_der.clone())
            .await
            .expect("get-certificate request");
        last_status = s;
        if s == 200 {
            let cert_resp = cert_resp.unwrap();

            // The returned data must be parseable DER (signatureless X.509).
            Certificate::from_der(&cert_resp.data)
                .expect("get-certificate returned invalid DER");

            assert!(
                cert_resp.landmark_id > 0,
                "landmark_id must be positive (index 0 is the initial null entry)"
            );

            return;
        }
        // 503 = landmark not yet available; anything else is unexpected.
        assert_eq!(s, 503, "expected 200 or 503, got {s}");

        if attempt + 1 < MAX_RETRIES {
            tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
        }
    }

    panic!(
        "get-certificate never returned 200 after {MAX_RETRIES} retries (last status: {last_status})"
    );
}
