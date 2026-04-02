// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Integration tests for the static CT API (`ct_worker`).
//!
//! These tests require a running `wrangler dev` instance.
//! Set `BASE_URL` to point at the server; defaults to `http://localhost:8787`.
//! Set `LOG_NAME` to choose which log shard; defaults to `dev2026h1a`.
//!
//! # Running
//!
//! ```text
//! # From crates/ct_worker/:
//! npx wrangler -e=dev dev &
//!
//! # From workspace root:
//! cargo test -p integration_tests --test static_ct_api
//! ```
//!
//! To run against a different shard or URL:
//! ```text
//! BASE_URL=http://localhost:8787 LOG_NAME=dev2026h1a cargo test -p integration_tests --test static_ct_api
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use integration_tests::{
    assertions::{
        assert_leaf_in_checkpoint, assert_sct_signature, assert_sct_structure,
        fetch_and_verify_checkpoint, fetch_checkpoint_until_size, leaf_index_from_sct,
    },
    client::CtClient,
    fixtures::{empty_chain, garbage_chain, make_chains},
};
use tokio::sync::OnceCell;

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

/// Shared once-per-binary initialization: ensures the worker is fully live and
/// has sequenced at least one entry before any test that depends on sequencer
/// state runs.
///
/// `ct_worker` initializes its root pool, Durable Objects, and sequencer lazily
/// on the first request.  Tests that run before initialization completes see
/// 503 (sequencer busy) or missing checkpoints.  Calling `ensure_initialized`
/// at the start of any such test avoids these races without requiring a
/// specific test ordering.
///
/// Tests that only need stateless metadata endpoints (`get-roots`,
/// `log.v3.json`, `unknown_log`) should NOT call this — they work immediately
/// and calling it would slow them down unnecessarily.
static INITIALIZED: OnceCell<()> = OnceCell::const_new();

async fn ensure_initialized() {
    INITIALIZED
        .get_or_init(|| async {
            const MAX_ATTEMPTS: u32 = 30;
            const RETRY_DELAY: Duration = Duration::from_secs(1);

            let client = CtClient::default_log();
            let chains = make_chains(&client.log).expect("make_chains for warmup");

            // Wait until get-roots succeeds before attempting add-chain.
            // get-roots triggers the CCADB fetch that populates the ROOTS
            // OnceCell.  If add-chain races with that fetch in-flight from
            // another request, the Workers runtime cancels it with a 500
            // (cross-request promise resolution is not permitted).  Waiting
            // here ensures ROOTS is fully populated before add-chain is called.
            let mut roots_ready = false;
            for _ in 0..MAX_ATTEMPTS {
                match client.get_roots().await {
                    Ok(_) => { roots_ready = true; break; }
                    Err(_) => tokio::time::sleep(RETRY_DELAY).await,
                }
            }
            if !roots_ready {
                panic!("ct_worker get-roots never succeeded after {MAX_ATTEMPTS}s");
            }

            // Fetch log metadata (needed for checkpoint verification).
            let meta = client.get_log_v3_json().await.expect("log.v3.json in warmup");

            for attempt in 0..MAX_ATTEMPTS {
                // Submit a chain to trigger full initialization (root pool load,
                // DO startup, sequencer first run).  On a completely fresh
                // wrangler dev instance the sequencer Durable Object may still
                // be waking up, causing the first add-chain to return 500.
                // Treat any non-200 response as "not yet ready" and retry.
                match client.add_chain(chains.chain.clone()).await {
                    Ok((200, Some(sct))) => {
                        // Wait for the sequencer to publish a checkpoint that
                        // covers our warmup entry before releasing the gate.
                        let leaf_index =
                            leaf_index_from_sct(&sct).expect("leaf_index from warmup SCT");
                        let _ = fetch_checkpoint_until_size(
                            &client,
                            &meta,
                            leaf_index + 1,
                            now_millis(),
                        )
                        .await;
                        return;
                    }
                    Ok((status, _)) => {
                        eprintln!(
                            "ensure_initialized: add-chain returned {status} \
                             (attempt {}/{MAX_ATTEMPTS}), retrying…",
                            attempt + 1
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "ensure_initialized: add-chain error: {e} \
                             (attempt {}/{MAX_ATTEMPTS}), retrying…",
                            attempt + 1
                        );
                    }
                }

                tokio::time::sleep(RETRY_DELAY).await;
            }

            panic!("ct_worker failed to initialize after {MAX_ATTEMPTS}s");
        })
        .await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `GET /logs/:log/ct/v1/get-roots` returns 200 with a non-empty list of
/// valid DER-encoded X.509 certificates.
#[tokio::test]
async fn get_roots_returns_valid_certs() {
    // get-roots triggers the CCADB fetch that populates the ROOTS OnceCell.
    // ensure_initialized uses get-roots as its readiness probe, so whichever
    // test runs first will serialize the fetch before add-chain is attempted.
    ensure_initialized().await;
    let client = CtClient::default_log();
    let roots = client.get_roots().await.expect("get-roots failed");

    assert!(
        !roots.certificates.is_empty(),
        "expected at least one root certificate"
    );

    for (i, cert_der) in roots.certificates.iter().enumerate() {
        use x509_cert::{der::Decode, Certificate};
        Certificate::from_der(cert_der)
            .unwrap_or_else(|e| panic!("certificate[{i}] is not valid DER: {e}"));
    }
}

/// `GET /logs/:log/log.v3.json` returns 200 with all required fields.
#[tokio::test]
async fn log_v3_json_returns_valid_metadata() {
    let client = CtClient::default_log();
    let meta = client
        .get_log_v3_json()
        .await
        .expect("log.v3.json failed");

    assert_eq!(meta.log_id.len(), 32, "log_id must be 32 bytes");
    assert!(!meta.key.is_empty(), "key must be non-empty");
    assert!(meta.mmd > 0, "mmd must be positive");
    assert!(!meta.submission_url.is_empty(), "submission_url must be set");

    // Key must be a valid P-256 SPKI.
    use p256::pkcs8::DecodePublicKey;
    p256::ecdsa::VerifyingKey::from_public_key_der(&meta.key)
        .expect("key must be a valid P-256 SPKI");

    // log_id must equal SHA-256(SPKI).
    use p256::pkcs8::EncodePublicKey;
    use sha2::{Digest, Sha256};
    let vkey = p256::ecdsa::VerifyingKey::from_public_key_der(&meta.key).unwrap();
    let pkix = vkey.to_public_key_der().unwrap();
    let expected_id: [u8; 32] = Sha256::digest(pkix.as_bytes()).into();
    assert_eq!(
        meta.log_id.as_slice(),
        expected_id.as_slice(),
        "log_id must equal SHA-256(SPKI)"
    );
}

/// Requesting an unknown log name returns 400.
#[tokio::test]
async fn unknown_log_returns_400() {
    let client = CtClient::new("this-log-does-not-exist");
    let status = client
        .get_status("ct/v1/get-roots")
        .await
        .expect("GET request");
    assert_eq!(status, 400, "expected 400 for unknown log");
}

/// `POST` with a JSON body that is not a valid DER certificate returns 400.
#[tokio::test]
async fn add_chain_with_garbage_cert_returns_400() {
    ensure_initialized().await;
    let client = CtClient::default_log();
    let (status, _) = client
        .add_chain(garbage_chain())
        .await
        .expect("add-chain request");
    assert_eq!(status, 400, "expected 400 for garbage cert chain");
}

/// `POST` with an empty chain returns 400.
#[tokio::test]
async fn add_chain_with_empty_chain_returns_400() {
    ensure_initialized().await;
    let client = CtClient::default_log();
    let (status, _) = client
        .add_chain(empty_chain())
        .await
        .expect("add-chain request");
    assert_eq!(status, 400, "expected 400 for empty chain");
}

/// `POST /logs/:log/ct/v1/add-chain` returns a structurally valid SCT with
/// a correct ECDSA P-256 signature.
#[tokio::test]
async fn add_chain_returns_sct_with_valid_signature() {
    ensure_initialized().await;
    let client = CtClient::default_log();
    let chains = make_chains(&client.log).expect("generating chain fixtures");
    let meta = client.get_log_v3_json().await.expect("log.v3.json");

    let (status, sct) = client
        .add_chain(chains.chain.clone())
        .await
        .expect("add-chain request");
    assert_eq!(status, 200, "expected 200 from add-chain");
    let sct = sct.unwrap();

    assert_sct_structure(&sct).expect("SCT structure check");
    assert_sct_signature(&sct, &meta, &chains.chain[0], &chains.chain[1])
        .expect("SCT signature verification");
}

/// `POST /logs/:log/ct/v1/add-pre-chain` returns a structurally valid SCT.
#[tokio::test]
async fn add_pre_chain_returns_valid_sct() {
    ensure_initialized().await;
    let client = CtClient::default_log();
    let chains = make_chains(&client.log).expect("generating chain fixtures");
    let meta = client.get_log_v3_json().await.expect("log.v3.json");

    let (status, sct) = client
        .add_pre_chain(chains.pre_chain.clone())
        .await
        .expect("add-pre-chain request");
    assert_eq!(status, 200, "expected 200 from add-pre-chain");
    let sct = sct.unwrap();

    assert_sct_structure(&sct).expect("SCT structure check");
    assert_sct_signature(&sct, &meta, &chains.pre_chain[0], &chains.pre_chain[1])
        .expect("pre-chain SCT signature verification");
}

/// Submitting the same chain twice returns identical SCTs (deduplication).
#[tokio::test]
async fn add_chain_deduplication_returns_identical_sct() {
    ensure_initialized().await;
    let client = CtClient::default_log();
    let chains = make_chains(&client.log).expect("generating chain fixtures");

    let (s1, sct1) = client
        .add_chain(chains.chain.clone())
        .await
        .expect("first add-chain");
    let (s2, sct2) = client
        .add_chain(chains.chain.clone())
        .await
        .expect("second add-chain");

    assert_eq!(s1, 200);
    assert_eq!(s2, 200);

    let sct1 = sct1.unwrap();
    let sct2 = sct2.unwrap();

    // Identical leaf → same leaf_index, timestamp, and signature.
    assert_eq!(sct1.timestamp, sct2.timestamp, "timestamps must match");
    assert_eq!(sct1.extensions, sct2.extensions, "extensions must match");
    assert_eq!(sct1.signature, sct2.signature, "signatures must match");
}

/// After a successful `add-chain`, the checkpoint is signed correctly and its
/// tree size covers the returned `leaf_index`.
#[tokio::test]
async fn add_chain_sct_appears_in_checkpoint() {
    ensure_initialized().await;
    let client = CtClient::default_log();
    let chains = make_chains(&client.log).expect("generating chain fixtures");
    let meta = client.get_log_v3_json().await.expect("log.v3.json");

    let (status, sct) = client
        .add_chain(chains.chain.clone())
        .await
        .expect("add-chain request");
    assert_eq!(status, 200, "expected 200 from add-chain");
    let sct = sct.unwrap();

    let leaf_index = leaf_index_from_sct(&sct).expect("extracting leaf_index");
    let min_size = leaf_index + 1;

    let checkpoint = fetch_checkpoint_until_size(&client, &meta, min_size, now_millis())
        .await
        .expect("waiting for checkpoint");

    assert!(
        checkpoint.text.size() >= min_size,
        "checkpoint size {} should be >= {min_size}",
        checkpoint.text.size()
    );
}

/// After a successful `add-chain`, the data tile containing the returned
/// `leaf_index` is readable, and the entry's Merkle hash is consistent with
/// the checkpoint's root hash (full end-to-end proof).
#[tokio::test]
async fn add_chain_leaf_verifiable_in_tree() {
    ensure_initialized().await;
    let client = CtClient::default_log();
    let chains = make_chains(&client.log).expect("generating chain fixtures");
    let meta = client.get_log_v3_json().await.expect("log.v3.json");

    let (status, sct) = client
        .add_chain(chains.chain.clone())
        .await
        .expect("add-chain request");
    assert_eq!(status, 200, "expected 200 from add-chain");
    let sct = sct.unwrap();

    let leaf_index = leaf_index_from_sct(&sct).expect("extracting leaf_index");

    let checkpoint = fetch_checkpoint_until_size(&client, &meta, leaf_index + 1, now_millis())
        .await
        .expect("waiting for checkpoint");

    assert_leaf_in_checkpoint(&client, &checkpoint, leaf_index)
        .await
        .expect("inclusion proof verification");
}

/// After a successful `add-pre-chain`, the data tile for the returned
/// `leaf_index` is readable and its Merkle hash verifies.
#[tokio::test]
async fn add_pre_chain_leaf_verifiable_in_tree() {
    ensure_initialized().await;
    let client = CtClient::default_log();
    let chains = make_chains(&client.log).expect("generating chain fixtures");
    let meta = client.get_log_v3_json().await.expect("log.v3.json");

    let (status, sct) = client
        .add_pre_chain(chains.pre_chain.clone())
        .await
        .expect("add-pre-chain request");
    assert_eq!(status, 200, "expected 200 from add-pre-chain");
    let sct = sct.unwrap();

    let leaf_index = leaf_index_from_sct(&sct).expect("extracting leaf_index");

    let checkpoint = fetch_checkpoint_until_size(&client, &meta, leaf_index + 1, now_millis())
        .await
        .expect("waiting for checkpoint");

    assert_leaf_in_checkpoint(&client, &checkpoint, leaf_index)
        .await
        .expect("inclusion proof verification for precert");
}

/// The checkpoint signature is valid (RFC 6962 ECDSA).
///
/// This test does not require an `add-chain` call — it just verifies the
/// existing checkpoint.  Useful as a health check against deployed environments.
#[tokio::test]
async fn checkpoint_signature_is_valid() {
    ensure_initialized().await;
    let client = CtClient::default_log();
    let meta = client.get_log_v3_json().await.expect("log.v3.json");

    fetch_and_verify_checkpoint(&client, &meta, None, now_millis())
        .await
        .expect("checkpoint signature verification");
}
