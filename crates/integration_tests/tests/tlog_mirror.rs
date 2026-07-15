// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! End-to-end integration tests for the `mirror_worker` implementation of
//! [c2sp.org/tlog-mirror][spec].
//!
//! These tests require a running `wrangler dev` instance of `mirror_worker`
//! on `localhost:8787` (or `BASE_URL`), backed by fresh persistent state.
//! Delete `crates/mirror_worker/.wrangler/state/` between runs to reset the
//! per-origin pending checkpoint the mirror has accepted. CI does this
//! automatically.
//!
//! The mirror's submission APIs are deeply stateful: each successful
//! `add-checkpoint`/`add-entries` advances a per-origin pending checkpoint
//! that every later submission must be consistent with. Rather than risk
//! cross-pollution between independently-ordered `#[tokio::test]`s, all
//! scenarios run as a single test that threads one in-memory [`ToyLog`]
//! through `add-checkpoint`, `add-entries`, and `sign-subtree` in order,
//! covering the happy path plus the spec's error codes. Each step asserts
//! the expected HTTP status and, on a successful advance, updates the local
//! log to match.
//!
//! Per spec the mirror MUST NOT cosign on `add-checkpoint` (the success
//! body is empty); cosignatures are emitted only by `add-entries` once
//! entries catch up to the pending tree size.
//!
//! # Key management
//!
//! The dev config models an MTC CA. Its `logs` entry is keyed by the CA
//! cosigner name (`LOG_KEY_NAME`, e.g. `oid/1.3.6.1.4.1.32473.2`), and
//! the checkpoints this test signs carry that name on their signature
//! line while their origin line is `LOG_ORIGIN` (the log ID, ending in
//! `.0.1`), deliberately exercising the cosigner-name-vs-origin split from
//! c2sp.org/mtc-tlog. The SPKI committed to
//! `crates/mirror_worker/config.dev.json` MUST match the ML-DSA-44 key
//! embedded below (see `crates/mirror_worker/src/lib.rs::dev_config_tests`).
//! If they diverge the mirror will 403 the tests with "No valid
//! signatures from trusted log keys".
//!
//! [spec]: https://c2sp.org/tlog-mirror

use ml_dsa::pkcs8::DecodePrivateKey as _;
use ml_dsa::{ExpandedSigningKey, MlDsa44};
use rand::Rng as _;
use rand::rng;
use serde::Deserialize;
use serde_with::{base64::Base64, serde_as};
use signed_note::{KeyName, Note, NoteSignature};
use std::time::Duration;
use tlog_checkpoint::{CheckpointSigner, TreeWithTimestamp};
use tlog_core::{
    HASH_SIZE, Hash, HashReader, Subtree, TlogError, consistency_proof, record_hash, stored_hashes,
    subtree_consistency_proof, subtree_hash, tree_hash,
};
use tlog_cosignature::{SubtreeV1CheckpointSigner, SubtreeV1NoteVerifier};
use tlog_mirror::{AddEntriesRequestHeader, EntryPackage, MirrorInfo, package_ranges};
use tlog_witness::{
    CONTENT_TYPE_TLOG_SIZE, parse_sign_subtree_response, serialize_add_checkpoint_request,
    serialize_sign_subtree_request,
};

// ---------------------------------------------------------------------------
// Test fixtures: MTC CA cosigner name, log origin, ML-DSA-44 log key
// ---------------------------------------------------------------------------

/// The MTC CA cosigner name, the note-signature name the checkpoint's
/// trusted signature carries. It is the key of the `logs` entry in
/// `crates/mirror_worker/config.dev.json` and is *different from* the log
/// origin (it has no `.0.<N>` log-number suffix), exactly as
/// c2sp.org/mtc-tlog specifies.
const LOG_KEY_NAME: &str = "oid/1.3.6.1.4.1.32473.2";

/// Origin the mirror is configured to accept checkpoints for: log number
/// 1 of the CA above (within the configured 1-6 window). This is the
/// checkpoint's origin line; note it differs from [`LOG_KEY_NAME`].
const LOG_ORIGIN: &str = "oid/1.3.6.1.4.1.32473.2.0.1";

/// PKCS#8 PEM for the ML-DSA-44 CA cosigner key (seed-only encoding). The
/// logs this mirror serves sign their checkpoints as `subtree/v1`. The
/// corresponding SPKI is committed in `crates/mirror_worker/config.dev.json`
/// under the [`LOG_KEY_NAME`] entry (and pinned by the
/// `dev_config_spki_matches_embedded_pem` unit test). DEV-ONLY: this
/// keypair is published in the repo and MUST NOT be used for anything
/// other than these integration tests.
const LOG_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
    MDQCAQAwCwYJYIZIAWUDBAMRBCKAIBERERERERERERERERERERERERERERERERER\n\
    ERERERER\n\
    -----END PRIVATE KEY-----\n";

fn log_signer() -> SubtreeV1CheckpointSigner {
    let sk = ExpandedSigningKey::<MlDsa44>::from_pkcs8_pem(LOG_SIGNING_KEY_PEM)
        .expect("parse dev log key");
    // The cosigner's note name is the CA ID, NOT the checkpoint origin.
    let name = KeyName::new(LOG_KEY_NAME.to_owned()).expect("KeyName for CA cosigner");
    SubtreeV1CheckpointSigner::new(name, sk)
}

/// Generate a fresh ML-DSA-44 log signer with a random key, under the
/// given cosigner name. Used by the untrusted-key (403) and
/// unknown-origin (404) steps.
fn random_log_signer(name: &str) -> SubtreeV1CheckpointSigner {
    let mut seed = ml_dsa::B32::default();
    rng().fill_bytes(&mut seed);
    let sk = ExpandedSigningKey::<MlDsa44>::from_seed(&seed);
    let name = KeyName::new(name.to_owned()).unwrap();
    SubtreeV1CheckpointSigner::new(name, sk)
}

/// Generate a fresh ML-DSA-44 log signer under the trusted CA cosigner
/// name but with an untrusted key, used by the 403 step.
fn untrusted_log_signer() -> SubtreeV1CheckpointSigner {
    random_log_signer(LOG_KEY_NAME)
}

// ---------------------------------------------------------------------------
// Toy log: maintains enough state to produce valid checkpoints and
// consistency proofs for whatever sequence of leaves the test has
// pushed. Identical shape to the witness integration test.
// ---------------------------------------------------------------------------

struct StoredHashes(Vec<Hash>);

impl HashReader for StoredHashes {
    fn read_hashes(&self, indexes: &[u64]) -> std::result::Result<Vec<Hash>, TlogError> {
        indexes
            .iter()
            .map(|&i| {
                self.0
                    .get(usize::try_from(i).unwrap())
                    .copied()
                    .ok_or(TlogError::IndexesNotInTree)
            })
            .collect()
    }
}

struct ToyLog {
    n: u64,
    stored: StoredHashes,
    /// Raw entry bytes for each leaf, indexed by log position. Retained
    /// so `add-entries` request bodies can replay the exact entry data
    /// whose `record_hash` the mirror recomputes during verification.
    entries: Vec<Vec<u8>>,
}

impl ToyLog {
    fn new() -> Self {
        Self {
            n: 0,
            stored: StoredHashes(Vec::new()),
            entries: Vec::new(),
        }
    }

    fn push(&mut self, data: &[u8]) {
        let new = stored_hashes(self.n, data, &self.stored).expect("stored_hashes");
        self.stored.0.extend(new);
        self.entries.push(data.to_vec());
        self.n += 1;
    }

    /// Push `count` deterministic distinct leaves, e.g. to grow the log
    /// to a size with interesting `add-entries` package structure.
    fn push_n(&mut self, count: u64) {
        for _ in 0..count {
            let data = format!("leaf-{}", self.n).into_bytes();
            self.push(&data);
        }
    }

    fn size(&self) -> u64 {
        self.n
    }

    fn root(&self, size: u64) -> Hash {
        tree_hash(size, &self.stored).expect("tree_hash")
    }

    fn subtree_hash(&self, subtree: &Subtree) -> Hash {
        subtree_hash(subtree, &self.stored).expect("subtree_hash")
    }

    fn sign_checkpoint(&self, signer: &SubtreeV1CheckpointSigner) -> Vec<u8> {
        let size = self.size();
        let hash = self.root(size);
        let tree = TreeWithTimestamp::new(size, hash, now_millis());
        tree.sign(LOG_ORIGIN, &[], &[signer], &mut rng())
            .expect("sign checkpoint")
    }

    /// `consistency_proof(old_size -> current)`. Wraps
    /// `tlog_core::consistency_proof`, whose argument order is reversed
    /// from RFC 6962 convention (larger size first).
    fn consistency_proof(&self, old_size: u64) -> Vec<Hash> {
        let size = self.size();
        if old_size == 0 || old_size == size {
            return Vec::new();
        }
        consistency_proof(size, old_size, &self.stored).expect("consistency_proof")
    }
}

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

fn base_url() -> String {
    std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8787".to_string())
}

struct AddCheckpointResult {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

async fn post_add_checkpoint(body: &[u8]) -> AddCheckpointResult {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/add-checkpoint", base_url()))
        .header("content-type", "text/plain; charset=utf-8")
        .body(body.to_vec())
        .send()
        .await
        .expect("add-checkpoint request");
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let body = resp.bytes().await.expect("response bytes").to_vec();
    AddCheckpointResult {
        status,
        content_type,
        body,
    }
}

/// POST an `add-entries` request body. When `gzip` is set the body is
/// gzip-compressed and `Content-Encoding: gzip` is sent, exercising the
/// mirror's own inflate path (the Workers runtime does not transparently
/// decompress request bodies).
async fn post_add_entries(body: &[u8], gzip: bool) -> AddCheckpointResult {
    let client = reqwest::Client::new();
    let mut req = client
        .post(format!("{}/add-entries", base_url()))
        .header("content-type", "application/octet-stream");
    let payload = if gzip {
        req = req.header("content-encoding", "gzip");
        gzip_bytes(body)
    } else {
        body.to_vec()
    };
    let resp = req.body(payload).send().await.expect("add-entries request");
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let body = resp.bytes().await.expect("response bytes").to_vec();
    AddCheckpointResult {
        status,
        content_type,
        body,
    }
}

/// Gzip-compress `bytes` (default compression), matching what a
/// body-limited client would upload with `Content-Encoding: gzip`.
fn gzip_bytes(bytes: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(bytes).expect("gzip write");
    enc.finish().expect("gzip finish")
}

/// Build an `add-entries` request body for `[upload_start, upload_end)`
/// against `log`'s current tree.
///
/// Each package carries the exact entry bytes for its range and a subtree
/// consistency proof from the package's 256-aligned subtree to the tree
/// of size `upload_end`. If `max_packages` is `Some(k)`, only the first
/// `k` packages are emitted and the body is truncated at that point,
/// simulating a client that stops early (partial-progress upload). When
/// `corrupt_proof` is set, the first package's proof is tampered with so
/// the mirror rejects it with 422.
fn build_add_entries_body(
    log: &ToyLog,
    upload_start: u64,
    upload_end: u64,
    ticket: Vec<u8>,
    max_packages: Option<usize>,
    corrupt_proof: bool,
) -> Vec<u8> {
    let mut buf = Vec::new();
    AddEntriesRequestHeader {
        log_origin: LOG_ORIGIN.to_owned(),
        upload_start,
        upload_end,
        ticket,
    }
    .write_to(&mut buf)
    .expect("write header");

    for (i, (pkg_start, pkg_end)) in package_ranges(upload_start, upload_end).enumerate() {
        if max_packages.is_some_and(|k| i >= k) {
            break;
        }
        let subtree_start = (pkg_start / 256) * 256;
        let subtree = Subtree::new(subtree_start, pkg_end).expect("valid subtree");
        let mut proof = subtree_consistency_proof(upload_end, &subtree, &log.stored)
            .expect("subtree consistency proof");
        if corrupt_proof && i == 0 && !proof.is_empty() {
            proof[0].0[0] ^= 0xff;
        }
        let entries: Vec<Vec<u8>> = (pkg_start..pkg_end)
            .map(|idx| log.entries[usize::try_from(idx).unwrap()].clone())
            .collect();
        EntryPackage { entries, proof }
            .write_to(&mut buf)
            .expect("write package");
    }
    buf
}

/// POST a `sign-subtree` request body.
async fn post_sign_subtree(body: &[u8]) -> AddCheckpointResult {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/sign-subtree", base_url()))
        .header("content-type", "text/plain; charset=utf-8")
        .body(body.to_vec())
        .send()
        .await
        .expect("sign-subtree request");
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let body = resp.bytes().await.expect("response bytes").to_vec();
    AddCheckpointResult {
        status,
        content_type,
        body,
    }
}

/// Build a `SubtreeV1NoteVerifier` from the mirror's `/metadata` SPKI and
/// configured name, used to verify `sign-subtree` responses.
fn mirror_verifier(meta: &MetadataResponse) -> SubtreeV1NoteVerifier {
    use pkcs8::DecodePublicKey;
    let mirror_vk = ml_dsa::VerifyingKey::<MlDsa44>::from_public_key_der(&meta.mirror_public_key)
        .expect("mirror SPKI must parse as ML-DSA-44");
    let name = KeyName::new(meta.mirror_name.clone()).expect("KeyName for mirror");
    SubtreeV1NoteVerifier::new(name, mirror_vk)
}

/// Sign `log`'s current tree and advance the mirror's pending checkpoint
/// to it via `add-checkpoint` (200 expected). `old_size` is the mirror's
/// current pending size, used to build the consistency proof.
async fn advance_pending(log: &ToyLog, signer: &SubtreeV1CheckpointSigner, old_size: u64) {
    let cp = log.sign_checkpoint(signer);
    let note = Note::from_bytes(&cp).unwrap();
    let proof = log.consistency_proof(old_size);
    let body = serialize_add_checkpoint_request(old_size, &proof, &note).unwrap();
    let r = post_add_checkpoint(&body).await;
    assert_eq!(
        r.status,
        200,
        "advance pending {old_size} -> {}: body={:?}",
        log.size(),
        String::from_utf8_lossy(&r.body)
    );
}

#[serde_as]
#[derive(Deserialize, Debug)]
struct MetadataResponse {
    mirror_name: String,
    #[allow(dead_code)]
    description: Option<String>,
    #[serde_as(as = "Base64")]
    mirror_public_key: Vec<u8>,
    mirror_algorithm: String,
    submission_prefix: String,
    #[allow(dead_code)]
    monitoring_prefix: String,
    logs: Vec<LogMetadata>,
}

#[serde_as]
#[derive(Deserialize, Debug)]
struct LogMetadata {
    #[allow(dead_code)]
    description: Option<String>,
    log_key_name: String,
    min_log_number: u64,
    max_log_number: u64,
    #[serde_as(as = "Vec<Base64>")]
    log_public_keys: Vec<Vec<u8>>,
}

async fn fetch_metadata() -> MetadataResponse {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/metadata", base_url()))
        .send()
        .await
        .expect("metadata request");
    assert_eq!(resp.status().as_u16(), 200, "metadata status");
    resp.json().await.expect("metadata json")
}

async fn wait_for_mirror() {
    for _ in 0..30 {
        if reqwest::Client::new()
            .get(format!("{}/metadata", base_url()))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("mirror did not become ready at {}", base_url());
}

// ---------------------------------------------------------------------------
// The whole test suite, as one ordered sequence.
// ---------------------------------------------------------------------------

// Scenarios are intentionally collapsed into one `#[tokio::test]` so
// they thread through a single `ToyLog`; see the module-level comment
// above. That makes this function long by design.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn tlog_mirror_end_to_end() {
    wait_for_mirror().await;

    // --- GET /metadata ---
    let meta = fetch_metadata().await;
    assert_eq!(meta.mirror_name, "dev.mirror.example");
    assert!(!meta.mirror_public_key.is_empty());
    assert_eq!(
        meta.mirror_algorithm, "subtree/v1",
        "dev mirror loads ML-DSA-44 from .dev.vars; algorithm must surface as subtree/v1",
    );
    assert!(meta.submission_prefix.starts_with("http"));
    let log_meta = meta
        .logs
        .iter()
        .find(|l| l.log_key_name == LOG_KEY_NAME)
        .unwrap_or_else(|| panic!("metadata does not list the {LOG_KEY_NAME} cosigner"));
    assert_eq!(log_meta.log_public_keys.len(), 1);
    // LOG_ORIGIN is LOG_KEY_NAME + ".0.1"; its log number (1) must fall
    // within the published [min_log_number, max_log_number] window.
    assert!(
        log_meta.min_log_number <= 1 && 1 <= log_meta.max_log_number,
        "published window [{}, {}] must cover log number 1 ({LOG_ORIGIN})",
        log_meta.min_log_number,
        log_meta.max_log_number,
    );

    let signer = log_signer();
    let mut log = ToyLog::new();

    // --- First submission: old=0 ---
    log.push(b"leaf 0");
    {
        let cp = log.sign_checkpoint(&signer);
        let note = Note::from_bytes(&cp).unwrap();
        let body = serialize_add_checkpoint_request(0, &[], &note).unwrap();
        let r = post_add_checkpoint(&body).await;
        assert_eq!(
            r.status,
            200,
            "first submission: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        // Mirror MUST NOT cosign on add-checkpoint; the response body is
        // empty. (Spec: "responding with an empty response body".)
        assert!(
            r.body.is_empty(),
            "mirror response body must be empty, got: {:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // --- Second submission with consistency proof ---
    let old_size = log.size();
    log.push(b"leaf 1");
    {
        let cp = log.sign_checkpoint(&signer);
        let note = Note::from_bytes(&cp).unwrap();
        let proof = log.consistency_proof(old_size);
        let body = serialize_add_checkpoint_request(old_size, &proof, &note).unwrap();
        let r = post_add_checkpoint(&body).await;
        assert_eq!(
            r.status,
            200,
            "second submission: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        assert!(r.body.is_empty(), "200 response body must be empty");
    }

    // --- Stale old_size -> 409 ---
    // At this point the mirror has recorded pending size = 2. Advance our
    // local log to size = 4 and submit with old=1 (stale).
    log.push(b"leaf 2");
    log.push(b"leaf 3");
    {
        let cp = log.sign_checkpoint(&signer);
        let note = Note::from_bytes(&cp).unwrap();
        let proof = log.consistency_proof(1);
        let body = serialize_add_checkpoint_request(1, &proof, &note).unwrap();
        let r = post_add_checkpoint(&body).await;
        assert_eq!(
            r.status,
            409,
            "stale old_size: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        assert_eq!(
            r.content_type.as_deref().map(str::trim),
            Some(CONTENT_TYPE_TLOG_SIZE),
            "409 must be Content-Type {CONTENT_TYPE_TLOG_SIZE}"
        );
        let size_str = std::str::from_utf8(&r.body).unwrap().trim_end_matches('\n');
        let recorded: u64 = size_str.parse().expect("409 body is a decimal size");
        assert_eq!(
            recorded, 2,
            "409 body must carry the mirror's latest pending size"
        );
    }

    // --- Unknown origin -> 404 ---
    {
        let origin = "not.configured.example/log";
        let other_signer = random_log_signer(origin);
        let tree = TreeWithTimestamp::new(1, record_hash(b"x"), now_millis());
        let cp = tree
            .sign(origin, &[], &[&other_signer], &mut rng())
            .unwrap();
        let note = Note::from_bytes(&cp).unwrap();
        let body = serialize_add_checkpoint_request(0, &[], &note).unwrap();
        let r = post_add_checkpoint(&body).await;
        assert_eq!(
            r.status,
            404,
            "unknown origin: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // --- Untrusted key -> 403 ---
    {
        let other = untrusted_log_signer();
        let tree = TreeWithTimestamp::new(1, record_hash(b"x"), now_millis());
        let cp = tree.sign(LOG_ORIGIN, &[], &[&other], &mut rng()).unwrap();
        let note = Note::from_bytes(&cp).unwrap();
        let body = serialize_add_checkpoint_request(0, &[], &note).unwrap();
        let r = post_add_checkpoint(&body).await;
        assert_eq!(
            r.status,
            403,
            "untrusted key: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // --- Trusted (name, id) but garbage signature bytes -> 403 ---
    //
    // Per c2sp.org/signed-note, a signature line that claims a trusted
    // `(name, id)` but whose bytes fail to verify makes the note
    // malformed. The mirror MUST surface this as 403 Forbidden (same
    // as "no trusted signature at all"), matching the witness behaviour.
    {
        let verifier = signer.verifier();
        let tree = TreeWithTimestamp::new(1, record_hash(b"x"), now_millis());
        // Sign a valid checkpoint, then replace the log's real
        // signature line with one carrying the right `(name, id)` but
        // garbage bytes (a correctly-sized subtree/v1 timestamped
        // signature blob, 8-byte timestamp + 2420-byte ML-DSA-44
        // signature, that is all zeroes and so fails to verify).
        let cp = tree.sign(LOG_ORIGIN, &[], &[&signer], &mut rng()).unwrap();
        let parsed = Note::from_bytes(&cp).unwrap();
        let bogus = NoteSignature::new(
            verifier.name().clone(),
            verifier.key_id(),
            vec![0u8; 8 + 2420],
        );
        let tampered = Note::new(parsed.text(), &[bogus]).unwrap();
        let body = serialize_add_checkpoint_request(0, &[], &tampered).unwrap();
        let r = post_add_checkpoint(&body).await;
        assert_eq!(
            r.status,
            403,
            "trusted key + bad sig bytes: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // --- Bad consistency proof -> 422 ---
    // Advance our local log by one more leaf so we need a proof to
    // submit it, then hand-craft a wrong proof of the right length.
    log.push(b"leaf 4");
    {
        let cp = log.sign_checkpoint(&signer);
        let note = Note::from_bytes(&cp).unwrap();
        let correct = log.consistency_proof(2);
        let bogus = vec![Hash([0u8; HASH_SIZE]); correct.len().max(1)];
        let body = serialize_add_checkpoint_request(2, &bogus, &note).unwrap();
        let r = post_add_checkpoint(&body).await;
        assert_eq!(
            r.status,
            422,
            "bad proof: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // --- old_size > checkpoint.size -> 400 ---
    {
        // Build a small independent log so checkpoint.size is
        // controllably small.
        let mut small = ToyLog::new();
        small.push(b"x");
        let cp = small.sign_checkpoint(&signer);
        let note = Note::from_bytes(&cp).unwrap();
        let body = serialize_add_checkpoint_request(999, &[], &note).unwrap();
        let r = post_add_checkpoint(&body).await;
        assert_eq!(
            r.status,
            400,
            "old > checkpoint size: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // --- Malformed body -> 400 ---
    {
        let r = post_add_checkpoint(b"old 0\n").await;
        assert_eq!(
            r.status,
            400,
            "malformed body: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // =======================================================================
    // add-entries scenarios. The mirror starts with committed = 0,
    // next_entry = 0 (no entries ingested yet). We grow the log and drive
    // the pending checkpoint forward with `add-checkpoint`, then feed
    // entries back in to exercise gzip, partial/202 progress, resume, and
    // the non-256-aligned `upload_start` path.
    // =======================================================================

    // --- Advance pending 2 -> 600 ---
    // 600 spans three packages ([0,256), [256,512), [512,600)); enough to
    // test partial progress and a non-aligned resume later.
    log.push_n(600 - log.size());
    advance_pending(&log, &signer, 2).await;

    // --- Partial upload via gzip -> 202 ---
    // Declare the full [0, 600) upload but send only the first package
    // ([0,256)) and truncate, gzip-compressed. The mirror ingests package
    // 0, persists [0,256), and returns 202 with next_entry = 256.
    {
        let body = build_add_entries_body(&log, 0, 600, Vec::new(), Some(1), false);
        let r = post_add_entries(&body, /* gzip */ true).await;
        assert_eq!(
            r.status,
            202,
            "partial gzip upload: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        let info = MirrorInfo::parse(&r.body).expect("202 body is mirror-info");
        assert_eq!(info.tree_size, 600, "202 tree_size is the pending size");
        assert_eq!(
            info.next_entry, 256,
            "202 next_entry is the advanced persisted frontier"
        );
    }

    // --- Resume [256, 600) -> 200 cosignature ---
    // Send the remaining two packages (plain, not gzipped). This reaches
    // the pending size, so the mirror cosigns and advances committed=600.
    {
        let body = build_add_entries_body(&log, 256, 600, Vec::new(), None, false);
        let r = post_add_entries(&body, /* gzip */ false).await;
        assert_eq!(
            r.status,
            200,
            "resume to full: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        assert!(
            !r.body.is_empty(),
            "200 add-entries body must carry the mirror cosignature line(s)"
        );
    }

    // --- Grow log, advance pending 600 -> 1000 ---
    // Now next_entry (= 600) is non-256-aligned, setting up the
    // non-aligned resume below.
    log.push_n(1000 - log.size());
    advance_pending(&log, &signer, 600).await;

    // --- Non-aligned resume [600, 1000) -> 200 ---
    // upload_start = 600 is not 256-aligned. The first package covers
    // [600, 768); its subtree starts at 512, so the mirror reads the
    // already-committed leaves [512, 600) back from R2 to reconstruct the
    // subtree hash. A full upload -> 200 cosignature, committed = 1000.
    //
    // Capture the mirror cosignature and assemble a reference checkpoint
    // (the size-1000 log note + the mirror's cosignature) for the
    // sign-subtree steps below.
    let cp_size = log.size(); // 1000
    let cosigned_checkpoint;
    {
        let body = build_add_entries_body(&log, 600, 1000, Vec::new(), None, false);
        let r = post_add_entries(&body, /* gzip */ false).await;
        assert_eq!(
            r.status,
            200,
            "non-aligned resume: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        let mirror_sigs = parse_sign_subtree_response(&r.body).expect("parse mirror cosignature");
        assert_eq!(mirror_sigs.len(), 1, "exactly one mirror cosignature line");
        let log_note = Note::from_bytes(&log.sign_checkpoint(&signer)).unwrap();
        cosigned_checkpoint =
            Note::new(log_note.text(), &mirror_sigs).expect("assemble cosigned reference note");
    }

    // --- Advance pending 1000 -> 1256 ---
    log.push_n(1256 - log.size());
    advance_pending(&log, &signer, 1000).await;

    // --- Truncate before any complete package -> 400 ---
    // Header declares [1000, 1256) but no packages follow. With zero
    // complete packages there is nothing to persist, so this is malformed.
    {
        let body = build_add_entries_body(&log, 1000, 1256, Vec::new(), Some(0), false);
        let r = post_add_entries(&body, /* gzip */ false).await;
        assert_eq!(
            r.status,
            400,
            "empty-package upload: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // --- Bad subtree proof -> 422 ---
    {
        // Last arg `true` corrupts the first package's subtree proof.
        let body = build_add_entries_body(&log, 1000, 1256, Vec::new(), None, true);
        let r = post_add_entries(&body, /* gzip */ false).await;
        assert_eq!(
            r.status,
            422,
            "corrupt proof: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // =======================================================================
    // sign-subtree scenarios. The mirror committed size 1000 above and
    // emitted a subtree/v1 cosignature over it; the `cosigned_checkpoint`
    // assembled there carries that cosignature and is the reference
    // checkpoint these requests verify statelessly against.
    // =======================================================================
    let verifier = mirror_verifier(&meta);

    // --- sign-subtree happy path (start = 0) ---
    {
        let subtree = Subtree::new(0, 512).expect("valid subtree");
        let s_hash = log.subtree_hash(&subtree);
        let proof =
            subtree_consistency_proof(cp_size, &subtree, &log.stored).expect("subtree proof");
        let body = serialize_sign_subtree_request(
            subtree.lo(),
            subtree.hi(),
            &s_hash,
            &[],
            &proof,
            &cosigned_checkpoint,
        )
        .unwrap();
        let r = post_sign_subtree(&body).await;
        assert_eq!(
            r.status,
            200,
            "sign-subtree happy path: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        let sigs = parse_sign_subtree_response(&r.body).expect("parse sign-subtree response");
        assert_eq!(sigs.len(), 1, "exactly one cosignature line");
        assert!(
            verifier.verify_subtree(LOG_ORIGIN, &subtree, &s_hash, sigs[0].signature()),
            "mirror signature must verify against the requested subtree",
        );
    }

    // --- sign-subtree with a non-256-aligned, non-zero start ---
    // The arbitrary-subtree path that Merkle Tree Certificate cosigning
    // relies on: subtree [512, 768) (start != 0). Its cosignature must
    // carry a zero timestamp per the spec.
    {
        let subtree = Subtree::new(512, 768).expect("valid subtree");
        let s_hash = log.subtree_hash(&subtree);
        let proof =
            subtree_consistency_proof(cp_size, &subtree, &log.stored).expect("subtree proof");
        let body = serialize_sign_subtree_request(
            subtree.lo(),
            subtree.hi(),
            &s_hash,
            &[],
            &proof,
            &cosigned_checkpoint,
        )
        .unwrap();
        let r = post_sign_subtree(&body).await;
        assert_eq!(
            r.status,
            200,
            "sign-subtree non-zero start: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        let sigs = parse_sign_subtree_response(&r.body).expect("parse sign-subtree response");
        assert!(
            verifier.verify_subtree(LOG_ORIGIN, &subtree, &s_hash, sigs[0].signature()),
            "mirror signature must verify against the non-zero-start subtree",
        );
    }

    // --- reference checkpoint NOT cosigned by this mirror -> 403 ---
    // A fresh log-signed checkpoint the mirror has never cosigned: stateless
    // verification rejects it (no mirror self-cosignature attached).
    {
        let mut other = ToyLog::new();
        other.push(b"a");
        other.push(b"b");
        let note = Note::from_bytes(&other.sign_checkpoint(&signer)).unwrap();
        let subtree = Subtree::new(0, 1).expect("valid subtree");
        let s_hash = other.subtree_hash(&subtree);
        let proof =
            subtree_consistency_proof(other.size(), &subtree, &other.stored).expect("proof");
        let body = serialize_sign_subtree_request(0, 1, &s_hash, &[], &proof, &note).unwrap();
        let r = post_sign_subtree(&body).await;
        assert_eq!(
            r.status,
            403,
            "reference checkpoint not cosigned by mirror: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // --- sign-subtree with end > checkpoint.size -> 400 ---
    {
        let body = serialize_sign_subtree_request(
            0,
            cp_size + 1,
            &Hash([0u8; HASH_SIZE]),
            &[],
            &[],
            &cosigned_checkpoint,
        )
        .unwrap();
        let r = post_sign_subtree(&body).await;
        assert_eq!(
            r.status,
            400,
            "end > checkpoint size: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }
}
