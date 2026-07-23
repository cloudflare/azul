// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! End-to-end integration tests for the `mirror_worker` implementation of
//! [c2sp.org/tlog-mirror][spec].
//!
//! These tests require a local `wrangler dev` instance of `mirror_worker`
//! on `localhost:8787` (or a loopback `BASE_URL`), backed by fresh state.
//! Delete `crates/mirror_worker/.wrangler/state/` between runs. CI starts
//! with fresh state.
//!
//! The submission APIs are stateful. All scenarios run in one test that
//! threads an in-memory [`ToyLog`] through `add-checkpoint`, `add-entries`,
//! and `sign-subtree` in order.
//!
//! Per spec the mirror MUST NOT cosign on `add-checkpoint` (the success
//! body is empty); cosignatures are emitted only by `add-entries` once
//! entries catch up to the pending tree size.
//!
//! `LOG_KEY_NAME` identifies the CA cosigner; `LOG_ORIGIN` identifies log 1.
//! The embedded key must match the SPKI in `config.dev.json`.
//!
//! [spec]: https://c2sp.org/tlog-mirror

use ml_dsa::pkcs8::DecodePrivateKey as _;
use ml_dsa::{ExpandedSigningKey, MlDsa44};
use rand::Rng as _;
use rand::rng;
use serde::Deserialize;
use serde_with::{base64::Base64, serde_as};
use sha2::{Digest as _, Sha256};
use signed_note::{KeyName, Note, NoteSignature, VerifierList};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tlog_checkpoint::{CheckpointSigner, TreeWithTimestamp};
use tlog_core::{
    HASH_SIZE, Hash, HashReader, Subtree, TlogError, consistency_proof, record_hash, stored_hashes,
    subtree_consistency_proof, subtree_hash, tree_hash,
};
use tlog_cosignature::{SubtreeV1CheckpointSigner, SubtreeV1NoteVerifier};
use tlog_mirror::{
    AddEntriesRequestHeader, EntryPackage, MIRROR_INFO_CONTENT_TYPE, MirrorInfo, package_ranges,
};
use tlog_tiles::{PathElem, PreloadedTlogTileReader, TileHashReader, TlogTile, TlogTileRecorder};
use tlog_witness::{
    CONTENT_TYPE_TLOG_SIZE, parse_sign_subtree_response, serialize_add_checkpoint_request,
    serialize_sign_subtree_request,
};

// ---------------------------------------------------------------------------
// Test fixtures: MTC CA cosigner name, log origin, ML-DSA-44 log key
// ---------------------------------------------------------------------------

/// CA cosigner name configured as the `logs` key.
const LOG_KEY_NAME: &str = "oid/1.3.6.1.4.1.32473.2";

/// Numbered log origin accepted under [`LOG_KEY_NAME`].
const LOG_ORIGIN: &str = "oid/1.3.6.1.4.1.32473.2.0.1";
const OTHER_LOG_ORIGIN: &str = "oid/1.3.6.1.4.1.32473.2.0.2";
const R2_BUCKET: &str = "tlog-mirror-public-dev";

/// Dev-only ML-DSA-44 `subtree/v1` key matching `config.dev.json`.
/// Do not use outside these integration tests.
const LOG_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
    MDQCAQAwCwYJYIZIAWUDBAMRBCKAIBERERERERERERERERERERERERERERERERER\n\
    ERERERER\n\
    -----END PRIVATE KEY-----\n";

fn log_signer() -> SubtreeV1CheckpointSigner {
    let sk = ExpandedSigningKey::<MlDsa44>::from_pkcs8_pem(LOG_SIGNING_KEY_PEM)
        .expect("parse dev log key");
    // The cosigner note name is the CA ID rather than the checkpoint origin.
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
        self.sign_checkpoint_for(LOG_ORIGIN, signer)
    }

    fn sign_checkpoint_for(&self, origin: &str, signer: &SubtreeV1CheckpointSigner) -> Vec<u8> {
        let size = self.size();
        let hash = self.root(size);
        let tree = TreeWithTimestamp::new(size, hash, now_millis());
        tree.sign(origin, &[], &[signer], &mut rng())
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

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build HTTP client")
}

fn mirror_worker_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../mirror_worker")
}

fn r2_key(path: &str) -> String {
    let origin_hash = hex::encode(Sha256::digest(LOG_ORIGIN.as_bytes()));
    format!("{R2_BUCKET}/{origin_hash}/{path}")
}

async fn local_r2_object(path: &str) -> Option<Vec<u8>> {
    let url = base_url();
    assert!(
        url.starts_with("http://localhost:") || url.starts_with("http://127.0.0.1:"),
        "local R2 inspection requires a loopback BASE_URL",
    );
    let command = tokio::process::Command::new("wrangler")
        .current_dir(mirror_worker_dir())
        .args([
            "r2",
            "object",
            "get",
            &r2_key(path),
            "--local",
            "--persist-to",
            ".wrangler/state",
            "--pipe",
        ])
        .output();
    let output = tokio::time::timeout(Duration::from_secs(30), command)
        .await
        .expect("wrangler r2 object get timed out")
        .expect("run wrangler r2 object get");
    if output.status.success() {
        return Some(output.stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("specified key does not exist") {
        return None;
    }
    panic!("wrangler r2 object get failed for {path}: {stderr}");
}

async fn require_local_r2_object(path: &str) -> Vec<u8> {
    local_r2_object(path)
        .await
        .unwrap_or_else(|| panic!("R2 object missing: {path}"))
}

async fn wait_for_local_r2_absence(paths: &[&str]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let mut any_present = false;
        for path in paths {
            any_present |= local_r2_object(path).await.is_some();
        }
        if !any_present {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "R2 objects were not cleaned: {paths:?}",
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn parse_entry_bundle(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        assert!(offset + 2 <= bytes.len(), "truncated entry length");
        let len = usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
        offset += 2;
        assert!(offset + len <= bytes.len(), "truncated entry");
        entries.push(bytes[offset..offset + len].to_vec());
        offset += len;
    }
    entries
}

async fn assert_cut_tiles(log: &ToyLog, tree_size: u64) {
    let leaf_index = tree_size - 1;
    let hash_index = tlog_core::stored_hash_index(0, leaf_index);
    let recorder = TlogTileRecorder::default();
    let reader = TileHashReader::new(tree_size, log.root(tree_size), &recorder);
    let _ = reader.read_hashes(&[hash_index]);

    let mut tile_data = HashMap::new();
    for tile in recorder.0.into_inner() {
        let bytes = require_local_r2_object(&tile.path()).await;
        tile_data.insert(tile, bytes);
    }
    let preloaded = PreloadedTlogTileReader(tile_data);
    let hashes = TileHashReader::new(tree_size, log.root(tree_size), &preloaded)
        .read_hashes(&[hash_index])
        .expect("authenticate cut hash tiles");
    let entry_index = usize::try_from(leaf_index).expect("leaf index fits usize");
    assert_eq!(hashes, [record_hash(&log.entries[entry_index])]);

    let hash_tile = TlogTile::from_leaf_index(leaf_index)
        .parent(0, tree_size)
        .expect("cut leaf tile");
    let data_path = hash_tile.with_data_path(PathElem::Entries).path();
    let entries = parse_entry_bundle(&require_local_r2_object(&data_path).await);
    let base = usize::try_from(leaf_index / 256 * 256).unwrap();
    let end = usize::try_from(tree_size).unwrap();
    assert_eq!(entries, log.entries[base..end]);
}

struct AddCheckpointResult {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

async fn post_add_checkpoint(body: &[u8]) -> AddCheckpointResult {
    let client = http_client();
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

/// POST `body` to `add-entries`, setting `Content-Encoding` when provided.
/// The body is sent unchanged.
async fn post_add_entries_payload(
    body: &[u8],
    content_encoding: Option<&str>,
) -> AddCheckpointResult {
    let client = http_client();
    let mut req = client
        .post(format!("{}/add-entries", base_url()))
        .header("content-type", "application/octet-stream");
    if let Some(encoding) = content_encoding {
        req = req.header("content-encoding", encoding);
    }
    let resp = req
        .body(body.to_vec())
        .send()
        .await
        .expect("add-entries request");
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

async fn post_add_entries(body: &[u8]) -> AddCheckpointResult {
    post_add_entries_payload(body, None).await
}

async fn post_gzip_add_entries(body: &[u8]) -> AddCheckpointResult {
    let compressed = gzip_bytes(body);
    post_add_entries_payload(&compressed, Some("gzip")).await
}

fn gzip_bytes(bytes: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(bytes).expect("gzip write");
    enc.finish().expect("gzip finish")
}

/// Build an `add-entries` body for `[upload_start, upload_end)`.
/// `max_packages` truncates at a package boundary; `corrupt_proof`
/// corrupts the first proof.
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

fn build_add_entries_header(upload_start: u64, upload_end: u64, ticket: Vec<u8>) -> Vec<u8> {
    build_add_entries_header_for(LOG_ORIGIN, upload_start, upload_end, ticket)
}

fn build_add_entries_header_for(
    origin: &str,
    upload_start: u64,
    upload_end: u64,
    ticket: Vec<u8>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    AddEntriesRequestHeader {
        log_origin: origin.to_owned(),
        upload_start,
        upload_end,
        ticket,
    }
    .write_to(&mut buf)
    .expect("write header");
    buf
}

fn parse_mirror_info(r: &AddCheckpointResult, status: u16) -> MirrorInfo {
    assert_eq!(
        r.status,
        status,
        "expected {status}: body={:?}",
        String::from_utf8_lossy(&r.body),
    );
    assert_eq!(
        r.content_type.as_deref().map(str::trim),
        Some(MIRROR_INFO_CONTENT_TYPE),
    );
    MirrorInfo::parse(&r.body).expect("response body is mirror-info")
}

async fn post_sign_subtree(body: &[u8]) -> AddCheckpointResult {
    let client = http_client();
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

fn verify_mirror_signature(
    checkpoint: &Note,
    signatures: &[NoteSignature],
    meta: &MetadataResponse,
) {
    let augmented = Note::new(checkpoint.text(), signatures).expect("assemble augmented note");
    let (verified, _) = augmented
        .verify(&VerifierList::new(vec![Box::new(mirror_verifier(meta))]))
        .expect("verify mirror signature");
    assert!(!verified.is_empty(), "mirror key did not sign response");
}

/// Sign `log`'s current tree and advance the mirror's pending checkpoint
/// to it via `add-checkpoint` (200 expected). `old_size` is the mirror's
/// current pending size, used to build the consistency proof.
async fn advance_pending(log: &ToyLog, signer: &SubtreeV1CheckpointSigner, old_size: u64) -> Note {
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
    note
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
    let client = http_client();
    let resp = client
        .get(format!("{}/metadata", base_url()))
        .send()
        .await
        .expect("metadata request");
    assert_eq!(resp.status().as_u16(), 200, "metadata status");
    resp.json().await.expect("metadata json")
}

async fn wait_for_mirror() {
    let client = http_client();
    for _ in 0..30 {
        if client
            .get(format!("{}/metadata", base_url()))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("mirror did not become ready at {}", base_url());
}

// The scenarios share one stateful mirror instance and must run in order.
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

    // A configured origin needs a pending checkpoint before accepting
    // entries.
    {
        let body = build_add_entries_header_for(OTHER_LOG_ORIGIN, 0, 0, Vec::new());
        let r = post_add_entries(&body).await;
        assert_eq!(
            r.status,
            422,
            "entries before checkpoint: body={:?}",
            String::from_utf8_lossy(&r.body),
        );
    }

    let mut other_log = ToyLog::new();
    other_log.push(b"other leaf 0");
    {
        let cp = other_log.sign_checkpoint_for(OTHER_LOG_ORIGIN, &signer);
        let note = Note::from_bytes(&cp).expect("other-origin checkpoint");
        let body = serialize_add_checkpoint_request(0, &[], &note).unwrap();
        let r = post_add_checkpoint(&body).await;
        assert_eq!(
            r.status,
            200,
            "other-origin checkpoint: body={:?}",
            String::from_utf8_lossy(&r.body),
        );
    }

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
    // The pending size is 2; submit size 4 with stale old_size=1.
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
    // Submit size 5 with an invalid proof for old_size=2.
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
    let checkpoint_600 = advance_pending(&log, &signer, 2).await;

    // `upload_end` names a pending checkpoint rather than the end of the
    // request body. Size 256 has no accepted checkpoint.
    {
        let body = build_add_entries_header(0, 256, Vec::new());
        let r = post_add_entries(&body).await;
        let info = parse_mirror_info(&r, 409);
        assert_eq!(info.tree_size, 600);
        assert_eq!(info.next_entry, 0);
        assert!(!info.ticket.is_empty());
    }

    {
        let body = build_add_entries_header(1, 600, Vec::new());
        let r = post_add_entries(&body).await;
        let info = parse_mirror_info(&r, 409);
        assert_eq!(info.tree_size, 600);
        assert_eq!(info.next_entry, 0);
    }

    // --- Malformed gzip -> 400 ---
    {
        let r = post_add_entries_payload(b"not a gzip stream", Some("gzip")).await;
        assert_eq!(
            r.status,
            400,
            "malformed gzip: body={:?}",
            String::from_utf8_lossy(&r.body),
        );
    }

    // --- Partial upload via gzip -> 202 ---
    // Declare the full [0, 600) upload but send only the first package
    // ([0,256)) and truncate, gzip-compressed. The mirror ingests package
    // 0, persists [0,256), and returns 202 with next_entry = 256.
    {
        let body = build_add_entries_body(&log, 0, 600, Vec::new(), Some(1), false);
        let r = post_gzip_add_entries(&body).await;
        let info = parse_mirror_info(&r, 202);
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
        let r = post_add_entries(&body).await;
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

    let partial_600 = ["tile/0/002.p/88", "tile/entries/002.p/88"];
    for path in partial_600 {
        require_local_r2_object(path).await;
    }

    // Re-verifying 256 already persisted entries is idempotent.
    {
        let body = build_add_entries_body(&log, 344, 600, Vec::new(), None, false);
        let r = post_add_entries(&body).await;
        assert_eq!(
            r.status,
            200,
            "replayed upload: body={:?}",
            String::from_utf8_lossy(&r.body),
        );
        let signatures = parse_sign_subtree_response(&r.body).expect("parse replay response");
        assert_eq!(signatures.len(), 1);
        verify_mirror_signature(&checkpoint_600, &signatures, &meta);
    }

    // --- Grow log, advance pending 600 -> 1000 ---
    // Now next_entry (= 600) is non-256-aligned, setting up the
    // non-aligned resume below.
    log.push_n(1000 - log.size());
    advance_pending(&log, &signer, 600).await;

    // The committed checkpoint remains a valid target after pending moves
    // ahead. No ticket is required.
    {
        let body = build_add_entries_header(600, 600, Vec::new());
        let r = post_add_entries(&body).await;
        assert_eq!(
            r.status,
            200,
            "committed checkpoint target: body={:?}",
            String::from_utf8_lossy(&r.body),
        );
        assert!(!r.body.is_empty());
    }

    // Replaying more than one package below the persisted frontier is
    // rejected before the request body is read.
    {
        let body = build_add_entries_header(0, 1000, Vec::new());
        let r = post_add_entries(&body).await;
        let info = parse_mirror_info(&r, 409);
        assert_eq!(info.tree_size, 1000);
        assert_eq!(info.next_entry, 600);
        assert!(!info.ticket.is_empty());
    }

    // --- Non-aligned resume [600, 1000) -> 200 ---
    // upload_start = 600 is not 256-aligned. The first package covers
    // [600, 768); its subtree starts at 512, so the mirror reads the
    // already-persisted leaves [512, 600) back from R2 to reconstruct the
    // subtree hash. A full upload -> 200 cosignature, committed = 1000.
    //
    // Capture the mirror cosignature and assemble a reference checkpoint
    // (the size-1000 log note + the mirror's cosignature) for the
    // sign-subtree steps below.
    let cp_size = log.size(); // 1000
    let cosigned_checkpoint;
    {
        let body = build_add_entries_body(&log, 600, 1000, Vec::new(), None, false);
        let r = post_add_entries(&body).await;
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

    wait_for_local_r2_absence(&partial_600).await;
    for path in [
        "tile/0/002",
        "tile/entries/002",
        "tile/0/003.p/232",
        "tile/entries/003.p/232",
    ] {
        require_local_r2_object(path).await;
    }

    // --- Advance pending 1000 -> 1256 ---
    log.push_n(1256 - log.size());
    advance_pending(&log, &signer, 1000).await;

    // --- Truncate before any complete package -> 400 ---
    // Header declares [1000, 1256) but no packages follow. With zero
    // complete packages there is nothing to persist, so this is malformed.
    {
        let body = build_add_entries_body(&log, 1000, 1256, Vec::new(), Some(0), false);
        let r = post_add_entries(&body).await;
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
        let r = post_add_entries(&body).await;
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

    // --- sign-subtree with a non-zero start ---
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

    // With `commit_packages = 2`, these uploads exercise multiple flushes
    // and resume from the last flushed package boundary.

    // --- Finish [1000, 1256) ---
    {
        let body = build_add_entries_body(&log, 1000, 1256, Vec::new(), None, false);
        let r = post_add_entries(&body).await;
        assert_eq!(
            r.status,
            200,
            "finish [1000, 1256): body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // --- Multi-flush complete upload [1256, 2280) -> 200 ---
    // Five packages produce two full flushes and a trailing flush.
    log.push_n(2280 - log.size());
    advance_pending(&log, &signer, 1256).await;
    {
        let body = build_add_entries_body(&log, 1256, 2280, Vec::new(), None, false);
        let r = post_add_entries(&body).await;
        assert_eq!(
            r.status,
            200,
            "multi-flush complete upload: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        assert!(
            !r.body.is_empty(),
            "200 add-entries body must carry the mirror cosignature line(s)"
        );
    }

    // --- Multi-flush truncated upload [2280, 3000) -> 202 ---
    // Three packages flush through 2816 before truncation.
    log.push_n(3000 - log.size());
    advance_pending(&log, &signer, 2280).await;
    {
        let body = build_add_entries_body(&log, 2280, 3000, Vec::new(), Some(3), false);
        let r = post_add_entries(&body).await;
        let info = parse_mirror_info(&r, 202);
        assert_eq!(info.tree_size, 3000, "202 tree_size is the pending size");
        assert_eq!(
            info.next_entry, 2816,
            "202 next_entry is the last flushed package boundary"
        );
    }

    // --- Resume from the mid-flush boundary [2816, 3000) -> 200 ---
    {
        let body = build_add_entries_body(&log, 2816, 3000, Vec::new(), None, false);
        let r = post_add_entries(&body).await;
        assert_eq!(
            r.status,
            200,
            "resume after truncation: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        assert!(
            !r.body.is_empty(),
            "200 add-entries body must carry the mirror cosignature line(s)"
        );
    }

    // --- Ticketed checkpoint below the persisted frontier ---
    // A ticket permits size 3256 after pending advances to 4000 and
    // persistence reaches 3328. The checkpoint requires cut tiles.
    log.push_n(3256 - log.size());
    let checkpoint_3256 = advance_pending(&log, &signer, 3000).await;
    let ticket_3256 = {
        let body = build_add_entries_header(3000, 3001, Vec::new());
        let r = post_add_entries(&body).await;
        let info = parse_mirror_info(&r, 409);
        assert_eq!(info.tree_size, 3256);
        assert_eq!(info.next_entry, 3000);
        assert!(!info.ticket.is_empty());
        info.ticket
    };

    {
        let body = build_add_entries_header_for(OTHER_LOG_ORIGIN, 0, 3256, ticket_3256.clone());
        let r = post_add_entries(&body).await;
        let info = parse_mirror_info(&r, 409);
        assert_eq!(info.tree_size, 1);
        assert_eq!(info.next_entry, 0);
    }

    log.push_n(4000 - log.size());
    advance_pending(&log, &signer, 3256).await;
    {
        let body = build_add_entries_body(&log, 3000, 4000, Vec::new(), Some(2), false);
        let r = post_add_entries(&body).await;
        let info = parse_mirror_info(&r, 202);
        assert_eq!(info.tree_size, 4000);
        assert_eq!(info.next_entry, 3328);
    }
    {
        let body = build_add_entries_body(&log, 3072, 3256, ticket_3256, None, false);
        let r = post_add_entries(&body).await;
        assert_eq!(
            r.status,
            200,
            "ticketed cut checkpoint: body={:?}",
            String::from_utf8_lossy(&r.body),
        );
        let signatures =
            parse_sign_subtree_response(&r.body).expect("parse ticketed checkpoint response");
        assert_eq!(signatures.len(), 1);
        verify_mirror_signature(&checkpoint_3256, &signatures, &meta);
        assert_cut_tiles(&log, 3256).await;
    }
}
