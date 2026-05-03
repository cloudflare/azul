// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! End-to-end integration tests for the [`witness_worker`] implementation of
//! [`c2sp.org/tlog-witness`].
//!
//! These tests require a running `wrangler dev` instance of `witness_worker`
//! on `localhost:8787` (or `BASE_URL`), backed by **fresh** persistent state.
//! Delete `crates/witness_worker/.wrangler/state/` between runs to reset the
//! per-origin `(size, hash)` the witness has cosigned. CI does this
//! automatically.
//!
//! # Test layout
//!
//! The witness's `add-checkpoint` API is deeply stateful: each successful
//! submission advances a per-origin `(latest_size, latest_hash)` that every
//! subsequent submission must be consistent with. Giving each case its own
//! `#[tokio::test]` would cross-pollute that state unpredictably (tests run in
//! a non-deterministic order by default), so we collapse the scenarios into a
//! single `#[tokio::test]` that threads one in-memory [`ToyLog`] through
//! every step in order. Each step asserts the expected HTTP status and then
//! (if the call was a successful advance) updates the local log to match what
//! the witness just recorded.
//!
//! Steps covered (happy-path + basic error codes per the spec):
//!
//! 1. `/metadata` returns the configured witness identity and log list.
//! 2. First `add-checkpoint` (`old=0`, no proof) → 200.
//! 3. Second `add-checkpoint` with consistency proof → 200, advancing state.
//! 4. Stale `old_size` → 409 with `text/x.tlog.size` body.
//! 5. Unknown origin → 404.
//! 6. Signature from untrusted key → 403.
//! 7. Trusted `(name, id)` but garbage signature bytes → 403.
//! 8. Bad consistency proof (right size, wrong hashes) → 422.
//! 9. `old > checkpoint.size` → 400.
//! 10. Malformed body (missing blank line) → 400.
//! 11. `/sign-subtree` happy path: cosign a subtree of the most-
//!     recently-cosigned checkpoint and verify the response signature.
//! 12. `/sign-subtree` with a checkpoint NOT cosigned by the witness → 403.
//! 13. `/sign-subtree` with `end > checkpoint.size` → 400.
//!
//! # Key management
//!
//! The witness's `add-checkpoint` cosignature is `subtree/v1` (ML-DSA-44),
//! per the dev `WITNESS_SIGNING_KEY` in `.dev.vars`. The log signing
//! key remains Ed25519. Both PEMs are duplicated in the witness crate's
//! unit tests so a rotation breaks closed; see
//! `crates/witness_worker/src/lib.rs::dev_config_tests`.
//!
//! [`witness_worker`]: ../../../crates/witness_worker
//! [`c2sp.org/tlog-witness`]: https://c2sp.org/tlog-witness

use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey as Ed25519SigningKey};
use ml_dsa::MlDsa44;
use rand::rng;
use serde::Deserialize;
use serde_with::{base64::Base64, serde_as};
use signed_note::{KeyName, Note, NoteSignature, VerifierList};
use std::time::Duration;
use tlog_cosignature::SubtreeV1NoteVerifier;
use tlog_tiles::{
    consistency_proof, record_hash, stored_hashes, subtree_consistency_proof, tree_hash,
    CheckpointSigner, Ed25519CheckpointSigner, Hash, HashReader, Subtree, TlogError,
    TreeWithTimestamp, HASH_SIZE,
};
use tlog_witness::{
    parse_add_checkpoint_response, parse_sign_subtree_response, serialize_add_checkpoint_request,
    serialize_sign_subtree_request, CONTENT_TYPE_TLOG_SIZE,
};

// ---------------------------------------------------------------------------
// Test fixtures: log origin + dev keypairs
// ---------------------------------------------------------------------------

/// Origin the witness is configured to accept checkpoints for (see
/// `crates/witness_worker/config.dev.json`).
const LOG_ORIGIN: &str = "example.com/log1";

/// PKCS#8 PEM for the Ed25519 log key. The corresponding SPKI is committed
/// in `crates/witness_worker/config.dev.json` as the only entry of
/// `log_public_keys`. DEV-ONLY — this keypair is published in the repo and
/// MUST NOT be used for anything other than these integration tests.
const LOG_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
    MC4CAQAwBQYDK2VwBCIEIA2VCmSeCNVJTboEACcXvVahZHSHEJDxSl94aej1Q8hQ\n\
    -----END PRIVATE KEY-----\n";

fn log_signer() -> Ed25519CheckpointSigner {
    let sk = Ed25519SigningKey::from_pkcs8_pem(LOG_SIGNING_KEY_PEM).expect("parse dev log key");
    let name = KeyName::new(LOG_ORIGIN.to_owned()).expect("KeyName for origin");
    Ed25519CheckpointSigner::new(name, sk).expect("build Ed25519CheckpointSigner")
}

/// Generate a fresh Ed25519 log signer that the witness does *not* trust —
/// used by the 403 step.
fn untrusted_log_signer() -> Ed25519CheckpointSigner {
    let sk = Ed25519SigningKey::generate(&mut rng());
    let name = KeyName::new(LOG_ORIGIN.to_owned()).unwrap();
    Ed25519CheckpointSigner::new(name, sk).unwrap()
}

// ---------------------------------------------------------------------------
// Toy log: maintains enough state to produce valid checkpoints and
// consistency proofs for whatever sequence of leaves the test has pushed.
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
}

impl ToyLog {
    fn new() -> Self {
        Self {
            n: 0,
            stored: StoredHashes(Vec::new()),
        }
    }

    fn push(&mut self, data: &[u8]) {
        let new = stored_hashes(self.n, data, &self.stored).expect("stored_hashes");
        self.stored.0.extend(new);
        self.n += 1;
    }

    fn size(&self) -> u64 {
        self.n
    }

    fn root(&self, size: u64) -> Hash {
        tree_hash(size, &self.stored).expect("tree_hash")
    }

    fn subtree_hash(&self, subtree: &Subtree) -> Hash {
        tlog_tiles::subtree_hash(subtree, &self.stored).expect("subtree_hash")
    }

    fn sign_checkpoint(&self, signer: &Ed25519CheckpointSigner) -> Vec<u8> {
        let size = self.size();
        let hash = self.root(size);
        let tree = TreeWithTimestamp::new(size, hash, now_millis());
        tree.sign(LOG_ORIGIN, &[], &[signer], &mut rng())
            .expect("sign checkpoint")
    }

    /// `consistency_proof(old_size → current)`. Wraps
    /// `tlog_tiles::consistency_proof`, whose argument order is reversed from
    /// RFC 6962 convention (larger size first).
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

#[serde_as]
#[derive(Deserialize, Debug)]
struct MetadataResponse {
    witness_name: String,
    #[allow(dead_code)]
    description: Option<String>,
    #[serde_as(as = "Base64")]
    witness_public_key: Vec<u8>,
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
    origin: String,
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

async fn wait_for_witness() {
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
    panic!("witness did not become ready at {}", base_url());
}

/// Build a `SubtreeV1NoteVerifier` from the witness's `/metadata` SPKI
/// and its configured name. Used to verify both `add-checkpoint` and
/// `sign-subtree` responses.
fn witness_verifier(meta: &MetadataResponse) -> SubtreeV1NoteVerifier {
    use pkcs8::DecodePublicKey;
    let witness_vk = ml_dsa::VerifyingKey::<MlDsa44>::from_public_key_der(&meta.witness_public_key)
        .expect("witness SPKI must parse as ML-DSA-44");
    let name = KeyName::new(meta.witness_name.clone()).expect("KeyName for witness");
    SubtreeV1NoteVerifier::new(name, witness_vk)
}

/// Verify that `sigs` (returned from /add-checkpoint) contains a valid
/// `subtree/v1` cosignature from the witness on the given checkpoint.
fn verify_witness_signature(checkpoint: &Note, sigs: &[NoteSignature], meta: &MetadataResponse) {
    let v = witness_verifier(meta);
    let augmented = Note::new(checkpoint.text(), sigs).expect("assemble augmented note");
    let (verified, _unverified) = augmented
        .verify(&VerifierList::new(vec![Box::new(v)]))
        .expect("verify witness sig");
    assert!(!verified.is_empty(), "witness key did not sign response");
}

// ---------------------------------------------------------------------------
// The whole test suite, as one ordered sequence.
// ---------------------------------------------------------------------------

// Scenarios are intentionally collapsed into one `#[tokio::test]` so
// they thread through a single `ToyLog` — see the module-level comment
// above. That makes this function long by design.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn tlog_witness_end_to_end() {
    wait_for_witness().await;

    // ----------------------- (1) /metadata -----------------------
    let meta = fetch_metadata().await;
    assert_eq!(meta.witness_name, "dev.witness.example");
    assert!(!meta.witness_public_key.is_empty());
    assert!(meta.submission_prefix.starts_with("http"));
    let log = meta
        .logs
        .iter()
        .find(|l| l.origin == LOG_ORIGIN)
        .unwrap_or_else(|| panic!("metadata does not list the {LOG_ORIGIN} origin"));
    assert_eq!(log.log_public_keys.len(), 1);

    let signer = log_signer();
    let mut log = ToyLog::new();

    // ----------------------- (2) First submission: old=0 -----------------------
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
        let sigs = parse_add_checkpoint_response(&r.body).expect("parse response");
        assert!(
            !sigs.is_empty(),
            "response must contain at least one signature"
        );
        verify_witness_signature(&note, &sigs, &meta);
    }

    // ----------------------- (3) Second submission with consistency proof -----------------------
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
    }

    // ----------------------- (4) Stale old_size → 409 -----------------------
    // At this point the witness has recorded size = 2. Advance our local log
    // to size = 4 and submit with old=1 (stale).
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
        assert_eq!(recorded, 2, "409 body must carry the witness's latest size");
    }

    // ----------------------- (5) Unknown origin → 404 -----------------------
    {
        let sk = Ed25519SigningKey::generate(&mut rng());
        let origin = "not.configured.example/log";
        let name = KeyName::new(origin.to_owned()).unwrap();
        let other_signer = Ed25519CheckpointSigner::new(name, sk).unwrap();
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

    // ----------------------- (6) Untrusted key → 403 -----------------------
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

    // ----- (7) Trusted (name, id) but garbage signature bytes → 403 -----
    //
    // Per c2sp.org/signed-note, a signature line that claims a trusted
    // `(name, id)` but whose bytes fail to verify makes the note malformed.
    // The witness MUST surface this as 403 Forbidden (same as "no trusted
    // signature at all"), matching sunlight and sigsum-go.
    {
        let verifier = signer.verifier();
        let tree = TreeWithTimestamp::new(1, record_hash(b"x"), now_millis());
        // Sign a valid checkpoint, then replace the log's real signature
        // line with one carrying the right `(name, id)` but garbage bytes.
        let cp = tree.sign(LOG_ORIGIN, &[], &[&signer], &mut rng()).unwrap();
        let parsed = Note::from_bytes(&cp).unwrap();
        let bogus = NoteSignature::new(verifier.name().clone(), verifier.key_id(), vec![0u8; 64]);
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

    // ----------------------- (8) Bad consistency proof → 422 -----------------------
    // Advance our local log by one more leaf so we need a proof to submit it,
    // then hand-craft a wrong proof of the right length.
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

    // ----------------------- (9) old_size > checkpoint.size → 400 -----------------------
    {
        // Build a small independent log so checkpoint.size is controllably small.
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

    // ----------------------- (10) Malformed body → 400 -----------------------
    {
        let r = post_add_checkpoint(b"old 0\n").await;
        assert_eq!(
            r.status,
            400,
            "malformed body: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // ----------------------- (11) /sign-subtree happy path -----------------------
    //
    // Re-advance the witness state to the current log size (5) by
    // submitting a fresh `add-checkpoint`, capture the witness's
    // cosignature on it, then ask `/sign-subtree` to cosign a subtree
    // of that checkpoint with a valid subtree consistency proof.
    let cosigned_checkpoint;
    {
        // The witness state is currently at size 2 (from step 3); the
        // local log is at size 5 (after pushes in steps 4 and 8). Build
        // and submit the consistency proof from 2 → 5.
        let cp = log.sign_checkpoint(&signer);
        let note = Note::from_bytes(&cp).unwrap();
        let proof = log.consistency_proof(2);
        let body = serialize_add_checkpoint_request(2, &proof, &note).unwrap();
        let r = post_add_checkpoint(&body).await;
        assert_eq!(
            r.status,
            200,
            "advance witness state to size 5: body={:?}",
            String::from_utf8_lossy(&r.body)
        );
        let witness_sigs = parse_add_checkpoint_response(&r.body).expect("parse response");
        // Build an augmented note carrying the original log signature
        // plus the witness's fresh cosignature, ready to feed back into
        // /sign-subtree as the reference checkpoint.
        let mut all_sigs = note.signatures().to_vec();
        all_sigs.extend(witness_sigs);
        cosigned_checkpoint = Note::new(note.text(), &all_sigs).expect("assemble cosigned note");
    }
    let cp_size = log.size();
    {
        // Subtree [0, 4) of the size-5 tree.
        let subtree = Subtree::new(0, 4).expect("valid subtree");
        let s_hash = log.subtree_hash(&subtree);
        let proof = subtree_consistency_proof(cp_size, &subtree, &log.stored)
            .expect("subtree consistency proof");
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
        // Verify the response is a valid subtree/v1 cosignature on the
        // requested subtree.
        let v = witness_verifier(&meta);
        assert!(
            v.verify_subtree(LOG_ORIGIN, &subtree, &s_hash, sigs[0].signature()),
            "witness signature must verify against the requested subtree",
        );
    }

    // ----------------------- (12) /sign-subtree with checkpoint NOT cosigned by us → 403 -----------------------
    //
    // Build a fresh checkpoint (signed by the trusted log key, but the
    // witness has never seen this size). Stateless verification rejects
    // it because no witness self-cosignature is attached.
    {
        let mut other_log = ToyLog::new();
        other_log.push(b"a");
        other_log.push(b"b");
        let cp = other_log.sign_checkpoint(&signer);
        let note = Note::from_bytes(&cp).unwrap();
        let subtree = Subtree::new(0, 1).expect("valid subtree");
        let s_hash = other_log.subtree_hash(&subtree);
        let proof = subtree_consistency_proof(other_log.size(), &subtree, &other_log.stored)
            .expect("subtree consistency proof");
        let body = serialize_sign_subtree_request(0, 1, &s_hash, &[], &proof, &note).unwrap();
        let r = post_sign_subtree(&body).await;
        assert_eq!(
            r.status,
            403,
            "no witness cosignature on reference checkpoint: body={:?}",
            String::from_utf8_lossy(&r.body),
        );
    }

    // ----------------------- (13) /sign-subtree with end > checkpoint.size → 400 -----------------------
    {
        // Reuse the cosigned checkpoint from step 11; ask for a subtree
        // ending past its size.
        let bogus_end = cp_size + 1; // checkpoint size is 5
        let body = serialize_sign_subtree_request(
            0,
            bogus_end,
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
            "end > checkpoint.size: body={:?}",
            String::from_utf8_lossy(&r.body),
        );
    }
}
