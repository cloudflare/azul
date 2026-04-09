// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Integration tests for the IETF MTC API (`ietf_mtc_worker`).
//!
//! These tests require a running `wrangler dev` instance.
//! Set `BASE_URL` to point at the server; defaults to `http://localhost:8787`.
//! Set `IETF_MTC_LOG_NAME` to choose which log shard; defaults to `dev2`.
//!
//! `dev2` is preferred because its `landmark_interval_secs: 10` makes the
//! landmark-dependent `get_certificate` test feasible without a long wait.
//!
//! # Running
//!
//! ```text
//! # From crates/ietf_mtc_worker/:
//! npx wrangler -e=dev dev &
//!
//! # From workspace root:
//! cargo test -p integration_tests --test ietf_mtc_api
//! ```

use std::time::Duration;

use ietf_mtc_api::{MtcVerifyingKey, ParsedMtcProof, TrustAnchorID};
use integration_tests::{
    client::{IetfMtcClient, ietf_mtc_log_name},
    fixtures::make_ietf_mtc_csr,
};
use tokio::sync::OnceCell;
use tlog_tiles::{evaluate_subtree_inclusion_proof, record_hash, Hash, Subtree};
use x509_cert::{der::Decode, Certificate};

/// OID for the MTC proof algorithm (id-alg-mtcproof).
const ID_ALG_MTCPROOF: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.44363.47.0");

/// Assert that `cert_der` is a valid MTC certificate:
/// - Parses as a valid X.509 DER certificate
/// - Uses `id-alg-mtcproof` as the signature algorithm
/// - Has a non-empty `signatureValue` (the encoded `MTCProof`)
/// - Has a non-empty subject
/// Extract the `MTCProof` bytes from a certificate's `signatureValue`.
///
/// The `signatureValue` is a DER `BIT STRING`. `raw_bytes()` returns the
/// content octets (the unused-bits byte is handled by the `der` crate
/// internally), which are exactly the `MTCProof` bytes.
fn extract_mtc_proof_bytes(cert: &Certificate) -> Vec<u8> {
    cert.signature
        .as_bytes()
        .expect("signatureValue BIT STRING must have 0 unused bits")
        .to_vec()
}

/// Compute `entry_hash` from a certificate following draft-ietf-plants-merkle-tree-certs §7.2
/// steps 4-5.
///
/// Steps 4a-4c reconstruct the `TBSCertificateLogEntry` from the certificate:
///   - Copy most TBS fields verbatim (4a)
///   - Set `subjectPublicKeyAlgorithm` from the SPKI `algorithm` field (4b)
///   - Set `subjectPublicKeyInfoHash` to HASH(DER(subjectPublicKeyInfo)) (4c)
///
/// Step 5: construct a `MerkleTreeCertEntry` of type `tbs_cert_entry` and compute
/// `entry_hash = MTH({entry}) = HASH(0x00 || entry)` i.e. `record_hash(entry_bytes)`.
///
/// Also asserts that the certificate's serial number encodes `leaf_index` (§7.2 step 3).
fn compute_entry_hash(cert: &Certificate, leaf_index: u64) -> Hash {
    use der::Encode;
    use ietf_mtc_api::{MerkleTreeCertEntry, TbsCertificateLogEntry};
    use sha2::Digest;

    // §7.2 step 3: serial number encodes `index`.
    let tbs = &cert.tbs_certificate;
    let serial_bytes = tbs.serial_number.as_bytes();
    let mut padded = [0u8; 8];
    let len = serial_bytes.len().min(8);
    padded[8 - len..].copy_from_slice(&serial_bytes[serial_bytes.len() - len..]);
    assert_eq!(
        u64::from_be_bytes(padded),
        leaf_index,
        "serial_number must encode leaf_index"
    );

    // §7.2 steps 4a-4c: reconstruct TBSCertificateLogEntry.
    let spki_der = tbs.subject_public_key_info.to_der().expect("encoding SPKI");
    let spki_hash =
        der::asn1::OctetString::new(&sha2::Sha256::digest(&spki_der)[..]).expect("OctetString");
    let log_entry = TbsCertificateLogEntry {
        version: tbs.version,
        issuer: tbs.issuer.clone(),
        validity: tbs.validity,
        subject: tbs.subject.clone(),
        // §7.2 step 4b
        subject_public_key_info_algorithm: tbs.subject_public_key_info.algorithm.clone(),
        // §7.2 step 4c
        subject_public_key_info_hash: spki_hash,
        issuer_unique_id: tbs.issuer_unique_id.clone(),
        subject_unique_id: tbs.subject_unique_id.clone(),
        extensions: tbs.extensions.clone(),
    };

    // §7.2 step 5: entry_hash = MTH({entry}) = record_hash(entry_bytes).
    let entry_bytes = MerkleTreeCertEntry::TbsCertEntry(log_entry)
        .encode()
        .expect("encoding MerkleTreeCertEntry");
    record_hash(&entry_bytes)
}

fn assert_valid_mtc_cert(cert_der: &[u8], context: &str) -> Certificate {
    let cert = Certificate::from_der(cert_der)
        .unwrap_or_else(|e| panic!("{context}: not a valid DER certificate: {e}"));

    assert_eq!(
        cert.signature_algorithm.oid,
        ID_ALG_MTCPROOF,
        "{context}: expected id-alg-mtcproof signature algorithm, got {}",
        cert.signature_algorithm.oid
    );
    assert_eq!(
        cert.tbs_certificate.signature.oid,
        ID_ALG_MTCPROOF,
        "{context}: TBSCertificate.signature algorithm mismatch"
    );
    assert!(
        !cert.signature.raw_bytes().is_empty(),
        "{context}: signatureValue (MTCProof) must be non-empty"
    );
    assert!(
        !cert.tbs_certificate.subject.0.is_empty(),
        "{context}: subject must be non-empty"
    );

    cert
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Initialization guard
// ---------------------------------------------------------------------------

/// Ensures the IETF MTC worker is fully live and has sequenced at least one
/// entry before any test that depends on sequencer state runs.
///
/// Unlike the bootstrap MTC worker, there is no CCADB roots `OnceCell` to
/// worry about, so we go straight to `add-entry` as the readiness probe.
static INITIALIZED: OnceCell<()> = OnceCell::const_new();

async fn ensure_initialized() {
    INITIALIZED
        .get_or_init(|| async {
            const MAX_ATTEMPTS: u32 = 30;
            const RETRY_DELAY: Duration = Duration::from_secs(1);

            let log_name = ietf_mtc_log_name();
            let client = IetfMtcClient::new(&log_name);
            let csr = make_ietf_mtc_csr(&log_name).expect("make_ietf_mtc_csr for warmup");

            for attempt in 0..MAX_ATTEMPTS {
                match client.add_entry(csr.csr_der.clone()).await {
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

            panic!("ietf_mtc_worker failed to initialize after {MAX_ATTEMPTS}s");
        })
        .await;
}

/// Fetch metadata and build an `MtcVerifyingKey` for the log's cosigner.
async fn fetch_verifying_key(client: &IetfMtcClient) -> (MtcVerifyingKey, TrustAnchorID, TrustAnchorID) {
    use std::str::FromStr;
    let meta = client.get_metadata().await.expect("metadata");
    // cosigner_public_key is SPKI DER — decode as Ed25519 verifying key.
    let vk = {
        use pkcs8::DecodePublicKey;
        let ed_vk = ed25519_dalek::VerifyingKey::from_public_key_der(&meta.cosigner_public_key)
            .expect("cosigner_public_key must be a valid Ed25519 SPKI");
        MtcVerifyingKey::Ed25519(ed_vk)
    };
    let cosigner_id = TrustAnchorID::from_str(&meta.cosigner_id).expect("cosigner_id");
    let log_id = TrustAnchorID::from_str(&meta.log_id).expect("log_id");
    (vk, cosigner_id, log_id)
}

/// Verify a standalone MTC certificate following draft-ietf-plants-merkle-tree-certs §7.2.
///
/// Steps performed:
/// 1. Check `id-alg-mtcProof` algorithm (already done by `assert_valid_mtc_cert`).
/// 2. Decode `signatureValue` as an `MTCProof`.
/// 3. Check `index` is not revoked (not implemented — no revocation list in test).
/// 4-5. Reconstruct `TBSCertificateLogEntry` and compute `entry_hash`.
/// 6. Evaluate the inclusion proof to get `expected_subtree_hash` (§4.3.2).
/// 7. No trusted subtree predistributed in test — proceed to step 8.
/// 8. Verify cosignatures satisfy relying party requirements (≥1 valid cosignature).
async fn verify_standalone_cert(
    _client: &IetfMtcClient,
    cert: &Certificate,
    leaf_index: u64,
    vk: &MtcVerifyingKey,
    cosigner_id: &TrustAnchorID,
    log_id: &TrustAnchorID,
) {
    // §7.2 step 2: decode signatureValue as MTCProof.
    let proof_bytes = extract_mtc_proof_bytes(cert);
    let proof = ParsedMtcProof::from_bytes(&proof_bytes)
        .expect("MTCProof must parse from signatureValue");

    // §7.2 step 8: standalone certs must carry cosignatures.
    assert!(
        !proof.signatures.is_empty(),
        "standalone cert must have at least one cosignature (§7.2 step 8)"
    );

    let subtree = Subtree::new(proof.start, proof.end)
        .expect("MTCProof subtree interval must be valid");
    assert!(
        subtree.lo() <= leaf_index && leaf_index < subtree.hi(),
        "leaf_index {leaf_index} must be within subtree [{}, {})",
        subtree.lo(),
        subtree.hi()
    );

    // §7.2 steps 4-5: compute entry_hash from the certificate.
    let entry_hash = compute_entry_hash(cert, leaf_index);

    // §7.2 step 6: evaluate the inclusion proof to get expected_subtree_hash (§4.3.2).
    let expected_subtree_hash = evaluate_subtree_inclusion_proof(
        &proof.inclusion_proof,
        &subtree,
        leaf_index,
        entry_hash,
    )
    .expect("inclusion proof evaluation must succeed");

    // §7.2 step 8: verify cosignatures against expected_subtree_hash.
    proof
        .verify_cosignature(&expected_subtree_hash, vk, cosigner_id, log_id)
        .expect("at least one cosignature must be valid");
}

/// Verify a landmark-relative MTC certificate following draft-ietf-plants-merkle-tree-certs §7.2.
///
/// Landmark-relative certs have no inline cosignatures (§6.3).  In a real relying
/// party, the subtree hash would be predistributed (§7.4).  In the test, we fetch
/// the `SignedSubtree` from R2 as a stand-in for predistributed trusted subtree info,
/// and also verify the CA's cosignature over that subtree hash.
///
/// Steps performed:
/// 1. Check `id-alg-mtcProof` (already done).
/// 2. Decode `signatureValue` as `MTCProof`.
/// 4-5. Reconstruct `TBSCertificateLogEntry` and compute `entry_hash`.
/// 6. Evaluate the inclusion proof to get `expected_subtree_hash` (§4.3.2).
/// 7. Compare `expected_subtree_hash` against the trusted subtree hash (from R2).
async fn verify_landmark_relative_cert(
    client: &IetfMtcClient,
    cert: &Certificate,
    leaf_index: u64,
    vk: &MtcVerifyingKey,
    cosigner_id: &TrustAnchorID,
    log_id: &TrustAnchorID,
) {
    // §7.2 step 2: decode signatureValue as MTCProof.
    let proof_bytes = extract_mtc_proof_bytes(cert);
    let proof = ParsedMtcProof::from_bytes(&proof_bytes)
        .expect("MTCProof must parse from signatureValue");

    // §6.3 / §7.2 step 7: landmark-relative certs carry no inline cosignatures.
    assert!(
        proof.signatures.is_empty(),
        "landmark-relative cert must have no inline cosignatures (§6.3)"
    );

    let subtree = Subtree::new(proof.start, proof.end)
        .expect("MTCProof subtree interval must be valid");

    // §7.2 steps 4-5: compute entry_hash.
    let entry_hash = compute_entry_hash(cert, leaf_index);

    // §7.2 step 6: evaluate the inclusion proof (§4.3.2).
    let expected_subtree_hash = evaluate_subtree_inclusion_proof(
        &proof.inclusion_proof,
        &subtree,
        leaf_index,
        entry_hash,
    )
    .expect("inclusion proof evaluation must succeed");

    // §7.2 step 7: compare against the trusted subtree hash.
    // In production, this hash is predistributed.  In the test, we fetch it
    // from R2 and also verify the CA's cosignature over it.
    let signed: ietf_mtc_api::SignedSubtree = client
        .get_signed_subtree(proof.start, proof.end)
        .await
        .expect("get_signed_subtree request")
        .unwrap_or_else(|| {
            panic!("SignedSubtree not found for [{}, {})", proof.start, proof.end)
        });
    let trusted_subtree_hash = Hash(signed.hash);
    assert_eq!(
        expected_subtree_hash, trusted_subtree_hash,
        "evaluated subtree hash must match the trusted (predistributed) subtree hash"
    );

    // Additionally verify the CA's cosignature over the trusted hash,
    // confirming the predistributed value is authentic.
    use std::str::FromStr;
    let signed_cosigner_id =
        TrustAnchorID::from_str(&signed.cosigner_id).expect("valid cosigner_id in SignedSubtree");
    let r2_proof = ParsedMtcProof {
        start: signed.lo,
        end: signed.hi,
        inclusion_proof: vec![],
        signatures: std::collections::HashMap::from([(signed_cosigner_id, signed.signature.clone())]),
    };
    r2_proof
        .verify_cosignature(&trusted_subtree_hash, vk, cosigner_id, log_id)
        .expect("CA cosignature over trusted subtree hash must be valid");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `GET /logs/:log/metadata` returns 200 with all required fields.
#[tokio::test]
async fn metadata_returns_valid_fields() {
    let client = IetfMtcClient::default_log();
    let meta = client.get_metadata().await.expect("metadata failed");

    assert!(!meta.log_id.is_empty(), "log_id must be non-empty");
    assert!(
        meta.log_id.contains('.'),
        "log_id must be a dotted-decimal OID, got: {}",
        meta.log_id
    );
    assert!(!meta.cosigner_id.is_empty(), "cosigner_id must be non-empty");
    // cosigner_public_key is a DER-encoded SubjectPublicKeyInfo. The algorithm
    // identifier is included so clients can determine the signing algorithm.
    assert!(
        !meta.cosigner_public_key.is_empty(),
        "cosigner_public_key must be non-empty"
    );
    assert!(!meta.submission_url.is_empty(), "submission_url must be set");
}

/// Requesting an unknown log name returns 400.
#[tokio::test]
async fn unknown_log_returns_400() {
    let client = IetfMtcClient::new("this-log-does-not-exist");
    let status = client
        .get_status("metadata")
        .await
        .expect("GET request");
    assert_eq!(status, 400, "expected 400 for unknown log");
}

/// `POST /logs/:log/add-entry` with a valid CSR returns 200 with a
/// structurally valid standalone MTC certificate.
#[tokio::test]
async fn add_entry_returns_valid_response() {
    ensure_initialized().await;
    let client = IetfMtcClient::default_log();
    let csr = make_ietf_mtc_csr(&client.log).expect("generating CSR");

    let (status, resp) = client
        .add_entry(csr.csr_der)
        .await
        .expect("add-entry request");
    assert_eq!(status, 200, "expected 200 from add-entry");
    let resp = resp.unwrap();

    // The response is a DER-encoded standalone MTC certificate.
    let cert = assert_valid_mtc_cert(&resp.certificate, "add-entry standalone cert");
    let serial_bytes = cert.tbs_certificate.serial_number.as_bytes();
    let mut padded = [0u8; 8];
    let len = serial_bytes.len().min(8);
    padded[8 - len..].copy_from_slice(&serial_bytes[serial_bytes.len() - len..]);
    let leaf_index = u64::from_be_bytes(padded);

    // Full signature and inclusion proof verification.
    let (vk, cosigner_id, log_id) = fetch_verifying_key(&client).await;
    verify_standalone_cert(&client, &cert, leaf_index, &vk, &cosigner_id, &log_id).await;
}

/// `POST` with garbage bytes (not a valid CSR) returns 400.
#[tokio::test]
async fn add_entry_with_invalid_csr_returns_400() {
    ensure_initialized().await;
    let client = IetfMtcClient::default_log();
    let (status, _) = client
        .add_entry(b"this is not a valid CSR".to_vec())
        .await
        .expect("add-entry request");
    assert_eq!(status, 400, "expected 400 for invalid CSR");
}

/// After `add-entry`, the certificate's serial number (= leaf_index) is covered
/// by the checkpoint.
#[tokio::test]
async fn add_entry_appears_in_checkpoint() {
    ensure_initialized().await;
    let client = IetfMtcClient::default_log();
    let csr = make_ietf_mtc_csr(&client.log).expect("generating CSR");

    let (status, resp) = client
        .add_entry(csr.csr_der)
        .await
        .expect("add-entry request");
    assert_eq!(status, 200, "expected 200 from add-entry");
    let resp = resp.unwrap();

    // The leaf_index is encoded as the certificate's serial number.
    let cert = assert_valid_mtc_cert(&resp.certificate, "add-entry standalone cert");
    let serial_bytes = cert.tbs_certificate.serial_number.as_bytes();
    let mut padded = [0u8; 8];
    let len = serial_bytes.len().min(8);
    padded[8 - len..].copy_from_slice(&serial_bytes[serial_bytes.len() - len..]);
    let leaf_index = u64::from_be_bytes(padded);
    let min_size = leaf_index + 1;

    const MAX_RETRIES: u32 = 12;
    const RETRY_DELAY_MS: u64 = 500;
    let mut last_size = 0u64;

    for attempt in 0..MAX_RETRIES {
        let checkpoint_bytes = client
            .get_checkpoint()
            .await
            .expect("fetching checkpoint");
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

/// After `add-entry`, `get-certificate` returns a parseable landmark-relative DER
/// certificate once a landmark has been produced.
///
/// This test uses `dev2` (10s landmark interval) and retries for up to 30s.
/// It is skipped if `IETF_MTC_LOG_NAME` is set to a log with a longer interval.
#[tokio::test]
async fn get_certificate_returns_valid_cert() {
    ensure_initialized().await;
    let log_name = ietf_mtc_log_name();
    if log_name != "dev2" {
        eprintln!("Skipping get_certificate test: IETF_MTC_LOG_NAME={log_name} (not dev2)");
        return;
    }

    let client = IetfMtcClient::new(&log_name);
    let csr = make_ietf_mtc_csr(&log_name).expect("generating CSR");
    let spki_der = csr.spki_der.clone();

    let (status, resp) = client
        .add_entry(csr.csr_der)
        .await
        .expect("add-entry request");
    assert_eq!(status, 200, "expected 200 from add-entry");
    let resp = resp.unwrap();

    let cert = assert_valid_mtc_cert(&resp.certificate, "add-entry standalone cert");
    let serial_bytes = cert.tbs_certificate.serial_number.as_bytes();
    let mut padded = [0u8; 8];
    let len = serial_bytes.len().min(8);
    padded[8 - len..].copy_from_slice(&serial_bytes[serial_bytes.len() - len..]);
    let leaf_index = u64::from_be_bytes(padded);

    const MAX_RETRIES: u32 = 30;
    const RETRY_DELAY_MS: u64 = 1_000;
    let mut last_status = 0u16;

    for attempt in 0..MAX_RETRIES {
        let (s, cert_resp) = client
            .get_certificate(leaf_index, spki_der.clone())
            .await
            .expect("get-certificate request");
        last_status = s;
        if s == 200 {
            let cert_resp = cert_resp.unwrap();

            let lm_cert = assert_valid_mtc_cert(
                &cert_resp.data,
                "get-certificate landmark-relative cert",
            );

            assert!(
                cert_resp.landmark_id > 0,
                "landmark_id must be positive (index 0 is the initial null entry)"
            );

            // Full signature and inclusion proof verification for landmark-relative cert.
            let (vk, cosigner_id, log_id) = fetch_verifying_key(&client).await;
            verify_landmark_relative_cert(
                &client, &lm_cert, leaf_index, &vk, &cosigner_id, &log_id,
            )
            .await;

            return;
        }
        assert_eq!(s, 503, "expected 200 or 503, got {s}");

        if attempt + 1 < MAX_RETRIES {
            tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
        }
    }

    panic!(
        "get-certificate never returned 200 after {MAX_RETRIES} retries (last status: {last_status})"
    );
}
