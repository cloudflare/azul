// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Integration tests for the IETF MTC API (`ietf_mtc_worker`).
//!
//! These tests require a running `wrangler dev` instance.
//! Set `BASE_URL` to point at the server; defaults to `http://localhost:8787`.
//! Set `IETF_MTC_LOG_NAME` to choose which log shard; defaults to `dev2`.
//!
//! `dev1` is configured with an ML-DSA-44 signing key, and `dev2` with an
//! Ed25519 key. Both have `landmark_interval_secs: 10` so all tests are
//! feasible under either algorithm.
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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use der::Tagged;
use ietf_mtc_api::{
    ID_ALG_MTCPROOF, ID_RDNA_TRUSTANCHOR_ID, MtcCheckpointNoteVerifier, MtcVerifyingKey,
    ParsedMtcProof, TrustAnchorID, UINT48_MAX,
};
use integration_tests::{
    client::{IetfMtcClient, ietf_mtc_log_name},
    fixtures::make_ietf_mtc_csr,
};
use signed_note::VerifierList;
use tlog_checkpoint::open_checkpoint;
use tlog_core::{
    Hash, Subtree, evaluate_subtree_inclusion_proof, record_hash, verify_subtree_consistency_proof,
};
use tokio::sync::OnceCell;
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
    name::RdnSequence,
};

/// Extract the `MTCProof` bytes from a certificate's `signatureValue`.
///
/// The `signatureValue` is a DER `BIT STRING`. `raw_bytes()` returns the
/// content octets (the unused-bits byte is handled by the `der` crate
/// internally), which are exactly the `MTCProof` bytes.
fn extract_mtc_proof_bytes(cert: &Certificate) -> Vec<u8> {
    cert.signature()
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
fn certificate_serial(cert: &Certificate) -> (u16, u64) {
    let bytes = cert.tbs_certificate().serial_number().as_bytes();
    assert!(bytes.len() <= 8, "certificate serial must fit uint64");
    let mut padded = [0u8; 8];
    padded[8 - bytes.len()..].copy_from_slice(bytes);
    let serial = u64::from_be_bytes(padded);
    ((serial >> 48) as u16, serial & ((1_u64 << 48) - 1))
}

fn assert_entry_and_proof_framing(entry: &[u8], proof: &[u8]) {
    let entry_extensions_len = usize::from(u16::from_be_bytes([entry[0], entry[1]]));
    let entry_type_offset = 2 + entry_extensions_len;
    assert_eq!(
        &entry[entry_type_offset..entry_type_offset + 2],
        &1_u16.to_be_bytes(),
        "entry type must follow its uint16-framed extensions"
    );

    let proof_extensions_len = usize::from(u16::from_be_bytes([proof[0], proof[1]]));
    let mut offset = 2 + proof_extensions_len;
    assert_eq!(
        &entry[..entry_type_offset],
        &proof[..offset],
        "entry extensions must be copied into MTCProof"
    );
    offset += 12; // uint48 start and uint48 end
    let inclusion_len = usize::from(u16::from_be_bytes([proof[offset], proof[offset + 1]]));
    assert_eq!(inclusion_len % 32, 0, "proof hashes must be 32-byte framed");
    offset += 2 + inclusion_len;
    let signatures_len = (usize::from(proof[offset]) << 16)
        | (usize::from(proof[offset + 1]) << 8)
        | usize::from(proof[offset + 2]);
    offset += 3 + signatures_len;
    assert_eq!(
        offset,
        proof.len(),
        "signature framing must consume MTCProof"
    );
}

fn compute_entry_hash(
    cert: &Certificate,
    proof: &ParsedMtcProof,
    log_number: u16,
    leaf_index: u64,
) -> Hash {
    use der::Encode;
    use ietf_mtc_api::{MerkleTreeCertEntry, TbsCertificateLogEntry};
    use sha2::Digest;

    // §7.2 step 3: serial number encodes `log_number || index`.
    let tbs = cert.tbs_certificate();
    assert_eq!(
        certificate_serial(cert),
        (log_number, leaf_index),
        "serial_number must equal (log_number << 48) | index"
    );

    // §7.2 steps 4a-4c: reconstruct TBSCertificateLogEntry.
    let spki = tbs.subject_public_key_info();
    let spki_der = spki.to_der().expect("encoding SPKI");
    let spki_hash =
        der::asn1::OctetString::new(&sha2::Sha256::digest(&spki_der)[..]).expect("OctetString");
    let log_entry = TbsCertificateLogEntry {
        version: tbs.version(),
        issuer: tbs.issuer().clone(),
        validity: *tbs.validity(),
        subject: tbs.subject().clone(),
        // §7.2 step 4b
        subject_public_key_info_algorithm: spki.algorithm.clone(),
        // §7.2 step 4c
        subject_public_key_info_hash: spki_hash,
        issuer_unique_id: tbs.issuer_unique_id().clone(),
        subject_unique_id: tbs.subject_unique_id().clone(),
        extensions: tbs.extensions().cloned(),
    };

    // §7.2 step 5: entry_hash = MTH({entry}) = record_hash(entry_bytes).
    let entry_bytes = MerkleTreeCertEntry::TbsCertEntry {
        extensions: proof.extensions.clone(),
        tbs_certificate: log_entry,
    }
    .encode()
    .expect("encoding MerkleTreeCertEntry");
    assert_entry_and_proof_framing(&entry_bytes, &extract_mtc_proof_bytes(cert));
    record_hash(&entry_bytes)
}

fn assert_valid_mtc_cert(cert_der: &[u8], context: &str) -> Certificate {
    let cert = Certificate::from_der(cert_der)
        .unwrap_or_else(|e| panic!("{context}: not a valid DER certificate: {e}"));

    assert_eq!(
        cert.signature_algorithm().oid,
        ID_ALG_MTCPROOF,
        "{context}: expected id-alg-mtcproof signature algorithm, got {}",
        cert.signature_algorithm().oid
    );
    assert_eq!(
        cert.tbs_certificate().signature().oid,
        ID_ALG_MTCPROOF,
        "{context}: TBSCertificate.signature algorithm mismatch"
    );
    assert!(
        !cert.signature().raw_bytes().is_empty(),
        "{context}: signatureValue (MTCProof) must be non-empty"
    );
    assert!(
        !cert.tbs_certificate().subject().is_empty(),
        "{context}: subject must be non-empty"
    );
    let issuer = RdnSequence::from_der(
        &cert
            .tbs_certificate()
            .issuer()
            .to_der()
            .expect("encode issuer"),
    )
    .expect("decode issuer RDN sequence");
    let issuer_id = TrustAnchorID::from_rdn_sequence(&issuer).expect("issuer trust anchor ID");
    let issuer_attribute = issuer.as_ref()[0].iter().next().expect("issuer attribute");
    assert_eq!(issuer_attribute.oid, ID_RDNA_TRUSTANCHOR_ID);
    assert_eq!(issuer_attribute.value.tag(), der::Tag::RelativeOid);
    assert!(!issuer_id.as_bytes().is_empty());

    cert
}

// ---------------------------------------------------------------------------
// Initialization guard
// ---------------------------------------------------------------------------

/// Ensures the IETF MTC worker is fully live and has sequenced at least one
/// entry before any test that depends on sequencer state runs.
///
/// `add-entry` is the readiness probe.
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
///
/// Dispatches on the SPKI `AlgorithmIdentifier` OID so the same integration test
/// can run against a log configured with Ed25519 or ML-DSA-44 signing keys.
struct VerificationContext {
    key: MtcVerifyingKey,
    ca_id: TrustAnchorID,
    log_number: u16,
    cosigner_id: TrustAnchorID,
    checkpoint_origin: String,
}

async fn fetch_verification_context(client: &IetfMtcClient) -> VerificationContext {
    use std::str::FromStr;
    // RFC 8410 Ed25519.
    const OID_ED25519: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112");
    // FIPS 204 ML-DSA-44.
    const OID_ML_DSA_44: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");

    let meta = client.get_metadata().await.expect("metadata");

    // `cosigner_public_key` is DER SPKI. Parse the algorithm OID to pick the
    // correct decoder.
    let spki: spki::SubjectPublicKeyInfoOwned =
        spki::SubjectPublicKeyInfoOwned::try_from(meta.cosigner_public_key.as_slice())
            .expect("cosigner_public_key must be a valid SPKI");

    let vk = match spki.algorithm.oid {
        OID_ED25519 => {
            use pkcs8::DecodePublicKey;
            let ed_vk = ed25519_dalek::VerifyingKey::from_public_key_der(&meta.cosigner_public_key)
                .expect("valid Ed25519 SPKI");
            MtcVerifyingKey::Ed25519(ed_vk)
        }
        OID_ML_DSA_44 => {
            use pkcs8::DecodePublicKey;
            let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::from_public_key_der(
                &meta.cosigner_public_key,
            )
            .expect("valid ML-DSA-44 SPKI");
            MtcVerifyingKey::MlDsa44(vk)
        }
        oid => panic!("unsupported cosigner SPKI algorithm OID: {oid}"),
    };

    let ca_id = TrustAnchorID::from_str(&meta.ca_id).expect("ca_id");
    let derived_log_id = ca_id.log_id(meta.log_number).expect("derive log_id");
    assert_eq!(derived_log_id.to_string(), meta.log_id);
    let cosigner_id = TrustAnchorID::from_str(&meta.cosigner_id).expect("cosigner_id");
    assert_eq!(cosigner_id, ca_id);
    let checkpoint_origin = derived_log_id.oid_name();
    VerificationContext {
        key: vk,
        ca_id,
        log_number: meta.log_number,
        cosigner_id,
        checkpoint_origin,
    }
}

/// Verify a standalone MTC certificate following draft-ietf-plants-merkle-tree-certs §7.2.
///
/// Steps performed:
/// 1. Check `id-alg-mtcProof` algorithm (already done by `assert_valid_mtc_cert`).
/// 2. Decode `signatureValue` as an `MTCProof`.
/// 3. Check `index` is not revoked (not implemented — no revocation list in test).
///    4-5. Reconstruct `TBSCertificateLogEntry` and compute `entry_hash`.
/// 6. Evaluate the inclusion proof to get `expected_subtree_hash` (§4.3.2).
/// 7. No trusted subtree predistributed in test — proceed to step 8.
/// 8. Verify cosignatures satisfy relying party requirements (≥1 valid cosignature).
fn verify_standalone_cert(cert: &Certificate, leaf_index: u64, context: &VerificationContext) {
    // §7.2 step 2: decode signatureValue as MTCProof.
    let proof_bytes = extract_mtc_proof_bytes(cert);
    let proof =
        ParsedMtcProof::from_bytes(&proof_bytes).expect("MTCProof must parse from signatureValue");

    // §7.2 step 8: standalone certs must carry cosignatures.
    assert!(
        !proof.signatures.is_empty(),
        "standalone cert must have at least one cosignature (§7.2 step 8)"
    );

    let subtree =
        Subtree::new(proof.start, proof.end).expect("MTCProof subtree interval must be valid");
    assert!(leaf_index < UINT48_MAX);
    assert!(subtree.hi() <= UINT48_MAX);
    assert!(
        subtree.lo() <= leaf_index && leaf_index < subtree.hi(),
        "leaf_index {leaf_index} must be within subtree [{}, {})",
        subtree.lo(),
        subtree.hi()
    );

    // §7.2 steps 4-5: compute entry_hash from the certificate.
    let entry_hash = compute_entry_hash(cert, &proof, context.log_number, leaf_index);

    // §7.2 step 6: evaluate the inclusion proof to get expected_subtree_hash (§4.3.2).
    let expected_subtree_hash =
        evaluate_subtree_inclusion_proof(&proof.inclusion_proof, &subtree, leaf_index, entry_hash)
            .expect("inclusion proof evaluation must succeed");

    // §7.2 step 8: verify cosignatures against expected_subtree_hash.
    proof
        .verify_cosignature(
            &expected_subtree_hash,
            &context.key,
            &context.cosigner_id,
            &context.ca_id,
            context.log_number,
        )
        .expect("at least one cosignature must be valid");
}

/// Verify a landmark-relative MTC certificate following draft-ietf-plants-merkle-tree-certs §7.2.
///
/// Landmark-relative certs have no inline cosignatures (§6.3).  In a real relying
/// party, the subtree hash would be predistributed (§7.4). In the test, the
/// authenticated landmark bundle stands in for predistributed trusted subtree info.
///
/// Steps performed:
/// 1. Check `id-alg-mtcProof` (already done).
/// 2. Decode `signatureValue` as `MTCProof`.
///    4-5. Reconstruct `TBSCertificateLogEntry` and compute `entry_hash`.
/// 6. Evaluate the inclusion proof to get `expected_subtree_hash` (§4.3.2).
/// 7. Compare `expected_subtree_hash` against the authenticated landmark bundle.
async fn verify_landmark_relative_cert(
    client: &IetfMtcClient,
    cert: &Certificate,
    leaf_index: u64,
    context: &VerificationContext,
) {
    // §7.2 step 2: decode signatureValue as MTCProof.
    let proof_bytes = extract_mtc_proof_bytes(cert);
    let proof =
        ParsedMtcProof::from_bytes(&proof_bytes).expect("MTCProof must parse from signatureValue");

    // §6.3 / §7.2 step 7: landmark-relative certs carry no inline cosignatures.
    assert!(
        proof.signatures.is_empty(),
        "landmark-relative cert must have no inline cosignatures (§6.3)"
    );

    let subtree =
        Subtree::new(proof.start, proof.end).expect("MTCProof subtree interval must be valid");
    assert!(leaf_index < UINT48_MAX);
    assert!(subtree.hi() <= UINT48_MAX);

    // §7.2 steps 4-5: compute entry_hash.
    let entry_hash = compute_entry_hash(cert, &proof, context.log_number, leaf_index);

    // §7.2 step 6: evaluate the inclusion proof (§4.3.2).
    let expected_subtree_hash =
        evaluate_subtree_inclusion_proof(&proof.inclusion_proof, &subtree, leaf_index, entry_hash)
            .expect("inclusion proof evaluation must succeed");

    // §7.2 step 7: authenticate the landmark bundle and compare its subtree hash.
    let bundle = client
        .get_landmark_bundle()
        .await
        .expect("get-landmark-bundle request");
    let (landmark_content_type, landmark_text) =
        client.get_landmark().await.expect("get landmark resource");
    assert_eq!(landmark_content_type, "text/plain; charset=utf-8");
    assert_eq!(landmark_text.last(), Some(&b'\n'));
    let checkpoint_verifier = MtcCheckpointNoteVerifier::new(
        context.cosigner_id.clone(),
        &context.ca_id,
        context.log_number,
        context.key.clone(),
    )
    .expect("checkpoint verifier");
    let verifiers = VerifierList::new(vec![Box::new(checkpoint_verifier)]);
    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_millis()
        .try_into()
        .expect("current time fits u64");
    let (checkpoint, _) = open_checkpoint(
        &context.checkpoint_origin,
        &verifiers,
        now_millis,
        bundle.checkpoint.as_bytes(),
    )
    .expect("landmark bundle checkpoint signature");

    let mut bundle_ranges = Vec::new();
    for (&lo, &hi) in bundle.landmarks.iter().zip(bundle.landmarks.iter().skip(1)) {
        let (left, right) = Subtree::split_interval(lo, hi).expect("valid landmark interval");
        bundle_ranges.extend([left, right]);
    }
    assert_eq!(bundle_ranges.len(), bundle.subtrees.len());
    if bundle
        .landmarks
        .iter()
        .zip(bundle.landmarks.iter().skip(1))
        .any(|(&lo, &hi)| hi - lo == 1)
    {
        assert!(
            bundle_ranges.iter().any(|range| range.lo() == range.hi()),
            "single-entry landmark intervals must publish an empty second subtree"
        );
    }
    assert!(
        bundle_ranges
            .iter()
            .filter(|range| range.contains(leaf_index))
            .all(|range| range.lo() < range.hi()),
        "empty landmark subtrees must not cover certificate entries"
    );
    let (_, trusted) = bundle_ranges
        .iter()
        .zip(&bundle.subtrees)
        .find(|(range, _)| **range == subtree)
        .expect("certificate subtree must be in landmark bundle");
    let trusted_subtree_hash = Hash(trusted.hash);
    assert_eq!(
        expected_subtree_hash, trusted_subtree_hash,
        "evaluated subtree hash must match the trusted (predistributed) subtree hash"
    );
    let consistency_proof = trusted
        .consistency_proof
        .iter()
        .copied()
        .map(Hash)
        .collect();
    verify_subtree_consistency_proof(
        &consistency_proof,
        checkpoint.size(),
        *checkpoint.hash(),
        &subtree,
        trusted_subtree_hash,
    )
    .expect("landmark subtree must be consistent with bundle checkpoint");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `GET /logs/:log/metadata` returns 200 with all required fields.
#[tokio::test]
async fn metadata_returns_valid_fields() {
    let client = IetfMtcClient::default_log();
    let meta = client.get_metadata().await.expect("metadata failed");

    let ca_id: TrustAnchorID = meta.ca_id.parse().expect("valid ca_id");
    let log_id: TrustAnchorID = meta.log_id.parse().expect("valid log_id");
    assert!(meta.log_number > 0, "log_number must be positive");
    assert_eq!(
        ca_id.log_id(meta.log_number).expect("derive log_id"),
        log_id,
        "log_id must be derived from ca_id and log_number"
    );
    assert!(!meta.log_id.is_empty(), "log_id must be non-empty");
    assert!(
        meta.log_id.contains('.'),
        "log_id must be a dotted-decimal OID, got: {}",
        meta.log_id
    );
    assert!(
        !meta.cosigner_id.is_empty(),
        "cosigner_id must be non-empty"
    );
    // cosigner_public_key is a DER-encoded SubjectPublicKeyInfo. The algorithm
    // identifier is included so clients can determine the signing algorithm.
    assert!(
        !meta.cosigner_public_key.is_empty(),
        "cosigner_public_key must be non-empty"
    );
    assert!(
        !meta.submission_url.is_empty(),
        "submission_url must be set"
    );
}

/// Requesting an unknown log name returns 400.
#[tokio::test]
async fn unknown_log_returns_400() {
    let client = IetfMtcClient::new("this-log-does-not-exist");
    let status = client.get_status("metadata").await.expect("GET request");
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
    let context = fetch_verification_context(&client).await;
    let (log_number, leaf_index) = certificate_serial(&cert);
    assert_eq!(log_number, context.log_number);

    // Full signature and inclusion proof verification.
    verify_standalone_cert(&cert, leaf_index, &context);
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

/// After `add-entry`, the index encoded in the certificate serial is covered by
/// the checkpoint.
#[tokio::test]
async fn add_entry_appears_in_checkpoint() {
    const MAX_RETRIES: u32 = 12;
    const RETRY_DELAY_MS: u64 = 500;

    ensure_initialized().await;
    let client = IetfMtcClient::default_log();
    let csr = make_ietf_mtc_csr(&client.log).expect("generating CSR");

    let (status, resp) = client
        .add_entry(csr.csr_der)
        .await
        .expect("add-entry request");
    assert_eq!(status, 200, "expected 200 from add-entry");
    let resp = resp.unwrap();

    // The serial encodes the log number in its high 16 bits and index in its low 48 bits.
    let cert = assert_valid_mtc_cert(&resp.certificate, "add-entry standalone cert");
    let context = fetch_verification_context(&client).await;
    let (log_number, leaf_index) = certificate_serial(&cert);
    assert_eq!(log_number, context.log_number);
    let min_size = leaf_index + 1;

    let mut last_size = 0u64;

    for attempt in 0..MAX_RETRIES {
        let checkpoint_bytes = client.get_checkpoint().await.expect("fetching checkpoint");
        let text = String::from_utf8_lossy(&checkpoint_bytes);
        if let Some(size_str) = text.lines().nth(1)
            && let Ok(size) = size_str.trim().parse::<u64>()
        {
            last_size = size;
            if size >= min_size {
                return;
            }
        }
        if attempt + 1 < MAX_RETRIES {
            tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
        }
    }

    panic!("checkpoint size {last_size} never reached {min_size} after {MAX_RETRIES} retries");
}

/// After `add-entry`, `get-certificate` returns a parseable landmark-relative DER
/// certificate once a landmark has been produced.
///
/// Assumes the configured log has a short `landmark_interval_secs` (≤10s);
/// both `dev1` and `dev2` in `config.dev.json` satisfy this. Retries for up to 30s.
#[tokio::test]
async fn get_certificate_returns_valid_cert() {
    const MAX_RETRIES: u32 = 30;
    const RETRY_DELAY_MS: u64 = 1_000;

    ensure_initialized().await;
    let log_name = ietf_mtc_log_name();

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
    let context = fetch_verification_context(&client).await;
    let (log_number, leaf_index) = certificate_serial(&cert);
    assert_eq!(log_number, context.log_number);

    let mut last_status = 0u16;

    for attempt in 0..MAX_RETRIES {
        let (s, cert_resp) = client
            .get_certificate(leaf_index, spki_der.clone())
            .await
            .expect("get-certificate request");
        last_status = s;
        if s == 200 {
            let cert_resp = cert_resp.unwrap();

            let lm_cert =
                assert_valid_mtc_cert(&cert_resp.data, "get-certificate landmark-relative cert");

            assert!(
                cert_resp.landmark_id > 0,
                "landmark_id must be positive (index 0 is the initial null entry)"
            );

            // Full signature and inclusion proof verification for landmark-relative cert.
            verify_landmark_relative_cert(&client, &lm_cert, leaf_index, &context).await;

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
