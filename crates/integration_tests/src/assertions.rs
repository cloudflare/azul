// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Assertion helpers for CT-specific cryptographic verification: SCT signatures,
//! checkpoint signatures, and Merkle inclusion proofs.

use anyhow::{bail, Context, Result};
use p256::{pkcs8::DecodePublicKey, pkcs8::EncodePublicKey};
use sct_validator::{
    sct::{ParsedSct, SctSignature, SignatureAlgorithm},
    verify::verify_sct_signature,
    CtLog, LogState,
};
use sha2::{Digest, Sha256};
use signed_note::{Ed25519NoteVerifier, KeyName, VerifierList};
use static_ct_api::{Extensions, RFC6962NoteVerifier, StaticCTLogEntry};
use tlog_tiles::{
    open_checkpoint, CheckpointText, HashReader, LogEntry, PathElem, PreloadedTlogTileReader,
    TileHashReader, TileIterator, TlogTile,
};
use x509_cert::{der::Decode, der::Encode, Certificate};

use crate::client::{AddChainResponse, CtClient, LogV3JsonResponse};

// ---------------------------------------------------------------------------
// SCT structure
// ---------------------------------------------------------------------------

/// Assert the basic structural invariants of an `add-[pre-]chain` response.
///
/// # Errors
///
/// Returns an error if any invariant is violated.
pub fn assert_sct_structure(sct: &AddChainResponse) -> Result<()> {
    if sct.sct_version != 0 {
        bail!(
            "expected sct_version == 0 (v1), got {}",
            sct.sct_version
        );
    }
    if sct.id.len() != 32 {
        bail!("expected log id to be 32 bytes, got {}", sct.id.len());
    }
    if sct.extensions.is_empty() {
        bail!("extensions must be non-empty (must contain leaf_index)");
    }
    // Parse extensions — this validates the leaf_index extension encoding.
    Extensions::from_bytes(&sct.extensions).context("parsing SCT extensions")?;
    if sct.signature.is_empty() {
        bail!("signature must be non-empty");
    }
    Ok(())
}

/// Extract the `leaf_index` from the SCT's extensions field.
///
/// # Errors
///
/// Returns an error if the extensions field is malformed.
pub fn leaf_index_from_sct(sct: &AddChainResponse) -> Result<u64> {
    let ext = Extensions::from_bytes(&sct.extensions).context("parsing SCT extensions")?;
    Ok(ext.leaf_index)
}

// ---------------------------------------------------------------------------
// SCT signature verification
// ---------------------------------------------------------------------------

/// Verify that the ECDSA P-256 signature in the SCT is valid over the correct
/// RFC 6962 signed data.
///
/// `log_meta` is the response from `GET /logs/:log/log.v3.json`.
/// `leaf_der` is the DER-encoded leaf certificate (for a plain cert chain,
/// this is the first element of the `chain` array posted to `add-chain`).
/// `issuer_der` is the DER-encoded issuer certificate.
///
/// # Errors
///
/// Returns an error if signature verification fails or any encoding step fails.
pub fn assert_sct_signature(
    sct: &AddChainResponse,
    log_meta: &LogV3JsonResponse,
    leaf_der: &[u8],
    issuer_der: &[u8],
) -> Result<()> {
    // Derive the verifying key from the log metadata's `key` field (DER SPKI).
    let vkey = p256::ecdsa::VerifyingKey::from_public_key_der(&log_meta.key)
        .context("decoding log verifying key")?;

    // Verify that the SCT log id matches the expected SHA-256(SPKI).
    let pkix = vkey.to_public_key_der().context("re-encoding verifying key")?;
    let expected_log_id: [u8; 32] = Sha256::digest(pkix.as_bytes()).into();
    if sct.id.as_slice() != expected_log_id {
        bail!(
            "SCT log id mismatch: expected {}, got {}",
            hex::encode(expected_log_id),
            hex::encode(&sct.id)
        );
    }

    // Extract the issuer `SubjectPublicKeyInfo` DER.
    let issuer_cert = Certificate::from_der(issuer_der).context("decoding issuer certificate")?;
    let issuer_spki_der = issuer_cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .context("encoding issuer SPKI")?;

    // Parse the RFC 5246 digitally-signed structure from the SCT signature bytes.
    // Format: hash_alg(1) | sig_alg(1) | len(2) | signature(len)
    let sig_bytes = &sct.signature;
    if sig_bytes.len() < 4 {
        bail!("SCT signature too short: {} bytes", sig_bytes.len());
    }
    let sig_len = u16::from_be_bytes([sig_bytes[2], sig_bytes[3]]) as usize;
    if sig_bytes.len() != 4 + sig_len {
        bail!(
            "SCT signature length mismatch: outer={} inner={}",
            sig_bytes.len(),
            4 + sig_len
        );
    }
    let der_signature = sig_bytes[4..].to_vec();

    let parsed_sct = ParsedSct {
        log_id: sct.id.as_slice().try_into().context("SCT id not 32 bytes")?,
        timestamp: sct.timestamp,
        extensions: sct.extensions.clone(),
        signature: SctSignature {
            algorithm: SignatureAlgorithm::EcdsaSha256,
            signature: der_signature,
        },
    };

    let ct_log = CtLog::new(
        "test".to_string(),
        expected_log_id,
        &log_meta.key,
        LogState::Usable,
        0,
        "test-operator".to_string(),
        vec![],
    )
    .context("constructing CtLog for verification")?;

    // For regular certs, the signed data uses x509_entry (no issuer hash).
    // For precerts, it uses precert_entry (with issuer hash).
    // We detect precerts by the presence of the CT poison extension (OID 1.3.6.1.4.1.11129.2.4.3).
    let ct_poison_oid = der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.3");
    let leaf_cert = Certificate::from_der(leaf_der).context("parsing leaf cert")?;
    let is_precert = leaf_cert
        .tbs_certificate()
        .extensions()
        .is_some_and(|exts| exts.iter().any(|e| e.extn_id == ct_poison_oid));

    // For precerts, the worker signs over the TBS with the CT poison extension
    // removed (via build_precert_tbs), not over the raw precert DER.
    let cert_to_sign: Vec<u8>;
    let effective_cert_der: &[u8];
    let effective_issuer_spki: &[u8];
    if is_precert {
        cert_to_sign = static_ct_api::build_precert_tbs(leaf_cert.tbs_certificate())
            .context("building precert TBS for signature verification")?;
        effective_cert_der = &cert_to_sign;
        effective_issuer_spki = &issuer_spki_der;
    } else {
        effective_cert_der = leaf_der;
        effective_issuer_spki = &[];
    }

    verify_sct_signature(&parsed_sct, &ct_log, effective_cert_der, effective_issuer_spki)
        .context("SCT signature verification failed")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Checkpoint verification
// ---------------------------------------------------------------------------

/// A parsed, verified checkpoint.
pub struct VerifiedCheckpoint {
    pub text: CheckpointText,
}

/// Fetch and verify the checkpoint signature(s) for a log.
///
/// Verifies the RFC 6962 ECDSA signature from the log's signing key.
/// If `witness_key_der` is provided, also verifies the Ed25519 witness cosignature.
///
/// # Errors
///
/// Returns an error if the checkpoint cannot be fetched or the signature is invalid.
pub async fn fetch_and_verify_checkpoint(
    client: &CtClient,
    log_meta: &LogV3JsonResponse,
    witness_key_der: Option<&[u8]>,
    now_millis: u64,
) -> Result<VerifiedCheckpoint> {
    let checkpoint_bytes = client
        .get_checkpoint()
        .await
        .context("fetching checkpoint")?;

    verify_checkpoint_bytes(
        &checkpoint_bytes,
        &client.log,
        log_meta,
        witness_key_der,
        now_millis,
    )
}

/// Verify checkpoint bytes (separated from the async fetch for testability).
///
/// # Errors
///
/// Returns an error if signature verification fails or the origin does not match.
pub fn verify_checkpoint_bytes(
    checkpoint_bytes: &[u8],
    log_name: &str,
    log_meta: &LogV3JsonResponse,
    witness_key_der: Option<&[u8]>,
    now_millis: u64,
) -> Result<VerifiedCheckpoint> {
    let vkey = p256::ecdsa::VerifyingKey::from_public_key_der(&log_meta.key)
        .context("decoding log verifying key")?;

    // The origin is derived from the submission URL (schema-less, no trailing slash).
    let origin = log_meta
        .submission_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');

    if !origin.contains(log_name) {
        bail!("origin '{origin}' does not contain log name '{log_name}'");
    }

    let key_name = KeyName::new(origin.to_string()).context("constructing key name")?;
    let rfc6962_verifier = RFC6962NoteVerifier::new(key_name.clone(), &vkey)
        .context("constructing RFC6962NoteVerifier")?;

    let verifiers: Vec<Box<dyn signed_note::NoteVerifier>> =
        if let Some(wkey_der) = witness_key_der {
            let ed25519_vkey = ed25519_dalek::VerifyingKey::from_public_key_der(wkey_der)
                .context("decoding witness verifying key")?;
            let encoded = signed_note::new_encoded_ed25519_verifier_key(&key_name, &ed25519_vkey);
            let witness_verifier = Ed25519NoteVerifier::new_from_encoded_key(&encoded)
                .context("constructing Ed25519NoteVerifier")?;
            vec![Box::new(rfc6962_verifier), Box::new(witness_verifier)]
        } else {
            vec![Box::new(rfc6962_verifier)]
        };

    let verifier_list = VerifierList::new(verifiers);
    let (text, _timestamp) = open_checkpoint(
        origin,
        &verifier_list,
        tlog_tiles::ValidationMode::All,
        now_millis,
        checkpoint_bytes,
    )
    .context("opening checkpoint")?;

    Ok(VerifiedCheckpoint { text })
}

// ---------------------------------------------------------------------------
// Inclusion proof / tile verification
// ---------------------------------------------------------------------------

/// Assert that `leaf_index` is covered by the checkpoint and that the entry's
/// Merkle hash is consistent with the tree root.
///
/// Fetches the hash tiles needed to reconstruct the proof path, then fetches
/// the data tile to read the leaf entry and verify its hash.
///
/// # Errors
///
/// Returns an error if the leaf is not yet in the tree, any tile fetch fails,
/// or the Merkle hash does not match.
///
/// # Panics
///
/// Panics if `leaf_index % FULL_WIDTH` does not fit in `usize` (impossible on
/// any supported platform since `FULL_WIDTH == 256`).
pub async fn assert_leaf_in_checkpoint(
    client: &CtClient,
    checkpoint: &VerifiedCheckpoint,
    leaf_index: u64,
) -> Result<()> {
    let tree_size = checkpoint.text.size();

    if leaf_index >= tree_size {
        bail!(
            "leaf_index {leaf_index} >= tree_size {tree_size}: entry not yet in checkpoint"
        );
    }

    // Compute the hash storage index for this leaf.
    let hash_index = tlog_tiles::stored_hash_index(0, leaf_index);
    let indexes = vec![hash_index];

    // Use TlogTileRecorder to discover which hash tiles are needed for the
    // inclusion proof without fetching them yet.  read_hashes() will always
    // fail with RecordedTilesOnly, but the recorder is populated with the tiles.
    let needed_tiles: Vec<TlogTile> = {
        let recorder = tlog_tiles::TlogTileRecorder::default();
        let hash_reader = TileHashReader::new(tree_size, *checkpoint.text.hash(), &recorder);
        let _ = hash_reader.read_hashes(&indexes);
        recorder.0.into_inner()
    };

    // Fetch the recorded hash tiles.
    let mut tile_data: std::collections::HashMap<TlogTile, Vec<u8>> =
        std::collections::HashMap::new();
    for tile in needed_tiles {
        let path: String = tile.path();
        let data = fetch_tile_with_retry(client, &path)
            .await
            .with_context(|| format!("fetching hash tile {path}"))?;
        tile_data.insert(tile, data);
    }

    // Verify the leaf hash against the tree root.
    let preloaded = PreloadedTlogTileReader(tile_data);
    let hash_reader = TileHashReader::new(tree_size, *checkpoint.text.hash(), &preloaded);
    let leaf_hashes = hash_reader
        .read_hashes(&indexes)
        .context("computing leaf hash via TileHashReader")?;

    // Fetch the data tile containing this leaf entry.
    // The worker only stores the current (widest) partial tile for each tile index.
    // Compute the correct width from the verified tree_size rather than from
    // leaf_index alone, to avoid requesting a stale narrower partial tile.
    // The tile index (which 256-entry tile this leaf falls in).
    let tile_n = leaf_index / u64::from(TlogTile::FULL_WIDTH);
    // Compute the correct width from the verified tree_size.
    // The worker only stores the current (widest) partial tile — not narrower
    // historical versions — so we must request the tile at its current width.
    let tile_width_from_tree =
        u32::try_from(tree_size - tile_n * u64::from(TlogTile::FULL_WIDTH))
            .unwrap_or(TlogTile::FULL_WIDTH)
            .min(TlogTile::FULL_WIDTH);
    let data_tile = TlogTile::new(0, tile_n, tile_width_from_tree, Some(PathElem::Data));
    let data_tile_path = data_tile.path();
    let tile_bytes = fetch_tile_with_retry(client, &data_tile_path)
        .await
        .with_context(|| format!("fetching data tile {data_tile_path}"))?;

    // Parse the leaf entry at its position within the tile.
    let entry_index_in_tile =
        usize::try_from(leaf_index % u64::from(TlogTile::FULL_WIDTH)).unwrap();

    let tile_width = data_tile.width() as usize;
    let mut entries = TileIterator::<StaticCTLogEntry>::new(&tile_bytes, tile_width);
    let mut entry_opt = None;
    for (i, result) in entries.by_ref().enumerate() {
        let entry = result.context("parsing tile entry")?;
        if i == entry_index_in_tile {
            entry_opt = Some(entry);
            break;
        }
    }

    let entry = entry_opt.with_context(|| {
        format!(
            "leaf_index {leaf_index} (offset {entry_index_in_tile}) not found in tile {data_tile_path}"
        )
    })?;

    // Verify the Merkle hash of the data tile entry matches the tree.
    let computed_hash = entry.merkle_tree_leaf();
    if computed_hash != leaf_hashes[0] {
        bail!(
            "Merkle hash mismatch for leaf_index {leaf_index}: \
             data tile entry hash {} != tree hash {}",
            hex::encode(computed_hash.0),
            hex::encode(leaf_hashes[0].0),
        );
    }

    // Verify the leaf_index field encoded in the entry.
    if entry.leaf_index != leaf_index {
        bail!(
            "leaf_index mismatch: entry.leaf_index={} != expected {leaf_index}",
            entry.leaf_index
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Retry helpers
// ---------------------------------------------------------------------------

/// Fetch a tile path, retrying up to `MAX_RETRIES` times with a short delay.
///
/// The sequencer publishes tiles asynchronously; there can be a brief window
/// between SCT issuance and tile availability when running against a live instance.
async fn fetch_tile_with_retry(client: &CtClient, path: &str) -> Result<Vec<u8>> {
    const MAX_RETRIES: u32 = 6;
    const RETRY_DELAY_MS: u64 = 500;

    let mut last_err = None;
    for attempt in 0..MAX_RETRIES {
        match client.get_raw(path).await {
            Ok(data) => return Ok(data),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 < MAX_RETRIES {
                    tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                }
            }
        }
    }
    Err(last_err.unwrap()).with_context(|| format!("all {MAX_RETRIES} attempts failed for {path}"))
}

/// Fetch and verify the checkpoint, retrying until the tree size is at least
/// `min_size`.
///
/// Used after `add-chain` to wait for the sequencer to incorporate the new
/// leaf before verifying inclusion.
///
/// # Errors
///
/// Returns an error if the checkpoint never reaches `min_size` within the
/// retry budget.
///
/// # Panics
///
/// Panics if no attempt was ever made (impossible given `MAX_RETRIES > 0`).
pub async fn fetch_checkpoint_until_size(
    client: &CtClient,
    log_meta: &LogV3JsonResponse,
    min_size: u64,
    now_millis: u64,
) -> Result<VerifiedCheckpoint> {
    const MAX_RETRIES: u32 = 12;
    const RETRY_DELAY_MS: u64 = 500;

    let mut last_err = None;
    for attempt in 0..MAX_RETRIES {
        match fetch_and_verify_checkpoint(client, log_meta, None, now_millis).await {
            Ok(cp) if cp.text.size() >= min_size => return Ok(cp),
            Ok(cp) => {
                last_err = Some(anyhow::anyhow!(
                    "checkpoint size {} < required {}",
                    cp.text.size(),
                    min_size
                ));
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
        if attempt + 1 < MAX_RETRIES {
            tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
        }
    }
    Err(last_err.unwrap()).with_context(|| {
        format!("checkpoint never reached size {min_size} after {MAX_RETRIES} retries")
    })
}
