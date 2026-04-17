// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! `sign-subtree` oracle parsers and verifier
//! (draft-ietf-plants-merkle-tree-certs-02, Appendix C.2).
//!
//! A cosigner (typically the CA itself, but in principle any witness/mirror)
//! exposes `POST <prefix>/sign-subtree` so that other parties can obtain
//! cosignatures on an already-known subtree hash without learning any
//! additional log state. The request body is a newline-delimited concatenation
//! of three blocks:
//!
//! 1. A **subtree signed note** (Appendix C.1) carrying the subtree interval
//!    and hash. The note may already have zero or more signatures; the endpoint
//!    MAY require at least one (e.g. from the CA) as a DoS mitigation.
//! 2. A **checkpoint signed note**, signed by the cosigner being asked to cosign
//!    the subtree. Its tree size must be at least `end` of the requested subtree.
//! 3. Zero or more **subtree consistency proof** lines, each a base64-encoded
//!    hash.
//!
//! On success the response body is a sequence of [`signed_note::NoteSignature`]
//! lines (each starting with an em dash, U+2014), one per cosignature the
//! server wishes to return.
//!
//! # What this module provides
//!
//! - [`SignSubtreeRequest`]: a parsed request body; exposes the subtree
//!   [`Note`], the checkpoint [`CheckpointText`], and the consistency-proof
//!   [`Hash`] list. No semantic checks (signature verification, proof
//!   verification) are performed at parse time — callers run those against their
//!   own policy.
//! - [`parse_sign_subtree_request`]: parse a request body into a
//!   [`SignSubtreeRequest`].
//! - [`serialize_sign_subtree_response`]: format a list of
//!   [`NoteSignature`]s into the on-wire response body.
//! - [`MtcSubtreeNoteVerifier`]: a [`NoteVerifier`] that validates signatures
//!   already attached to the incoming subtree note. Relocated from
//!   [`crate::cosigner`] because it is only meaningful in the context of the
//!   `sign-subtree` flow.
//!
//! The semantic-validation and cosigning logic (checking the checkpoint
//! signature against the cosigner's own key, verifying the consistency proof,
//! producing a cosignature via [`crate::MtcCosigner::sign_subtree`], etc.) is
//! *not* in this module — that belongs in the worker, where keys, log state,
//! and policy decisions live.
//!
//! [`CheckpointText`]: tlog_tiles::CheckpointText

use base64::prelude::*;
use signed_note::{KeyName, Note, NoteError, NoteSignature, NoteVerifier};
use tlog_tiles::{CheckpointText, Hash, LeafIndex, MalformedCheckpointTextError};

use crate::{
    cosigner::serialize_mtc_subtree_signature_input, MtcError, MtcVerifyingKey, TrustAnchorID,
    ID_RDNA_TRUSTANCHOR_ID,
};

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// A parsed `sign-subtree` request body.
///
/// Contains the three sections of the body: the subtree signed note, the
/// cosigner-signed checkpoint, and the (possibly empty) consistency proof.
/// Signatures on the subtree note and the checkpoint are *not* verified at
/// parse time — the caller runs signature verification and proof verification
/// against its own policy.
#[derive(Debug)]
pub struct SignSubtreeRequest {
    /// The subtree signed note (Appendix C.1). Carries the subtree interval
    /// `[start, end)` and subtree hash in its text body. The caller inspects
    /// `subtree.sigs` to decide whether any required signatures (e.g. from the
    /// CA) are present.
    pub subtree: Note,
    /// The parsed subtree body (origin, start, end, hash). Present because
    /// re-parsing [`Note::text`] everywhere would be error-prone.
    pub subtree_body: SubtreeNoteBody,
    /// The parsed checkpoint the caller claims the cosigner has signed. The
    /// caller runs signature verification against this note's signer list
    /// (`checkpoint_note.sigs`) using its own [`NoteVerifier`].
    pub checkpoint_note: Note,
    /// The parsed checkpoint text, for convenience. `checkpoint.size()` must
    /// be at least `subtree_body.end` to serve as a legitimate tree head for
    /// the requested subtree.
    pub checkpoint: CheckpointText,
    /// Consistency proof hashes, in order. Empty if the subtree is trivially
    /// contained in the checkpoint (e.g. `subtree.end == checkpoint.size()`).
    pub consistency_proof: Vec<Hash>,
}

/// The parsed text body of a subtree signed note.
#[derive(Debug, Clone, PartialEq)]
pub struct SubtreeNoteBody {
    pub origin: String,
    pub start: LeafIndex,
    pub end: LeafIndex,
    pub hash: Hash,
}

/// Maximum number of consistency-proof lines a client may send (per §C.2).
///
/// A subtree consistency proof has at most 63 hashes, since a Merkle Tree
/// built over a 64-bit-indexed log has depth ≤ 63.
pub const MAX_CONSISTENCY_PROOF_HASHES: usize = 63;

/// Parse a `sign-subtree` request body.
///
/// The body format is specified in §C.2:
///
/// ```text
/// <subtree signed note>
/// \n
/// <checkpoint signed note signed by the cosigner>
/// \n
/// <zero or more base64-encoded consistency-proof hashes, one per line>
/// ```
///
/// # Errors
///
/// Returns an error if the body is not valid UTF-8, does not contain the
/// required blank-line-delimited sections, if either note fails to parse, if
/// the subtree body is malformed, or if the consistency proof contains more
/// than [`MAX_CONSISTENCY_PROOF_HASHES`] lines.
///
/// # Wire-format TODO (feedback for the spec)
///
/// The §C.2 body uses a blank line (`\n\n`) as the inter-section separator,
/// but each c2sp.org/signed-note *already* contains a blank line between its
/// text body and its signature block. A standalone parser cannot locate
/// section boundaries without exploiting the invariant "each note contains
/// exactly one internal `\n\n`" (what this function does), or by peeking
/// ahead to distinguish signature lines (which start with `— `) from the
/// start of the next section. Neither is obvious from the spec text.
///
/// Two cleaner alternatives worth proposing upstream:
///
/// 1. **Length-prefixed sections.** Each section is preceded by a
///    fixed-format header line such as `subtree-note: <len>\n`,
///    `checkpoint-note: <len>\n`, `consistency-proof: <count>\n`. Keeps the
///    body text-friendly while making section boundaries unambiguous and
///    streamable.
///
/// 2. **Binary framing.** Replace the concatenated-notes body with a TLS
///    presentation-language `struct` carrying explicit-length opaque fields
///    for each note and a fixed-length-hash vector for the consistency
///    proof. Most consumers of this endpoint are already binary-speaking
///    (CA, cosigner, monitor) and the signed-note text format is an
///    artifact of the transport rather than a direct requirement of the
///    protocol. This aligns better with the rest of the MTC certificate
///    and subtree-signature formats, which are already TLS-binary.
///
/// The current implementation is correct for well-formed input, but the
/// ambiguity is the kind of thing that makes a protocol subtly hard to
/// implement interoperably and is worth raising in the working group.
pub fn parse_sign_subtree_request(body: &[u8]) -> Result<SignSubtreeRequest, MtcError> {
    // The wire format is `<subtree_note>\n<checkpoint_note>\n<proof>` (§C.2).
    //
    // A signed note itself contains exactly one internal `\n\n` (between its
    // text block and its signatures). The two note-terminating blank lines
    // (the "\n"s before each separator) mean the body contains, in order:
    //
    //     \n\n (inside subtree note)
    //     \n\n (separator between subtree and checkpoint)
    //     \n\n (inside checkpoint note)
    //     \n\n (separator between checkpoint and proof)
    //
    // So we slice at the 2nd and 4th `\n\n` boundaries.
    let boundaries: Vec<usize> = body
        .windows(2)
        .enumerate()
        .filter_map(|(i, w)| (w == b"\n\n").then_some(i))
        .take(4)
        .collect();
    if boundaries.len() < 4 {
        return Err(MtcError::Dynamic(
            "sign-subtree body is missing required blank-line separators".into(),
        ));
    }
    // boundaries[1] is the separator after the subtree note.
    // boundaries[3] is the separator after the checkpoint note.
    let subtree_bytes = &body[..=boundaries[1]]; // includes trailing \n of note
    let checkpoint_bytes = &body[boundaries[1] + 2..=boundaries[3]];
    let proof_bytes = &body[boundaries[3] + 2..];

    // Parse the subtree signed note.
    let subtree = Note::from_bytes(subtree_bytes)
        .map_err(|e| MtcError::Dynamic(format!("parsing subtree note: {e:?}")))?;
    let subtree_body = parse_subtree_note_body(subtree.text())
        .ok_or_else(|| MtcError::Dynamic("malformed subtree note body".into()))?;

    // Parse the checkpoint signed note.
    let checkpoint_note = Note::from_bytes(checkpoint_bytes)
        .map_err(|e| MtcError::Dynamic(format!("parsing checkpoint note: {e:?}")))?;
    let checkpoint = CheckpointText::from_bytes(checkpoint_note.text()).map_err(
        |e: MalformedCheckpointTextError| {
            MtcError::Dynamic(format!("parsing checkpoint text: {e:?}"))
        },
    )?;

    // Parse the consistency proof: one base64 hash per line.
    let consistency_proof = parse_consistency_proof(proof_bytes)?;

    Ok(SignSubtreeRequest {
        subtree,
        subtree_body,
        checkpoint_note,
        checkpoint,
        consistency_proof,
    })
}

/// Parse a consistency-proof block (one base64 hash per line, possibly empty).
fn parse_consistency_proof(buf: &[u8]) -> Result<Vec<Hash>, MtcError> {
    let text = std::str::from_utf8(buf)
        .map_err(|_| MtcError::Dynamic("consistency proof is not valid UTF-8".into()))?;
    // Trim a trailing newline so "a\nb\n" and "a\nb" both yield two lines.
    let trimmed = text.strip_suffix('\n').unwrap_or(text);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut hashes = Vec::new();
    for line in trimmed.split('\n') {
        if hashes.len() >= MAX_CONSISTENCY_PROOF_HASHES {
            return Err(MtcError::Dynamic(format!(
                "consistency proof exceeds {MAX_CONSISTENCY_PROOF_HASHES} hashes"
            )));
        }
        let decoded = BASE64_STANDARD
            .decode(line)
            .map_err(|e| MtcError::Dynamic(format!("decoding consistency proof line: {e}")))?;
        let arr: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
            MtcError::Dynamic(format!(
                "consistency proof hash is {} bytes, want 32",
                v.len()
            ))
        })?;
        hashes.push(Hash(arr));
    }
    Ok(hashes)
}

/// Parse a subtree note text body in the Appendix C.1 format:
/// ```text
/// <origin>\n<start> <end>\n<base64-hash>\n
/// ```
fn parse_subtree_note_body(msg: &[u8]) -> Option<SubtreeNoteBody> {
    let text = std::str::from_utf8(msg).ok()?;
    let mut lines = text.splitn(4, '\n');
    let origin = lines.next()?.to_owned();
    let range_line = lines.next()?;
    let hash_line = lines.next()?;

    let mut parts = range_line.splitn(2, ' ');
    let start: LeafIndex = parts.next()?.parse().ok()?;
    let end: LeafIndex = parts.next()?.parse().ok()?;
    if start > end {
        return None;
    }

    let hash_bytes = BASE64_STANDARD.decode(hash_line).ok()?;
    let hash_arr: [u8; 32] = hash_bytes.try_into().ok()?;
    Some(SubtreeNoteBody {
        origin,
        start,
        end,
        hash: Hash(hash_arr),
    })
}

// ---------------------------------------------------------------------------
// Response serialization
// ---------------------------------------------------------------------------

/// Serialize a `sign-subtree` response body: one `— name b64sig\n` line per
/// signature, in order. Empty if `sigs` is empty (but per §C.2 the endpoint
/// must return at least one signature on success, so callers should not pass
/// an empty slice for a successful response).
#[must_use]
pub fn serialize_sign_subtree_response(sigs: &[NoteSignature]) -> Vec<u8> {
    let mut out = Vec::new();
    for sig in sigs {
        out.extend_from_slice(&sig.to_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Client-side helpers (CA requesting cosignatures from a mirror)
// ---------------------------------------------------------------------------

/// Serialize the text body of a subtree signed note per §C.1:
/// `<origin>\n<start> <end>\n<base64-hash>\n`.
///
/// The returned bytes are suitable for passing to [`signed_note::Note::new`]
/// as the note text, together with any already-attached signatures.
#[must_use]
pub fn serialize_subtree_note_body(body: &SubtreeNoteBody) -> Vec<u8> {
    let hash_b64 = BASE64_STANDARD.encode(body.hash.0);
    format!(
        "{}\n{} {}\n{}\n",
        body.origin, body.start, body.end, hash_b64
    )
    .into_bytes()
}

/// Serialize a full `sign-subtree` request body (§C.2).
///
/// Layout:
///
/// ```text
/// <subtree_note.to_bytes()>
/// \n
/// <checkpoint_note.to_bytes()>
/// \n
/// <one base64 hash per line from consistency_proof>
/// ```
///
/// The caller is responsible for providing a fully-assembled `subtree_note`
/// (with whatever signatures the target endpoint requires, typically the CA's
/// own subtree cosignature as a DoS-mitigation signal) and
/// `checkpoint_note` (the CA's own signed checkpoint, whose tree size must
/// cover `subtree.end`). This function performs no semantic validation.
///
/// # Errors
///
/// Returns an error if `consistency_proof.len() > MAX_CONSISTENCY_PROOF_HASHES`.
pub fn serialize_sign_subtree_request(
    subtree_note: &Note,
    checkpoint_note: &Note,
    consistency_proof: &[Hash],
) -> Result<Vec<u8>, MtcError> {
    if consistency_proof.len() > MAX_CONSISTENCY_PROOF_HASHES {
        return Err(MtcError::Dynamic(format!(
            "consistency proof exceeds {MAX_CONSISTENCY_PROOF_HASHES} hashes"
        )));
    }
    let mut out = subtree_note.to_bytes();
    out.push(b'\n');
    out.extend_from_slice(&checkpoint_note.to_bytes());
    out.push(b'\n');
    for h in consistency_proof {
        out.extend_from_slice(BASE64_STANDARD.encode(h.0).as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

/// Parse a `sign-subtree` response body (§C.2).
///
/// The body is a sequence of note signature lines, each starting with an
/// em dash (U+2014) and terminated by a newline. Returns one
/// [`NoteSignature`] per line.
///
/// Callers should verify each returned signature with the appropriate
/// [`MtcSubtreeNoteVerifier`] (one per cosigner key) before using it.
///
/// # Errors
///
/// Returns an error if the body is not valid UTF-8 or if any line fails
/// [`NoteSignature::from_bytes`] parsing. An empty body is an error — §C.2
/// requires at least one signature in a successful response.
pub fn parse_sign_subtree_response(body: &[u8]) -> Result<Vec<NoteSignature>, MtcError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| MtcError::Dynamic("sign-subtree response is not valid UTF-8".into()))?;
    let trimmed = text.strip_suffix('\n').unwrap_or(text);
    if trimmed.is_empty() {
        return Err(MtcError::Dynamic(
            "sign-subtree response must contain at least one signature line".into(),
        ));
    }
    let mut sigs = Vec::new();
    for line in trimmed.split('\n') {
        let sig = NoteSignature::from_bytes(line.as_bytes())
            .map_err(|e| MtcError::Dynamic(format!("parsing signature line: {e:?}")))?;
        sigs.push(sig);
    }
    Ok(sigs)
}

// ---------------------------------------------------------------------------
// MtcSubtreeNoteVerifier
// ---------------------------------------------------------------------------

/// Verifier for MTC subtree cosignatures in signed-note format (Appendix C.1/C.2).
///
/// Used when verifying signatures attached to the incoming subtree note at the
/// `sign-subtree` endpoint. The key ID is derived from the `mtc-subtree/v1`
/// context string, distinct from checkpoint cosignatures.
///
/// Certificates embed raw signature bytes directly (not signed-note lines); use
/// [`crate::ParsedMtcProof::verify_cosignature`] for those.
///
/// See <https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-02.html#appendix-C.1>.
#[derive(Clone)]
pub struct MtcSubtreeNoteVerifier {
    cosigner_id: TrustAnchorID,
    log_id: TrustAnchorID,
    name: KeyName,
    id: u32,
    verifying_key: MtcVerifyingKey,
}

impl MtcSubtreeNoteVerifier {
    /// Construct a new subtree note verifier.
    ///
    /// # Panics
    ///
    /// Will panic if the trust anchor ID cannot be formatted as a valid key
    /// name per <https://c2sp.org/signed-note#format>.
    #[must_use]
    pub fn new(
        cosigner_id: TrustAnchorID,
        log_id: TrustAnchorID,
        verifying_key: MtcVerifyingKey,
    ) -> Self {
        let name = KeyName::new(format!("oid/{ID_RDNA_TRUSTANCHOR_ID}.{log_id}")).unwrap();
        let id = signed_note::compute_key_id(&name, b"\xffmtc-subtree/v1", &[]);
        Self {
            cosigner_id,
            log_id,
            name,
            id,
            verifying_key,
        }
    }
}

impl NoteVerifier for MtcSubtreeNoteVerifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    /// Verify a subtree cosignature. `msg` is the raw subtree note body in the
    /// Appendix C.1 text format (`<origin>\n<start> <end>\n<base64-hash>\n`);
    /// it is parsed to recover the subtree interval and hash, which are then
    /// used to reconstruct the `MTCSubtreeSignatureInput` binary message
    /// bytes that the cosigner's key actually signs.
    fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> bool {
        let Some(body) = parse_subtree_note_body(msg) else {
            return false;
        };
        let msg = serialize_mtc_subtree_signature_input(
            &self.cosigner_id,
            &self.log_id,
            body.start,
            body.end,
            &body.hash,
        );
        self.verifying_key.verify(&msg, sig_bytes)
    }

    fn extract_timestamp_millis(&self, _sig: &[u8]) -> Result<Option<u64>, NoteError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid body of three sections: subtree note, checkpoint
    /// note, and consistency proof. Uses a made-up bogus signature so we
    /// exercise parsing without needing keys.
    fn build_request(proof_hashes: &[[u8; 32]]) -> Vec<u8> {
        // Subtree note: origin + "start end" + base64 hash, then one signature line.
        let subtree_hash_b64 = BASE64_STANDARD.encode([0x11u8; 32]);
        let subtree_text = format!("oid/1.3.6.1.4.1.32473.1\n4 8\n{subtree_hash_b64}\n");
        // Craft a plausible signature line: "— <name> <base64(4-byte-id || sig)>"
        let sig_bytes = vec![0u8; 64];
        let mut keyed = vec![0xaau8, 0xbb, 0xcc, 0xdd];
        keyed.extend(&sig_bytes);
        let subtree_sig_line = format!(
            "— oid/1.3.6.1.4.1.32473.1 {}\n",
            BASE64_STANDARD.encode(&keyed)
        );
        let subtree_note = format!("{subtree_text}\n{subtree_sig_line}");

        // Checkpoint note.
        let checkpoint_hash_b64 = BASE64_STANDARD.encode([0x22u8; 32]);
        let checkpoint_text = format!("oid/1.3.6.1.4.1.32473.1\n8\n{checkpoint_hash_b64}\n");
        let mut keyed = vec![0x11u8, 0x22, 0x33, 0x44];
        keyed.extend(vec![1u8; 64]);
        let checkpoint_sig_line = format!(
            "— oid/1.3.6.1.4.1.32473.1 {}\n",
            BASE64_STANDARD.encode(&keyed)
        );
        let checkpoint_note = format!("{checkpoint_text}\n{checkpoint_sig_line}");

        // Consistency proof.
        let mut proof = String::new();
        for h in proof_hashes {
            proof.push_str(&BASE64_STANDARD.encode(h));
            proof.push('\n');
        }

        format!("{subtree_note}\n{checkpoint_note}\n{proof}").into_bytes()
    }

    #[test]
    fn test_parse_sign_subtree_request_no_proof() {
        let body = build_request(&[]);
        let req = parse_sign_subtree_request(&body).unwrap();
        assert_eq!(req.subtree_body.origin, "oid/1.3.6.1.4.1.32473.1");
        assert_eq!(req.subtree_body.start, 4);
        assert_eq!(req.subtree_body.end, 8);
        assert_eq!(req.subtree_body.hash.0, [0x11u8; 32]);
        assert_eq!(req.checkpoint.size(), 8);
        assert_eq!(req.checkpoint.hash().0, [0x22u8; 32]);
        assert!(req.consistency_proof.is_empty());
    }

    #[test]
    fn test_parse_sign_subtree_request_with_proof() {
        let body = build_request(&[[0x33u8; 32], [0x44u8; 32]]);
        let req = parse_sign_subtree_request(&body).unwrap();
        assert_eq!(req.consistency_proof.len(), 2);
        assert_eq!(req.consistency_proof[0].0, [0x33u8; 32]);
        assert_eq!(req.consistency_proof[1].0, [0x44u8; 32]);
    }

    #[test]
    fn test_parse_sign_subtree_request_missing_blank_line() {
        // No blank line after the subtree note at all.
        let body = b"oid/x\n4 8\nAAAA\n\xe2\x80\x94 oid/x sig\n";
        assert!(parse_sign_subtree_request(body).is_err());
    }

    #[test]
    fn test_parse_sign_subtree_request_malformed_subtree() {
        // Subtree note body has a non-numeric start.
        let bad_text =
            "oid/x\nfour eight\n".to_string() + &BASE64_STANDARD.encode([0u8; 32]) + "\n";
        let mut keyed = vec![0u8, 0, 0, 0];
        keyed.extend(vec![0u8; 64]);
        let sig_line = format!("— oid/x {}\n", BASE64_STANDARD.encode(&keyed));
        let subtree = format!("{bad_text}\n{sig_line}");
        let chk_text = format!("oid/x\n8\n{}\n", BASE64_STANDARD.encode([0u8; 32]));
        let chk = format!("{chk_text}\n{sig_line}");
        let body = format!("{subtree}\n{chk}\n");
        assert!(parse_sign_subtree_request(body.as_bytes()).is_err());
    }

    #[test]
    fn test_parse_sign_subtree_request_too_many_proof_hashes() {
        let mut hashes = Vec::new();
        for _ in 0..=MAX_CONSISTENCY_PROOF_HASHES {
            hashes.push([0x55u8; 32]);
        }
        let body = build_request(&hashes);
        let err = parse_sign_subtree_request(&body).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("exceeds"), "unexpected error: {msg}");
    }

    #[test]
    fn test_parse_sign_subtree_request_bad_proof_length() {
        let subtree_hash_b64 = BASE64_STANDARD.encode([0u8; 32]);
        let subtree_text = format!("oid/x\n0 4\n{subtree_hash_b64}\n");
        let mut keyed = vec![0u8; 4];
        keyed.extend(vec![0u8; 64]);
        let sig_line = format!("— oid/x {}\n", BASE64_STANDARD.encode(&keyed));
        let subtree = format!("{subtree_text}\n{sig_line}");
        let chk_text = format!("oid/x\n4\n{subtree_hash_b64}\n");
        let chk = format!("{chk_text}\n{sig_line}");
        // 16-byte hash (wrong size) rather than 32.
        let bad_hash = BASE64_STANDARD.encode([0u8; 16]);
        let body = format!("{subtree}\n{chk}\n{bad_hash}\n");
        let err = parse_sign_subtree_request(body.as_bytes()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("32"), "unexpected error: {msg}");
    }

    #[test]
    fn test_serialize_sign_subtree_response_empty() {
        assert!(serialize_sign_subtree_response(&[]).is_empty());
    }

    #[test]
    fn test_serialize_sign_subtree_response_roundtrip() {
        let name = KeyName::new("oid/1.3.6.1.4.1.32473.1".to_owned()).unwrap();
        let id = 0xdead_beef;
        let sig = vec![0x42u8; 64];
        let ns = NoteSignature::new(name, id, sig);
        let bytes = serialize_sign_subtree_response(std::slice::from_ref(&ns));
        let line = std::str::from_utf8(&bytes).unwrap();
        assert!(line.starts_with("— oid/1.3.6.1.4.1.32473.1 "));
        assert!(line.ends_with('\n'));

        // Round-trip through NoteSignature::from_bytes.
        let parsed = NoteSignature::from_bytes(line.trim_end_matches('\n').as_bytes()).unwrap();
        assert_eq!(parsed.name(), ns.name());
        assert_eq!(parsed.id(), ns.id());
        assert_eq!(parsed.signature(), ns.signature());
    }

    #[test]
    fn test_serialize_sign_subtree_response_multiple() {
        let name = KeyName::new("oid/x".to_owned()).unwrap();
        let ns1 = NoteSignature::new(name.clone(), 1, vec![0u8; 64]);
        let ns2 = NoteSignature::new(name, 2, vec![1u8; 64]);
        let bytes = serialize_sign_subtree_response(&[ns1, ns2]);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(text.matches('\n').count(), 2);
        assert_eq!(text.matches("— ").count(), 2);
    }

    // ---- Client-side helpers (CA side) ----

    /// Build a minimal valid `Note` for use in client-side tests. Uses fake
    /// signature bytes — these round-trip through serialize/parse without ever
    /// needing a real keypair.
    fn fake_signed_note(text: &str, sig_name: &str, sig_id: u32) -> Note {
        let name = KeyName::new(sig_name.to_owned()).unwrap();
        let sig = NoteSignature::new(name, sig_id, vec![0x5au8; 64]);
        Note::new(text.as_bytes(), std::slice::from_ref(&sig)).unwrap()
    }

    #[test]
    fn test_serialize_subtree_note_body_format() {
        let body = SubtreeNoteBody {
            origin: "oid/1.3.6.1.4.1.32473.1".to_owned(),
            start: 4,
            end: 8,
            hash: Hash([0x11u8; 32]),
        };
        let bytes = serialize_subtree_note_body(&body);
        let text = std::str::from_utf8(&bytes).unwrap();
        let hash_b64 = BASE64_STANDARD.encode([0x11u8; 32]);
        assert_eq!(text, format!("oid/1.3.6.1.4.1.32473.1\n4 8\n{hash_b64}\n"));
    }

    #[test]
    fn test_serialize_subtree_note_body_roundtrips_through_parser() {
        let body = SubtreeNoteBody {
            origin: "oid/x".to_owned(),
            start: 0,
            end: 16,
            hash: Hash([0x99u8; 32]),
        };
        let text = serialize_subtree_note_body(&body);
        let parsed = parse_subtree_note_body(&text).unwrap();
        assert_eq!(parsed, body);
    }

    /// Build a request via [`serialize_sign_subtree_request`], feed it into
    /// [`parse_sign_subtree_request`], and confirm every section is recovered.
    #[test]
    fn test_serialize_parse_sign_subtree_request_roundtrip() {
        // Subtree note: text body from SubtreeNoteBody + one fake signature.
        let subtree_body = SubtreeNoteBody {
            origin: "oid/1.3.6.1.4.1.32473.1".to_owned(),
            start: 4,
            end: 8,
            hash: Hash([0x11u8; 32]),
        };
        let subtree_text = serialize_subtree_note_body(&subtree_body);
        let ca_name = KeyName::new("oid/1.3.6.1.4.1.32473.1".to_owned()).unwrap();
        let ca_sig = NoteSignature::new(ca_name.clone(), 0xdead_beef, vec![0x42u8; 64]);
        let subtree_note = Note::new(&subtree_text, std::slice::from_ref(&ca_sig)).unwrap();

        // Checkpoint note with a plausible CheckpointText body.
        let checkpoint_hash_b64 = BASE64_STANDARD.encode([0x22u8; 32]);
        let checkpoint_text =
            format!("oid/1.3.6.1.4.1.32473.1\n8\n{checkpoint_hash_b64}\n").into_bytes();
        let ck_sig = NoteSignature::new(ca_name, 0xcafe_cafe, vec![0x24u8; 64]);
        let checkpoint_note = Note::new(&checkpoint_text, std::slice::from_ref(&ck_sig)).unwrap();

        let proof = vec![Hash([0x33u8; 32]), Hash([0x44u8; 32])];

        let body = serialize_sign_subtree_request(&subtree_note, &checkpoint_note, &proof).unwrap();
        let req = parse_sign_subtree_request(&body).unwrap();

        assert_eq!(req.subtree_body, subtree_body);
        assert_eq!(req.checkpoint.size(), 8);
        assert_eq!(req.checkpoint.hash().0, [0x22u8; 32]);
        assert_eq!(req.consistency_proof, proof);
    }

    #[test]
    fn test_serialize_sign_subtree_request_rejects_oversize_proof() {
        let subtree_body = SubtreeNoteBody {
            origin: "oid/x".to_owned(),
            start: 0,
            end: 1,
            hash: Hash([0u8; 32]),
        };
        let subtree_text = serialize_subtree_note_body(&subtree_body);
        let subtree_note = fake_signed_note(
            std::str::from_utf8(&subtree_text).unwrap(),
            "oid/x",
            0x1111_1111,
        );
        let checkpoint_note = fake_signed_note(
            &format!("oid/x\n1\n{}\n", BASE64_STANDARD.encode([0u8; 32])),
            "oid/x",
            0x2222_2222,
        );
        let proof = vec![Hash([0u8; 32]); MAX_CONSISTENCY_PROOF_HASHES + 1];
        let err =
            serialize_sign_subtree_request(&subtree_note, &checkpoint_note, &proof).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("exceeds"), "unexpected error: {msg}");
    }

    #[test]
    fn test_parse_sign_subtree_response_single_line() {
        let name = KeyName::new("oid/mirror".to_owned()).unwrap();
        let ns = NoteSignature::new(name, 0xabcd_ef01, vec![0x7fu8; 64]);
        let body = serialize_sign_subtree_response(std::slice::from_ref(&ns));
        let sigs = parse_sign_subtree_response(&body).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].name(), ns.name());
        assert_eq!(sigs[0].id(), ns.id());
        assert_eq!(sigs[0].signature(), ns.signature());
    }

    #[test]
    fn test_parse_sign_subtree_response_multiple() {
        let name = KeyName::new("oid/mirror".to_owned()).unwrap();
        let ns1 = NoteSignature::new(name.clone(), 0x1111_1111, vec![0u8; 64]);
        let ns2 = NoteSignature::new(name, 0x2222_2222, vec![1u8; 64]);
        let body = serialize_sign_subtree_response(&[ns1.clone(), ns2.clone()]);
        let sigs = parse_sign_subtree_response(&body).unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].id(), ns1.id());
        assert_eq!(sigs[1].id(), ns2.id());
    }

    #[test]
    fn test_parse_sign_subtree_response_empty() {
        assert!(parse_sign_subtree_response(b"").is_err());
        assert!(parse_sign_subtree_response(b"\n").is_err());
    }

    #[test]
    fn test_parse_sign_subtree_response_bad_line() {
        // "\xE2\x80\x94" is the UTF-8 encoding of the em-dash (U+2014).
        let body = b"\xE2\x80\x94 oid/mirror notvalidbase64!!\n";
        assert!(parse_sign_subtree_response(body).is_err());
    }
}
