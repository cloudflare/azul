// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Parsers and serializers for the optional `sign-subtree` endpoint.
//!
//! Spec: <https://c2sp.org/tlog-witness#sign-subtree>.
//!
//! # Wire format
//!
//! The request body consists of:
//!
//! ```text
//! subtree <start> <end>\n         ← subtree range (ASCII decimal, no leading zeros)
//! <base64 subtree hash>\n         ← Merkle Tree hash of the subtree
//! [— <name> <b64 cosig blob>\n]   ← 0..8 subtree cosignature lines (DoS protection)
//! [<base64 proof hash>\n]         ← 0..63 consistency-proof hashes
//! \n                              ← empty line separator
//! <reference checkpoint>          ← either a signed-note checkpoint
//!                                   (origin\nsize\nhash\n\n— sig\n...) or
//!                                   a bare three-line checkpoint body
//!                                   (origin\nsize\nhash\n) when no
//!                                   checkpoint signatures are supplied.
//! ```
//!
//! Per the spec, when checkpoint signatures are omitted the request body
//! terminates with the newline that concludes the checkpoint root-hash
//! line — no trailing blank line after the bare checkpoint body.
//!
//! Subtree cosignature lines are distinguished from consistency-proof
//! lines by a leading em-dash character (U+2014, UTF-8 `0xE2 0x80 0x94`),
//! and the spec mandates that all cosignature lines appear before any
//! proof lines. The parser enforces this ordering.
//!
//! The response body (on HTTP 200) is a sequence of one or more
//! `signed-note` signature lines for the subtree, identical in shape to
//! the `add-checkpoint` response.

use base64::prelude::*;
use signed_note::{Note, NoteSignature};
use tlog_tiles::Hash;

use crate::common::{parse_proof_line, MAX_CONSISTENCY_PROOF_LINES};
use crate::TlogWitnessError;

/// Maximum number of subtree-cosignature lines a client may send in a
/// `sign-subtree` request, per
/// [c2sp.org/tlog-witness#sign-subtree](https://c2sp.org/tlog-witness#sign-subtree).
///
/// Subtree cosignature lines are an OPTIONAL DoS-protection mechanism;
/// the spec caps them at 8 to bound the verification work the witness
/// must do before deciding whether to cosign.
pub const MAX_SUBTREE_COSIGNATURE_LINES: usize = 8;

/// Maximum number of checkpoint signatures a client may send inside the
/// reference checkpoint of a `sign-subtree` request, per
/// [c2sp.org/tlog-witness#sign-subtree](https://c2sp.org/tlog-witness#sign-subtree).
///
/// The signatures are OPTIONAL; if omitted, the witness is expected to
/// statefully verify the checkpoint instead. When supplied, they let the
/// witness verify the checkpoint statelessly via its own past
/// cosignature.
pub const MAX_CHECKPOINT_SIGNATURES: usize = 8;

/// A parsed `sign-subtree` request body.
///
/// Subtree cosignature lines and checkpoint signatures (if any) are
/// returned alongside the parsed checkpoint as opaque [`NoteSignature`]
/// values; the witness applies its own trust policy to verify them.
#[derive(Debug)]
pub struct SignSubtreeRequest {
    /// Subtree start index (`subtree <start> <end>` line).
    pub subtree_start: u64,
    /// Subtree end index (exclusive).
    pub subtree_end: u64,
    /// Merkle Tree hash of the subtree.
    pub subtree_hash: Hash,
    /// Subtree cosignature lines, in order. Up to
    /// [`MAX_SUBTREE_COSIGNATURE_LINES`] entries; a DoS-protection
    /// mechanism the client may use to demonstrate this subtree has
    /// been seen by another known cosigner. The witness is expected
    /// to ignore cosignatures from unknown keys.
    pub subtree_cosignatures: Vec<NoteSignature>,
    /// Consistency proof hashes from the subtree to the reference
    /// checkpoint, per draft-ietf-plants-merkle-tree-certs §4.4. Up
    /// to [`MAX_CONSISTENCY_PROOF_LINES`] entries.
    pub consistency_proof: Vec<Hash>,
    /// The reference checkpoint, with any client-supplied checkpoint
    /// signatures attached. When the client omitted signatures, this
    /// is a `Note` whose `signatures()` slice is empty and whose
    /// `text()` is the bare `origin\nsize\nhash\n` body.
    ///
    /// The two shapes are distinguishable post-parse only by
    /// inspecting `signatures().is_empty()`. Witnesses that support
    /// stateless verification will reject a request whose signatures
    /// don't include one of the witness's own past cosignatures;
    /// witnesses that support stateful verification fall back to
    /// their own stored state when `signatures()` is empty.
    pub checkpoint: Note,
}

/// Parse a `sign-subtree` request body.
///
/// # Errors
///
/// Returns [`TlogWitnessError::MalformedRequest`] if the request fails
/// any structural check (missing required line, wrong line ordering,
/// over-bound counts, malformed `subtree` line, malformed base64) or
/// [`TlogWitnessError::Note`] if any cosignature or checkpoint-signature
/// line fails [`NoteSignature::from_bytes`] / the embedded note fails
/// [`Note::from_bytes`].
pub fn parse_sign_subtree_request(body: &[u8]) -> Result<SignSubtreeRequest, TlogWitnessError> {
    // Split on the first blank line. Everything before it is the
    // subtree header (range line + hash line + cosig lines + proof
    // lines); everything after it is the reference checkpoint (either
    // a signed-note checkpoint, which itself contains a `\n\n`
    // separator, or a bare three-line checkpoint body).
    let pos = body.windows(2).position(|w| w == b"\n\n").ok_or_else(|| {
        TlogWitnessError::MalformedRequest(
            "missing blank line between subtree header and checkpoint".into(),
        )
    })?;
    let header = &body[..pos]; // excludes the trailing '\n' of the last header line
    let checkpoint_bytes = &body[pos + 2..];

    let header_text = std::str::from_utf8(header).map_err(|_| {
        TlogWitnessError::MalformedRequest("subtree header is not valid UTF-8".into())
    })?;
    let mut lines = header_text.split('\n');

    // First line: "subtree <start> <end>".
    let range_line = lines
        .next()
        .ok_or_else(|| TlogWitnessError::MalformedRequest("missing 'subtree' range line".into()))?;
    let (subtree_start, subtree_end) = parse_subtree_range_line(range_line)?;

    // Second line: base64 subtree hash.
    let hash_line = lines
        .next()
        .ok_or_else(|| TlogWitnessError::MalformedRequest("missing subtree hash line".into()))?;
    let subtree_hash = parse_proof_line(hash_line)?; // same shape: 32-byte hash, base64.

    // Remaining header lines: cosignature lines first (lines starting
    // with U+2014 em-dash), then proof lines. The spec requires this
    // ordering; once the parser sees a non-cosignature line it switches
    // to proof-line mode and rejects any subsequent cosignature lines.
    let mut subtree_cosignatures = Vec::new();
    let mut consistency_proof = Vec::new();
    let mut in_proof = false;
    for line in lines {
        if line.starts_with('\u{2014}') {
            if in_proof {
                return Err(TlogWitnessError::MalformedRequest(
                    "subtree cosignature line after consistency-proof lines".into(),
                ));
            }
            if subtree_cosignatures.len() >= MAX_SUBTREE_COSIGNATURE_LINES {
                return Err(TlogWitnessError::MalformedRequest(format!(
                    "subtree cosignatures exceed {MAX_SUBTREE_COSIGNATURE_LINES} lines"
                )));
            }
            // `NoteSignature::from_bytes` expects the line WITHOUT a
            // trailing newline (the standard base64 decoder rejects
            // embedded whitespace), matching how `Note::from_bytes`
            // calls it on lines produced by `split('\n')`.
            subtree_cosignatures
                .push(NoteSignature::from_bytes(line.as_bytes()).map_err(TlogWitnessError::Note)?);
        } else {
            in_proof = true;
            if consistency_proof.len() >= MAX_CONSISTENCY_PROOF_LINES {
                return Err(TlogWitnessError::MalformedRequest(format!(
                    "consistency proof exceeds {MAX_CONSISTENCY_PROOF_LINES} lines"
                )));
            }
            consistency_proof.push(parse_proof_line(line)?);
        }
    }

    // Parse the checkpoint section. Two shapes are valid: a full signed
    // note (with a `\n\n` separating body from signatures), or a bare
    // checkpoint body (`origin\nsize\nhash\n` with no signatures and
    // no trailing blank line). Try the signed-note shape first; if it
    // fails, fall back to the bare body.
    let checkpoint =
        parse_reference_checkpoint(checkpoint_bytes).map_err(TlogWitnessError::Note)?;

    Ok(SignSubtreeRequest {
        subtree_start,
        subtree_end,
        subtree_hash,
        subtree_cosignatures,
        consistency_proof,
        checkpoint,
    })
}

/// Serialize a `sign-subtree` request body. Inverse of
/// [`parse_sign_subtree_request`].
///
/// `checkpoint` may be a signed-note checkpoint (with up to
/// [`MAX_CHECKPOINT_SIGNATURES`] signatures attached) or a bare
/// checkpoint body (no signatures). The serializer emits the signature
/// block only when the note has at least one signature, and otherwise
/// terminates the body with the checkpoint root-hash line's newline.
///
/// # Errors
///
/// Returns [`TlogWitnessError::MalformedRequest`] if any of the
/// spec-mandated counts are exceeded:
///
/// - `subtree_cosignatures.len() > [MAX_SUBTREE_COSIGNATURE_LINES]`
/// - `consistency_proof.len() > [MAX_CONSISTENCY_PROOF_LINES]`
/// - the embedded checkpoint has more than [`MAX_CHECKPOINT_SIGNATURES`]
///   signatures.
pub fn serialize_sign_subtree_request(
    subtree_start: u64,
    subtree_end: u64,
    subtree_hash: &Hash,
    subtree_cosignatures: &[NoteSignature],
    consistency_proof: &[Hash],
    checkpoint: &Note,
) -> Result<Vec<u8>, TlogWitnessError> {
    if subtree_cosignatures.len() > MAX_SUBTREE_COSIGNATURE_LINES {
        return Err(TlogWitnessError::MalformedRequest(format!(
            "subtree cosignatures exceed {MAX_SUBTREE_COSIGNATURE_LINES} lines"
        )));
    }
    if consistency_proof.len() > MAX_CONSISTENCY_PROOF_LINES {
        return Err(TlogWitnessError::MalformedRequest(format!(
            "consistency proof exceeds {MAX_CONSISTENCY_PROOF_LINES} lines"
        )));
    }
    if checkpoint.signatures().len() > MAX_CHECKPOINT_SIGNATURES {
        return Err(TlogWitnessError::MalformedRequest(format!(
            "checkpoint signatures exceed {MAX_CHECKPOINT_SIGNATURES}"
        )));
    }

    let mut out = Vec::new();
    out.extend_from_slice(format!("subtree {subtree_start} {subtree_end}\n").as_bytes());
    out.extend_from_slice(BASE64_STANDARD.encode(subtree_hash.0).as_bytes());
    out.push(b'\n');
    for sig in subtree_cosignatures {
        out.extend_from_slice(&sig.to_bytes());
    }
    for h in consistency_proof {
        out.extend_from_slice(BASE64_STANDARD.encode(h.0).as_bytes());
        out.push(b'\n');
    }
    out.push(b'\n');

    if checkpoint.signatures().is_empty() {
        // Bare checkpoint body. `Note::text()` returns the body bytes
        // including the trailing newline; per the spec the body MUST
        // terminate with that newline, with no empty line afterwards.
        out.extend_from_slice(checkpoint.text());
    } else {
        out.extend_from_slice(&checkpoint.to_bytes());
    }
    Ok(out)
}

/// Serialize a `sign-subtree` success response body: one
/// `— name b64sig\n` line per signature.
///
/// Per the spec the response MUST contain at least one signature line;
/// callers should not pass an empty slice for a successful response.
#[must_use]
pub fn serialize_sign_subtree_response(sigs: &[NoteSignature]) -> Vec<u8> {
    let mut out = Vec::new();
    for sig in sigs {
        out.extend_from_slice(&sig.to_bytes());
    }
    out
}

/// Parse a `sign-subtree` success response body into a list of
/// [`NoteSignature`]s.
///
/// Identical wire shape to [`crate::parse_add_checkpoint_response`].
/// Callers should verify each returned signature with the appropriate
/// [`signed_note::NoteVerifier`] before using it.
///
/// # Errors
///
/// Returns [`TlogWitnessError::MalformedResponse`] if the body is empty
/// or not valid UTF-8, and [`TlogWitnessError::Note`] if any line fails
/// [`NoteSignature::from_bytes`] parsing.
pub fn parse_sign_subtree_response(body: &[u8]) -> Result<Vec<NoteSignature>, TlogWitnessError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| TlogWitnessError::MalformedResponse("response is not valid UTF-8".into()))?;
    let trimmed = text.strip_suffix('\n').unwrap_or(text);
    if trimmed.is_empty() {
        return Err(TlogWitnessError::MalformedResponse(
            "response must contain at least one signature line".into(),
        ));
    }
    let mut sigs = Vec::new();
    for line in trimmed.split('\n') {
        sigs.push(NoteSignature::from_bytes(line.as_bytes()).map_err(TlogWitnessError::Note)?);
    }
    Ok(sigs)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_subtree_range_line(line: &str) -> Result<(u64, u64), TlogWitnessError> {
    let rest = line.strip_prefix("subtree ").ok_or_else(|| {
        TlogWitnessError::MalformedRequest(
            "first line must start with \"subtree \" followed by start and end".into(),
        )
    })?;
    let mut parts = rest.split(' ');
    let start_text = parts.next().ok_or_else(|| {
        TlogWitnessError::MalformedRequest("missing subtree start in 'subtree' line".into())
    })?;
    let end_text = parts.next().ok_or_else(|| {
        TlogWitnessError::MalformedRequest("missing subtree end in 'subtree' line".into())
    })?;
    if parts.next().is_some() {
        return Err(TlogWitnessError::MalformedRequest(
            "trailing data after end in 'subtree' line".into(),
        ));
    }
    let start = parse_decimal(start_text, "start")?;
    let end = parse_decimal(end_text, "end")?;
    Ok((start, end))
}

/// Parse an ASCII decimal `u64` per the spec's tree-size encoding rules:
/// no leading zeros except for the value zero itself.
fn parse_decimal(text: &str, what: &str) -> Result<u64, TlogWitnessError> {
    if text.is_empty() {
        return Err(TlogWitnessError::MalformedRequest(format!(
            "empty subtree {what}"
        )));
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(TlogWitnessError::MalformedRequest(format!(
            "subtree {what} has leading zeros"
        )));
    }
    text.parse::<u64>()
        .map_err(|e| TlogWitnessError::MalformedRequest(format!("parsing subtree {what}: {e}")))
}


/// Parse the reference checkpoint section of a `sign-subtree` request.
///
/// Two on-the-wire shapes are valid:
///
/// 1. A full signed-note checkpoint: `origin\nsize\nhash\n\n— sig\n...`,
///    distinguished by the inner `\n\n` separator between body and
///    signature block.
/// 2. A bare checkpoint body with no signatures: `origin\nsize\nhash\n`,
///    used when the client expects the witness to verify the checkpoint
///    statefully against its own stored state.
///
/// We discriminate on the presence of `\n\n` rather than fall back on
/// any error from [`Note::from_bytes`]: otherwise a payload with a
/// signature block whose bytes happen to fail [`Note::from_bytes`]
/// (e.g. a malformed signature line) would silently re-enter the
/// bare-body branch and the handler would treat the client's mangled
/// signed checkpoint as a stateful-verification request.
fn parse_reference_checkpoint(bytes: &[u8]) -> Result<Note, signed_note::NoteError> {
    if bytes.windows(2).any(|w| w == b"\n\n") {
        // Signed-note shape; surface signature-block errors instead
        // of silently reinterpreting them as a bare body.
        Note::from_bytes(bytes)
    } else {
        // Bare body case: no signatures, body ends at `<root>\n`.
        // `Note::new(text, &[])` requires a trailing newline on the
        // text and doesn't permit signatures, which is what we want.
        Note::new(bytes, &[])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use signed_note::KeyName;

    fn fake_checkpoint_with_sigs(origin: &str, size: u64, hash_byte: u8, n_sigs: usize) -> Note {
        let hash_b64 = BASE64_STANDARD.encode([hash_byte; 32]);
        let text = format!("{origin}\n{size}\n{hash_b64}\n");
        let name = KeyName::new(origin.to_owned()).unwrap();
        let sigs: Vec<NoteSignature> = (0..n_sigs)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                NoteSignature::new(name.clone(), 0xdead_0000 + i as u32, vec![0x42u8; 64])
            })
            .collect();
        Note::new(text.as_bytes(), &sigs).unwrap()
    }

    fn fake_signed_checkpoint(origin: &str, size: u64, hash_byte: u8) -> Note {
        fake_checkpoint_with_sigs(origin, size, hash_byte, 1)
    }

    fn fake_bare_checkpoint(origin: &str, size: u64, hash_byte: u8) -> Note {
        fake_checkpoint_with_sigs(origin, size, hash_byte, 0)
    }

    fn fake_subtree_cosig(name: &str, key_id: u32, sig_byte: u8) -> NoteSignature {
        NoteSignature::new(
            KeyName::new(name.to_owned()).unwrap(),
            key_id,
            // ML-DSA-44 cosignatures attached as DoS-protection here
            // would be 8-byte timestamp + 2420-byte signature, but the
            // wire format itself doesn't constrain the blob beyond
            // base64-decodable; 64 bytes is enough for the test.
            vec![sig_byte; 64],
        )
    }

    /// Roundtrip with no cosigs, no proof, signed checkpoint.
    #[test]
    fn request_roundtrip_minimal_signed_checkpoint() {
        let cp = fake_signed_checkpoint("example.com/log", 42, 0xaa);
        let body = serialize_sign_subtree_request(0, 16, &Hash([0x77u8; 32]), &[], &[], &cp)
            .expect("serialize");
        let parsed = parse_sign_subtree_request(&body).expect("parse");
        assert_eq!(parsed.subtree_start, 0);
        assert_eq!(parsed.subtree_end, 16);
        assert_eq!(parsed.subtree_hash.0, [0x77u8; 32]);
        assert!(parsed.subtree_cosignatures.is_empty());
        assert!(parsed.consistency_proof.is_empty());
        assert_eq!(parsed.checkpoint.text(), cp.text());
        assert_eq!(parsed.checkpoint.signatures().len(), 1);
    }

    /// Roundtrip with a bare (signature-less) checkpoint body. This is
    /// the form used when the witness is expected to verify the
    /// checkpoint statefully against its own past cosignature.
    #[test]
    fn request_roundtrip_bare_checkpoint() {
        let cp = fake_bare_checkpoint("example.com/log", 100, 0xbb);
        let body = serialize_sign_subtree_request(0, 64, &Hash([0x33u8; 32]), &[], &[], &cp)
            .expect("serialize");
        // Spec: when signatures are omitted, the body MUST terminate
        // with the newline that concludes the checkpoint root-hash
        // line, with no trailing blank line. Pin the exact suffix
        // (the bare body's full text) so a future serializer change
        // can't accidentally append a blank line and slip past a
        // weaker negative assertion.
        assert!(
            body.ends_with(cp.text()),
            "body must end with the bare checkpoint text: body={body:?}, cp_text={:?}",
            cp.text(),
        );
        let parsed = parse_sign_subtree_request(&body).expect("parse");
        assert_eq!(parsed.checkpoint.text(), cp.text());
        assert!(parsed.checkpoint.signatures().is_empty());
    }

    /// Roundtrip with the full feature set: cosignatures, a
    /// consistency proof, and a signed checkpoint.
    #[test]
    fn request_roundtrip_full() {
        let cp = fake_signed_checkpoint("example.com/log", 200, 0xcc);
        let cosigs = vec![
            fake_subtree_cosig("witness1.example/w", 1, 0x11),
            fake_subtree_cosig("witness2.example/w", 2, 0x22),
        ];
        let proof = vec![Hash([0x01u8; 32]), Hash([0x02u8; 32]), Hash([0x03u8; 32])];
        let body =
            serialize_sign_subtree_request(8, 128, &Hash([0x55u8; 32]), &cosigs, &proof, &cp)
                .expect("serialize");
        let parsed = parse_sign_subtree_request(&body).expect("parse");
        assert_eq!(parsed.subtree_cosignatures.len(), 2);
        assert_eq!(parsed.subtree_cosignatures[0].id(), 1);
        assert_eq!(parsed.subtree_cosignatures[1].id(), 2);
        assert_eq!(parsed.consistency_proof, proof);
        assert_eq!(parsed.checkpoint.text(), cp.text());
    }

    /// Pin the literal shape of the spec's example request body
    /// (without subtree cosignatures and without checkpoint
    /// signatures, which is the simpler of the two examples).
    #[test]
    fn request_matches_spec_example_shape() {
        let cp = fake_bare_checkpoint("example.com/behind-the-sofa", 14, 0x99);
        let proof = vec![Hash([1; 32]), Hash([2; 32]), Hash([3; 32]), Hash([4; 32])];
        let body = serialize_sign_subtree_request(8, 13, &Hash([0x88u8; 32]), &[], &proof, &cp)
            .expect("serialize");
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.starts_with("subtree 8 13\n"),
            "first line must be the subtree range: {text:?}",
        );
        // Subtree hash on the second line (44 chars of base64 + \n).
        assert!(
            text.lines().nth(1).unwrap().len() == 44,
            "second line must be the subtree hash (44 b64 chars): {text:?}",
        );
        assert!(
            text.contains("\n\nexample.com/behind-the-sofa\n"),
            "blank line must precede the checkpoint origin: {text:?}",
        );
    }

    #[test]
    fn request_rejects_oversize_cosignatures() {
        let cp = fake_signed_checkpoint("example.com/log", 1, 0);
        let cosigs = vec![fake_subtree_cosig("a", 0, 0); MAX_SUBTREE_COSIGNATURE_LINES + 1];
        let err =
            serialize_sign_subtree_request(0, 1, &Hash([0u8; 32]), &cosigs, &[], &cp).unwrap_err();
        assert!(matches!(err, TlogWitnessError::MalformedRequest(_)));
    }

    #[test]
    fn request_rejects_oversize_proof() {
        let cp = fake_signed_checkpoint("example.com/log", 1, 0);
        let proof = vec![Hash([0u8; 32]); MAX_CONSISTENCY_PROOF_LINES + 1];
        let err =
            serialize_sign_subtree_request(0, 1, &Hash([0u8; 32]), &[], &proof, &cp).unwrap_err();
        assert!(matches!(err, TlogWitnessError::MalformedRequest(_)));
    }

    #[test]
    fn request_rejects_oversize_checkpoint_signatures() {
        let cp = fake_checkpoint_with_sigs("example.com/log", 1, 0, MAX_CHECKPOINT_SIGNATURES + 1);
        let err =
            serialize_sign_subtree_request(0, 1, &Hash([0u8; 32]), &[], &[], &cp).unwrap_err();
        assert!(matches!(err, TlogWitnessError::MalformedRequest(_)));
    }

    /// The spec requires all subtree cosignature lines to come before
    /// any consistency-proof lines. Pin the parser's rejection of an
    /// interleaved request.
    #[test]
    fn request_rejects_cosignature_after_proof() {
        let cp = fake_signed_checkpoint("example.com/log", 1, 0);
        let mut body = Vec::new();
        body.extend_from_slice(b"subtree 0 1\n");
        body.extend_from_slice(BASE64_STANDARD.encode([0u8; 32]).as_bytes());
        body.push(b'\n');
        // Proof first.
        body.extend_from_slice(BASE64_STANDARD.encode([1u8; 32]).as_bytes());
        body.push(b'\n');
        // Then a cosig — out of order.
        let cosig = fake_subtree_cosig("a", 0, 0);
        body.extend_from_slice(&cosig.to_bytes());
        body.push(b'\n');
        body.extend_from_slice(&cp.to_bytes());
        let err = parse_sign_subtree_request(&body).unwrap_err();
        assert!(matches!(err, TlogWitnessError::MalformedRequest(_)));
    }

    #[test]
    fn request_rejects_missing_blank_line() {
        let body = b"subtree 0 1\nAAAA\n";
        let err = parse_sign_subtree_request(body).unwrap_err();
        assert!(matches!(err, TlogWitnessError::MalformedRequest(_)));
    }

    #[test]
    fn request_rejects_missing_subtree_prefix() {
        let mut body = Vec::new();
        body.extend_from_slice(b"0 1\n");
        body.extend_from_slice(BASE64_STANDARD.encode([0u8; 32]).as_bytes());
        body.push(b'\n');
        body.push(b'\n');
        body.extend_from_slice(b"example.com/log\n1\n");
        body.extend_from_slice(BASE64_STANDARD.encode([0u8; 32]).as_bytes());
        body.push(b'\n');
        let err = parse_sign_subtree_request(&body).unwrap_err();
        assert!(matches!(err, TlogWitnessError::MalformedRequest(_)));
    }

    #[test]
    fn request_rejects_leading_zeros_in_range() {
        let mut body = Vec::new();
        body.extend_from_slice(b"subtree 008 16\n");
        body.extend_from_slice(BASE64_STANDARD.encode([0u8; 32]).as_bytes());
        body.push(b'\n');
        body.push(b'\n');
        body.extend_from_slice(b"example.com/log\n16\n");
        body.extend_from_slice(BASE64_STANDARD.encode([0u8; 32]).as_bytes());
        body.push(b'\n');
        let err = parse_sign_subtree_request(&body).unwrap_err();
        assert!(matches!(err, TlogWitnessError::MalformedRequest(_)));
    }

    #[test]
    fn request_rejects_bad_subtree_hash_length() {
        let mut body = Vec::new();
        body.extend_from_slice(b"subtree 0 1\n");
        // 16 bytes, not 32.
        body.extend_from_slice(BASE64_STANDARD.encode([0u8; 16]).as_bytes());
        body.push(b'\n');
        body.push(b'\n');
        body.extend_from_slice(b"example.com/log\n1\n");
        body.extend_from_slice(BASE64_STANDARD.encode([0u8; 32]).as_bytes());
        body.push(b'\n');
        let err = parse_sign_subtree_request(&body).unwrap_err();
        assert!(matches!(err, TlogWitnessError::MalformedRequest(_)));
    }

    /// A reference-checkpoint section that contains `\n\n` (i.e. claims
    /// to be a signed-note shape) but whose signature block is malformed
    /// MUST surface the [`Note::from_bytes`] error rather than silently
    /// reinterpret the bytes as a bare body. Otherwise the handler
    /// would route a client's malformed signed checkpoint to the
    /// stateful-verification path.
    #[test]
    fn request_rejects_malformed_signed_checkpoint() {
        let mut body = Vec::new();
        body.extend_from_slice(b"subtree 0 1\n");
        body.extend_from_slice(BASE64_STANDARD.encode([0u8; 32]).as_bytes());
        body.push(b'\n');
        body.push(b'\n'); // header / checkpoint separator.
                          // Reference checkpoint claiming to be signed-note shape: it has
                          // a `\n\n` between body and "signature" block, but the signature
                          // line is not a valid `— name b64\n` line.
        body.extend_from_slice(b"example.com/log\n1\n");
        body.extend_from_slice(BASE64_STANDARD.encode([0u8; 32]).as_bytes());
        body.push(b'\n');
        body.push(b'\n');
        body.extend_from_slice(b"GARBAGE-NOT-A-SIGNATURE\n");
        let err = parse_sign_subtree_request(&body).unwrap_err();
        assert!(
            matches!(err, TlogWitnessError::Note(_)),
            "expected Note(_) error, got {err:?}",
        );
    }

    /// Same wire shape as `add-checkpoint`, so the response helpers
    /// behave symmetrically.
    #[test]
    fn response_roundtrip() {
        let name = KeyName::new("witness.example/w".to_owned()).unwrap();
        let sigs = vec![
            NoteSignature::new(name.clone(), 1, vec![0u8; 64]),
            NoteSignature::new(name, 2, vec![1u8; 64]),
        ];
        let body = serialize_sign_subtree_response(&sigs);
        let parsed = parse_sign_subtree_response(&body).expect("parse");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn response_rejects_empty() {
        assert!(matches!(
            parse_sign_subtree_response(b"").unwrap_err(),
            TlogWitnessError::MalformedResponse(_)
        ));
    }
}
