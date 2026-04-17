// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Parsers and serializers for the `add-checkpoint` endpoint.
//!
//! Spec: <https://c2sp.org/tlog-witness#add-checkpoint>.
//!
//! # Wire format
//!
//! The request body consists of:
//!
//! ```text
//! old <N>\n            ← "old" followed by the tree size of the previous checkpoint
//! <proof-line-1>\n     ← zero or more consistency-proof hashes, base64-encoded, one per line
//! <proof-line-2>\n
//! ...
//! \n                   ← empty line
//! <checkpoint note>    ← a c2sp.org/signed-note checkpoint, terminated by its signature block
//! ```
//!
//! The response body (on HTTP 200) is a sequence of c2sp.org/signed-note
//! signature lines, each beginning with `—` (U+2014) and ending with `\n`.
//!
//! The single blank line cleanly splits the "control block" (old size +
//! proof) from the embedded signed note, and the note itself is parsed by the
//! standard [`signed_note::Note::from_bytes`] routine consuming the rest of
//! the body.

use base64::prelude::*;
use signed_note::{Note, NoteSignature};
use tlog_tiles::{Hash, HASH_SIZE};

/// Maximum number of consistency-proof lines a client may send, per
/// [c2sp.org/tlog-witness#add-checkpoint](https://c2sp.org/tlog-witness#add-checkpoint).
///
/// A Merkle consistency proof over a log with at most `2^64` entries has at
/// most 63 hashes.
pub const MAX_CONSISTENCY_PROOF_LINES: usize = 63;

/// Content type used for `409 Conflict` response bodies carrying a decimal
/// tree size, per the spec.
pub const CONTENT_TYPE_TLOG_SIZE: &str = "text/x.tlog.size";

/// Errors produced by this crate's parsers and serializers.
#[derive(Debug, thiserror::Error)]
pub enum TlogWitnessError {
    /// The body failed high-level structural checks (missing blank line,
    /// malformed `old` line, too many proof lines, etc.).
    #[error("malformed request: {0}")]
    MalformedRequest(String),

    /// The response body was malformed.
    #[error("malformed response: {0}")]
    MalformedResponse(String),

    /// An embedded signed-note (checkpoint or signature line) failed to parse.
    #[error("signed note: {0:?}")]
    Note(signed_note::NoteError),
}

/// A parsed `add-checkpoint` request body.
///
/// Signatures on `checkpoint` are NOT verified at parse time; callers apply
/// their own trust policy (see `signed_note::VerifierList`).
#[derive(Debug)]
pub struct AddCheckpointRequest {
    /// The tree size of the client's previously-recorded checkpoint ("old"
    /// line). The witness compares this to its own stored latest size for
    /// the log's origin.
    pub old_size: u64,
    /// Consistency proof hashes, in order.
    ///
    /// Per c2sp.org/tlog-witness the proof MUST be empty when `old_size`
    /// is zero (no previously-recorded checkpoint exists to prove
    /// against) and also when `old_size` equals the checkpoint's tree
    /// size (identical trees do not need a proof). In every other case,
    /// it MUST contain the Merkle consistency proof from `old_size` to
    /// the checkpoint's tree size per RFC 6962 §2.1.2. The parser does
    /// not enforce these invariants — that is the witness's job — but
    /// it caps the number of lines at
    /// [`MAX_CONSISTENCY_PROOF_LINES`] (63) per the spec.
    pub consistency_proof: Vec<Hash>,
    /// The client's proposed new checkpoint, as a parsed signed note.
    pub checkpoint: Note,
}

/// Parse an `add-checkpoint` request body.
///
/// # Errors
///
/// Returns [`TlogWitnessError::MalformedRequest`] if the control block is not
/// well formed, and [`TlogWitnessError::Note`] if the embedded checkpoint
/// note fails to parse.
pub fn parse_add_checkpoint_request(body: &[u8]) -> Result<AddCheckpointRequest, TlogWitnessError> {
    // Split the body at the first blank line (`\n\n`). The control block
    // (old + proof lines) precedes it; the checkpoint note follows.
    let pos = body.windows(2).position(|w| w == b"\n\n").ok_or_else(|| {
        TlogWitnessError::MalformedRequest(
            "missing blank line between control block and checkpoint".into(),
        )
    })?;
    let control = &body[..pos]; // excludes the trailing '\n' of the last line
    let note_bytes = &body[pos + 2..];

    let control_text = std::str::from_utf8(control).map_err(|_| {
        TlogWitnessError::MalformedRequest("control block is not valid UTF-8".into())
    })?;
    let mut lines = control_text.split('\n');

    // First line: "old <N>".
    let old_line = lines
        .next()
        .ok_or_else(|| TlogWitnessError::MalformedRequest("missing 'old' line".into()))?;
    let old_size = parse_old_line(old_line)?;

    // Remaining lines: base64-encoded consistency-proof hashes.
    let mut consistency_proof = Vec::new();
    for line in lines {
        if consistency_proof.len() >= MAX_CONSISTENCY_PROOF_LINES {
            return Err(TlogWitnessError::MalformedRequest(format!(
                "consistency proof exceeds {MAX_CONSISTENCY_PROOF_LINES} lines"
            )));
        }
        consistency_proof.push(parse_proof_line(line)?);
    }

    let checkpoint = Note::from_bytes(note_bytes).map_err(TlogWitnessError::Note)?;

    Ok(AddCheckpointRequest {
        old_size,
        consistency_proof,
        checkpoint,
    })
}

/// Serialize an `add-checkpoint` request body. Inverse of
/// [`parse_add_checkpoint_request`].
///
/// # Errors
///
/// Returns [`TlogWitnessError::MalformedRequest`] if the consistency proof
/// exceeds [`MAX_CONSISTENCY_PROOF_LINES`].
pub fn serialize_add_checkpoint_request(
    old_size: u64,
    consistency_proof: &[Hash],
    checkpoint: &Note,
) -> Result<Vec<u8>, TlogWitnessError> {
    if consistency_proof.len() > MAX_CONSISTENCY_PROOF_LINES {
        return Err(TlogWitnessError::MalformedRequest(format!(
            "consistency proof exceeds {MAX_CONSISTENCY_PROOF_LINES} lines"
        )));
    }
    let mut out = Vec::new();
    out.extend_from_slice(format!("old {old_size}\n").as_bytes());
    for h in consistency_proof {
        out.extend_from_slice(BASE64_STANDARD.encode(h.0).as_bytes());
        out.push(b'\n');
    }
    out.push(b'\n');
    out.extend_from_slice(&checkpoint.to_bytes());
    Ok(out)
}

/// Serialize an `add-checkpoint` success response body: one `— name b64sig\n`
/// line per signature.
///
/// Per the spec the response MUST contain at least one signature; callers
/// should not pass an empty slice for a successful response.
#[must_use]
pub fn serialize_add_checkpoint_response(sigs: &[NoteSignature]) -> Vec<u8> {
    let mut out = Vec::new();
    for sig in sigs {
        out.extend_from_slice(&sig.to_bytes());
    }
    out
}

/// Parse an `add-checkpoint` success response body into a list of
/// [`NoteSignature`]s.
///
/// Callers should verify each returned signature with the appropriate
/// [`signed_note::NoteVerifier`] before using it.
///
/// # Errors
///
/// Returns [`TlogWitnessError::MalformedResponse`] if the body is empty or
/// not valid UTF-8, and [`TlogWitnessError::Note`] if any line fails
/// [`NoteSignature::from_bytes`] parsing.
pub fn parse_add_checkpoint_response(body: &[u8]) -> Result<Vec<NoteSignature>, TlogWitnessError> {
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

fn parse_old_line(line: &str) -> Result<u64, TlogWitnessError> {
    // Per spec: literal "old", single 0x20, then decimal tree size with no
    // leading zeros except for the value zero itself.
    let rest = line.strip_prefix("old ").ok_or_else(|| {
        TlogWitnessError::MalformedRequest(
            "first line must start with \"old \" followed by a tree size".into(),
        )
    })?;
    // Reject leading zeros (with the sole exception of "0" itself).
    if rest.is_empty() {
        return Err(TlogWitnessError::MalformedRequest(
            "empty tree size in 'old' line".into(),
        ));
    }
    if rest.len() > 1 && rest.starts_with('0') {
        return Err(TlogWitnessError::MalformedRequest(
            "tree size in 'old' line has leading zeros".into(),
        ));
    }
    rest.parse::<u64>()
        .map_err(|e| TlogWitnessError::MalformedRequest(format!("parsing 'old' tree size: {e}")))
}

fn parse_proof_line(line: &str) -> Result<Hash, TlogWitnessError> {
    let decoded = BASE64_STANDARD
        .decode(line)
        .map_err(|e| TlogWitnessError::MalformedRequest(format!("base64 proof line: {e}")))?;
    let arr: [u8; HASH_SIZE] = decoded.try_into().map_err(|v: Vec<u8>| {
        TlogWitnessError::MalformedRequest(format!(
            "consistency proof hash is {} bytes, want {HASH_SIZE}",
            v.len()
        ))
    })?;
    Ok(Hash(arr))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use signed_note::KeyName;

    fn fake_checkpoint(origin: &str, size: u64, hash_byte: u8) -> Note {
        let hash_b64 = BASE64_STANDARD.encode([hash_byte; 32]);
        let text = format!("{origin}\n{size}\n{hash_b64}\n");
        let name = KeyName::new(origin.to_owned()).unwrap();
        let sig = NoteSignature::new(name, 0xdead_beef, vec![0x42u8; 64]);
        Note::new(text.as_bytes(), std::slice::from_ref(&sig)).unwrap()
    }

    #[test]
    fn request_roundtrip_no_proof() {
        let cp = fake_checkpoint("example.com/log", 0, 0xaa);
        let body = serialize_add_checkpoint_request(0, &[], &cp).unwrap();
        let parsed = parse_add_checkpoint_request(&body).unwrap();
        assert_eq!(parsed.old_size, 0);
        assert!(parsed.consistency_proof.is_empty());
        assert_eq!(parsed.checkpoint.text(), cp.text());
    }

    #[test]
    fn request_roundtrip_with_proof() {
        let cp = fake_checkpoint("example.com/log", 42, 0xbb);
        let proof = vec![Hash([0x11u8; 32]), Hash([0x22u8; 32]), Hash([0x33u8; 32])];
        let body = serialize_add_checkpoint_request(10, &proof, &cp).unwrap();
        let parsed = parse_add_checkpoint_request(&body).unwrap();
        assert_eq!(parsed.old_size, 10);
        assert_eq!(parsed.consistency_proof, proof);
        assert_eq!(parsed.checkpoint.text(), cp.text());
    }

    #[test]
    fn request_matches_spec_example_shape() {
        // The spec's example body has the literal shape "old N\n<proof>...\n\n<note>";
        // we verify our serializer produces exactly that.
        let cp = fake_checkpoint("example.com/behind-the-sofa", 20_852_163, 0x99);
        let proof = vec![Hash([1; 32]), Hash([2; 32]), Hash([3; 32]), Hash([4; 32])];
        let body = serialize_add_checkpoint_request(20_852_014, &proof, &cp).unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.starts_with("old 20852014\n"));
        assert!(text.contains("\n\nexample.com/behind-the-sofa\n"));
    }

    #[test]
    fn request_rejects_oversize_proof() {
        let cp = fake_checkpoint("example.com/log", 0, 0);
        let proof = vec![Hash([0u8; 32]); MAX_CONSISTENCY_PROOF_LINES + 1];
        let err = serialize_add_checkpoint_request(0, &proof, &cp).unwrap_err();
        assert!(matches!(err, TlogWitnessError::MalformedRequest(_)));

        // Now hand-craft a too-long body and confirm the parser also rejects it.
        let mut body = Vec::new();
        body.extend_from_slice(b"old 0\n");
        for _ in 0..=MAX_CONSISTENCY_PROOF_LINES {
            body.extend_from_slice(BASE64_STANDARD.encode([0u8; 32]).as_bytes());
            body.push(b'\n');
        }
        body.push(b'\n');
        body.extend_from_slice(&cp.to_bytes());
        assert!(matches!(
            parse_add_checkpoint_request(&body).unwrap_err(),
            TlogWitnessError::MalformedRequest(_)
        ));
    }

    #[test]
    fn request_rejects_missing_blank_line() {
        // A body with no blank line between control and note.
        let body = b"old 5\n\xe2\x80\x94 name sig\n";
        assert!(matches!(
            parse_add_checkpoint_request(body).unwrap_err(),
            TlogWitnessError::MalformedRequest(_)
        ));
    }

    #[test]
    fn request_rejects_missing_old_prefix() {
        let cp = fake_checkpoint("example.com/log", 0, 0);
        let mut body = Vec::new();
        body.extend_from_slice(b"5\n\n"); // no "old " prefix
        body.extend_from_slice(&cp.to_bytes());
        assert!(matches!(
            parse_add_checkpoint_request(&body).unwrap_err(),
            TlogWitnessError::MalformedRequest(_)
        ));
    }

    #[test]
    fn request_rejects_leading_zeros_in_old_size() {
        let cp = fake_checkpoint("example.com/log", 0, 0);
        let mut body = Vec::new();
        body.extend_from_slice(b"old 007\n\n");
        body.extend_from_slice(&cp.to_bytes());
        assert!(matches!(
            parse_add_checkpoint_request(&body).unwrap_err(),
            TlogWitnessError::MalformedRequest(_)
        ));
    }

    #[test]
    fn request_rejects_bad_proof_hash_length() {
        let cp = fake_checkpoint("example.com/log", 0, 0);
        let mut body = Vec::new();
        body.extend_from_slice(b"old 0\n");
        body.extend_from_slice(BASE64_STANDARD.encode([0u8; 16]).as_bytes()); // 16 bytes, not 32
        body.push(b'\n');
        body.push(b'\n');
        body.extend_from_slice(&cp.to_bytes());
        assert!(matches!(
            parse_add_checkpoint_request(&body).unwrap_err(),
            TlogWitnessError::MalformedRequest(_)
        ));
    }

    #[test]
    fn response_roundtrip_single() {
        let name = KeyName::new("witness.example/w1".to_owned()).unwrap();
        let ns = NoteSignature::new(name, 0xabcd_ef01, vec![0x7fu8; 64]);
        let body = serialize_add_checkpoint_response(std::slice::from_ref(&ns));
        let sigs = parse_add_checkpoint_response(&body).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].name(), ns.name());
        assert_eq!(sigs[0].id(), ns.id());
        assert_eq!(sigs[0].signature(), ns.signature());
    }

    /// Pin the wire shape of a witness response line: a leading em-dash
    /// (U+2014) + space, and a trailing newline (U+000A) on every line.
    /// These are both MUSTs in c2sp.org/tlog-witness.
    #[test]
    fn response_matches_spec_line_shape() {
        let name = KeyName::new("witness.example/w1".to_owned()).unwrap();
        let ns = NoteSignature::new(name, 0, vec![0u8; 64]);
        let body = serialize_add_checkpoint_response(std::slice::from_ref(&ns));
        assert!(
            body.starts_with("\u{2014} ".as_bytes()),
            "response line must start with '\u{2014} ': {:?}",
            String::from_utf8_lossy(&body),
        );
        assert_eq!(
            body.last().copied(),
            Some(b'\n'),
            "response line must end with a newline: {:?}",
            String::from_utf8_lossy(&body),
        );
    }

    #[test]
    fn response_roundtrip_multiple() {
        let name = KeyName::new("witness.example/w1".to_owned()).unwrap();
        let n2 = KeyName::new("witness.example/w2".to_owned()).unwrap();
        let sigs = vec![
            NoteSignature::new(name, 1, vec![0u8; 64]),
            NoteSignature::new(n2, 2, vec![1u8; 64]),
        ];
        let body = serialize_add_checkpoint_response(&sigs);
        let parsed = parse_add_checkpoint_response(&body).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id(), 1);
        assert_eq!(parsed[1].id(), 2);
    }

    #[test]
    fn response_rejects_empty() {
        assert!(matches!(
            parse_add_checkpoint_response(b"").unwrap_err(),
            TlogWitnessError::MalformedResponse(_)
        ));
        assert!(matches!(
            parse_add_checkpoint_response(b"\n").unwrap_err(),
            TlogWitnessError::MalformedResponse(_)
        ));
    }

    #[test]
    fn response_rejects_bad_line() {
        // Malformed signature line (em-dash in UTF-8 is E2 80 94).
        let body = b"\xe2\x80\x94 oid/mirror not-valid-base64!!\n";
        assert!(matches!(
            parse_add_checkpoint_response(body).unwrap_err(),
            TlogWitnessError::Note(_)
        ));
    }
}
