// Ported from "mod" (https://pkg.go.dev/golang.org/x/mod)
// Copyright 2009 The Go Authors
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause
//
// Ported from "sunlight" (https://github.com/FiloSottile/sunlight)
// Copyright 2023 The Sunlight Authors
// Licensed under ISC License found in the LICENSE file or at https://opensource.org/license/isc-license-txt
//
// This ports code from the original Go projects "mod" and "sunlight" and adapts it to Rust idioms.
//
// Modifications and Rust implementation Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! A Checkpoint is a tree head to be formatted according to the [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint) specification.
//!
//! A checkpoint looks like this:
//! ```text
//! example.com/origin
//! 923748
//! nND/nri//U0xuHUrYSy0HtMeal2vzD9V4k/BO79C+QeI=
//! ```
//!
//! It can be followed by extra extension lines.
//!
//! This file contains code ported from the original projects [tlog](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog) and [sunlight](https://github.com/FiloSottile/sunlight).
//!
//! References:
//! - [note.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/tlog/note.go)
//! - [note_test.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/tlog/note_test.go)
//! - [checkpoint.go](https://github.com/FiloSottile/sunlight/blob/36be227ff4599ac11afe3cec37a5febcd61da16a/checkpoint.go)

use crate::{tlog::Hash, HashReader, TlogError, UnixTimestamp};
use base64::{prelude::BASE64_STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use rand::{seq::SliceRandom, Rng};
use sha2::{Digest, Sha256};
use signed_note::{
    Ed25519NoteVerifier, Note, NoteError, NoteVerifier, Signature as NoteSignature, VerifierList,
    Verifiers,
};
use std::{
    fmt,
    io::{BufRead, Read},
};

/// This works like `BufRead::lines`, except it reports a final newline as a
/// length-0 line
struct StrictLines<'a, R: BufRead> {
    buf: &'a mut R,
    return_final_empty_line: bool,
}

impl<'a, R: BufRead> StrictLines<'a, R> {
    const END_NEWLINE: &'static str = "\n";

    fn new(buf: &'a mut R) -> Self {
        Self {
            buf,
            return_final_empty_line: false,
        }
    }
}

impl<R: BufRead> Iterator for StrictLines<'_, R> {
    type Item = Result<String, std::io::Error>;

    fn next(&mut self) -> Option<Result<String, std::io::Error>> {
        let mut s = String::new();
        let bytes_read = match self.buf.read_line(&mut s) {
            Ok(bytes_read) => bytes_read,
            Err(e) => return Some(Err(e)),
        };

        // The buf is at an EOF
        if bytes_read == 0 {
            // If we set the flag, return a final empty line, and unset the flag
            if self.return_final_empty_line {
                self.return_final_empty_line = false;
                Some(Ok(Self::END_NEWLINE.to_string()))
            } else {
                // We're done
                None
            }
        } else {
            // There's two ways the buf ends. Either it's NEWLINE+EOF, or EOF.
            // If it's NEWLINE+EOF, we will report that as a separate line.
            // That new line can be interpreted by caller functions.
            let ended = self.buf.fill_buf().unwrap().is_empty();
            let ends_with_newline = s.ends_with('\n');
            let ends_with_newline_eof = ended && ends_with_newline;

            // Remove the extra newline if there is one
            if ends_with_newline {
                s.pop();
            }

            // If we ended with NEWLINE+EOF, make sure the last output we have
            // is an empty string
            if ends_with_newline_eof {
                self.return_final_empty_line = true;
            }

            Some(Ok(s))
        }
    }
}

/// A Checkpoint is a tree head to be formatted according to c2sp.org/checkpoint.
#[derive(PartialEq, Debug)]
pub struct Checkpoint {
    origin: String,
    size: u64,
    hash: Hash,
    /// Extension is empty or a sequence of non-empty lines,
    /// each terminated by a newline character.
    extension: String,
}

/// Maximum checkpoint size we're willing to parse.
const MAX_CHECKPOINT_SIZE: usize = 1_000_000;

/// An error that can occur when parsing a tree.
#[derive(Debug)]
pub struct MalformedCheckpointError;

impl std::error::Error for MalformedCheckpointError {}

impl fmt::Display for MalformedCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed checkpoint")
    }
}

impl Checkpoint {
    /// Return the checkpoint's origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Return the size of the checkpoint's tree.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Return the root hash of the checkpoint's tree.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Return the checkpoint's extensions.
    pub fn extension(&self) -> &str {
        &self.extension
    }

    /// Return a new checkpoint with the given arguments. The items in
    /// `extensions` MUST NOT be empty or contain a newline.
    ///
    /// # Errors
    ///
    /// Returns a [`MalformedCheckpointError`] if the arguments do not comply with
    /// the [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint) specification.
    pub fn new(
        origin: &str,
        size: u64,
        hash: Hash,
        extensions: &[&str],
    ) -> Result<Self, MalformedCheckpointError> {
        if origin.is_empty() {
            return Err(MalformedCheckpointError);
        }

        if extensions.iter().any(|e| e.is_empty() || e.contains('\n')) {
            return Err(MalformedCheckpointError);
        }

        let extension = if extensions.is_empty() {
            String::new()
        } else {
            extensions.join("\n") + "\n"
        };

        Ok(Self {
            origin: origin.to_string(),
            size,
            hash,
            extension,
        })
    }

    /// Parse a checkpoint from encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the checkpoint is malformed.
    pub fn from_bytes(text: &[u8]) -> Result<Self, MalformedCheckpointError> {
        let mut reader = std::io::Cursor::new(text);

        Self::from_reader(&mut reader, true)
    }

    /// Parse a checkpoint from encoded bytes reader.
    /// If `strict` is set to true, the `reader` should exactly match a checkpoint.
    /// Otherwise, read until we encounter a blank line (only a newline).
    ///
    /// # Errors
    ///
    /// Returns an error if the checkpoint is malformed.
    pub fn from_reader<R: BufRead>(
        reader: &mut R,
        strict: bool,
    ) -> Result<Self, MalformedCheckpointError> {
        let mut reader = reader.take(MAX_CHECKPOINT_SIZE as u64);
        let mut lines: Box<dyn Iterator<Item = Result<String, std::io::Error>>> = if strict {
            Box::new(StrictLines::new(&mut reader))
        } else {
            Box::new((&mut reader).lines())
        };

        let Some(Ok(origin)) = lines.next() else {
            return Err(MalformedCheckpointError);
        };
        let Some(Ok(n_str)) = lines.next() else {
            return Err(MalformedCheckpointError);
        };
        let Some(Ok(h_str)) = lines.next() else {
            return Err(MalformedCheckpointError);
        };

        let mut extensions = vec![];
        let mut next_line = lines.next();
        while let Some(Ok(ref line)) = next_line {
            if line.is_empty() || line == "\n" {
                break;
            };
            extensions.push(line.clone());

            next_line = lines.next();
        }
        // last line is not empty
        if next_line.is_none() && strict {
            return Err(MalformedCheckpointError);
        }
        if let Some(line) = next_line {
            match line {
                Ok(line) => {
                    if line != "\n" && strict {
                        return Err(MalformedCheckpointError);
                    }
                }
                Err(_) => return Err(MalformedCheckpointError),
            }
        }

        let Ok(n) = n_str.parse::<u64>() else {
            return Err(MalformedCheckpointError);
        };
        if n_str != n.to_string() {
            return Err(MalformedCheckpointError);
        }

        let Ok(hash) = Hash::parse_hash(&h_str) else {
            return Err(MalformedCheckpointError);
        };

        Self::new(
            &origin,
            n,
            hash,
            &extensions.iter().map(String::as_str).collect::<Vec<_>>(),
        )
    }

    /// Returns an encoded checkpoint.
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "{}\n{}\n{}\n{}",
            self.origin, self.size, self.hash, self.extension
        )
        .into()
    }
}

/// An object that can produce a [note signature](https://github.com/C2SP/C2SP/blob/main/signed-note.md) for a given checkpoint
pub trait CheckpointSigner {
    /// Returns the server name associated with the key.
    /// The name must be non-empty and not have any Unicode spaces or pluses.
    fn name(&self) -> &str;

    /// Returns the key ID.
    fn key_id(&self) -> u32;

    /// Signs a checkpoint using the given timestamp
    ///
    /// # Errors
    ///
    /// Errors if the signing fails.
    fn sign(
        &self,
        timestamp_unix_millis: u64,
        checkpoint: &Checkpoint,
    ) -> Result<NoteSignature, NoteError>;

    /// Returns the verifier for this signing object.
    // We unfortuantely need the return value to be a trait object because CheckpointSigner needs to
    // be dyn-compatible, because we must be able to pass in a list of CheckpointSigners into
    // log configs
    fn verifier(&self) -> Box<dyn NoteVerifier>;
}

/// Implementation of [`NoteSigner`] that signs with a Ed25519 key.
pub struct Ed25519CheckpointSigner {
    v: Ed25519NoteVerifier,
    k: Ed25519SigningKey,
}

impl Ed25519CheckpointSigner {
    /// Returns a new `Ed25519Signer`.
    ///
    /// # Errors
    ///
    /// Errors if a verifier cannot be created from the provided signing key.
    pub fn new(name: &str, k: Ed25519SigningKey) -> Result<Self, TlogError> {
        let vk = signed_note::new_ed25519_verifier_key(name, &k.verifying_key());
        // Checks if the key name is valid
        let v = Ed25519NoteVerifier::new(&vk)?;
        Ok(Self { v, k })
    }
}

impl CheckpointSigner for Ed25519CheckpointSigner {
    fn name(&self) -> &str {
        self.v.name()
    }

    fn key_id(&self) -> u32 {
        self.v.key_id()
    }

    fn sign(&self, _: UnixTimestamp, checkpoint: &Checkpoint) -> Result<NoteSignature, NoteError> {
        let msg = checkpoint.to_bytes();
        // Ed25519 signing cannot fail
        let sig = self.k.try_sign(&msg).unwrap();

        // Return the note signature. We can unwrap() here because the only cause for error is if
        // the name is invalid, which is checked in the constructor.
        Ok(NoteSignature::new(self.name().to_string(), self.key_id(), sig.to_vec()).unwrap())
    }

    fn verifier(&self) -> Box<dyn NoteVerifier> {
        let vk = signed_note::new_ed25519_verifier_key(self.name(), &self.k.verifying_key());
        // We can unwrap because it only fails on an invalid key name, but this was checked in the constructor.
        Box::new(Ed25519NoteVerifier::new(&vk).unwrap())
    }
}

/// Open and verify a serialized checkpoint encoded as a [note](c2sp.org/signed-note), returning a
/// [Checkpoint] and the latest timestamp of any of its cosignatures (if
/// defined).
///
/// # Errors
///
/// Returns an error if the checkpoint cannot be successfully opened and verified.
pub fn open_checkpoint(
    origin: &str,
    verifiers: &VerifierList,
    current_time: UnixTimestamp,
    b: &[u8],
) -> Result<(Checkpoint, Option<UnixTimestamp>), TlogError> {
    let n = Note::from_bytes(b)?;
    let (verified_sigs, _) = n.verify(verifiers)?;

    // Go through the signatures and make sure we find all the key IDs in our verifiers list
    let mut key_ids_to_observe = verifiers.key_ids();
    // The latest timestamp of the signatures in the note. We use this to check that nothing was signed in the future
    let mut latest_timestamp: Option<UnixTimestamp> = None;
    for sig in &verified_sigs {
        // Fetch the verifier for this signature, if it's here
        let verif = match verifiers.verifier(sig.name(), sig.id()) {
            Ok(v) => {
                // We've now observed this key ID. Remove it from the list
                key_ids_to_observe.remove(&sig.id());
                v
            }
            Err(_) => continue,
        };

        // Extract the timestamp if it's in the sig, and update the latest running timestamp
        let sig_timestamp = verif.extract_timestamp_millis(sig.signature())?;
        if let Some(t) = sig_timestamp {
            latest_timestamp = Some(core::cmp::max(latest_timestamp.unwrap_or(0), t));
        }
    }

    // If we didn't see all the verifiers we wanted to see, error
    if !key_ids_to_observe.is_empty() {
        return Err(TlogError::MissingVerifierSignature);
    }
    let checkpoint = Checkpoint::from_bytes(n.text())?;
    if current_time < latest_timestamp.unwrap_or(0) {
        return Err(TlogError::InvalidTimestamp);
    }
    if checkpoint.origin() != origin {
        return Err(TlogError::OriginMismatch);
    }

    Ok((checkpoint, latest_timestamp))
}

/// A transparency log tree with a timestamp.
#[derive(Default, Debug)]
pub struct TreeWithTimestamp {
    size: u64,
    hash: Hash,
    time: UnixTimestamp,
}

impl TreeWithTimestamp {
    /// Returns a new tree with the given hash.
    pub fn new(size: u64, hash: Hash, time: UnixTimestamp) -> Self {
        Self { size, hash, time }
    }

    /// Calculates the tree hash by reading tiles from the reader.
    ///
    /// # Errors
    ///
    /// Returns an error if unable to compute the tree hash.
    ///
    pub fn from_hash_reader<R: HashReader>(
        size: u64,
        r: &R,
        time: UnixTimestamp,
    ) -> Result<TreeWithTimestamp, TlogError> {
        let hash = crate::tree_hash(size, r)?;
        Ok(Self { size, hash, time })
    }

    /// Returns the size of the tree.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the root hash of the tree.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Returns the timestamp of the tree.
    pub fn time(&self) -> UnixTimestamp {
        self.time
    }

    /// Signs the tree and returns a [checkpoint](c2sp.org/tlog-checkpoint).
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(
        &self,
        origin: &str,
        extensions: &[&str],
        signers: &[&dyn CheckpointSigner],
        rng: &mut impl Rng,
    ) -> Result<Vec<u8>, TlogError> {
        // Shuffle the signer order
        let mut signers = signers.to_vec();
        signers.shuffle(rng);

        // Construct the checkpoint with no extension lines
        let checkpoint = Checkpoint::new(origin, self.size, self.hash, extensions)?;

        // Sign the checkpoint with the given signers
        let sigs = signers
            .iter()
            .map(|s| s.sign(self.time, &checkpoint))
            .collect::<Result<Vec<_>, NoteError>>()?;
        // Generate some fake signatures as grease
        let grease_sigs = gen_grease_signatures(origin, rng);

        // Make a new signed note from the checkpoint and serialize it
        let signed_note = Note::new(&checkpoint.to_bytes(), &[grease_sigs, sigs].concat())?;
        Ok(signed_note.to_bytes())
    }
}

/// Produces unverifiable but otherwise correct signatures.
/// Clients MUST ignore unknown signatures, and including some "grease" ones
/// ensures they do.
fn gen_grease_signatures(origin: &str, rng: &mut impl Rng) -> Vec<NoteSignature> {
    let mut g1 = vec![0u8; 5 + rng.gen_range(0..100)];
    rng.fill(&mut g1[..]);

    let mut g2 = vec![0u8; 5 + rng.gen_range(0..100)];
    let mut hasher = Sha256::new();
    hasher.update(b"grease\n");
    hasher.update([rng.gen()]);
    let h = hasher.finalize();
    g2[..4].copy_from_slice(&h[..4]);
    rng.fill(&mut g2[4..]);

    let mut signatures = vec![
        NoteSignature::from_bytes(
            format!(
                "— {name} {signature}",
                name = "grease.invalid",
                signature = BASE64_STANDARD.encode(&g1)
            )
            .as_bytes(),
        )
        .unwrap(),
        NoteSignature::from_bytes(
            format!(
                "— {name} {signature}",
                name = origin,
                signature = BASE64_STANDARD.encode(&g2)
            )
            .as_bytes(),
        )
        .unwrap(),
    ];

    signatures.shuffle(rng);

    signatures
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::tlog::record_hash;

    #[test]
    fn test_parse_checkpoint() {
        let c = Checkpoint::new(
            "example.com/origin",
            123,
            record_hash(b"hello world"),
            &["abc", "def"],
        )
        .unwrap();
        let c2 = Checkpoint::from_bytes(&c.to_bytes()).unwrap();
        assert_eq!(c, c2);
        assert_eq!(c.to_bytes(), c2.to_bytes());
        assert_eq!(
            c.to_bytes(),
            b"example.com/origin\n123\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\nabc\ndef\n"
        );

        // Check valid checkpoints.
        let good_checkpoints: Vec<&[u8]> = vec![
            // valid with extension
            b"example.com/origin\n123\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\nabc\ndef\n",
            // valid without extension
            b"example.com/origin\n123\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\n",
            // valid short origin
            b"e\n123\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\nabc\ndef\n",
        ];

        for text in &good_checkpoints {
            let c = Checkpoint::from_bytes(text);
            assert!(c.is_ok());
            assert_eq!(c.unwrap().to_bytes(), *text);
        }

        // Check invalid checkpoints.
        let bad_checkpoints: Vec<&[u8]> = vec![
            // empty origin
            b"\n123\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\nabc\ndef\n",
            // invalid tree size
            b"example.com/origin\n0xabcdef\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\nabc\ndef\n",
            // too big tree size
            b"example.com/origin\n18446744073709551616\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\nabc\ndef\n",
            // invalid base64 hash
            b"example.com/origin\n0xabcdef\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0\nabc\ndef\n",
            // too big base64 hash
            b"example.com/origin\n0xabcdef\nQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBCg==\nabc\ndef\n",
            // empty extension line
            b"example.com/origin\n123\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\nabc\n\n",
            // non-newline-terminated extension line
            b"example.com/origin\n123\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\nabc\ndef",
        ];
        for (i, text) in bad_checkpoints.iter().enumerate() {
            assert!(
                Checkpoint::from_bytes(text).is_err(),
                "expected error at index {i}: {text:?}"
            );
        }

        // Now use from_reader
        for text in good_checkpoints {
            let mut reader = std::io::Cursor::new(text);
            let c = Checkpoint::from_reader(&mut reader, true);
            assert!(c.is_ok());
            assert_eq!(c.unwrap().to_bytes(), text);
            let mut reader = std::io::Cursor::new(text);
            let c = Checkpoint::from_reader(&mut reader, false);
            assert!(c.is_ok());
            assert_eq!(c.unwrap().to_bytes(), text);
        }

        // Check buffer which fail strict validation. When strict, the buffer has to be an exact match
        let non_strict_checkpoints: Vec<&[u8]> = vec![
            // empty extension line
            b"example.com/origin\n123\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\nabc\n\n",
            // valid with extension and something after
            b"example.com/origin\n123\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\nabc\ndef\n\nHello world",
            // valid without extension and something after
            b"example.com/origin\n123\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\n\nHello world",
        ];
        for (i, text) in non_strict_checkpoints.iter().enumerate() {
            let mut reader = std::io::Cursor::new(text);
            let c = Checkpoint::from_reader(&mut reader, true);
            assert!(c.is_err(), "expected error at index {i}: {text:?}");
            let mut reader = std::io::Cursor::new(text);
            let c = Checkpoint::from_reader(&mut reader, false);
            assert!(c.is_ok());
            assert!(text.starts_with(&c.unwrap().to_bytes()));
        }
    }

    #[test]
    fn test_sign_verify() {
        let mut rng = OsRng;

        let origin = "example.com/origin";
        let timestamp = 100;
        let tree_size = 4;

        // Make a tree head and sign it
        let tree = TreeWithTimestamp::new(tree_size, record_hash(b"hello world"), timestamp);
        let signer = {
            let sk = Ed25519SigningKey::generate(&mut rng);
            Ed25519CheckpointSigner::new("my-signer", sk).unwrap()
        };
        let checkpoint = tree.sign(origin, &[], &[&signer], &mut rng).unwrap();

        // Now verify the signed checkpoint
        let verifier = signer.verifier();
        open_checkpoint(
            origin,
            &VerifierList::new(vec![verifier]),
            timestamp,
            &checkpoint,
        )
        .unwrap();
    }
}
