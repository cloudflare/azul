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

use crate::tlog::Hash;
use signed_note::{NoteError, Signature as NoteSignature, Verifier as NoteVerifier};
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

    /// Return a new checkpoint with the given arguments.
    ///
    /// # Errors
    ///
    /// Returns a [`MalformedCheckpointError`] if the arguments do not comply with
    /// the [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint) specification.
    pub fn new(
        origin: &str,
        size: u64,
        hash: Hash,
        extension: &str,
    ) -> Result<Self, MalformedCheckpointError> {
        if origin.is_empty() {
            return Err(MalformedCheckpointError);
        }

        let mut rest = extension;
        while !rest.is_empty() {
            if let Some((before, after)) = rest.split_once('\n') {
                if before.is_empty() {
                    return Err(MalformedCheckpointError);
                }
                rest = after;
            } else {
                return Err(MalformedCheckpointError);
            }
        }

        Ok(Self {
            origin: origin.to_string(),
            size,
            hash,
            extension: extension.to_string(),
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
        let extension = if extensions.is_empty() {
            String::new()
        } else {
            extensions.join("\n") + "\n"
        };

        let Ok(n) = n_str.parse::<u64>() else {
            return Err(MalformedCheckpointError);
        };
        if n_str != n.to_string() {
            return Err(MalformedCheckpointError);
        }

        let Ok(hash) = Hash::parse_hash(&h_str) else {
            return Err(MalformedCheckpointError);
        };

        Self::new(&origin, n, hash, &extension)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlog::record_hash;

    #[test]
    fn test_parse_checkpoint() {
        let c = Checkpoint::new(
            "example.com/origin",
            123,
            record_hash(b"hello world"),
            "abc\ndef\n",
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
}
