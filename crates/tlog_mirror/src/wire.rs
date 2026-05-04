// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Wire format for the [c2sp.org/tlog-mirror](https://c2sp.org/tlog-mirror)
//! HTTP API. Framing for two message bodies:
//!
//! * The `add-entries` request body: a header
//!   ([`AddEntriesRequestHeader`]) followed by a sequence of entry
//!   packages ([`EntryPackage`]), each covering a `[start, end)` range
//!   from [`package_ranges`] with a subtree consistency proof.
//! * The `text/x.tlog.mirror-info` 409 response body ([`MirrorInfo`]):
//!   pending tree size, next entry, and a base64 ticket.
//!
//! Request bodies are unbounded, so parsing works over `Read`/`Write`
//! streams: read the header, then iterate [`package_ranges`] and parse
//! each [`EntryPackage`].

use std::io::{self, Read, Write};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use tlog_core::{HASH_SIZE, Hash};

use crate::error::ParseError;

/// `Content-Type` of the 409 Conflict response body.
pub const MIRROR_INFO_CONTENT_TYPE: &str = "text/x.tlog.mirror-info";

/// Spec maximum number of hashes in a subtree consistency proof.
pub const MAX_HASHES_PER_PROOF: u8 = 63;

/// Entry-package alignment, matching the tlog-tiles entry-bundle
/// granularity.
pub const PACKAGE_ALIGNMENT: u64 = 256;

/// Header parsed from an `add-entries` request body, followed on the wire
/// by the [`EntryPackage`]s covering `[upload_start, upload_end)` (see
/// [`package_ranges`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddEntriesRequestHeader {
    /// Origin of the log being uploaded to. UTF-8, max 65535 bytes.
    pub log_origin: String,
    /// First log index in the upload, inclusive. Must be `<= upload_end`.
    pub upload_start: u64,
    /// First log index after the upload, exclusive. Per spec, must equal
    /// a known pending checkpoint's tree size.
    pub upload_end: u64,
    /// Opaque ticket bytes, possibly empty (max 65535). The default
    /// scheme is [`TicketSealer`](crate::TicketSealer); operators MAY use
    /// any authenticated payload.
    pub ticket: Vec<u8>,
}

impl AddEntriesRequestHeader {
    /// Read the header, leaving the cursor at the first entry package.
    ///
    /// # Errors
    /// [`ParseError::Io`] on short reads, [`ParseError::LogOriginNotUtf8`]
    /// if the origin is not valid UTF-8, or
    /// [`ParseError::UploadRangeInverted`] if `upload_start > upload_end`.
    pub fn read_from<R: Read>(mut reader: R) -> Result<Self, ParseError> {
        let log_origin_size = reader.read_u16::<BigEndian>()?;
        let mut log_origin_bytes = vec![0u8; usize::from(log_origin_size)];
        reader.read_exact(&mut log_origin_bytes).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                ParseError::LogOriginTruncated {
                    advertised: log_origin_size,
                }
            } else {
                ParseError::Io(e)
            }
        })?;
        let log_origin =
            String::from_utf8(log_origin_bytes).map_err(|_| ParseError::LogOriginNotUtf8)?;

        let upload_start = reader.read_u64::<BigEndian>()?;
        let upload_end = reader.read_u64::<BigEndian>()?;
        if upload_start > upload_end {
            return Err(ParseError::UploadRangeInverted {
                start: upload_start,
                end: upload_end,
            });
        }

        let ticket_size = reader.read_u16::<BigEndian>()?;
        let mut ticket = vec![0u8; usize::from(ticket_size)];
        reader.read_exact(&mut ticket)?;

        Ok(Self {
            log_origin,
            upload_start,
            upload_end,
            ticket,
        })
    }

    /// Write the header.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`] if `log_origin` or `ticket` exceeds
    /// the u16 length-prefix limit (65535 bytes); otherwise the writer's
    /// IO errors.
    pub fn write_to<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let log_origin_size =
            u16::try_from(self.log_origin.len()).map_err(|_| oversize("log_origin"))?;
        let ticket_size = u16::try_from(self.ticket.len()).map_err(|_| oversize("ticket"))?;
        writer.write_u16::<BigEndian>(log_origin_size)?;
        writer.write_all(self.log_origin.as_bytes())?;
        writer.write_u64::<BigEndian>(self.upload_start)?;
        writer.write_u64::<BigEndian>(self.upload_end)?;
        writer.write_u16::<BigEndian>(ticket_size)?;
        writer.write_all(&self.ticket)?;
        Ok(())
    }
}

fn oversize(field: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{field} exceeds u16 length prefix (max {})", u16::MAX),
    )
}

/// Iterator over the `[start, end)` ranges of the entry packages in an
/// `add-entries` body for the given `[upload_start, upload_end)`.
///
/// Packages are aligned at multiples of [`PACKAGE_ALIGNMENT`] (256), so
/// the first and last are typically partial. Empty when
/// `upload_start == upload_end`. Prefer this over recomputing the
/// rounding math by hand.
#[must_use]
pub fn package_ranges(upload_start: u64, upload_end: u64) -> PackageRanges {
    PackageRanges {
        upload_end,
        next: upload_start,
    }
}

/// Iterator returned by [`package_ranges`].
#[derive(Debug, Clone)]
pub struct PackageRanges {
    upload_end: u64,
    next: u64,
}

impl Iterator for PackageRanges {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.upload_end {
            return None;
        }
        // Spec: package i covers [start, end) with
        //   start = max(upload_start, rounded_start + i*256)
        //   end   = min(upload_end,   rounded_start + (i+1)*256)
        // `start` is already >= rounded_start + i*256, so the next end is
        // `start` rounded up to the next 256 boundary. Saturate at
        // upload_end if that overflows (start >= u64::MAX - 254, from
        // hostile wire input); the min below would clamp there anyway.
        let start = self.next;
        let next_boundary = (start / PACKAGE_ALIGNMENT)
            .checked_add(1)
            .and_then(|q| q.checked_mul(PACKAGE_ALIGNMENT))
            .unwrap_or(self.upload_end);
        let end = next_boundary.min(self.upload_end);
        self.next = end;
        Some((start, end))
    }
}

/// One entry package: the log entries for a `[start, end)` range plus the
/// subtree consistency proof to the checkpoint at `upload_end`.
///
/// Only [`PartialEq`] (not [`Eq`]) because [`tlog_core::Hash`] is
/// `PartialEq` only.
#[derive(Debug, Clone, PartialEq)]
pub struct EntryPackage {
    /// Log entries in order, each u16-length-prefixed on the wire (max
    /// 65535 bytes). Count equals `end - start` for the package range.
    pub entries: Vec<Vec<u8>>,
    /// Subtree consistency proof hashes, max [`MAX_HASHES_PER_PROOF`]
    /// (empty is valid).
    pub proof: Vec<Hash>,
}

impl EntryPackage {
    /// Read one entry package. `num_entries` must be `end - start` for the
    /// package's range from [`package_ranges`].
    ///
    /// # Errors
    /// [`ParseError::Io`] on short reads, or [`ParseError::TooManyHashes`]
    /// if `num_hashes` exceeds 63.
    pub fn read_from<R: Read>(mut reader: R, num_entries: u64) -> Result<Self, ParseError> {
        let num_entries = usize::try_from(num_entries)
            .map_err(|_| io::Error::other("num_entries overflows usize"))?;
        let mut entries = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            let entry_size = reader.read_u16::<BigEndian>()?;
            let mut entry = vec![0u8; usize::from(entry_size)];
            reader.read_exact(&mut entry)?;
            entries.push(entry);
        }

        let num_hashes = reader.read_u8()?;
        if num_hashes > MAX_HASHES_PER_PROOF {
            return Err(ParseError::TooManyHashes(num_hashes));
        }
        let mut proof = Vec::with_capacity(usize::from(num_hashes));
        for _ in 0..num_hashes {
            let mut hash = [0u8; HASH_SIZE];
            reader.read_exact(&mut hash)?;
            proof.push(Hash(hash));
        }

        Ok(Self { entries, proof })
    }

    /// Write one entry package.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`] if the proof exceeds 63 hashes or
    /// any entry exceeds 65535 bytes; otherwise the writer's IO errors.
    pub fn write_to<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.proof.len() > usize::from(MAX_HASHES_PER_PROOF) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "proof has {} hashes, max is {MAX_HASHES_PER_PROOF}",
                    self.proof.len()
                ),
            ));
        }
        for entry in &self.entries {
            let len = u16::try_from(entry.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("entry of {} bytes exceeds u16 length prefix", entry.len()),
                )
            })?;
            writer.write_u16::<BigEndian>(len)?;
            writer.write_all(entry)?;
        }
        // Length already validated; cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        writer.write_u8(self.proof.len() as u8)?;
        for hash in &self.proof {
            writer.write_all(&hash.0)?;
        }
        Ok(())
    }
}

/// Body of a `text/x.tlog.mirror-info` 409 Conflict response, returned
/// when the client is out of sync. On the wire, three `\n`-terminated
/// lines: `tree_size` (decimal), `next_entry` (decimal), and a base64
/// `ticket` (may be empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorInfo {
    /// Tree size of a valid pending checkpoint to retry against.
    pub tree_size: u64,
    /// Next entry index the mirror is expecting.
    pub next_entry: u64,
    /// Opaque ticket bytes (base64-decoded), possibly empty.
    pub ticket: Vec<u8>,
}

impl MirrorInfo {
    /// Parse a `text/x.tlog.mirror-info` 409 response body.
    ///
    /// # Errors
    /// [`ParseError::MalformedMirrorInfo`] if the body is not exactly
    /// three `\n`-terminated lines, [`ParseError::InvalidDecimal`] if a
    /// size line is not a `u64`, or [`ParseError::InvalidTicketBase64`]
    /// if the ticket line is not valid base64.
    pub fn parse(body: &[u8]) -> Result<Self, ParseError> {
        let s = std::str::from_utf8(body)
            .map_err(|_| ParseError::MalformedMirrorInfo("not valid UTF-8"))?;
        let mut lines = s.split_inclusive('\n');
        let tree_size_line = lines
            .next()
            .ok_or(ParseError::MalformedMirrorInfo("missing tree_size line"))?;
        let next_entry_line = lines
            .next()
            .ok_or(ParseError::MalformedMirrorInfo("missing next_entry line"))?;
        let ticket_line = lines
            .next()
            .ok_or(ParseError::MalformedMirrorInfo("missing ticket line"))?;
        if lines.next().is_some() {
            return Err(ParseError::MalformedMirrorInfo("unexpected trailing data"));
        }
        let tree_size_str =
            tree_size_line
                .strip_suffix('\n')
                .ok_or(ParseError::MalformedMirrorInfo(
                    "tree_size line not newline-terminated",
                ))?;
        let next_entry_str =
            next_entry_line
                .strip_suffix('\n')
                .ok_or(ParseError::MalformedMirrorInfo(
                    "next_entry line not newline-terminated",
                ))?;
        let ticket_str = ticket_line
            .strip_suffix('\n')
            .ok_or(ParseError::MalformedMirrorInfo(
                "ticket line not newline-terminated",
            ))?;

        let tree_size = parse_decimal_u64("tree_size", tree_size_str)?;
        let next_entry = parse_decimal_u64("next_entry", next_entry_str)?;
        let ticket = BASE64
            .decode(ticket_str)
            .map_err(|_| ParseError::InvalidTicketBase64)?;
        Ok(Self {
            tree_size,
            next_entry,
            ticket,
        })
    }

    /// Serialize this `MirrorInfo` as a `text/x.tlog.mirror-info` body.
    #[must_use]
    pub fn to_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            // Two 20-char decimals + 3 newlines + base64 (3:4 ratio,
            // rounded up).
            20 + 1 + 20 + 1 + (self.ticket.len().div_ceil(3) * 4) + 1,
        );
        // Writing into a Vec is infallible.
        let _ = writeln!(out, "{}", self.tree_size);
        let _ = writeln!(out, "{}", self.next_entry);
        out.extend_from_slice(BASE64.encode(&self.ticket).as_bytes());
        out.push(b'\n');
        out
    }
}

/// Strict decimal-`u64` parser for the `text/x.tlog.mirror-info` body.
/// Rejects empty input, leading zeros (except the literal `"0"`), signs,
/// whitespace, and any non-ASCII-decimal byte, enforcing one canonical
/// encoding per integer.
fn parse_decimal_u64(field: &'static str, value: &str) -> Result<u64, ParseError> {
    if value.is_empty() {
        return Err(ParseError::InvalidDecimal {
            field,
            value: value.to_owned(),
        });
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err(ParseError::InvalidDecimal {
            field,
            value: value.to_owned(),
        });
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::InvalidDecimal {
            field,
            value: value.to_owned(),
        });
    }
    value
        .parse::<u64>()
        .map_err(|_| ParseError::InvalidDecimal {
            field,
            value: value.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_header() -> AddEntriesRequestHeader {
        AddEntriesRequestHeader {
            log_origin: "log.example/m1".to_owned(),
            upload_start: 12_345,
            upload_end: 12_400,
            ticket: vec![0xAB, 0xCD, 0xEF],
        }
    }

    #[test]
    fn header_roundtrip() {
        let header = sample_header();
        let mut buf = Vec::new();
        header.write_to(&mut buf).unwrap();
        let parsed = AddEntriesRequestHeader::read_from(Cursor::new(&buf)).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn header_roundtrip_empty_origin_and_ticket() {
        let header = AddEntriesRequestHeader {
            log_origin: String::new(),
            upload_start: 0,
            upload_end: 0,
            ticket: Vec::new(),
        };
        let mut buf = Vec::new();
        header.write_to(&mut buf).unwrap();
        // Exact-bytes pin: u16(0) || u64(0) || u64(0) || u16(0) = 20 zero bytes.
        assert_eq!(buf, vec![0u8; 20]);
        let parsed = AddEntriesRequestHeader::read_from(Cursor::new(&buf)).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn header_rejects_upload_range_inverted() {
        let mut buf = Vec::new();
        // log_origin_size = 0
        buf.extend_from_slice(&0u16.to_be_bytes());
        // upload_start = 100, upload_end = 50 (inverted)
        buf.extend_from_slice(&100u64.to_be_bytes());
        buf.extend_from_slice(&50u64.to_be_bytes());
        // ticket_size = 0
        buf.extend_from_slice(&0u16.to_be_bytes());
        let err = AddEntriesRequestHeader::read_from(Cursor::new(&buf)).unwrap_err();
        assert!(matches!(
            err,
            ParseError::UploadRangeInverted {
                start: 100,
                end: 50
            }
        ));
    }

    #[test]
    fn header_rejects_non_utf8_origin() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u16.to_be_bytes()); // log_origin_size = 2
        buf.extend_from_slice(&[0xFF, 0xFE]); // not valid UTF-8
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        let err = AddEntriesRequestHeader::read_from(Cursor::new(&buf)).unwrap_err();
        assert!(matches!(err, ParseError::LogOriginNotUtf8));
    }

    #[test]
    fn header_rejects_truncated_origin() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u16.to_be_bytes()); // claims 5 origin bytes
        buf.extend_from_slice(b"abc"); // but only 3 follow
        let err = AddEntriesRequestHeader::read_from(Cursor::new(&buf)).unwrap_err();
        assert!(matches!(
            err,
            ParseError::LogOriginTruncated { advertised: 5 }
        ));
    }

    #[test]
    fn package_ranges_empty_when_start_equals_end() {
        let ranges: Vec<_> = package_ranges(1024, 1024).collect();
        assert!(ranges.is_empty());
    }

    #[test]
    fn package_ranges_aligned() {
        // Both endpoints aligned: exactly two full packages.
        let ranges: Vec<_> = package_ranges(0, 512).collect();
        assert_eq!(ranges, vec![(0, 256), (256, 512)]);
    }

    #[test]
    fn package_ranges_partial_first_only() {
        // Start mid-package, end aligned.
        let ranges: Vec<_> = package_ranges(100, 256).collect();
        assert_eq!(ranges, vec![(100, 256)]);
    }

    #[test]
    fn package_ranges_partial_last_only() {
        // Start aligned, end mid-package.
        let ranges: Vec<_> = package_ranges(256, 300).collect();
        assert_eq!(ranges, vec![(256, 300)]);
    }

    #[test]
    fn package_ranges_partial_both() {
        // Start and end both mid-package, spanning multiple packages.
        let ranges: Vec<_> = package_ranges(100, 600).collect();
        assert_eq!(ranges, vec![(100, 256), (256, 512), (512, 600)]);
    }

    #[test]
    fn package_ranges_all_in_one_partial() {
        // Both endpoints inside the same package boundary.
        let ranges: Vec<_> = package_ranges(100, 200).collect();
        assert_eq!(ranges, vec![(100, 200)]);
    }

    #[test]
    fn package_ranges_no_overflow_at_u64_max() {
        // Regression: `(start / 256 + 1) * 256` overflows near u64::MAX,
        // reachable since `read_from` accepts any 8-byte upload_end.
        let ranges: Vec<_> = package_ranges(u64::MAX - 1, u64::MAX).collect();
        assert_eq!(ranges, vec![(u64::MAX - 1, u64::MAX)]);

        let edge = u64::MAX - (u64::MAX % PACKAGE_ALIGNMENT);
        let ranges: Vec<_> = package_ranges(edge, u64::MAX).collect();
        assert_eq!(ranges, vec![(edge, u64::MAX)]);
    }

    #[test]
    fn entry_package_roundtrip() {
        let pkg = EntryPackage {
            entries: vec![b"hello".to_vec(), b"world".to_vec(), Vec::new()],
            proof: vec![Hash([0x11; HASH_SIZE]), Hash([0x22; HASH_SIZE])],
        };
        let mut buf = Vec::new();
        pkg.write_to(&mut buf).unwrap();
        let parsed = EntryPackage::read_from(Cursor::new(&buf), 3).unwrap();
        assert_eq!(parsed, pkg);
    }

    #[test]
    fn entry_package_rejects_too_many_hashes_on_read() {
        let mut buf = Vec::new();
        // Zero entries, num_hashes = 64 (exceeds 63).
        buf.push(64u8);
        buf.extend_from_slice(&[0u8; 64 * HASH_SIZE]);
        let err = EntryPackage::read_from(Cursor::new(&buf), 0).unwrap_err();
        assert!(matches!(err, ParseError::TooManyHashes(64)));
    }

    #[test]
    fn entry_package_rejects_too_many_hashes_on_write() {
        let pkg = EntryPackage {
            entries: vec![],
            proof: (0..64).map(|_| Hash([0u8; HASH_SIZE])).collect(),
        };
        let mut buf = Vec::new();
        let err = pkg.write_to(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn entry_package_rejects_oversize_entry_on_write() {
        let pkg = EntryPackage {
            entries: vec![vec![0u8; usize::from(u16::MAX) + 1]],
            proof: vec![],
        };
        let mut buf = Vec::new();
        let err = pkg.write_to(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    fn sample_mirror_info() -> MirrorInfo {
        MirrorInfo {
            tree_size: 12_400,
            next_entry: 12_345,
            ticket: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        }
    }

    #[test]
    fn mirror_info_roundtrip() {
        let info = sample_mirror_info();
        let body = info.to_body();
        let parsed = MirrorInfo::parse(&body).unwrap();
        assert_eq!(parsed, info);
    }

    #[test]
    fn mirror_info_pin_exact_body() {
        // Pin the exact wire bytes for a known input. Base64("\x01\x02\x03\x04\x05") = "AQIDBAU=".
        let info = sample_mirror_info();
        assert_eq!(info.to_body(), b"12400\n12345\nAQIDBAU=\n");
    }

    #[test]
    fn mirror_info_roundtrip_empty_ticket() {
        let info = MirrorInfo {
            tree_size: 0,
            next_entry: 0,
            ticket: Vec::new(),
        };
        assert_eq!(info.to_body(), b"0\n0\n\n");
        assert_eq!(MirrorInfo::parse(b"0\n0\n\n").unwrap(), info);
    }

    #[test]
    fn mirror_info_rejects_missing_newline_terminators() {
        // Missing trailing newline on the ticket line.
        let body = b"100\n50\nAQID";
        let err = MirrorInfo::parse(body).unwrap_err();
        assert!(matches!(err, ParseError::MalformedMirrorInfo(_)));
    }

    #[test]
    fn mirror_info_rejects_too_many_lines() {
        let body = b"100\n50\nAQID\nextra\n";
        let err = MirrorInfo::parse(body).unwrap_err();
        assert!(matches!(err, ParseError::MalformedMirrorInfo(_)));
    }

    #[test]
    fn mirror_info_rejects_leading_zero() {
        let body = b"0100\n50\nAQID\n";
        let err = MirrorInfo::parse(body).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidDecimal {
                field: "tree_size",
                ..
            }
        ));
    }

    #[test]
    fn mirror_info_rejects_leading_plus() {
        let body = b"+100\n50\nAQID\n";
        let err = MirrorInfo::parse(body).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidDecimal {
                field: "tree_size",
                ..
            }
        ));
    }

    #[test]
    fn mirror_info_rejects_negative() {
        let body = b"-100\n50\nAQID\n";
        let err = MirrorInfo::parse(body).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidDecimal {
                field: "tree_size",
                ..
            }
        ));
    }

    #[test]
    fn mirror_info_rejects_bad_base64_ticket() {
        let body = b"100\n50\n!!!notbase64!!!\n";
        let err = MirrorInfo::parse(body).unwrap_err();
        assert!(matches!(err, ParseError::InvalidTicketBase64));
    }

    #[test]
    fn mirror_info_accepts_zero_literal() {
        let body = b"0\n0\nAQID\n";
        let info = MirrorInfo::parse(body).unwrap();
        assert_eq!(info.tree_size, 0);
        assert_eq!(info.next_entry, 0);
    }
}
