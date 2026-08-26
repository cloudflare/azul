// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Request-body decoding for `add-entries`.
//!
//! [c2sp.org/tlog-mirror][spec] requires mirrors to accept
//! `Content-Encoding: gzip` request bodies (see [Request Body][reqbody]);
//! clients MAY send gzip without negotiating first. The Cloudflare Workers
//! runtime does not transparently decompress request bodies (unlike
//! responses, which it (de)compresses based on `Accept-Encoding`), so the
//! mirror must gunzip the body itself.
//!
//! This module reads the whole body into memory and inflates it in one
//! pass. A follow-up commit replaces this with incremental streaming so a
//! large upload does not have to buffer the entire body (Workers isolates
//! have a ~128 MB memory ceiling).
//!
//! [spec]: https://c2sp.org/tlog-mirror#add-entries
//! [reqbody]: https://c2sp.org/tlog-mirror#request-body

use std::io::Read as _;

use flate2::read::GzDecoder;
use futures_util::StreamExt as _;
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::frontend_worker::{ApiResult, AppError};

/// Read the whole request body and decode it per `Content-Encoding`.
///
/// `identity` (or an absent header) returns the body unchanged;
/// `gzip`/`x-gzip` is inflated. Any other encoding is unsupported: the
/// mirror can't authenticate a body it can't read, so this returns 415.
///
/// # Errors
///
/// Returns [`AppError::UnsupportedMediaType`] for an unrecognized
/// `Content-Encoding`, [`AppError::BadRequest`] for a malformed/truncated
/// gzip body, or a transport error while reading the body stream.
pub(crate) async fn read_decoded_body(
    headers: &axum::http::HeaderMap,
    body: axum::body::Body,
) -> ApiResult<Vec<u8>> {
    let encoding = headers
        .get(axum::http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    let mut raw = Vec::new();
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Error::from(e.to_string()))?;
        raw.extend_from_slice(&chunk);
    }

    match encoding.as_str() {
        "" | "identity" => Ok(raw),
        "gzip" | "x-gzip" => {
            let mut out = Vec::new();
            GzDecoder::new(raw.as_slice())
                .read_to_end(&mut out)
                .map_err(|e| AppError::BadRequest(format!("gzip decode failed: {e}")))?;
            Ok(out)
        }
        other => Err(AppError::UnsupportedMediaType(format!(
            "Unsupported Content-Encoding: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;

    /// gzip-compress `data` into a single buffer for test input.
    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// Inflate `compressed` the same way [`read_decoded_body`] does.
    fn gunzip(compressed: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        GzDecoder::new(compressed)
            .read_to_end(&mut out)
            .map_err(|e| Error::from(format!("gzip decode failed: {e}")))?;
        Ok(out)
    }

    #[test]
    fn gzip_roundtrips() {
        let mut plain: Vec<u8> = Vec::new();
        for i in 0..20_000u32 {
            plain.extend_from_slice(format!("entry-{i};").as_bytes());
        }
        let decoded = gunzip(&gzip(&plain)).expect("roundtrip");
        assert_eq!(decoded, plain);
    }

    #[test]
    fn empty_payload_roundtrips() {
        let decoded = gunzip(&gzip(b"")).expect("roundtrip");
        assert!(decoded.is_empty());
    }

    #[test]
    fn truncated_gzip_errors() {
        let mut compressed = gzip(b"the quick brown fox jumps over the lazy dog");
        compressed.truncate(compressed.len() - 6);
        assert!(gunzip(&compressed).is_err(), "truncated gzip must error");
    }

    #[test]
    fn corrupt_gzip_errors() {
        let mut compressed = gzip(b"hello world, this is a test payload for corruption");
        let mid = compressed.len() / 2;
        compressed[mid] ^= 0xff;
        assert!(gunzip(&compressed).is_err(), "corrupt gzip must error");
    }
}
