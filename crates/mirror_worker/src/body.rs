// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Request-body decoding for `add-entries`.
//!
//! [c2sp.org/tlog-mirror][spec] requires mirrors to accept
//! `Content-Encoding: gzip` request bodies ([C2SP/C2SP#251]); clients MAY
//! send gzip without negotiating first. The Cloudflare Workers runtime
//! does not transparently decompress request bodies (unlike responses,
//! which it (de)compresses based on `Accept-Encoding`), so the mirror must
//! gunzip the body itself.
//!
//! `add-entries` bodies are unbounded and Workers isolates have a ~128 MB
//! memory ceiling, so the body must be decompressed *incrementally* rather
//! than slurped-then-inflated. [`gunzip`] wraps the runtime's chunked
//! [`futures_util::Stream`] body in a decoding stream that inflates each
//! compressed chunk as it arrives and yields the plaintext chunks, keeping
//! the same streaming contract the identity path relies on (see
//! [`crate::stream_buffer`]).
//!
//! [spec]: https://c2sp.org/tlog-mirror#add-entries
//! [C2SP/C2SP#251]: https://github.com/C2SP/C2SP/pull/251

use std::io::Write as _;
use std::pin::Pin;

use flate2::write::GzDecoder;
use futures_util::stream::{Stream, StreamExt as _};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::frontend_worker::{ApiResult, AppError};

/// A boxed, `Unpin` body stream, the common type the `add-entries`
/// handler feeds to [`crate::stream_buffer::StreamBuffer`] regardless of
/// whether the request body was identity- or gzip-encoded.
pub(crate) type BodyStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>>>>>;

/// Open the request body as a decoded chunk stream, honoring
/// `Content-Encoding`.
///
/// `identity` (or an absent header) passes the body through unchanged;
/// `gzip`/`x-gzip` is inflated incrementally via [`gunzip`]. Any other
/// encoding is unsupported: the mirror can't authenticate a body it can't
/// read, so this returns 415.
///
/// # Errors
///
/// Returns [`AppError::UnsupportedMediaType`] for an unrecognized
/// `Content-Encoding`.
pub(crate) fn decoded_stream(
    headers: &axum::http::HeaderMap,
    body: axum::body::Body,
) -> ApiResult<BodyStream> {
    let encoding = headers
        .get(axum::http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    // Adapt axum's body data stream (`Result<Bytes, axum::Error>`) to the
    // `Result<Vec<u8>>` chunk contract the buffer/gunzip pipeline expects.
    let raw = body.into_data_stream().map(|r| {
        r.map(|b| b.to_vec())
            .map_err(|e| Error::from(e.to_string()))
    });
    let stream: BodyStream = match encoding.as_str() {
        "" | "identity" => Box::pin(raw),
        "gzip" | "x-gzip" => gunzip(raw),
        other => {
            return Err(AppError::UnsupportedMediaType(format!(
                "Unsupported Content-Encoding: {other}"
            )));
        }
    };
    Ok(stream)
}

/// Incremental gzip inflater: feed compressed bytes with [`Self::push`]
/// and drain the plaintext produced so far; call [`Self::finish`] once the
/// compressed input ends to validate the gzip trailer (CRC-32 + ISIZE).
///
/// Backed by [`flate2`]'s pure-Rust `rust_backend` (`miniz_oxide`), so it
/// compiles to and runs under WASM. `flate2::write::GzDecoder` handles all
/// gzip framing: the 10-byte header, optional FNAME/FEXTRA/etc. fields
/// (buffered across `push` calls if split across chunks), and the trailer.
struct GzipInflater {
    decoder: GzDecoder<Vec<u8>>,
}

impl GzipInflater {
    fn new() -> Self {
        Self {
            decoder: GzDecoder::new(Vec::new()),
        }
    }

    /// Feed one compressed chunk and return the plaintext bytes produced.
    /// May return an empty `Vec` if `input` only completed part of the
    /// gzip header or a DEFLATE block that hasn't emitted output yet.
    fn push(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.decoder
            .write_all(input)
            .map_err(|e| Error::from(format!("gzip decode failed: {e}")))?;
        Ok(std::mem::take(self.decoder.get_mut()))
    }

    /// Finish decompression, returning any trailing plaintext. Errors if
    /// the gzip stream was truncated or its CRC-32/ISIZE trailer does not
    /// match the decompressed data.
    fn finish(self) -> Result<Vec<u8>> {
        self.decoder
            .finish()
            .map_err(|e| Error::from(format!("gzip stream incomplete or corrupt: {e}")))
    }
}

/// Wrap a compressed body `Stream` in a decoding stream that yields the
/// gunzipped plaintext chunks.
///
/// The returned stream inflates lazily: each poll pulls compressed chunks
/// from `inner` until it can emit at least one plaintext byte, so memory
/// use stays bounded by the chunk size rather than the whole body. A
/// decode error (malformed gzip) or a truncated stream surfaces as a
/// terminal `Err` item, after which the stream ends.
pub(crate) fn gunzip<S>(inner: S) -> BodyStream
where
    S: Stream<Item = Result<Vec<u8>>> + Unpin + 'static,
{
    struct DecodeState<S> {
        inner: S,
        inflater: Option<GzipInflater>,
        done: bool,
    }

    Box::pin(futures_util::stream::unfold(
        DecodeState {
            inner,
            inflater: Some(GzipInflater::new()),
            done: false,
        },
        |mut st| async move {
            if st.done {
                return None;
            }
            loop {
                match st.inner.next().await {
                    Some(Ok(chunk)) => {
                        let out = match st.inflater.as_mut().expect("inflater present").push(&chunk)
                        {
                            Ok(out) => out,
                            Err(e) => {
                                st.done = true;
                                return Some((Err(e), st));
                            }
                        };
                        // A chunk may not yet yield any plaintext (partial
                        // header / block); pull more instead of emitting an
                        // empty item.
                        if out.is_empty() {
                            continue;
                        }
                        return Some((Ok(out), st));
                    }
                    Some(Err(e)) => {
                        st.done = true;
                        return Some((Err(e), st));
                    }
                    None => {
                        st.done = true;
                        let inflater = st.inflater.take().expect("inflater present");
                        return match inflater.finish() {
                            Ok(tail) if !tail.is_empty() => Some((Ok(tail), st)),
                            Ok(_) => None,
                            Err(e) => Some((Err(e), st)),
                        };
                    }
                }
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use futures_util::stream;

    /// gzip-compress `data` into a single buffer for test input.
    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// Split `bytes` into chunks of `size` and build a stream of them.
    fn chunked_stream(
        bytes: &[u8],
        size: usize,
    ) -> impl Stream<Item = Result<Vec<u8>>> + Unpin + 'static {
        let chunks: Vec<Result<Vec<u8>>> =
            bytes.chunks(size.max(1)).map(|c| Ok(c.to_vec())).collect();
        stream::iter(chunks)
    }

    async fn collect(mut s: impl Stream<Item = Result<Vec<u8>>> + Unpin) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(item) = s.next().await {
            out.extend_from_slice(&item?);
        }
        Ok(out)
    }

    #[tokio::test]
    async fn roundtrips_across_chunk_sizes() {
        // A payload big enough to span multiple DEFLATE flushes, and
        // compressible enough to exercise real inflation.
        let mut plain: Vec<u8> = Vec::new();
        for i in 0..20_000u32 {
            plain.extend_from_slice(format!("entry-{i};").as_bytes());
        }
        let compressed = gzip(&plain);
        // Feeding the compressed stream in a variety of chunk sizes (incl.
        // 1-byte chunks that split the header/trailer) must all reconstruct
        // the original plaintext.
        for size in [1usize, 2, 7, 64, 1024, compressed.len()] {
            let decoded = collect(gunzip(chunked_stream(&compressed, size)))
                .await
                .unwrap_or_else(|e| panic!("chunk size {size} failed: {e}"));
            assert_eq!(decoded, plain, "chunk size {size} mismatch");
        }
    }

    #[tokio::test]
    async fn empty_payload_roundtrips() {
        let compressed = gzip(b"");
        let decoded = collect(gunzip(chunked_stream(&compressed, 3)))
            .await
            .unwrap();
        assert!(decoded.is_empty());
    }

    #[tokio::test]
    async fn truncated_stream_errors() {
        let mut compressed = gzip(b"the quick brown fox jumps over the lazy dog");
        // Drop the trailer (and some of the deflate payload) so the stream
        // ends mid-member; finish() must report the truncation.
        compressed.truncate(compressed.len() - 6);
        let err = collect(gunzip(chunked_stream(&compressed, 4))).await;
        assert!(err.is_err(), "truncated gzip must surface an error");
    }

    #[tokio::test]
    async fn corrupt_data_errors() {
        let mut compressed = gzip(b"hello world, this is a test payload for corruption");
        // Corrupt a byte in the middle of the DEFLATE payload.
        let mid = compressed.len() / 2;
        compressed[mid] ^= 0xff;
        let err = collect(gunzip(chunked_stream(&compressed, 5))).await;
        assert!(err.is_err(), "corrupt gzip must surface an error");
    }

    #[tokio::test]
    async fn upstream_error_propagates() {
        let compressed = gzip(b"partial");
        let mut chunks: Vec<Result<Vec<u8>>> = vec![Ok(compressed[..4].to_vec())];
        chunks.push(Err(Error::from("boom")));
        let err = collect(gunzip(stream::iter(chunks))).await;
        assert!(err.is_err(), "upstream stream error must propagate");
    }
}
