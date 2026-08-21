// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Request-body decoding for `add-entries`.
//!
//! [c2sp.org/tlog-mirror][spec] requires mirrors to accept
//! `Content-Encoding: gzip` request bodies (see [Request Body][reqbody]);
//! clients MAY send gzip without negotiating first. The Cloudflare Workers
//! runtime does not transparently decompress request bodies (unlike responses,
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
//! [reqbody]: https://c2sp.org/tlog-mirror#request-body

use std::io::Write as _;
use std::pin::Pin;

use flate2::write::GzDecoder;
use futures_util::stream::{Stream, StreamExt as _};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::frontend_worker::{ApiResult, AppError};

/// An error surfaced by a [`BodyStream`], distinguishing a client-side
/// decode fault from a transport failure so the `add-entries` handler can
/// map each to the right HTTP status (see `From<BodyError> for AppError`).
#[derive(Debug)]
pub(crate) enum BodyError {
    /// Malformed or truncated gzip body: a client fault, mapped to 400.
    Decode(String),
    /// Transport failure reading the underlying request body: mapped to
    /// 500.
    Transport(Error),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyError::Decode(e) => write!(f, "{e}"),
            BodyError::Transport(e) => write!(f, "{e}"),
        }
    }
}

/// A boxed, `Unpin` body stream, the common type the `add-entries`
/// handler feeds to [`crate::stream_buffer::StreamBuffer`] regardless of
/// whether the request body was identity- or gzip-encoded.
pub(crate) type BodyStream = Pin<Box<dyn Stream<Item = std::result::Result<Vec<u8>, BodyError>>>>;

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
            .map_err(|e| BodyError::Transport(Error::from(e.to_string())))
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

/// Largest compressed slice fed to the decoder per step, and the point at
/// which accumulated plaintext is drained. DEFLATE can inflate a small
/// input by a large factor (a hostile "zip bomb" reaches ~1000x), so a
/// single unbounded `write_all` of a whole chunk could balloon the sink
/// `Vec` far past the isolate's memory ceiling. Feeding the decoder in
/// bounded slices and draining between them keeps the plaintext held at
/// once proportional to this window, not to the compression ratio.
const INFLATE_STEP: usize = 64 * 1024;

/// Incremental gzip inflater: feed compressed bytes with [`Self::push`]
/// and drain the plaintext produced so far; call [`Self::finish`] once the
/// compressed input ends to validate the gzip trailer (CRC-32 + ISIZE).
///
/// Backed by [`flate2`]'s pure-Rust `rust_backend` (`miniz_oxide`), so it
/// compiles to and runs under WASM. `flate2::write::GzDecoder` handles all
/// gzip framing: the 10-byte header, optional FNAME/FEXTRA/etc. fields
/// (buffered across `push` calls if split across chunks), and the trailer.
///
/// [`Self::push`] feeds the decoder at most [`INFLATE_STEP`] compressed
/// bytes at a time and drains after each step, so the sink never holds
/// more than one step's worth of inflated output regardless of how large
/// or compressible the caller's chunk is.
struct GzipInflater {
    decoder: GzDecoder<Vec<u8>>,
}

impl GzipInflater {
    fn new() -> Self {
        Self {
            decoder: GzDecoder::new(Vec::new()),
        }
    }

    /// Feed one compressed chunk, invoking `emit` with each bounded
    /// plaintext run produced. `emit` may be called zero times (the input
    /// only advanced the gzip header or a not-yet-emitting DEFLATE block),
    /// once, or many times for a highly compressible chunk.
    ///
    /// Input is written to the decoder one [`INFLATE_STEP`] slice at a
    /// time, draining the sink after each, and every drained run is further
    /// split into at most [`INFLATE_STEP`]-byte emissions. So no single
    /// emitted run (what flows downstream) exceeds one step regardless of
    /// the (attacker-controlled) compression ratio, and the sink is drained
    /// per input step instead of accumulating the whole chunk's output.
    fn push(&mut self, input: &[u8], mut emit: impl FnMut(Vec<u8>)) -> Result<()> {
        for slice in input.chunks(INFLATE_STEP) {
            self.decoder
                .write_all(slice)
                .map_err(|e| Error::from(format!("gzip decode failed: {e}")))?;
            let produced = std::mem::take(self.decoder.get_mut());
            for run in produced.chunks(INFLATE_STEP) {
                emit(run.to_vec());
            }
        }
        Ok(())
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
/// from `inner` until it can emit at least one plaintext run, so memory
/// use stays bounded by the chunk size rather than the whole body. A
/// single compressed chunk that inflates a lot is emitted as several
/// [`INFLATE_STEP`]-bounded runs, drained from `pending` across polls, so
/// a hostile compression ratio cannot force one giant allocation. A decode
/// error (malformed gzip) or a truncated stream surfaces as a terminal
/// `Err` item, after which the stream ends.
pub(crate) fn gunzip<S>(inner: S) -> BodyStream
where
    S: Stream<Item = std::result::Result<Vec<u8>, BodyError>> + Unpin + 'static,
{
    struct DecodeState<S> {
        inner: S,
        inflater: Option<GzipInflater>,
        /// Plaintext runs decoded from the last compressed chunk but not
        /// yet emitted, drained one per poll (front to back).
        pending: std::collections::VecDeque<Vec<u8>>,
        done: bool,
    }

    Box::pin(futures_util::stream::unfold(
        DecodeState {
            inner,
            inflater: Some(GzipInflater::new()),
            pending: std::collections::VecDeque::new(),
            done: false,
        },
        |mut st| async move {
            if let Some(run) = st.pending.pop_front() {
                return Some((Ok(run), st));
            }
            if st.done {
                return None;
            }
            loop {
                match st.inner.next().await {
                    Some(Ok(chunk)) => {
                        let inflater = st.inflater.as_mut().expect("inflater present");
                        let mut runs = std::collections::VecDeque::new();
                        if let Err(e) = inflater.push(&chunk, |run| runs.push_back(run)) {
                            st.done = true;
                            return Some((Err(BodyError::Decode(e.to_string())), st));
                        }
                        // A chunk may not yet yield any plaintext (partial
                        // header / block); pull more instead of emitting an
                        // empty item. Otherwise emit the first run now and
                        // queue the rest for subsequent polls.
                        let Some(first) = runs.pop_front() else {
                            continue;
                        };
                        st.pending = runs;
                        return Some((Ok(first), st));
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
                            Err(e) => Some((Err(BodyError::Decode(e.to_string())), st)),
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
    ) -> impl Stream<Item = std::result::Result<Vec<u8>, BodyError>> + Unpin + 'static {
        let chunks: Vec<std::result::Result<Vec<u8>, BodyError>> =
            bytes.chunks(size.max(1)).map(|c| Ok(c.to_vec())).collect();
        stream::iter(chunks)
    }

    async fn collect(
        mut s: impl Stream<Item = std::result::Result<Vec<u8>, BodyError>> + Unpin,
    ) -> std::result::Result<Vec<u8>, BodyError> {
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
        assert!(
            matches!(err, Err(BodyError::Decode(_))),
            "truncated gzip must surface a client decode error"
        );
    }

    #[tokio::test]
    async fn corrupt_data_errors() {
        let mut compressed = gzip(b"hello world, this is a test payload for corruption");
        // Corrupt a byte in the middle of the DEFLATE payload.
        let mid = compressed.len() / 2;
        compressed[mid] ^= 0xff;
        let err = collect(gunzip(chunked_stream(&compressed, 5))).await;
        assert!(
            matches!(err, Err(BodyError::Decode(_))),
            "corrupt gzip must surface a client decode error"
        );
    }

    // A highly compressible payload whose plaintext far exceeds
    // INFLATE_STEP, delivered as a single compressed chunk, must inflate
    // to the exact original but be emitted as several bounded runs so no
    // single allocation exceeds the step. This is the zip-bomb guard.
    #[tokio::test]
    async fn large_ratio_chunk_emits_bounded_runs() {
        let plain = vec![0u8; INFLATE_STEP * 10 + 123];
        let compressed = gzip(&plain);
        assert!(
            compressed.len() < INFLATE_STEP,
            "test payload should compress to well under one step"
        );
        // Feed the whole compressed body as one chunk.
        let mut s = gunzip(stream::iter(vec![Ok::<_, BodyError>(compressed)]));
        let mut total = 0usize;
        let mut runs = 0usize;
        while let Some(item) = s.next().await {
            let run = item.unwrap();
            assert!(
                run.len() <= INFLATE_STEP,
                "run of {} bytes exceeds INFLATE_STEP {INFLATE_STEP}",
                run.len()
            );
            total += run.len();
            runs += 1;
        }
        assert_eq!(total, plain.len());
        assert!(
            runs > 1,
            "a >step payload must span multiple runs, got {runs}"
        );
    }

    #[tokio::test]
    async fn upstream_error_propagates() {
        let compressed = gzip(b"partial");
        let mut chunks: Vec<std::result::Result<Vec<u8>, BodyError>> =
            vec![Ok(compressed[..4].to_vec())];
        chunks.push(Err(BodyError::Transport(Error::from("boom"))));
        let err = collect(gunzip(stream::iter(chunks))).await;
        assert!(err.is_err(), "upstream stream error must propagate");
    }
}
