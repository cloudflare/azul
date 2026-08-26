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

/// Compressed bytes fed to the decoder per [`GzipInflater::step`] call.
/// `write_all` inflates its whole slice into the decoder's sink before
/// returning, and DEFLATE reaches ~1032x, so a step holds up to
/// `INFLATE_INPUT_STEP * 1032` bytes of plaintext transiently (~4 MiB
/// here). A small input step keeps that under the isolate's ~128 MB
/// ceiling even for a zip bomb; a larger chunk or the whole body is never
/// handed to `write_all` at once.
const INFLATE_INPUT_STEP: usize = 4 * 1024;

/// Largest plaintext run emitted downstream. The plaintext drained after a
/// step is split into runs no larger than this.
const EMIT_STEP: usize = 64 * 1024;

/// Incremental gzip inflater: feed a bounded compressed slice with
/// [`Self::step`], draining the plaintext it produced; call
/// [`Self::finish`] once the compressed input ends to validate the gzip
/// trailer (CRC-32 + ISIZE).
///
/// Backed by [`flate2`]'s pure-Rust `rust_backend` (`miniz_oxide`), so it
/// compiles to and runs under WASM. `flate2::write::GzDecoder` handles all
/// gzip framing: the 10-byte header, optional FNAME/FEXTRA/etc. fields
/// (buffered across calls if split across steps), and the trailer.
///
/// The caller (see [`gunzip`]) feeds at most [`INFLATE_INPUT_STEP`] bytes
/// per [`Self::step`] and stops once a step yields plaintext, leaving the
/// rest of the compressed chunk unfed. At most one step is inflated ahead
/// of what has been emitted.
struct GzipInflater {
    decoder: GzDecoder<Vec<u8>>,
}

impl GzipInflater {
    fn new() -> Self {
        Self {
            decoder: GzDecoder::new(Vec::new()),
        }
    }

    /// Feed one compressed slice (at most [`INFLATE_INPUT_STEP`] bytes),
    /// invoking `emit` with each [`EMIT_STEP`]-bounded plaintext run the
    /// step produced. `emit` may be called zero times (the slice only
    /// advanced the gzip header or a not-yet-emitting DEFLATE block), once,
    /// or several times for a highly compressible slice.
    ///
    /// # Panics
    ///
    /// Debug-asserts `slice.len() <= INFLATE_INPUT_STEP`; a larger slice
    /// breaks the transient-plaintext bound.
    fn step(&mut self, slice: &[u8], mut emit: impl FnMut(Vec<u8>)) -> Result<()> {
        debug_assert!(slice.len() <= INFLATE_INPUT_STEP, "input slice too large");
        self.decoder
            .write_all(slice)
            .map_err(|e| Error::from(format!("gzip decode failed: {e}")))?;
        let produced = std::mem::take(self.decoder.get_mut());
        for run in produced.chunks(EMIT_STEP) {
            emit(run.to_vec());
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
/// Each poll feeds the decoder at most [`INFLATE_INPUT_STEP`] compressed
/// bytes and stops once a step yields plaintext, leaving the rest of the
/// current chunk unfed until the next poll (tracked by `current`/`pos`).
/// At most one input step is inflated ahead of what has been emitted, so
/// the transient plaintext is bounded by `INFLATE_INPUT_STEP * ratio`
/// rather than the whole chunk's inflation. A step that produces more than
/// [`EMIT_STEP`] of plaintext yields several bounded runs drained from
/// `pending`. A decode error (malformed gzip) or a truncated stream
/// surfaces as a terminal `Err` item, after which the stream ends.
pub(crate) fn gunzip<S>(inner: S) -> BodyStream
where
    S: Stream<Item = std::result::Result<Vec<u8>, BodyError>> + Unpin + 'static,
{
    struct DecodeState<S> {
        inner: S,
        inflater: Option<GzipInflater>,
        /// Compressed chunk currently being fed, and the offset of the
        /// next unfed byte. Bytes at `pos..` are not fed until the current
        /// runs drain, capping how far ahead the decoder inflates.
        current: Vec<u8>,
        pos: usize,
        /// Plaintext runs from the last step not yet emitted, drained one
        /// per poll (front to back).
        pending: std::collections::VecDeque<Vec<u8>>,
        done: bool,
    }

    Box::pin(futures_util::stream::unfold(
        DecodeState {
            inner,
            inflater: Some(GzipInflater::new()),
            current: Vec::new(),
            pos: 0,
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
                // Feed the unfed tail of the current chunk one bounded
                // step at a time, stopping as soon as a step emits.
                while st.pos < st.current.len() {
                    let end = (st.pos + INFLATE_INPUT_STEP).min(st.current.len());
                    let slice = st.current[st.pos..end].to_vec();
                    st.pos = end;
                    let inflater = st.inflater.as_mut().expect("inflater present");
                    let mut runs = std::collections::VecDeque::new();
                    if let Err(e) = inflater.step(&slice, |run| runs.push_back(run)) {
                        st.done = true;
                        return Some((Err(BodyError::Decode(e.to_string())), st));
                    }
                    if let Some(first) = runs.pop_front() {
                        st.pending = runs;
                        return Some((Ok(first), st));
                    }
                }

                // Current chunk fully fed; pull the next compressed chunk.
                match st.inner.next().await {
                    Some(Ok(chunk)) => {
                        st.current = chunk;
                        st.pos = 0;
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

    // A compressible payload whose plaintext exceeds EMIT_STEP, delivered
    // as one compressed chunk, reconstructs and is emitted as
    // EMIT_STEP-bounded runs rather than a single unbounded one.
    #[tokio::test]
    async fn large_ratio_chunk_emits_bounded_runs() {
        let plain = vec![0u8; EMIT_STEP * 10 + 123];
        let compressed = gzip(&plain);
        assert!(
            compressed.len() < EMIT_STEP,
            "test payload should compress to well under one emit step"
        );
        // Feed the whole compressed body as one chunk.
        let mut s = gunzip(stream::iter(vec![Ok::<_, BodyError>(compressed)]));
        let mut total = 0usize;
        let mut runs = 0usize;
        while let Some(item) = s.next().await {
            let run = item.unwrap();
            assert!(
                run.len() <= EMIT_STEP,
                "run of {} bytes exceeds EMIT_STEP {EMIT_STEP}",
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

    // Feeding INFLATE_INPUT_STEP-bounded slices (as gunzip does) round-trips
    // a body whose compressed form spans several steps.
    #[test]
    fn inflater_step_bounds_input() {
        // A poorly-compressible body whose compressed form spans several
        // input steps.
        let mut plain = Vec::new();
        for i in 0u32..0x1_0000 {
            plain.extend_from_slice(&i.wrapping_mul(2_654_435_761).to_le_bytes());
        }
        let compressed = gzip(&plain);
        assert!(
            compressed.len() > INFLATE_INPUT_STEP,
            "test needs a body spanning multiple input steps"
        );

        let mut inflater = GzipInflater::new();
        let mut total = 0usize;
        // Feed as gunzip does: INFLATE_INPUT_STEP-bounded slices.
        for slice in compressed.chunks(INFLATE_INPUT_STEP) {
            inflater
                .step(slice, |run| {
                    assert!(run.len() <= EMIT_STEP, "run exceeds EMIT_STEP");
                    total += run.len();
                })
                .unwrap();
        }
        total += inflater.finish().unwrap().len();
        assert_eq!(total, plain.len());
    }

    // One compressed chunk whose inflation exceeds a step: the first poll
    // returns an EMIT_STEP-bounded run, leaving the rest unfed, and the
    // full stream reconstructs the original.
    #[tokio::test]
    async fn large_ratio_chunk_emits_before_full_feed() {
        let plain = vec![0u8; EMIT_STEP * 8];
        let compressed = gzip(&plain);
        let mut s = gunzip(stream::iter(vec![Ok::<_, BodyError>(compressed)]));
        let first = s.next().await.expect("a run").expect("no error");
        assert!(
            first.len() <= EMIT_STEP,
            "first emitted run must be bounded, got {}",
            first.len()
        );
        // The remaining runs complete the original.
        let mut total = first.len();
        while let Some(item) = s.next().await {
            total += item.unwrap().len();
        }
        assert_eq!(total, plain.len());
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
