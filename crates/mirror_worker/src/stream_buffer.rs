// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Streaming buffer adapter that bridges the worker runtime's async
//! [`futures_util::Stream`] of byte chunks to the synchronous
//! [`std::io::Read`] API expected by [`tlog_mirror::wire`]'s parsers.
//!
//! The adapter holds an internal `Vec<u8>` byte buffer. Callers pull
//! more bytes from the underlying stream asynchronously (via
//! [`StreamBuffer::pull_one`]), then parse synchronously over a
//! [`Cursor`](std::io::Cursor) wrapping the buffered slice. The natural
//! parse pattern is a retry loop: attempt the parse, and on
//! [`std::io::ErrorKind::UnexpectedEof`] pull another chunk and retry.
//! On success, [`StreamBuffer::consume`] advances past the parsed bytes
//! so subsequent parses start at the next byte.
//!
//! This pattern lets the `add-entries` handler process each entry
//! package's bytes as soon as enough have arrived, without buffering
//! the entire (potentially 100 MB) request body in memory at once.

use futures_util::stream::{Stream, StreamExt as _};

/// A growable byte buffer fed by an async `Stream<Item = Result<Vec<u8>,
/// E>>`. See the module-level comment for the intended usage pattern.
pub(crate) struct StreamBuffer<S> {
    stream: S,
    buf: Vec<u8>,
    /// Set when the underlying stream has signalled end-of-stream.
    /// Subsequent [`Self::pull_one`] calls return `Ok(false)`
    /// without polling the (already-finished) stream.
    eof: bool,
}

impl<S, E> StreamBuffer<S>
where
    S: Stream<Item = std::result::Result<Vec<u8>, E>> + Unpin,
{
    /// Construct a new streaming buffer wrapping `stream`. The buffer
    /// starts empty; callers must call [`Self::pull_one`] (or its
    /// helpers) to populate it before parsing.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            eof: false,
        }
    }

    /// Pull one chunk from the underlying stream and append to the
    /// internal buffer. Returns `Ok(true)` if a chunk was appended,
    /// `Ok(false)` if the stream ended (clean EOF). Once the stream has
    /// ended, all subsequent calls return `Ok(false)` without polling
    /// the stream again.
    ///
    /// # Errors
    /// Propagates any error from the underlying stream.
    pub async fn pull_one(&mut self) -> std::result::Result<bool, E> {
        if self.eof {
            return Ok(false);
        }
        match self.stream.next().await {
            Some(Ok(chunk)) => {
                self.buf.extend_from_slice(&chunk);
                Ok(true)
            }
            Some(Err(e)) => Err(e),
            None => {
                self.eof = true;
                Ok(false)
            }
        }
    }

    /// View the currently-buffered bytes. Used to construct a sync
    /// `Cursor` for parsing.
    pub fn buffered(&self) -> &[u8] {
        &self.buf
    }

    /// Number of bytes currently buffered.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// `true` if the underlying stream has signalled end-of-stream
    /// (regardless of whether bytes remain in the buffer).
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// Discard the first `n` bytes of the buffer. The caller should
    /// call this after a successful parse to advance past consumed
    /// input.
    ///
    /// # Panics
    /// Panics if `n > self.len()`.
    pub fn consume(&mut self, n: usize) {
        assert!(
            n <= self.buf.len(),
            "StreamBuffer::consume({n}) but only {} bytes buffered",
            self.buf.len()
        );
        // Drain in-place. For typical mirror workloads each consume
        // is a few KB, so the O(n) shift is fine. If we ever see this
        // in a profile we can switch to a ring-buffer or VecDeque.
        self.buf.drain(..n);
    }
}

#[cfg(test)]
mod tests {
    use super::StreamBuffer;
    use futures_util::stream;

    /// Build a `StreamBuffer` over an in-memory iterator-of-Results.
    /// Used to unit-test the buffering behaviour without a real worker
    /// runtime.
    fn from_chunks(
        chunks: Vec<Vec<u8>>,
    ) -> StreamBuffer<impl futures_util::Stream<Item = std::io::Result<Vec<u8>>> + Unpin> {
        StreamBuffer::new(stream::iter(
            chunks.into_iter().map(Ok::<_, std::io::Error>),
        ))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pull_one_returns_chunks_in_order() {
        let mut buf = from_chunks(vec![b"foo".to_vec(), b"bar".to_vec()]);
        assert!(buf.pull_one().await.unwrap());
        assert_eq!(buf.buffered(), b"foo");
        assert!(buf.pull_one().await.unwrap());
        assert_eq!(buf.buffered(), b"foobar");
        // Stream is now empty; further pulls return Ok(false).
        assert!(!buf.pull_one().await.unwrap());
        assert!(buf.is_eof());
        assert!(!buf.pull_one().await.unwrap());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn consume_advances_past_used_bytes() {
        let mut buf = from_chunks(vec![b"abcdef".to_vec()]);
        buf.pull_one().await.unwrap();
        buf.consume(2);
        assert_eq!(buf.buffered(), b"cdef");
        buf.consume(4);
        assert_eq!(buf.buffered(), b"");
        assert_eq!(buf.len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    #[should_panic(expected = "StreamBuffer::consume")]
    async fn consume_past_end_panics() {
        let mut buf = from_chunks(vec![b"ab".to_vec()]);
        buf.pull_one().await.unwrap();
        buf.consume(99);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn errors_propagate() {
        let chunks: Vec<std::io::Result<Vec<u8>>> =
            vec![Ok(b"foo".to_vec()), Err(std::io::Error::other("boom"))];
        let mut buf = StreamBuffer::new(stream::iter(chunks));
        assert!(buf.pull_one().await.unwrap());
        let err = buf.pull_one().await.unwrap_err();
        assert_eq!(err.to_string(), "boom");
    }
}
