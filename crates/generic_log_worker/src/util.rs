// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Utility functions.

use futures_util::StreamExt as _;
#[cfg(test)]
use parking_lot::ReentrantMutex;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Returns the current Unix timestamp at millisecond precision.
#[must_use]
#[cfg(not(test))]
pub fn now_millis() -> u64 {
    worker::Date::now().as_millis()
}
#[must_use]
#[cfg(test)]
pub fn now_millis() -> u64 {
    let _lock = TIME_MUX.lock();
    if FREEZE_TIME.load(Ordering::Relaxed) {
        GLOBAL_TIME.load(Ordering::Relaxed)
    } else {
        GLOBAL_TIME.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
static GLOBAL_TIME: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static FREEZE_TIME: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(crate) static TIME_MUX: ReentrantMutex<()> = ReentrantMutex::new(());

#[cfg(test)]
pub(crate) fn set_freeze_time(b: bool) {
    FREEZE_TIME.store(b, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn set_global_time(time: u64) {
    GLOBAL_TIME.store(time, Ordering::Relaxed);
}

pub struct WorkerByteStream(worker::send::SendWrapper<worker::ByteStream>);
impl WorkerByteStream {
    #[must_use]
    pub fn new(stream: worker::ByteStream) -> Self {
        Self(worker::send::SendWrapper::new(stream))
    }
}

impl futures_util::Stream for WorkerByteStream {
    type Item = Result<Vec<u8>, worker::Error>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.as_mut().0.0.poll_next_unpin(cx)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.0.size_hint()
    }
}
