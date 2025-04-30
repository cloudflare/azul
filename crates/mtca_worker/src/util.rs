// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Utility functions.

use std::sync::Once;

#[cfg(test)]
use parking_lot::ReentrantMutex;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Returns the current Unix timestamp at millisecond precision.
#[cfg(not(test))]
pub(crate) fn now_millis() -> u64 {
    worker::Date::now().as_millis()
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

#[cfg(test)]
pub(crate) fn now_millis() -> u64 {
    let _lock = TIME_MUX.lock();
    if FREEZE_TIME.load(Ordering::Relaxed) {
        GLOBAL_TIME.load(Ordering::Relaxed)
    } else {
        GLOBAL_TIME.fetch_add(1, Ordering::Relaxed)
    }
}

static INIT_LOGGING: Once = Once::new();

pub(crate) fn init_logging(level: log::Level) {
    INIT_LOGGING.call_once(|| {
        console_log::init_with_level(level).expect("error initializing logger");
    });
}
