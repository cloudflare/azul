// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! Utility functions.

use std::sync::Once;

static INIT_LOGGING: Once = Once::new();

pub(crate) fn init_logging(level: log::Level) {
    INIT_LOGGING.call_once(|| {
        console_log::init_with_level(level).expect("error initializing logger");
    });
}
