// Ported from "mod" (https://pkg.go.dev/golang.org/x/mod)
// Copyright 2009 The Go Authors
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause
//
// This ports code from the original Go project "mod" and adapts it to Rust idioms.
//
// Modifications and Rust implementation Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! This file contains code ported from the original project [tlog](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog).
//!
//! References:
//! - [note_test.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/tlog/note_test.go)

#![no_main]

use libfuzzer_sys::fuzz_target;
use tlog_tiles::checkpoint::CheckpointText;

fuzz_target!(|data: &[u8]| {
    let _ = CheckpointText::from_bytes(data);
});
