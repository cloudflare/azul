//! This file contains code ported from the original project [tlog](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog) ([BSD-3-Clause license](https://pkg.go.dev/golang.org/x/mod/sumdb/note?tab=licenses)).
//! See the LICENSE file in the root of this repository for the full license text.
//!
//! References:
//! - [note_test.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/tlog/note_test.go)

#![no_main]

use libfuzzer_sys::fuzz_target;
use tlog_tiles::checkpoint::Checkpoint;

fuzz_target!(|data: &[u8]| {
    let _ = Checkpoint::from_bytes(data);
});
