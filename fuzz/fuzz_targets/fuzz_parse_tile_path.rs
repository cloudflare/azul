//! This file contains code ported from the original project [tlog](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog) ([BSD-3-Clause license](https://pkg.go.dev/golang.org/x/mod/sumdb/note?tab=licenses)).
//! See the LICENSE file in the root of this repository for the full license text.
//!
//! References:
//! - [tlog_test.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/tlog/tlog_test.go)

#![no_main]

use libfuzzer_sys::fuzz_target;
use tlog_tiles::tile::Tile;

fuzz_target!(|data: &str| {
    let _ = Tile::from_path(data);
});
