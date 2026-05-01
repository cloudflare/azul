# Tlog Tiles

A Rust implementation of the [C2SP tlog-tiles](https://c2sp.org/tlog-tiles)
HTTP wire format for tile-encoded transparency logs.

The Merkle math primitives ([`Hash`], proof builders/verifiers,
[`Subtree`]) live in the [`tlog_core`] crate. The signed-note checkpoint
format lives in [`tlog_checkpoint`]. This crate is the tile-encoding
layer on top of both.

[`Hash`]: https://docs.rs/tlog_core/latest/tlog_core/struct.Hash.html
[`Subtree`]: https://docs.rs/tlog_core/latest/tlog_core/struct.Subtree.html
[`tlog_core`]: https://docs.rs/tlog_core
[`tlog_checkpoint`]: https://docs.rs/tlog_checkpoint

## Test

    cargo test

## Acknowledgements

The project ports code from [tlog](https://golang.org/x/mod/sumdb/tlog).

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
