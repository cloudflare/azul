# tlog_checkpoint

A Rust implementation of the [C2SP tlog-checkpoint][tc] specification: the
signed-note format that tiled transparency logs use to represent their
signed tree heads.

This crate provides:

- [`CheckpointText`] — the text portion of a signed checkpoint (origin,
  size, root hash, optional extension lines).
- [`CheckpointSigner`] — a trait for signers that produce checkpoint
  cosignatures, plus an [`Ed25519CheckpointSigner`] implementation for
  the basic Ed25519 signed-note algorithm (`0x01`).
- [`TreeWithTimestamp`] — pairs a tree size + root hash with a Unix
  timestamp; what a log signs to produce a checkpoint.
- [`open_checkpoint`] — caller-side parsing/verification path used by
  full-coverage clients (every configured verifier must sign).

The Merkle math (the [`Hash`] type, the proof builders/verifiers, the
`Subtree` type) lives in the [`tlog_core`] crate; this crate adds the
checkpoint signed-note shape on top.

[tc]: https://c2sp.org/tlog-checkpoint
[`Hash`]: https://docs.rs/tlog_core/latest/tlog_core/struct.Hash.html
[`tlog_core`]: https://docs.rs/tlog_core

## Test

    cargo test

## Acknowledgements

Ports code from [tlog](https://golang.org/x/mod/sumdb/tlog) and
[sunlight](https://github.com/FiloSottile/sunlight).

## License

[BSD-3-Clause](./LICENSE).
