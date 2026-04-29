# tlog_cosignature

An implementation of [`c2sp.org/tlog-cosignature`](https://c2sp.org/tlog-cosignature):
*Transparency Log Cosignatures*.

A *cosignature* is a statement by a cosigner that it verified the
consistency of a [checkpoint](https://c2sp.org/tlog-checkpoint) (or, in
future revisions of the spec, a subtree). Log clients combine cosignatures
from multiple cosigners to prevent split-view attacks before trusting an
inclusion proof.

This crate provides signers and verifiers for the cosignature formats
specified by the C2SP document. Today only the Ed25519 `cosignature/v1`
format is implemented; the ML-DSA-44 `subtree/v1` format will be added
in a follow-up.

## What's in scope

- [`CosignatureV1CheckpointSigner`] / [`CosignatureV1NoteVerifier`]: the
  Ed25519 `cosignature/v1` signed-message format. The signed message is
  `cosignature/v1\ntime <ts>\n<note body>` and the timestamped signature
  is the 64-byte Ed25519 signature prefixed with a big-endian `u64`
  POSIX timestamp.

## What's out of scope

- HTTP transports for requesting cosignatures (see `tlog_witness` for
  `c2sp.org/tlog-witness` parsers/serializers).
- Persistent state for a witness — that's a deployment concern.

## License

The project is licensed under the [BSD-3-Clause License](../../LICENSE).
