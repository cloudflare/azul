# tlog_core

Merkle Tree primitives for transparency logs: the algorithm-only core
shared by every transparency-log spec in this workspace.

This crate provides the [`Hash`] type, the RFC 6962 hash builders, and
inclusion / consistency proof builders and verifiers (with the subtree
variants from [draft-ietf-plants-merkle-tree-certs][mtc]). It is
transport-agnostic: no HTTP, no tile encoding, no checkpoint signing.

Higher-level crates that build on top of `tlog_core`:

- [`tlog_tiles`](../tlog_tiles): the [C2SP tlog-tiles][tt] HTTP wire format.
- [`tlog_checkpoint`](../tlog_tiles): the [C2SP tlog-checkpoint][tc] signed-note
  format. (Currently still inside `tlog_tiles`; planned move tracked in
  [issue #230](https://github.com/cloudflare/azul/issues/230).)
- [`tlog_witness`](../tlog_witness): the [C2SP tlog-witness][tw] HTTP witness
  protocol.
- [`tlog_cosignature`](../tlog_cosignature): the [C2SP tlog-cosignature][cs]
  cosignature formats.

## Test

    cargo test

## Acknowledgements

Ported from the Go [tlog package][go-tlog]; see per-function references
in the source back to the upstream commit.

## License

[BSD-3-Clause](./LICENSE).

[mtc]: https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/
[tt]: https://c2sp.org/tlog-tiles
[tc]: https://c2sp.org/tlog-checkpoint
[tw]: https://c2sp.org/tlog-witness
[cs]: https://c2sp.org/tlog-cosignature
[go-tlog]: https://pkg.go.dev/golang.org/x/mod/sumdb/tlog
