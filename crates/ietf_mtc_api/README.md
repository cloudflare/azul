# ietf_mtc_api

Core types and logic for the [IETF MTC CA](../ietf_mtc_worker/README.md).

This crate implements the bootstrap-specific protocol layer on top of the shared
[`tlog_tiles`](../tlog_tiles/) infrastructure:

- **X.509 bootstrap chain validation** — validates a submitted certificate chain
  against a root pool, enforces EKU (`serverAuth`), filters extensions, and
  converts the leaf to a `TBSCertificateLogEntry`.
- **`MerkleTreeCertEntry` encoding/decoding** — the binary log entry format
  (approximately draft-davidben-tls-merkle-tree-certs-09).
- **`serialize_signatureless_cert`** — constructs the signatureless MTC
  certificate from a sequenced log entry, an inclusion proof, and the subscriber's
  SPKI. (The IETF draft renamed these to "landmark-relative" certificates.)
- **Landmark sequence** — tracks the active landmark subtrees and their Merkle
  roots for inclusion proof generation.
- **Cosigner** — Ed25519-based subtree cosigning over the `mtc-subtree/v1` note
  format.

This crate is intentionally frozen at the bootstrap protocol version and will not
be updated to track the IETF draft.

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
