# ietf_mtc_api

Core types and logic for the [IETF Merkle Tree CA Worker](../ietf_mtc_worker/README.md).

This crate implements the IETF draft protocol layer on top of the shared
[`tlog_tiles`](../tlog_tiles/) infrastructure, targeting
[draft-ietf-plants-merkle-tree-certs-02](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/).

Key components:

- **`AddEntryRequest`** — PKCS#10 CSR submission request (base64url-encoded DER,
  matching the ACME `finalize` format per RFC 8555 §7.4).
- **`build_pending_entry`** — parses a CSR, extracts subject, SPKI algorithm,
  SPKI hash, and SANs, and constructs an `IetfMtcPendingLogEntry`.
- **`TbsCertificateLogEntry`** — the plants-02 wire format: fields encoded as raw
  concatenated DER (no outer SEQUENCE wrapper), including the new
  `subjectPublicKeyInfoAlgorithm` field.
- **`MerkleTreeCertEntry`** — entry type enum (`NullEntry` / `TbsCertEntry`) with
  encode/decode.
- **`serialize_landmark_relative_cert`** — constructs the landmark-relative MTC
  certificate from a sequenced log entry, an inclusion proof, and the subscriber's
  SPKI.
- **Landmark sequence** — tracks the active landmark subtrees and their Merkle
  roots.
- **Cosigner** — Ed25519-based subtree cosigning over the `mtc-subtree/v1` note
  format.

For the older bootstrap experiment (draft-davidben-tls-merkle-tree-certs-09),
see [`bootstrap_mtc_api`](../bootstrap_mtc_api/).

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
