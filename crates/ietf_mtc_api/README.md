# ietf_mtc_api

Core types and logic for the [IETF Merkle Tree CA Worker](../ietf_mtc_worker/README.md).

This crate implements the IETF draft protocol layer on top of the shared
split transparency-log crates, targeting
[draft-ietf-plants-merkle-tree-certs-06](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/).

Key components:

- **`AddEntryRequest`** — PKCS#10 CSR submission request (base64url-encoded DER,
  matching the ACME `finalize` format per RFC 8555 §7.4).
- **`build_pending_entry`** — parses a CSR, extracts subject, SPKI algorithm,
  SPKI hash, and SANs, and constructs an `IetfMtcPendingLogEntry`.
- **`TbsCertificateLogEntry`** — the current wire format: fields encoded as raw
  concatenated DER (no outer SEQUENCE wrapper), including the new
  `subjectPublicKeyInfoAlgorithm` field.
- **`MerkleTreeCertEntry`** — entry type enum (`NullEntry` / `TbsCertEntry`) with
  encode/decode.
- **`serialize_landmark_relative_cert`** — constructs the landmark-relative MTC
  certificate from a sequenced log entry, an inclusion proof, and the subscriber's
  SPKI.
- **Landmark sequence** — tracks the active landmark subtrees and their Merkle
  roots.
- **Cosigner** — Ed25519 and ML-DSA-44 subtree cosigning over the `subtree/v1`
  format.

## License

The project is licensed under the [BSD-3-Clause License](./LICENSE).
