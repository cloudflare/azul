// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! [`MirrorState`] Durable Object: per-origin atomic state for the
//! [c2sp.org/tlog-mirror][spec] protocol.
//!
//! The DO holds two pieces of per-origin state:
//!
//! - `pending`: the latest signed checkpoint the mirror has accepted via
//!   [`add-checkpoint`][add-cp] but has not yet fully ingested entries
//!   for. Stored as the full signed-note bytes so the mirror can later
//!   serve them back to `add-entries` clients (the spec recommends
//!   storing the signed checkpoint in the ticket; we do that via
//!   [`tlog_mirror::TicketMacer`] from the frontend, but we also keep
//!   the latest pending here as the canonical source of truth for the
//!   `add-checkpoint` consistency proof check).
//!
//! - `mirror`: the latest checkpoint for which the mirror has cosigned
//!   and committed all entries. Always at-or-behind `pending`. Not yet
//!   used in this slice — `add-entries` (a future slice) is what
//!   advances `mirror`.
//!
//! For now, only `pending` is updated. The DO exposes a single internal
//! RPC consumed by the frontend handler in the same worker:
//!
//! - `POST /update-pending` — body is a JSON
//!   [`UpdatePendingRequest`] carrying the client-claimed `old_size`,
//!   the proposed new `size`/`hash`, the consistency proof, and the
//!   full signed-note bytes of the new pending checkpoint. The DO reads
//!   its persisted state, verifies that the recorded pending size
//!   matches `old_size`, verifies the Merkle consistency proof against
//!   the stored pending hash (when a proof is required), and on success
//!   writes the new pending state and returns 200 with a
//!   [`PendingCheckpoint`] body. On size / same-size-different-hash
//!   mismatch it returns 409 with a [`PendingCheckpoint`] body carrying
//!   the current state so the caller can produce the spec's
//!   `text/x.tlog.size` response. On proof verification failure it
//!   returns 422.
//!
//! Atomicity of the read-verify-compare-write sequence is provided by
//! Cloudflare Durable Objects' input/output gates (see the inline
//! commentary in the handler).
//!
//! [spec]: https://c2sp.org/tlog-mirror
//! [add-cp]: https://c2sp.org/tlog-mirror#add-checkpoint

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64 as Base64As, serde_as};
use tlog_core::{verify_consistency_proof, Hash};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::MIRROR_STATE_BINDING;

const PENDING_KEY: &str = "pending";

/// The persisted *pending checkpoint* for a single log origin.
///
/// The mirror stores the full signed-note bytes (not just size+hash) so
/// that it can serve them back to `add-entries` clients via the ticket
/// scheme, and so the log's signature on the pending checkpoint is
/// retained per spec.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PendingCheckpoint {
    /// Tree size of the latest pending checkpoint. Zero if the mirror
    /// has never accepted a pending checkpoint for this origin.
    pub size: u64,
    /// Root hash of the latest pending checkpoint. All-zero if `size`
    /// is 0.
    #[serde(with = "hash_hex")]
    pub hash: Hash,
    /// The full signed-note bytes of the pending checkpoint, including
    /// the log's signature. Empty if `size` is 0. Encoded as base64 in
    /// the on-disk JSON so the DO state remains valid UTF-8 (signed
    /// notes are ASCII text but the JSON-with-arbitrary-bytes
    /// alternative is fragile, and base64 keeps the storage layer
    /// uniform with the wire format used by the ticket scheme).
    #[serde_as(as = "Base64As")]
    pub signed_note_bytes: Vec<u8>,
}

/// Body of the internal `/update-pending` RPC.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct UpdatePendingRequest {
    /// The client-claimed old size; must equal the persisted pending
    /// size or the update is rejected (409 Conflict).
    pub old_size: u64,
    /// Proposed new tree size.
    pub new_size: u64,
    /// Proposed new root hash.
    #[serde(with = "hash_hex")]
    pub new_hash: Hash,
    /// Consistency proof from `(old_size, stored_hash)` to
    /// `(new_size, new_hash)`, per RFC 6962 §2.1.2. MUST be empty if
    /// `old_size == 0` or `old_size == new_size`, otherwise MUST verify.
    #[serde(with = "hash_vec_hex")]
    pub proof: Vec<Hash>,
    /// Full signed-note bytes of the new pending checkpoint. Persisted
    /// alongside the size/hash so the mirror can serve them back to
    /// `add-entries` clients.
    #[serde_as(as = "Base64As")]
    pub signed_note_bytes: Vec<u8>,
}

/// A Durable Object holding the latest pending (and, in future slices,
/// committed) checkpoint state for a single log origin.
#[durable_object(fetch)]
struct MirrorState {
    state: State,
}

impl DurableObject for MirrorState {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();
        match (req.method(), path.as_str()) {
            (Method::Post, "/update-pending") => {
                // Atomicity of the read-verify-compare-write sequence
                // below relies on Cloudflare Durable Objects' input/output
                // gates:
                //
                //   * Input gate: while this handler is awaiting, no other
                //     incoming message for this DO instance is delivered,
                //     so concurrent /update-pending requests for the same
                //     origin cannot interleave. Each request sees a
                //     consistent view of storage before making its
                //     decision.
                //
                //   * Output gate: the response returned from this handler
                //     is held back until every prior storage write has
                //     been durably committed. This means the caller is
                //     never told "we accepted N+K" before N+K has actually
                //     been persisted as the new pending — so an
                //     immediately-following `add-entries` cannot race the
                //     write.
                //
                // See: https://developers.cloudflare.com/durable-objects/reference/in-memory-state/
                let body: UpdatePendingRequest = req.json().await?;
                let current: PendingCheckpoint = self
                    .state
                    .storage()
                    .get(PENDING_KEY)
                    .await
                    .unwrap_or(None)
                    .unwrap_or_default();
                if current.size != body.old_size {
                    // Spec: respond with the latest pending size so the
                    // caller can build a 409 response body.
                    return Response::from_json(&current).map(|r| r.with_status(409));
                }
                // If old_size == new_size, the spec requires identical
                // root hashes AND the proof MUST be empty.
                if body.old_size == body.new_size {
                    if current.hash.0 != body.new_hash.0 {
                        return Response::from_json(&current).map(|r| r.with_status(409));
                    }
                    if !body.proof.is_empty() {
                        return Response::error(
                            "consistency proof must be empty when old_size == checkpoint size",
                            400,
                        );
                    }
                } else if body.old_size == 0 {
                    // First pending for this origin. Per the spec the
                    // proof MUST be empty.
                    if !body.proof.is_empty() {
                        return Response::error(
                            "consistency proof must be empty when old_size is 0 (first pending checkpoint for this origin)",
                            400,
                        );
                    }
                } else {
                    // 0 < old_size < new_size: consistency proof
                    // required. `verify_consistency_proof` takes the
                    // larger tree first (n=new_size), then the smaller
                    // (m=old_size).
                    if verify_consistency_proof(
                        &body.proof,
                        body.new_size,
                        body.new_hash,
                        body.old_size,
                        current.hash,
                    )
                    .is_err()
                    {
                        return Response::error("consistency proof failed", 422);
                    }
                }
                let new_state = PendingCheckpoint {
                    size: body.new_size,
                    hash: body.new_hash,
                    signed_note_bytes: body.signed_note_bytes,
                };
                self.state.storage().put(PENDING_KEY, &new_state).await?;
                Response::from_json(&new_state)
            }
            _ => Response::error("not found", 404),
        }
    }
}

/// Lookup helper used by the frontend: get a stub for the DO serving a
/// particular log origin.
pub(crate) fn state_stub(env: &Env, origin: &str) -> Result<Stub> {
    let namespace = env.durable_object(MIRROR_STATE_BINDING)?;
    namespace.id_from_name(origin)?.get_stub()
}

// ---------------------------------------------------------------------------
// Serde helpers: emit/parse `Hash` as hex. Same shape as
// `witness_worker/src/witness_state_do.rs`; we use hex so the DO's JSON
// state is human-readable in wrangler's dev console. The exact encoding
// is internal and doesn't need to be compact.
// ---------------------------------------------------------------------------
mod hash_hex {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tlog_core::{Hash, HASH_SIZE};

    pub fn serialize<S>(h: &Hash, ser: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(h.0).serialize(ser)
    }

    pub fn deserialize<'de, D>(de: D) -> std::result::Result<Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        from_hex(&s).map_err(serde::de::Error::custom)
    }

    /// Decode a single hex-encoded [`Hash`]. Shared with the `Vec<Hash>`
    /// helper in the sibling `hash_vec_hex` module.
    pub(super) fn from_hex(s: &str) -> std::result::Result<Hash, String> {
        let bytes: [u8; HASH_SIZE] = hex::decode(s)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|v: Vec<u8>| format!("hash must be {} bytes, got {}", HASH_SIZE, v.len()))?;
        Ok(Hash(bytes))
    }
}

/// Serde helper for `Vec<Hash>`. Encodes as a JSON array of hex strings
/// so the DO RPC body stays human-readable alongside the other
/// [`hash_hex`]-encoded fields.
mod hash_vec_hex {
    use super::hash_hex::from_hex;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tlog_core::Hash;

    pub fn serialize<S>(v: &[Hash], ser: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        v.iter()
            .map(|h| hex::encode(h.0))
            .collect::<Vec<_>>()
            .serialize(ser)
    }

    pub fn deserialize<'de, D>(de: D) -> std::result::Result<Vec<Hash>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strs = Vec::<String>::deserialize(de)?;
        strs.iter()
            .map(|s| from_hex(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{PendingCheckpoint, UpdatePendingRequest};
    use tlog_core::{Hash, HASH_SIZE};

    /// Pin the on-disk JSON layout of `PendingCheckpoint`. Changing
    /// this format would make already-deployed mirrors unable to read
    /// their persisted state after a worker upgrade, so any change
    /// here must be paired with a migration plan.
    #[test]
    fn pending_checkpoint_json_format_unchanged() {
        let mut bytes = [0u8; HASH_SIZE];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let pc = PendingCheckpoint {
            size: 42,
            hash: Hash(bytes),
            signed_note_bytes: b"signed-note-bytes".to_vec(),
        };
        let json = serde_json::to_string(&pc).unwrap();
        // Pin the expected canonical encoding, matching base64 of the
        // signed-note bytes.
        assert_eq!(
            json,
            r#"{"size":42,"hash":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","signed_note_bytes":"c2lnbmVkLW5vdGUtYnl0ZXM="}"#
        );

        // Round-trip: an existing state blob must still parse after a
        // rebuild.
        let decoded: PendingCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.size, 42);
        assert_eq!(decoded.hash.0, bytes);
        assert_eq!(decoded.signed_note_bytes, b"signed-note-bytes");
    }

    /// Pin the wire shape of the internal DO RPC body. The frontend
    /// and the DO are in the same worker, but a format change still
    /// needs both sides updated in lockstep.
    #[test]
    fn update_pending_request_json_format_unchanged() {
        let req = UpdatePendingRequest {
            old_size: 10,
            new_size: 20,
            new_hash: Hash([0xaa; HASH_SIZE]),
            proof: vec![Hash([0xbb; HASH_SIZE]), Hash([0xcc; HASH_SIZE])],
            signed_note_bytes: b"sn".to_vec(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"old_size":10,"new_size":20,"new_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","proof":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"signed_note_bytes":"c24="}"#
        );
        let decoded: UpdatePendingRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.old_size, 10);
        assert_eq!(decoded.new_size, 20);
        assert_eq!(decoded.new_hash.0, [0xaa; HASH_SIZE]);
        assert_eq!(decoded.proof.len(), 2);
        assert_eq!(decoded.signed_note_bytes, b"sn");
    }

    /// The proof array is empty for first-pending and same-size cases;
    /// make sure it round-trips as `[]` not omitted.
    #[test]
    fn update_pending_request_empty_proof_roundtrip() {
        let req = UpdatePendingRequest {
            old_size: 0,
            new_size: 1,
            new_hash: Hash([0u8; HASH_SIZE]),
            proof: vec![],
            signed_note_bytes: vec![],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains(r#""proof":[]"#),
            "proof must be serialized as an empty array, got: {json}"
        );
        let decoded: UpdatePendingRequest = serde_json::from_str(&json).unwrap();
        assert!(decoded.proof.is_empty());
    }

    /// The default `PendingCheckpoint` represents "never accepted a
    /// pending for this origin"; the frontend relies on the zero-sized
    /// default when a DO has no stored state.
    #[test]
    fn pending_checkpoint_default_is_zero() {
        let pc = PendingCheckpoint::default();
        assert_eq!(pc.size, 0);
        assert_eq!(pc.hash.0, [0u8; HASH_SIZE]);
        assert!(pc.signed_note_bytes.is_empty());
    }
}
