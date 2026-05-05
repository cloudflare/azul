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
//! - `committed`: the latest *mirror checkpoint* — the state for which
//!   the mirror has fully ingested entries and emitted a cosignature.
//!   Always at-or-behind `pending`. Advanced by `add-entries` once a
//!   round of entry packages catches up to a pending checkpoint;
//!   advancement is monotone (the DO refuses to roll back).
//!
//! The DO exposes three internal RPCs consumed by the frontend handler
//! in the same worker:
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
//! - `POST /get-state` — read-only snapshot of both `pending` and
//!   `committed`. Used by the `add-entries` handler (future slice) to
//!   early-reject 409 / 404 cases before reading the streaming
//!   request body.
//!
//! - `POST /commit` — body is a JSON [`CommitRequest`] carrying a new
//!   `(size, hash, signed_note_bytes)` tuple. The DO atomically
//!   advances `committed` to that tuple iff the proposed `size` is
//!   `>= committed.size` and `<= pending.size`. If `size <
//!   committed.size`, a concurrent `add-entries` already advanced past
//!   us; the DO returns 200 with the *current* committed state and
//!   does not write (the caller treats this as a no-op success). If
//!   `size > pending.size`, the request is malformed (cannot commit
//!   beyond pending); 400.
//!
//! Atomicity of the read-verify-compare-write sequences is provided by
//! Cloudflare Durable Objects' input/output gates (see the inline
//! commentary in the handlers).
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
const COMMITTED_KEY: &str = "committed";

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

/// The persisted *committed checkpoint* (a.k.a. the *mirror
/// checkpoint*) for a single log origin.
///
/// This is the state for which the mirror has fully ingested entries
/// and is willing to emit a cosignature on. Always at-or-behind
/// [`PendingCheckpoint`]. Advanced monotonically by `/commit`.
///
/// We store the full signed-note bytes here too so the mirror can
/// serve a cosigned checkpoint at `<monitoring>/<encoded-origin>/checkpoint`
/// without needing to look up historic pending state. The bytes match
/// what the log signed for this `(size, hash)` — i.e. they are a
/// historic value of [`PendingCheckpoint::signed_note_bytes`] (or the
/// current one, when committed has caught up to pending).
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CommittedCheckpoint {
    /// Tree size of the latest committed (mirror) checkpoint. Zero if
    /// the mirror has not yet committed any entries for this origin.
    pub size: u64,
    /// Root hash of the latest committed checkpoint. All-zero if
    /// `size` is 0.
    #[serde(with = "hash_hex")]
    pub hash: Hash,
    /// The full signed-note bytes for the committed `(size, hash)`,
    /// as the log originally signed them. Empty if `size` is 0. The
    /// mirror's `<monitoring>/<encoded-origin>/checkpoint` serves
    /// these bytes plus the mirror's own cosignature lines.
    #[serde_as(as = "Base64As")]
    pub signed_note_bytes: Vec<u8>,
}

/// Snapshot of both the pending and committed state, returned by
/// `/get-state`. Used by the `add-entries` handler (future slice) to
/// early-reject 409/404 cases before reading the streaming request
/// body.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MirrorStateSnapshot {
    pub pending: PendingCheckpoint,
    pub committed: CommittedCheckpoint,
}

/// Body of the internal `/commit` RPC. The DO atomically advances
/// `committed` to `(size, hash, signed_note_bytes)` iff `size` is at
/// least the current committed size and at most the current pending
/// size. See the module-level comment for the full state-machine.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct CommitRequest {
    /// Proposed new committed tree size.
    pub size: u64,
    /// Proposed new committed root hash.
    #[serde(with = "hash_hex")]
    pub hash: Hash,
    /// Full signed-note bytes for `(size, hash)`. Persisted alongside
    /// size+hash so the mirror can serve them at
    /// `<monitoring>/<encoded-origin>/checkpoint` along with its
    /// cosignature.
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
            (Method::Post, "/get-state") => {
                // Read-only snapshot of both pending and committed.
                // Atomicity comes for free from the DO input gate: no
                // other handler is running concurrently for this DO,
                // so the pair is consistent.
                let snapshot = self.read_snapshot().await;
                Response::from_json(&snapshot)
            }
            (Method::Post, "/commit") => {
                // Atomic mirror-checkpoint advance. Compare-and-swap
                // semantics:
                //
                //   * If `body.size < current_committed.size`, a
                //     concurrent `add-entries` for the same origin
                //     already advanced past us. The spec is explicit
                //     that the mirror MUST NOT roll back the mirror
                //     checkpoint in this case; we treat the call as a
                //     no-op success and return the *current* committed
                //     state so the caller knows the mirror is already
                //     ahead.
                //
                //   * If `body.size > current_pending.size`, the
                //     caller is trying to commit beyond what the
                //     mirror has accepted as a pending checkpoint
                //     (programmer error in the frontend or stale
                //     pending state); 400.
                //
                //   * Otherwise (committed.size <= body.size <=
                //     pending.size), advance committed to the
                //     proposed `(size, hash, signed_note_bytes)`.
                //
                // The DO input gate serializes commits for this
                // origin, so two concurrent `add-entries` calls each
                // see a consistent view and the higher one wins.
                let body: CommitRequest = req.json().await?;
                let snapshot = self.read_snapshot().await;
                if body.size > snapshot.pending.size {
                    return Response::error(
                        format!(
                            "commit beyond pending: requested size {} > pending size {}",
                            body.size, snapshot.pending.size
                        ),
                        400,
                    );
                }
                if body.size < snapshot.committed.size {
                    // Already ahead; no-op success.
                    return Response::from_json(&snapshot.committed);
                }
                let new_committed = CommittedCheckpoint {
                    size: body.size,
                    hash: body.hash,
                    signed_note_bytes: body.signed_note_bytes,
                };
                self.state
                    .storage()
                    .put(COMMITTED_KEY, &new_committed)
                    .await?;
                Response::from_json(&new_committed)
            }
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

impl MirrorState {
    /// Read both `pending` and `committed` from DO storage. Missing
    /// keys are treated as `Default::default()` (size 0, all-zero
    /// hash, empty bytes), representing "this origin has no state
    /// yet".
    async fn read_snapshot(&self) -> MirrorStateSnapshot {
        let pending: PendingCheckpoint = self
            .state
            .storage()
            .get(PENDING_KEY)
            .await
            .unwrap_or(None)
            .unwrap_or_default();
        let committed: CommittedCheckpoint = self
            .state
            .storage()
            .get(COMMITTED_KEY)
            .await
            .unwrap_or(None)
            .unwrap_or_default();
        MirrorStateSnapshot { pending, committed }
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
    use super::{
        CommitRequest, CommittedCheckpoint, MirrorStateSnapshot, PendingCheckpoint,
        UpdatePendingRequest,
    };
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

    /// Pin the on-disk JSON layout of `CommittedCheckpoint`. Same
    /// migration considerations as `PendingCheckpoint`: deployed
    /// mirrors must keep parsing this after a worker upgrade.
    #[test]
    fn committed_checkpoint_json_format_unchanged() {
        let mut bytes = [0u8; HASH_SIZE];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let cc = CommittedCheckpoint {
            size: 42,
            hash: Hash(bytes),
            signed_note_bytes: b"signed-note-bytes".to_vec(),
        };
        let json = serde_json::to_string(&cc).unwrap();
        assert_eq!(
            json,
            r#"{"size":42,"hash":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","signed_note_bytes":"c2lnbmVkLW5vdGUtYnl0ZXM="}"#
        );
        let decoded: CommittedCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.size, 42);
        assert_eq!(decoded.hash.0, bytes);
        assert_eq!(decoded.signed_note_bytes, b"signed-note-bytes");
    }

    /// The default `CommittedCheckpoint` represents "never committed
    /// any entries for this origin".
    #[test]
    fn committed_checkpoint_default_is_zero() {
        let cc = CommittedCheckpoint::default();
        assert_eq!(cc.size, 0);
        assert_eq!(cc.hash.0, [0u8; HASH_SIZE]);
        assert!(cc.signed_note_bytes.is_empty());
    }

    /// Pin the wire shape of the `/get-state` response.
    #[test]
    fn mirror_state_snapshot_json_format() {
        let snap = MirrorStateSnapshot {
            pending: PendingCheckpoint {
                size: 5,
                hash: Hash([0xaa; HASH_SIZE]),
                signed_note_bytes: b"p".to_vec(),
            },
            committed: CommittedCheckpoint {
                size: 3,
                hash: Hash([0xbb; HASH_SIZE]),
                signed_note_bytes: b"c".to_vec(),
            },
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert!(
            json.contains(r#""pending":{"#) && json.contains(r#""committed":{"#),
            "snapshot must include both pending and committed: {json}"
        );
        let decoded: MirrorStateSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.pending.size, 5);
        assert_eq!(decoded.committed.size, 3);
    }

    /// Pin the wire shape of the `/commit` request body.
    #[test]
    fn commit_request_json_format_unchanged() {
        let req = CommitRequest {
            size: 7,
            hash: Hash([0xcc; HASH_SIZE]),
            signed_note_bytes: b"cm".to_vec(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"size":7,"hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","signed_note_bytes":"Y20="}"#
        );
        let decoded: CommitRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.size, 7);
        assert_eq!(decoded.hash.0, [0xcc; HASH_SIZE]);
        assert_eq!(decoded.signed_note_bytes, b"cm");
    }
}
