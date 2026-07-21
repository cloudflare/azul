// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! [`MirrorState`] Durable Object: per-origin atomic state for the
//! [c2sp.org/tlog-mirror][spec] protocol.
//!
//! The DO holds three pieces of per-origin state, always ordered
//! `committed.size <= next_entry.size <= pending.size`:
//!
//! - `pending`: the latest signed checkpoint accepted via
//!   [`add-checkpoint`][add-cp], the source of truth for the consistency
//!   proof check.
//! - `committed`: the latest *mirror checkpoint*, the state entries have
//!   been fully ingested and cosigned for. Advanced monotonically.
//! - `next_entry`: the *persisted-entry frontier*, how far entry bundles
//!   have been durably written. Advanced monotonically, including by
//!   partial uploads that don't yet reach a signed pending size.
//!
//! It exposes internal RPCs (`/update-pending`, `/get-state`,
//! `/advance-next-entry`, `/commit`) consumed by the frontend handler in
//! the same worker; see each request type and handler for semantics.
//! Atomicity of the read-verify-compare-write sequences comes from the
//! DO's input/output gates.
//!
//! [spec]: https://c2sp.org/tlog-mirror
//! [add-cp]: https://c2sp.org/tlog-mirror#add-checkpoint

use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64 as Base64As, serde_as};
use tlog_core::{Hash, verify_consistency_proof};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::MIRROR_STATE_BINDING;

const PENDING_KEY: &str = "pending";
const COMMITTED_KEY: &str = "committed";
const NEXT_ENTRY_KEY: &str = "next_entry";

/// The persisted *pending checkpoint* for a single log origin.
///
/// Stores the full signed-note bytes (not just size+hash) so the mirror
/// can serve them back to `add-entries` clients and retain the log's
/// signature per spec.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PendingCheckpoint {
    /// Tree size, or zero if no pending checkpoint has been accepted for
    /// this origin.
    pub size: u64,
    /// Root hash. All-zero if `size` is 0.
    #[serde(with = "hash_hex")]
    pub hash: Hash,
    /// Full signed-note bytes, empty if `size` is 0. Base64 in the
    /// on-disk JSON so the state stays valid UTF-8.
    #[serde_as(as = "Base64As")]
    pub signed_note_bytes: Vec<u8>,
}

/// The persisted *committed checkpoint* (the *mirror checkpoint*) for a
/// single log origin: the state entries have been fully ingested and
/// cosigned for. Always at-or-behind [`PendingCheckpoint`], advanced
/// monotonically by `/commit`.
///
/// Stores the full signed-note bytes so the mirror can serve a cosigned
/// checkpoint at `<monitoring>/<encoded-origin>/checkpoint` without
/// looking up historic pending state.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CommittedCheckpoint {
    /// Tree size, or zero if no entries have been committed for this
    /// origin.
    pub size: u64,
    /// Root hash. All-zero if `size` is 0.
    #[serde(with = "hash_hex")]
    pub hash: Hash,
    /// Full signed-note bytes as the log signed them, empty if `size` is
    /// 0. Served with the mirror's cosignature lines appended.
    #[serde_as(as = "Base64As")]
    pub signed_note_bytes: Vec<u8>,
}

/// The persisted *next entry* frontier for a single log origin: how far
/// entry bundles have been durably written.
///
/// Sits between the committed and pending checkpoints. A partial
/// `add-entries` upload advances this without advancing the mirror
/// checkpoint, which requires reaching a signed pending size. `hash` is
/// the tree root at `size`, retained so a resuming `add-entries` can
/// authenticate the frontier.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct NextEntry {
    /// Number of entries durably persisted as bundles for this origin.
    pub size: u64,
    /// Tree root at `size`. All-zero (and unused) when `size` is 0.
    #[serde(with = "hash_hex")]
    pub hash: Hash,
}

/// Snapshot of the pending, committed, and next-entry state, returned by
/// `/get-state`. Used by the `add-entries` handler to early-reject
/// 409/404/422 cases and to resume appending from the persisted frontier.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MirrorStateSnapshot {
    pub pending: PendingCheckpoint,
    pub committed: CommittedCheckpoint,
    /// The persisted-entry frontier. `#[serde(default)]` so a snapshot
    /// serialized by an older worker (before this field existed) still
    /// deserializes to the zero frontier during a rolling deploy.
    #[serde(default)]
    pub next_entry: NextEntry,
}

/// Body of the internal `/commit` RPC, advancing `committed`. See the
/// handler for the compare-and-swap semantics.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct CommitRequest {
    /// Proposed new committed tree size.
    pub size: u64,
    /// Proposed new committed root hash.
    #[serde(with = "hash_hex")]
    pub hash: Hash,
    /// Full signed-note bytes for `(size, hash)`, served with the
    /// mirror's cosignature.
    #[serde_as(as = "Base64As")]
    pub signed_note_bytes: Vec<u8>,
}

/// Body of the internal `/advance-next-entry` RPC, advancing the
/// persisted-entry frontier. See the handler for the semantics.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct AdvanceNextEntryRequest {
    /// Proposed new persisted-entry frontier size.
    pub size: u64,
    /// Tree root at `size`.
    #[serde(with = "hash_hex")]
    pub hash: Hash,
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
    /// `(new_size, new_hash)`, per RFC 6962 section 2.1.2. MUST be empty if
    /// `old_size == 0` or `old_size == new_size`, otherwise MUST verify.
    #[serde(with = "hash_vec_hex")]
    pub proof: Vec<Hash>,
    /// Full signed-note bytes of the new pending checkpoint. Persisted
    /// alongside the size/hash so the mirror can serve them back to
    /// `add-entries` clients.
    #[serde_as(as = "Base64As")]
    pub signed_note_bytes: Vec<u8>,
}

/// A Durable Object holding the latest pending and committed checkpoint
/// state for a single log origin.
#[durable_object(fetch)]
struct MirrorState {
    state: State,
}

impl DurableObject for MirrorState {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.fetch_inner(req).await
    }
}

impl MirrorState {
    async fn fetch_inner(&self, mut req: Request) -> Result<Response> {
        let path = req.path();
        match (req.method(), path.as_str()) {
            (Method::Post, "/get-state") => {
                let snapshot = self.read_snapshot().await?;
                Response::from_json(&snapshot)
            }
            (Method::Post, "/commit") => {
                // Compare-and-swap advance of the mirror checkpoint:
                //   * size > next_entry.size: commit beyond the
                //     persisted-entry frontier, i.e. cosigning entries
                //     that have not been durably written yet; 400. This
                //     preserves `committed.size <= next_entry.size`. Since
                //     `next_entry.size <= pending.size`, it also rejects
                //     commits beyond the accepted pending checkpoint.
                //   * size < committed.size: a concurrent add-entries
                //     already advanced past us. Spec forbids rolling
                //     back, so no-op and return the current state.
                //   * otherwise: advance committed.
                let body: CommitRequest = req.json().await?;
                let snapshot = self.read_snapshot().await?;
                if body.size > snapshot.next_entry.size {
                    return Response::error(
                        format!(
                            "commit beyond persisted-entry frontier: requested size {} > next_entry size {}",
                            body.size, snapshot.next_entry.size
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
            (Method::Post, "/advance-next-entry") => {
                let body: AdvanceNextEntryRequest = req.json().await?;
                self.advance_next_entry(body).await
            }
            (Method::Post, "/update-pending") => {
                // The DO input/output gates make the read-verify-compare-
                // write below atomic: concurrent requests for this origin
                // cannot interleave, and the response is held until the
                // write is durable, so a following add-entries cannot race
                // it.
                let body: UpdatePendingRequest = req.json().await?;
                let current: PendingCheckpoint = self
                    .state
                    .storage()
                    .get(PENDING_KEY)
                    .await?
                    .unwrap_or_default();
                if current.size != body.old_size {
                    // Return the latest pending so the caller can build a
                    // 409 body.
                    return Response::from_json(&current).map(|r| r.with_status(409));
                }
                // Same size: hashes must match and the proof must be empty.
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
                    // First pending for this origin: proof must be empty.
                    if !body.proof.is_empty() {
                        return Response::error(
                            "consistency proof must be empty when old_size is 0 (first pending checkpoint for this origin)",
                            400,
                        );
                    }
                } else {
                    // 0 < old_size < new_size: proof required.
                    // `verify_consistency_proof` takes the larger tree
                    // first, then the smaller.
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
    /// Handle `/advance-next-entry`: monotonically advance the
    /// persisted-entry frontier. Compare-and-swap, like `/commit`:
    ///
    ///   * `size > pending.size`: cannot persist beyond pending; 400.
    ///   * `size <= next_entry.size`: a concurrent `add-entries` already
    ///     reached here; return the current frontier without rewinding.
    ///   * otherwise: advance to `(size, hash)`.
    async fn advance_next_entry(&self, body: AdvanceNextEntryRequest) -> Result<Response> {
        let snapshot = self.read_snapshot().await?;
        if body.size > snapshot.pending.size {
            return Response::error(
                format!(
                    "advance beyond pending: requested size {} > pending size {}",
                    body.size, snapshot.pending.size
                ),
                400,
            );
        }
        if body.size <= snapshot.next_entry.size {
            return Response::from_json(&snapshot.next_entry);
        }
        let new_next = NextEntry {
            size: body.size,
            hash: body.hash,
        };
        self.state.storage().put(NEXT_ENTRY_KEY, &new_next).await?;
        Response::from_json(&new_next)
    }

    /// Read `pending`, `committed`, and `next_entry` from DO storage.
    /// Missing keys default to the zero state ("no state yet").
    async fn read_snapshot(&self) -> Result<MirrorStateSnapshot> {
        let storage = self.state.storage();
        let pending: PendingCheckpoint = storage.get(PENDING_KEY).await?.unwrap_or_default();
        let committed: CommittedCheckpoint = storage.get(COMMITTED_KEY).await?.unwrap_or_default();
        let next_entry: NextEntry = storage.get(NEXT_ENTRY_KEY).await?.unwrap_or_default();
        Ok(MirrorStateSnapshot {
            pending,
            committed,
            next_entry,
        })
    }
}

/// Lookup helper used by the frontend: get a stub for the DO serving a
/// particular log origin.
pub(crate) fn state_stub(env: &Env, origin: &str) -> Result<Stub> {
    let namespace = env.durable_object(MIRROR_STATE_BINDING)?;
    namespace.id_from_name(origin)?.get_stub()
}

// ---------------------------------------------------------------------------
// Serde helpers: emit/parse `Hash` as hex, so the DO's JSON state is
// human-readable in wrangler's dev console.
// ---------------------------------------------------------------------------
mod hash_hex {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tlog_core::{HASH_SIZE, Hash};

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

    /// Decode a single hex-encoded [`struct@Hash`]. Shared with the `Vec<Hash>`
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
        AdvanceNextEntryRequest, CommitRequest, CommittedCheckpoint, MirrorStateSnapshot,
        NextEntry, PendingCheckpoint, UpdatePendingRequest,
    };
    use tlog_core::{HASH_SIZE, Hash};

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
            next_entry: NextEntry {
                size: 4,
                hash: Hash([0xcc; HASH_SIZE]),
            },
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert!(
            json.contains(r#""pending":{"#)
                && json.contains(r#""committed":{"#)
                && json.contains(r#""next_entry":{"#),
            "snapshot must include pending, committed, and next_entry: {json}"
        );
        let decoded: MirrorStateSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.pending.size, 5);
        assert_eq!(decoded.committed.size, 3);
        assert_eq!(decoded.next_entry.size, 4);
    }

    /// A snapshot serialized before `next_entry` existed must still
    /// deserialize (to the zero frontier), so a rolling deploy that mixes
    /// worker versions doesn't fail the `/get-state` round-trip.
    #[test]
    fn mirror_state_snapshot_defaults_next_entry() {
        let legacy = r#"{"pending":{"size":5,"hash":"aa","signed_note_bytes":""},"committed":{"size":3,"hash":"bb","signed_note_bytes":""}}"#
            .replace("\"aa\"", &format!("\"{}\"", "aa".repeat(HASH_SIZE)))
            .replace("\"bb\"", &format!("\"{}\"", "bb".repeat(HASH_SIZE)));
        let decoded: MirrorStateSnapshot = serde_json::from_str(&legacy).unwrap();
        assert_eq!(decoded.next_entry.size, 0);
        assert_eq!(decoded.next_entry.hash.0, [0u8; HASH_SIZE]);
    }

    /// Pin the on-disk JSON layout of `NextEntry`. Same migration
    /// considerations as the other persisted checkpoint types.
    #[test]
    fn next_entry_json_format_unchanged() {
        let ne = NextEntry {
            size: 9,
            hash: Hash([0xde; HASH_SIZE]),
        };
        let json = serde_json::to_string(&ne).unwrap();
        assert_eq!(
            json,
            r#"{"size":9,"hash":"dededededededededededededededededededededededededededededededede"}"#
        );
        let decoded: NextEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.size, 9);
        assert_eq!(decoded.hash.0, [0xde; HASH_SIZE]);
    }

    /// Pin the wire shape of the `/advance-next-entry` request body.
    #[test]
    fn advance_next_entry_request_json_format_unchanged() {
        let req = AdvanceNextEntryRequest {
            size: 11,
            hash: Hash([0xef; HASH_SIZE]),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"size":11,"hash":"efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"}"#
        );
        let decoded: AdvanceNextEntryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.size, 11);
        assert_eq!(decoded.hash.0, [0xef; HASH_SIZE]);
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
