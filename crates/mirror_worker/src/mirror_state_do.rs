// Copyright (c) 2025-2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! [`MirrorState`] Durable Object: per-origin atomic state for the
//! [c2sp.org/tlog-mirror][spec] protocol.
//!
//! Mirror-enabled state is ordered `committed.size <= next_entry.size <= pending.size`.
//! If `publishing` exists, `/commit` finishes publishing it before evaluating
//! another request. Publication is ordered `publishing -> R2 -> committed -> clear`.
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

use std::future::Future;

use generic_log_worker::ObjectBackend;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64 as Base64As, serde_as};
use tlog_core::Hash;
use tlog_witness::{
    CheckpointState, CheckpointTransitionError, ProofRequirement, validate_checkpoint_transition,
};
use tokio::sync::Mutex;
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::{MIRROR_STATE_BINDING, commit, storage::load_origin_bucket};

const PENDING_KEY: &str = "pending";
const COMMITTED_KEY: &str = "committed";
const PUBLISHING_KEY: &str = "publishing";
const NEXT_ENTRY_KEY: &str = "next_entry";

/// The persisted latest checkpoint for a single log origin.
///
/// This is the witness's latest checkpoint and the mirror's pending
/// checkpoint. The signed note is retained for mirror `add-entries`.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PendingCheckpoint {
    /// Tree size. Zero is a valid accepted checkpoint.
    pub size: u64,
    /// Root hash. All-zero if `size` is 0.
    #[serde(with = "generic_log_worker::hash_serde::hex")]
    pub hash: Hash,
    /// Full signed-note bytes, encoded as base64 in persisted JSON.
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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommittedCheckpoint {
    /// Tree size. Zero is a valid committed empty-tree checkpoint.
    pub size: u64,
    /// Root hash. All-zero if `size` is 0.
    #[serde(with = "generic_log_worker::hash_serde::hex")]
    pub hash: Hash,
    /// The source log's signed checkpoint note.
    #[serde_as(as = "Base64As")]
    pub checkpoint_note_bytes: Vec<u8>,
    /// The served checkpoint bytes: the log's signed note with the
    /// mirror's cosignature line(s) appended, exactly as written to R2.
    #[serde_as(as = "Base64As")]
    pub signed_note_bytes: Vec<u8>,
}

/// A checkpoint whose publication must complete before another commit.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
struct PublicationIntent(CommittedCheckpoint);

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
    #[serde(with = "generic_log_worker::hash_serde::hex")]
    pub hash: Hash,
}

/// Snapshot of the pending, committed, and next-entry state, returned by
/// `/get-state`. Used by the `add-entries` handler to early-reject
/// 409/404/422 cases and to resume appending from the persisted frontier.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MirrorStateSnapshot {
    pub pending: Option<PendingCheckpoint>,
    pub committed: Option<CommittedCheckpoint>,
    /// The persisted-entry frontier.
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
    #[serde(with = "generic_log_worker::hash_serde::hex")]
    pub hash: Hash,
    /// The source log's signed checkpoint note.
    #[serde_as(as = "Base64As")]
    pub checkpoint_note_bytes: Vec<u8>,
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
    #[serde(with = "generic_log_worker::hash_serde::hex")]
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
    #[serde(with = "generic_log_worker::hash_serde::hex")]
    pub new_hash: Hash,
    /// Consistency proof from `(old_size, stored_hash)` to
    /// `(new_size, new_hash)`, per RFC 6962 section 2.1.2. MUST be empty if
    /// `old_size == 0` or `old_size == new_size`, otherwise MUST verify.
    #[serde(with = "generic_log_worker::hash_serde::vec_hex")]
    pub proof: Vec<Hash>,
    /// Full signed-note bytes of the new pending checkpoint. Persisted
    /// alongside the size/hash so the mirror can serve them back to
    /// `add-entries` clients.
    #[serde_as(as = "Base64As")]
    pub signed_note_bytes: Vec<u8>,
}

/// Per-origin witness and mirror state.
#[durable_object(fetch)]
struct MirrorState {
    state: State,
    env: Env,
    /// Invariant: publication recovery and new commits are serialized.
    commit_mux: Mutex<()>,
}

// SAFETY: Durable Objects are single-threaded; the `RefUnwindSafe` bound
// is required by `wasm-bindgen` when building with `panic=unwind` (so the
// sentry catch-unwind guard can wrap the fetch handler).
impl std::panic::RefUnwindSafe for MirrorState {}

impl DurableObject for MirrorState {
    fn new(state: State, env: Env) -> Self {
        crate::init_sentry(&env);
        Self {
            state,
            env,
            commit_mux: Mutex::new(()),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        generic_log_worker::obs::sentry::catch_unwind_report_and_flush(
            &[("handler", "do_fetch"), ("do_type", "mirror_state")],
            self.fetch_inner(req),
        )
        .await
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
                let body: CommitRequest = req.json().await?;
                self.commit(body).await
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
                let current: Option<PendingCheckpoint> =
                    self.state.storage().get(PENDING_KEY).await?;
                let transition = validate_checkpoint_transition(
                    current.as_ref().map(|checkpoint| CheckpointState {
                        size: checkpoint.size,
                        hash: checkpoint.hash,
                    }),
                    body.old_size,
                    CheckpointState {
                        size: body.new_size,
                        hash: body.new_hash,
                    },
                    &body.proof,
                );
                if let Err(error) = transition {
                    return match error {
                        CheckpointTransitionError::OldSizeMismatch
                        | CheckpointTransitionError::HashMismatch => {
                            Response::from_json(&current.unwrap_or_default())
                                .map(|response| response.with_status(409))
                        }
                        CheckpointTransitionError::ProofMustBeEmpty(ProofRequirement::SameSize) => {
                            Response::error(
                                "consistency proof must be empty when old_size == checkpoint size",
                                400,
                            )
                        }
                        CheckpointTransitionError::ProofMustBeEmpty(ProofRequirement::Initial) => {
                            Response::error(
                                "consistency proof must be empty when old_size is 0 (first pending checkpoint for this origin)",
                                400,
                            )
                        }
                        CheckpointTransitionError::ConsistencyProofFailed => {
                            Response::error("consistency proof failed", 422)
                        }
                        CheckpointTransitionError::InvalidEmptyTreeHash => Response::error(
                            "size-zero checkpoint must use the empty-tree hash",
                            400,
                        ),
                    };
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
    /// Reconcile publication, then publish without rewinding.
    async fn commit(&self, body: CommitRequest) -> Result<Response> {
        let _guard = self.commit_mux.lock().await;

        let origin = self
            .state
            .id()
            .name()
            .ok_or_else(|| Error::from("mirror state DO missing origin name"))?;
        let bucket = load_origin_bucket(&self.env, &origin)?;
        let storage = self.state.storage();

        if let Some(intent) = storage.get::<PublicationIntent>(PUBLISHING_KEY).await? {
            finish_publication(
                &bucket,
                &intent.0,
                storage.put(COMMITTED_KEY, &intent.0),
                async {
                    storage.delete(PUBLISHING_KEY).await?;
                    Ok(())
                },
            )
            .await?;
        }

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
        if let Some(committed) = snapshot.committed.as_ref()
            && body.size < committed.size
        {
            return Response::from_json(committed);
        }
        if let Some(committed) = snapshot.committed.as_ref()
            && body.size == committed.size
            && body.hash != committed.hash
        {
            return Response::error("commit hash differs at the committed size", 400);
        }

        let new_committed = CommittedCheckpoint {
            size: body.size,
            hash: body.hash,
            checkpoint_note_bytes: body.checkpoint_note_bytes,
            signed_note_bytes: body.signed_note_bytes,
        };
        storage
            .put(PUBLISHING_KEY, &PublicationIntent(new_committed.clone()))
            .await?;
        finish_publication(
            &bucket,
            &new_committed,
            storage.put(COMMITTED_KEY, &new_committed),
            async {
                storage.delete(PUBLISHING_KEY).await?;
                Ok(())
            },
        )
        .await?;

        Response::from_json(&new_committed)
    }

    /// Handle `/advance-next-entry`: monotonically advance the
    /// persisted-entry frontier. Compare-and-swap, like `/commit`:
    ///
    ///   * `size > pending.size`: cannot persist beyond pending; 400.
    ///   * `size <= next_entry.size`: a concurrent `add-entries` already
    ///     reached here; return the current frontier without rewinding.
    ///   * otherwise: advance to `(size, hash)`.
    async fn advance_next_entry(&self, body: AdvanceNextEntryRequest) -> Result<Response> {
        let snapshot = self.read_snapshot().await?;
        let Some(pending) = snapshot.pending.as_ref() else {
            return Response::error("advance without a pending checkpoint", 400);
        };
        if body.size > pending.size {
            return Response::error(
                format!(
                    "advance beyond pending: requested size {} > pending size {}",
                    body.size, pending.size
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
    /// Missing pending and committed keys remain `None`; `next_entry`
    /// defaults to the zero frontier.
    async fn read_snapshot(&self) -> Result<MirrorStateSnapshot> {
        let storage = self.state.storage();
        let pending: Option<PendingCheckpoint> = storage.get(PENDING_KEY).await?;
        let committed: Option<CommittedCheckpoint> = storage.get(COMMITTED_KEY).await?;
        let next_entry: NextEntry = storage.get(NEXT_ENTRY_KEY).await?.unwrap_or_default();
        Ok(MirrorStateSnapshot {
            pending,
            committed,
            next_entry,
        })
    }
}

/// Complete an intent in the order required for crash recovery.
async fn finish_publication<O, F, G>(
    object: &O,
    checkpoint: &CommittedCheckpoint,
    persist: F,
    clear: G,
) -> Result<()>
where
    O: ObjectBackend,
    F: Future<Output = Result<()>>,
    G: Future<Output = Result<()>>,
{
    commit::write_checkpoint(object, checkpoint.signed_note_bytes.clone()).await?;
    persist.await?;
    clear.await
}

/// Lookup helper used by the frontend: get a stub for the DO serving a
/// particular log origin.
pub(crate) fn state_stub(env: &Env, origin: &str) -> Result<Stub> {
    let namespace = env.durable_object(MIRROR_STATE_BINDING)?;
    namespace.id_from_name(origin)?.get_stub()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unused_async_trait_impl)]

    use super::{
        AdvanceNextEntryRequest, CommitRequest, CommittedCheckpoint, MirrorStateSnapshot,
        NextEntry, PendingCheckpoint, PublicationIntent, UpdatePendingRequest, finish_publication,
    };
    use generic_log_worker::{ObjectBackend, log_ops::UploadOptions};
    use std::{cell::RefCell, collections::HashMap};
    use tlog_core::{HASH_SIZE, Hash};

    #[test]
    fn pending_checkpoint_json_format() {
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

        let decoded: PendingCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.size, 42);
        assert_eq!(decoded.hash.0, bytes);
        assert_eq!(decoded.signed_note_bytes, b"signed-note-bytes");
    }

    /// Pin the wire shape of the internal DO RPC body. The frontend
    /// and the DO are in the same worker, but a format change still
    /// needs both sides updated in lockstep.
    #[test]
    fn update_pending_request_json_format() {
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

    #[test]
    fn pending_checkpoint_default_is_zero() {
        let pc = PendingCheckpoint::default();
        assert_eq!(pc.size, 0);
        assert_eq!(pc.hash.0, [0u8; HASH_SIZE]);
        assert!(pc.signed_note_bytes.is_empty());
    }

    #[test]
    fn committed_checkpoint_json_format() {
        let mut bytes = [0u8; HASH_SIZE];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let cc = CommittedCheckpoint {
            size: 42,
            hash: Hash(bytes),
            checkpoint_note_bytes: b"source-note-bytes".to_vec(),
            signed_note_bytes: b"signed-note-bytes".to_vec(),
        };
        let json = serde_json::to_string(&cc).unwrap();
        assert_eq!(
            json,
            r#"{"size":42,"hash":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","checkpoint_note_bytes":"c291cmNlLW5vdGUtYnl0ZXM=","signed_note_bytes":"c2lnbmVkLW5vdGUtYnl0ZXM="}"#
        );
        let decoded: CommittedCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.size, 42);
        assert_eq!(decoded.hash.0, bytes);
        assert_eq!(decoded.checkpoint_note_bytes, b"source-note-bytes");
        assert_eq!(decoded.signed_note_bytes, b"signed-note-bytes");
    }

    #[test]
    fn publication_intent_json_format() {
        let intent = PublicationIntent(CommittedCheckpoint {
            size: 42,
            hash: Hash([0xaa; HASH_SIZE]),
            checkpoint_note_bytes: b"source".to_vec(),
            signed_note_bytes: b"served".to_vec(),
        });
        let json = serde_json::to_string(&intent).unwrap();
        assert_eq!(
            json,
            r#"{"size":42,"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","checkpoint_note_bytes":"c291cmNl","signed_note_bytes":"c2VydmVk"}"#
        );
        let decoded: PublicationIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.0.size, 42);
        assert_eq!(decoded.0.signed_note_bytes, b"served");
    }

    /// Pin the wire shape of the `/get-state` response.
    #[test]
    fn mirror_state_snapshot_json_format() {
        let snap = MirrorStateSnapshot {
            pending: Some(PendingCheckpoint {
                size: 5,
                hash: Hash([0xaa; HASH_SIZE]),
                signed_note_bytes: b"p".to_vec(),
            }),
            committed: Some(CommittedCheckpoint {
                size: 3,
                hash: Hash([0xbb; HASH_SIZE]),
                checkpoint_note_bytes: b"p".to_vec(),
                signed_note_bytes: b"c".to_vec(),
            }),
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
        assert_eq!(decoded.pending.unwrap().size, 5);
        assert_eq!(decoded.committed.unwrap().size, 3);
        assert_eq!(decoded.next_entry.size, 4);
    }

    #[test]
    fn snapshot_distinguishes_no_pending_from_size_zero() {
        let no_pending = MirrorStateSnapshot::default();
        assert!(no_pending.pending.is_none());

        let zero = MirrorStateSnapshot {
            pending: Some(PendingCheckpoint {
                size: 0,
                hash: tlog_core::EMPTY_HASH,
                signed_note_bytes: b"zero checkpoint".to_vec(),
            }),
            ..MirrorStateSnapshot::default()
        };
        let decoded: MirrorStateSnapshot =
            serde_json::from_str(&serde_json::to_string(&zero).unwrap()).unwrap();
        let pending = decoded.pending.unwrap();
        assert_eq!(pending.size, 0);
        assert_eq!(pending.hash, tlog_core::EMPTY_HASH);
        assert!(!pending.signed_note_bytes.is_empty());
    }

    #[test]
    fn snapshot_distinguishes_no_commit_from_size_zero() {
        let no_commit = MirrorStateSnapshot::default();
        assert!(no_commit.committed.is_none());

        let zero = MirrorStateSnapshot {
            committed: Some(CommittedCheckpoint {
                size: 0,
                hash: tlog_core::EMPTY_HASH,
                checkpoint_note_bytes: b"zero checkpoint".to_vec(),
                signed_note_bytes: b"cosigned zero checkpoint".to_vec(),
            }),
            ..MirrorStateSnapshot::default()
        };
        let json = serde_json::to_string(&zero).unwrap();
        assert!(json.contains(r#""committed":{"size":0"#));
        let decoded: MirrorStateSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.committed.unwrap().size, 0);
    }

    #[derive(Default)]
    struct RecordingBackend {
        objects: RefCell<HashMap<String, Vec<u8>>>,
        events: RefCell<Vec<&'static str>>,
        fail_upload: bool,
    }

    impl ObjectBackend for RecordingBackend {
        async fn upload<S: AsRef<str>, D: Into<Vec<u8>>>(
            &self,
            key: S,
            data: D,
            _opts: &UploadOptions,
        ) -> worker::Result<()> {
            self.events.borrow_mut().push("r2");
            if self.fail_upload {
                return Err(worker::Error::from("injected R2 failure"));
            }
            self.objects
                .borrow_mut()
                .insert(key.as_ref().to_owned(), data.into());
            Ok(())
        }

        async fn fetch<S: AsRef<str>>(&self, key: S) -> worker::Result<Option<Vec<u8>>> {
            Ok(self.objects.borrow().get(key.as_ref()).cloned())
        }
    }

    #[tokio::test]
    async fn publication_finishes_in_order() {
        let backend = RecordingBackend::default();
        let events = &backend.events;
        let checkpoint = CommittedCheckpoint {
            size: 1,
            hash: Hash([1; HASH_SIZE]),
            checkpoint_note_bytes: vec![],
            signed_note_bytes: b"checkpoint".to_vec(),
        };
        finish_publication(
            &backend,
            &checkpoint,
            async {
                events.borrow_mut().push("committed");
                Ok(())
            },
            async {
                events.borrow_mut().push("clear");
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(&*backend.events.borrow(), &["r2", "committed", "clear"]);
    }

    #[tokio::test]
    async fn publication_r2_failure_does_not_persist_state() {
        let backend = RecordingBackend {
            fail_upload: true,
            ..RecordingBackend::default()
        };
        let events = &backend.events;
        let checkpoint = CommittedCheckpoint {
            size: 1,
            hash: Hash([1; HASH_SIZE]),
            checkpoint_note_bytes: vec![],
            signed_note_bytes: b"checkpoint".to_vec(),
        };
        assert!(
            finish_publication(
                &backend,
                &checkpoint,
                async {
                    events.borrow_mut().push("committed");
                    Ok(())
                },
                async {
                    events.borrow_mut().push("clear");
                    Ok(())
                },
            )
            .await
            .is_err()
        );
        assert_eq!(&*backend.events.borrow(), &["r2"]);
    }

    #[tokio::test]
    async fn publication_state_failure_retains_intent() {
        let backend = RecordingBackend::default();
        let events = &backend.events;
        let checkpoint = CommittedCheckpoint {
            size: 1,
            hash: Hash([1; HASH_SIZE]),
            checkpoint_note_bytes: vec![],
            signed_note_bytes: b"checkpoint".to_vec(),
        };
        assert!(
            finish_publication(
                &backend,
                &checkpoint,
                async {
                    events.borrow_mut().push("committed");
                    Err(worker::Error::from("injected state failure"))
                },
                async {
                    events.borrow_mut().push("clear");
                    Ok(())
                },
            )
            .await
            .is_err()
        );
        assert_eq!(&*backend.events.borrow(), &["r2", "committed"]);
    }

    #[tokio::test]
    async fn publication_clear_failure_is_retryable() {
        let backend = RecordingBackend::default();
        let events = &backend.events;
        let checkpoint = CommittedCheckpoint {
            size: 1,
            hash: Hash([1; HASH_SIZE]),
            checkpoint_note_bytes: vec![],
            signed_note_bytes: b"checkpoint".to_vec(),
        };
        assert!(
            finish_publication(
                &backend,
                &checkpoint,
                async {
                    events.borrow_mut().push("committed");
                    Ok(())
                },
                async {
                    events.borrow_mut().push("clear");
                    Err(worker::Error::from("injected clear failure"))
                },
            )
            .await
            .is_err()
        );
        finish_publication(
            &backend,
            &checkpoint,
            async {
                events.borrow_mut().push("committed");
                Ok(())
            },
            async {
                events.borrow_mut().push("clear");
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(
            &*backend.events.borrow(),
            &["r2", "committed", "clear", "r2", "committed", "clear"]
        );
    }

    #[test]
    fn next_entry_json_format() {
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
    fn advance_next_entry_request_json_format() {
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
    fn commit_request_json_format() {
        let req = CommitRequest {
            size: 7,
            hash: Hash([0xcc; HASH_SIZE]),
            checkpoint_note_bytes: b"cp".to_vec(),
            signed_note_bytes: b"cm".to_vec(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"size":7,"hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","checkpoint_note_bytes":"Y3A=","signed_note_bytes":"Y20="}"#
        );
        let decoded: CommitRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.size, 7);
        assert_eq!(decoded.hash.0, [0xcc; HASH_SIZE]);
        assert_eq!(decoded.checkpoint_note_bytes, b"cp");
        assert_eq!(decoded.signed_note_bytes, b"cm");
    }
}
