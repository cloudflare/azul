// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! [`WitnessState`] Durable Object: per-origin atomic `(size, hash)` storage
//! for the [c2sp.org/tlog-witness][spec] protocol.
//!
//! The spec's [`add-checkpoint`][add] endpoint requires that checking the
//! client's `old` size against the witness's latest cosigned size, verifying
//! the consistency proof, and persisting the new state all happen atomically
//! for a given origin — otherwise concurrent requests could roll back the
//! cosigned state (see the "race" example in the spec). Durable Objects
//! naturally serialize `fetch` handlers per object, so routing all requests
//! for a given origin to the same DO instance gives us that atomicity for
//! free without any explicit locking.
//!
//! Each origin gets its own DO instance (`idFromName(origin)`). The instance
//! holds a single key, `latest`, whose value is the JSON-serialized
//! [`LatestCheckpoint`].
//!
//! This DO exposes a single internal RPC, consumed only by the frontend
//! handler in the same worker:
//!
//! - `POST /check-and-update` — body is a JSON [`CheckAndUpdateRequest`]
//!   carrying the client-claimed `old_size`, the proposed new `size`+`hash`,
//!   and the consistency proof lines (as hashes). The DO reads its
//!   persisted state, verifies that the recorded size matches `old_size`,
//!   verifies the Merkle consistency proof against the stored root hash
//!   (when a proof is required), and on success writes the new
//!   `(size, hash)` and returns 200 with a [`LatestCheckpoint`] body. On
//!   size / same-size-different-hash mismatch it returns 409 with a
//!   [`LatestCheckpoint`] body carrying the current state so the caller
//!   can produce the spec's `text/x.tlog.size` response. On proof
//!   verification failure it returns 422.
//!
//! Verifying the consistency proof in the same handler that reads and
//! writes the stored state keeps the whole sequence — including the
//! comparison against the stored `latest_hash` — inside a single atomic
//! DO transaction.
//!
//! [spec]: https://c2sp.org/tlog-witness
//! [add]: https://c2sp.org/tlog-witness#add-checkpoint

use serde::{Deserialize, Serialize};
use tlog_tiles::{verify_consistency_proof, Hash};
#[allow(clippy::wildcard_imports)]
use worker::*;

use crate::WITNESS_STATE_BINDING;

const STATE_KEY: &str = "latest";

/// The persisted state for a single log origin.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub struct LatestCheckpoint {
    /// Tree size of the latest checkpoint this witness has cosigned for the
    /// origin. Zero if the witness has never cosigned a checkpoint for this
    /// origin.
    pub size: u64,
    /// Root hash of the latest cosigned checkpoint. All-zero if `size` is 0.
    #[serde(with = "hash_hex")]
    pub hash: Hash,
}

/// Body of the internal `/check-and-update` RPC.
#[derive(Serialize, Deserialize, Debug)]
pub struct CheckAndUpdateRequest {
    /// The client-claimed old size; must equal the persisted size or the
    /// update is rejected (409 Conflict).
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
}

/// A Durable Object holding the latest cosigned (size, hash) for a single
/// log origin.
#[durable_object(fetch)]
struct WitnessState {
    state: State,
}

impl DurableObject for WitnessState {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();
        match (req.method(), path.as_str()) {
            (Method::Post, "/check-and-update") => {
                // Atomicity of the read-verify-compare-write sequence
                // below relies on Cloudflare Durable Objects' input/output
                // gates:
                //
                //   * Input gate: while this handler is awaiting, no other
                //     incoming message for this DO instance is delivered,
                //     so concurrent /check-and-update requests for the same
                //     origin cannot interleave. Each request sees a
                //     consistent view of storage before making its decision.
                //
                //   * Output gate: the response returned from this handler
                //     is held back until every prior storage write has been
                //     durably committed. This means the caller is never
                //     told "we cosigned N+K" before N+K has actually been
                //     persisted as the new latest size — which rules out
                //     the rollback race the tlog-witness spec warns about
                //     (example C there).
                //
                // See: https://developers.cloudflare.com/durable-objects/reference/in-memory-state/
                //
                // Together these two gates make `get(STATE_KEY)` →
                // comparisons → consistency-proof verify → `put(STATE_KEY,
                // …)` behave as a single atomic transaction per DO without
                // us having to write any explicit locking or
                // `put_multiple`/`transaction` calls. The proof is
                // verified against the exact stored hash that the
                // compare-and-swap will check, so there is no TOCTOU
                // window.
                let body: CheckAndUpdateRequest = req.json().await?;
                let current: LatestCheckpoint = self
                    .state
                    .storage()
                    .get(STATE_KEY)
                    .await
                    .unwrap_or(None)
                    .unwrap_or_default();
                if current.size != body.old_size {
                    // Spec: respond with the latest size so the caller can
                    // build a 409 response body.
                    return Response::from_json(&current).map(|r| r.with_status(409));
                }
                // If old_size == new_size, the spec requires identical root
                // hashes AND the proof MUST be empty.
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
                    // First cosignature for this origin. Per the spec the
                    // proof MUST be empty.
                    if !body.proof.is_empty() {
                        return Response::error(
                            "consistency proof must be empty when old_size is 0 (first cosignature for this origin)",
                            400,
                        );
                    }
                } else {
                    // 0 < old_size < new_size: consistency proof required.
                    // `verify_consistency_proof` takes the larger tree
                    // first (n=new_size), then the smaller (m=old_size).
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
                let new_state = LatestCheckpoint {
                    size: body.new_size,
                    hash: body.new_hash,
                };
                self.state.storage().put(STATE_KEY, &new_state).await?;
                Response::from_json(&new_state)
            }
            _ => Response::error("not found", 404),
        }
    }
}

/// Lookup helper used by the frontend: get a stub for the DO serving a
/// particular log origin.
pub(crate) fn state_stub(env: &Env, origin: &str) -> Result<Stub> {
    let namespace = env.durable_object(WITNESS_STATE_BINDING)?;
    namespace.id_from_name(origin)?.get_stub()
}

// ---------------------------------------------------------------------------
// Serde helper: emit/parse `Hash` as hex. We use hex so the DO's JSON state
// is human-readable in wrangler's dev console; the exact encoding is internal
// and doesn't need to be compact.
// ---------------------------------------------------------------------------
mod hash_hex {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tlog_tiles::{Hash, HASH_SIZE};

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

/// Serde helper for `Vec<Hash>`. Encodes as a JSON array of hex strings so
/// the DO RPC body stays human-readable alongside the other
/// [`hash_hex`]-encoded fields.
mod hash_vec_hex {
    use super::hash_hex::from_hex;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use tlog_tiles::Hash;

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
    use super::{CheckAndUpdateRequest, LatestCheckpoint};
    use tlog_tiles::{Hash, HASH_SIZE};

    /// Pin the on-disk JSON layout of `LatestCheckpoint`. Changing this
    /// format would make already-deployed witnesses unable to read their
    /// persisted state after a worker upgrade, so any change here must be
    /// paired with a migration plan.
    #[test]
    fn latest_checkpoint_json_format_unchanged() {
        let mut bytes = [0u8; HASH_SIZE];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let lc = LatestCheckpoint {
            size: 42,
            hash: Hash(bytes),
        };
        let json = serde_json::to_string(&lc).unwrap();
        assert_eq!(
            json,
            r#"{"size":42,"hash":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}"#
        );

        // Round-trip: an existing state blob must still parse after a
        // rebuild.
        let decoded: LatestCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.size, 42);
        assert_eq!(decoded.hash.0, bytes);
    }

    /// Pin the wire shape of the internal DO RPC body. The frontend and
    /// the DO are in the same worker, but a format change still needs
    /// both sides updated in lockstep.
    #[test]
    fn check_and_update_request_json_format_unchanged() {
        let req = CheckAndUpdateRequest {
            old_size: 10,
            new_size: 20,
            new_hash: Hash([0xaa; HASH_SIZE]),
            proof: vec![Hash([0xbb; HASH_SIZE]), Hash([0xcc; HASH_SIZE])],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"old_size":10,"new_size":20,"new_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","proof":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]}"#
        );

        let decoded: CheckAndUpdateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.old_size, 10);
        assert_eq!(decoded.new_size, 20);
        assert_eq!(decoded.new_hash.0, [0xaa; HASH_SIZE]);
        assert_eq!(decoded.proof.len(), 2);
        assert_eq!(decoded.proof[0].0, [0xbb; HASH_SIZE]);
        assert_eq!(decoded.proof[1].0, [0xcc; HASH_SIZE]);
    }

    /// The proof array is empty for first-cosign and same-size cases; make
    /// sure it round-trips as `[]` not omitted.
    #[test]
    fn check_and_update_request_empty_proof_roundtrip() {
        let req = CheckAndUpdateRequest {
            old_size: 0,
            new_size: 1,
            new_hash: Hash([0u8; HASH_SIZE]),
            proof: vec![],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains(r#""proof":[]"#),
            "proof must be serialized as an empty array, got: {json}"
        );
        let decoded: CheckAndUpdateRequest = serde_json::from_str(&json).unwrap();
        assert!(decoded.proof.is_empty());
    }

    /// The default `LatestCheckpoint` represents "never cosigned for this
    /// origin"; the frontend relies on the zero-sized default when a DO
    /// has no stored state.
    #[test]
    fn latest_checkpoint_default_is_zero() {
        let lc = LatestCheckpoint::default();
        assert_eq!(lc.size, 0);
        assert_eq!(lc.hash.0, [0u8; HASH_SIZE]);
    }
}
