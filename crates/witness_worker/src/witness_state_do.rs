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
//! This DO exposes a minimal internal RPC surface, consumed only by the
//! frontend handler in the same worker:
//!
//! - `GET /get` — return the current [`LatestCheckpoint`] (or `{ "size": 0 }`
//!   if never updated).
//! - `POST /check-and-update` — body is a JSON [`CheckAndUpdateRequest`]
//!   containing the client-claimed `old_size` and the proposed new
//!   `size`+`hash`. If the recorded latest size matches `old_size` (or there
//!   is no record yet and `old_size == 0`), the record is replaced with the
//!   proposal and the endpoint returns 200. Otherwise it returns 409 with
//!   the current size in the body so the caller can produce the spec's
//!   `text/x.tlog.size` response.
//!
//! [spec]: https://c2sp.org/tlog-witness
//! [add]: https://c2sp.org/tlog-witness#add-checkpoint

use serde::{Deserialize, Serialize};
use tlog_tiles::Hash;
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
    /// update is rejected.
    pub old_size: u64,
    /// Proposed new tree size.
    pub new_size: u64,
    /// Proposed new root hash.
    #[serde(with = "hash_hex")]
    pub new_hash: Hash,
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
            (Method::Get, "/get") => {
                let latest: LatestCheckpoint = self
                    .state
                    .storage()
                    .get(STATE_KEY)
                    .await
                    .unwrap_or(None)
                    .unwrap_or_default();
                Response::from_json(&latest)
            }
            (Method::Post, "/check-and-update") => {
                // Atomicity of the read-compare-write sequence below relies
                // on Cloudflare Durable Objects' input/output gates:
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
                // comparisons → `put(STATE_KEY, …)` behave as a single
                // atomic transaction per DO without us having to write any
                // explicit locking or `put_multiple`/`transaction` calls.
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
                // hashes. The frontend enforces this before reaching us, but
                // double-check defensively.
                if body.old_size == body.new_size && current.hash.0 != body.new_hash.0 {
                    return Response::from_json(&current).map(|r| r.with_status(409));
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
        let mut buf = [0u8; HASH_SIZE * 2];
        for (i, b) in h.0.iter().enumerate() {
            buf[i * 2..i * 2 + 2]
                .copy_from_slice(format!("{b:02x}").as_bytes());
        }
        std::str::from_utf8(&buf).unwrap().serialize(ser)
    }

    pub fn deserialize<'de, D>(de: D) -> std::result::Result<Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        if s.len() != HASH_SIZE * 2 {
            return Err(serde::de::Error::custom(format!(
                "hash must be {} hex chars, got {}",
                HASH_SIZE * 2,
                s.len()
            )));
        }
        let mut out = [0u8; HASH_SIZE];
        for i in 0..HASH_SIZE {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(Hash(out))
    }
}
