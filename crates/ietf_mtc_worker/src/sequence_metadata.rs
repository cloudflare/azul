// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! [`IetfMtcSequenceMetadata`] — the per-entry metadata produced by the
//! IETF MTC sequencer.

use generic_log_worker::SequencerMetadata;
use serde::{Deserialize, Deserializer, Serialize, de};
use tlog_checkpoint::UnixTimestampMillis;
use tlog_core::{LeafIndex, Subtree};

pub const SUBTREE_SIG_KEY_PREFIX: &str = "subtree-sig";

pub fn subtree_sig_key(lo: LeafIndex, hi: LeafIndex) -> String {
    format!("{SUBTREE_SIG_KEY_PREFIX}/{lo:020}-{hi:020}")
}

#[derive(Serialize)]
pub struct SignedSubtree {
    pub lo: LeafIndex,
    pub hi: LeafIndex,
    pub hash: [u8; 32],
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_size: u64,
    pub signatures: Vec<CachedSubtreeSignature>,
}

#[derive(Deserialize)]
struct SignedSubtreeWire {
    lo: LeafIndex,
    hi: LeafIndex,
    hash: [u8; 32],
    checkpoint_hash: [u8; 32],
    checkpoint_size: u64,
    signatures: Option<Vec<CachedSubtreeSignature>>,
    signature: Option<Vec<u8>>,
    cosigner_id: Option<String>,
}

impl<'de> Deserialize<'de> for SignedSubtree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SignedSubtreeWire::deserialize(deserializer)?;
        let signatures = match (wire.signatures, wire.signature, wire.cosigner_id) {
            (Some(signatures), None, None) => signatures,
            (None, Some(signature), Some(cosigner_id)) => {
                vec![CachedSubtreeSignature {
                    signature,
                    cosigner_id,
                }]
            }
            _ => {
                return Err(de::Error::custom(
                    "expected signatures or legacy signature and cosigner_id fields",
                ));
            }
        };
        Ok(Self {
            lo: wire.lo,
            hi: wire.hi,
            hash: wire.hash,
            checkpoint_hash: wire.checkpoint_hash,
            checkpoint_size: wire.checkpoint_size,
            signatures,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct CachedSubtreeSignature {
    pub signature: Vec<u8>,
    pub cosigner_id: String,
}

impl SignedSubtree {
    pub fn as_subtree(&self) -> Result<Subtree, tlog_core::TlogError> {
        Subtree::new(self.lo, self.hi)
    }

    pub fn has_signatures_for<'a>(&self, required_ids: impl IntoIterator<Item = &'a str>) -> bool {
        required_ids.into_iter().all(|required_id| {
            self.signatures
                .iter()
                .any(|signature| signature.cosigner_id == required_id)
        })
    }
}

/// Sequencer metadata for an IETF MTC log entry.
///
/// Carries only the fields the IETF MTC worker actually consumes downstream:
/// the `leaf_index` of the sequenced entry and the tree sizes before and after
/// the sequencing batch. The frontend uses `old_tree_size` and `new_tree_size`
/// together with `leaf_index` to identify the single covering subtree in
/// `Subtree::split_interval(old, new)` that contains this entry — and
/// therefore the exact R2 key of its cached subtree signature — without
/// having to enumerate candidate subtree keys.
///
/// Unlike bootstrap/static-ct metadata, there is no `timestamp` field: the
/// IETF MTC `add-entry` response is a DER-encoded §6.2 standalone certificate,
/// whose validity is carried inside the TBS entry rather than returned
/// separately.
///
/// The default JSON representation is stored in the sequencer's short-term
/// dedup cache so retries receive the original sequencing metadata.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IetfMtcSequenceMetadata {
    /// Zero-based index of the sequenced entry.
    pub leaf_index: LeafIndex,
    /// Tree size immediately before the batch that sequenced this entry.
    pub old_tree_size: u64,
    /// Tree size immediately after the batch that sequenced this entry.
    pub new_tree_size: u64,
}

impl SequencerMetadata for IetfMtcSequenceMetadata {
    fn new(
        leaf_index: LeafIndex,
        _timestamp: UnixTimestampMillis,
        old_tree_size: u64,
        new_tree_size: u64,
    ) -> Self {
        Self {
            leaf_index,
            old_tree_size,
            new_tree_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_subtree_reads_legacy_signature() {
        let value = serde_json::json!({
            "lo": 1,
            "hi": 2,
            "hash": vec![0; 32],
            "checkpoint_hash": vec![1; 32],
            "checkpoint_size": 3,
            "signature": [4, 5],
            "cosigner_id": "1.2.3"
        });

        let signed: SignedSubtree = serde_json::from_value(value).unwrap();
        assert_eq!(signed.signatures.len(), 1);
        assert_eq!(signed.signatures[0].signature, [4, 5]);
        assert_eq!(signed.signatures[0].cosigner_id, "1.2.3");
    }

    #[test]
    fn signed_subtree_writes_current_format() {
        let signed = SignedSubtree {
            lo: 1,
            hi: 2,
            hash: [0; 32],
            checkpoint_hash: [1; 32],
            checkpoint_size: 3,
            signatures: vec![CachedSubtreeSignature {
                signature: vec![4, 5],
                cosigner_id: "1.2.3".to_owned(),
            }],
        };

        let value = serde_json::to_value(signed).unwrap();
        assert!(value.get("signatures").is_some());
        assert!(value.get("signature").is_none());
        assert!(value.get("cosigner_id").is_none());
    }

    #[test]
    fn signed_subtree_requires_every_configured_signature() {
        let signed = SignedSubtree {
            lo: 1,
            hi: 2,
            hash: [0; 32],
            checkpoint_hash: [1; 32],
            checkpoint_size: 3,
            signatures: vec![
                CachedSubtreeSignature {
                    signature: vec![4],
                    cosigner_id: "1.2.3".to_owned(),
                },
                CachedSubtreeSignature {
                    signature: vec![5],
                    cosigner_id: "1.2.4".to_owned(),
                },
            ],
        };

        assert!(signed.has_signatures_for(["1.2.3", "1.2.4"]));
        assert!(!signed.has_signatures_for(["1.2.3", "1.2.5"]));
    }
}
