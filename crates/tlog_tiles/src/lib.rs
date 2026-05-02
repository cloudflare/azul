// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

//! # `tlog_tiles`
//!
//! Implementation of the [C2SP tlog-tiles](https://c2sp.org/tlog-tiles)
//! HTTP wire format for tile-encoded transparency logs.
//!
//! The Merkle math (the [`Hash`] type, the proof builders/verifiers,
//! the `Subtree` type) lives in the [`tlog_core`] crate; the
//! [tlog-checkpoint][tc] signed-note format lives in the
//! [`tlog_checkpoint`] crate; this crate is the tile-encoding layer on
//! top of both.
//!
//! [tc]: https://c2sp.org/tlog-checkpoint
//! [`Hash`]: tlog_core::Hash
//! [`tlog_core`]: https://docs.rs/tlog_core
//! [`tlog_checkpoint`]: https://docs.rs/tlog_checkpoint

pub mod entries;
pub mod tile;

pub use entries::*;
pub use tile::*;

#[cfg(test)]
mod tests {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer};
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use tlog_core::{
        record_hash, verify_consistency_proof, verify_inclusion_proof, Hash, TlogError,
    };
    use url::form_urlencoded;

    #[derive(Deserialize)]
    struct CtTree {
        #[serde(rename = "tree_size")]
        size: u64,
        #[serde(rename = "sha256_root_hash")]
        hash: Hash,
    }

    #[derive(Deserialize)]
    struct CtEntries {
        entries: Vec<CtEntry>,
    }

    #[derive(Deserialize)]
    struct CtEntry {
        #[serde(rename = "leaf_input", deserialize_with = "from_base64")]
        data: Vec<u8>,
    }

    fn from_base64<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        BASE64_STANDARD
            .decode(&base64)
            .map_err(serde::de::Error::custom)
    }

    #[derive(Deserialize)]
    struct CtInclusionProof {
        #[serde(rename = "audit_path")]
        proof: Vec<Hash>,
    }

    #[derive(Deserialize)]
    struct CtConsistencyProof {
        consistency: Vec<Hash>,
    }

    // Returns vendored HTTP responses from CT logs for use in tests.
    fn http_get<T: for<'de> Deserialize<'de>>(url: &str) -> T {
        let basename = &url
            .rsplit_once('/')
            .unwrap()
            .1
            .to_string()
            .replace(|c| !char::is_ascii_alphanumeric(&c), "-");

        let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests/http_get", basename]
            .iter()
            .collect();
        let mut file = File::open(path).expect("Unable to open file");
        let mut body = String::new();

        file.read_to_string(&mut body).expect("Unable to read file");

        serde_json::from_str(&body).expect("File contained invalid JSON")
    }

    #[test]
    fn test_certificate_transparency() -> Result<(), TlogError> {
        let root: CtTree = http_get("http://ct.googleapis.com/logs/argon2020/ct/v1/get-sth");

        let leaf: CtEntries = http_get(
            "http://ct.googleapis.com/logs/argon2020/ct/v1/get-entries?start=10000&end=10000",
        );

        let hash = record_hash(&leaf.entries[0].data);

        let url = format!(
            "http://ct.googleapis.com/logs/argon2020/ct/v1/get-proof-by-hash?tree_size={}&hash={}",
            root.size,
            form_urlencoded::byte_serialize(hash.to_string().as_bytes()).collect::<String>()
        );
        let rp: CtInclusionProof = http_get(&url);

        verify_inclusion_proof(&rp.proof, root.size, root.hash, 10000, hash)?;

        let url = format!(
        "http://ct.googleapis.com/logs/argon2020/ct/v1/get-sth-consistency?first=3654490&second={}",
        root.size);
        let tp: CtConsistencyProof = http_get(&url);

        let oh = Hash::parse_hash("AuIZ5V6sDUj1vn3Y1K85oOaQ7y+FJJKtyRTl1edIKBQ=")?;
        verify_consistency_proof(&tp.consistency, root.size, root.hash, 3_654_490, oh)?;

        Ok(())
    }
}
