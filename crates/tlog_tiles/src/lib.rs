//! # tlog tiles
//!
//! Implementation of the [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) and [C2SP checkpoint](https://c2sp.org/tlog-checkpoint) specifications.
//!
//! This file contains code ported from the original project [tlog](https://pkg.go.dev/golang.org/x/mod/sumdb/tlog) ([BSD-3-Clause license](https://pkg.go.dev/golang.org/x/mod/sumdb/note?tab=licenses)).
//! See the LICENSE file in the root of this repository for the full license text.
//!
//! References:
//! - [ct_test.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/tlog/ct_test.go)

pub mod checkpoint;
pub mod tile;
pub mod tlog;

pub use checkpoint::*;
pub use tile::*;
pub use tlog::*;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer};
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
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
    struct CtRecordProof {
        #[serde(rename = "audit_path")]
        proof: Vec<Hash>,
    }

    #[derive(Deserialize)]
    struct CtTreeProof {
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
    fn test_certificate_transparency() -> Result<(), Error> {
        let root: CtTree = http_get("http://ct.googleapis.com/logs/argon2020/ct/v1/get-sth");

        let leaf: CtEntries = http_get(
            "http://ct.googleapis.com/logs/argon2020/ct/v1/get-entries?start=10000&end=10000",
        );

        let hash = tlog::record_hash(&leaf.entries[0].data);

        let url = format!(
            "http://ct.googleapis.com/logs/argon2020/ct/v1/get-proof-by-hash?tree_size={}&hash={}",
            root.size,
            form_urlencoded::byte_serialize(hash.to_string().as_bytes()).collect::<String>()
        );
        let rp: CtRecordProof = http_get(&url);

        tlog::check_record(&rp.proof, root.size, root.hash, 10000, hash)?;

        let url = format!(
        "http://ct.googleapis.com/logs/argon2020/ct/v1/get-sth-consistency?first=3654490&second={}",
        root.size);
        let tp: CtTreeProof = http_get(&url);

        let oh = Hash::parse_hash("AuIZ5V6sDUj1vn3Y1K85oOaQ7y+FJJKtyRTl1edIKBQ=")?;
        tlog::check_tree(&tp.consistency, root.size, root.hash, 3_654_490, oh)?;

        Ok(())
    }
}
