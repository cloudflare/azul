use tlog_core::{HASH_SIZE, Hash};

fn from_hex(s: &str) -> Result<Hash, String> {
    let bytes: [u8; HASH_SIZE] = ::hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|v: Vec<u8>| format!("hash must be {} bytes, got {}", HASH_SIZE, v.len()))?;
    Ok(Hash(bytes))
}

pub mod hex {
    use super::{Hash, from_hex};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a hash as a lowercase hex string.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error.
    pub fn serialize<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ::hex::encode(hash.0).serialize(serializer)
    }

    /// Deserialize a hash from a hex string.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid hex or a hash of the wrong length.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        from_hex(&value).map_err(serde::de::Error::custom)
    }
}

pub mod vec_hex {
    use super::{Hash, from_hex};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize hashes as an array of lowercase hex strings.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error.
    pub fn serialize<S>(hashes: &[Hash], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hashes
            .iter()
            .map(|hash| ::hex::encode(hash.0))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    /// Deserialize hashes from an array of hex strings.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid hex or a hash of the wrong length.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Hash>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|value| from_hex(value).map_err(serde::de::Error::custom))
            .collect()
    }
}
