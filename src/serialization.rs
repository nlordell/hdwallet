//! Module with JSON serialization helpers.

use serde_json::{Map, Value};

/// A JSON object.
pub type JsonObject = Map<String, Value>;

/// Permisive deserialization for optional 256-bit integer types.
pub mod numopt {
    use ethnum::serde::permissive::Permissive;
    use serde::{Deserialize, Deserializer};

    #[derive(Deserialize)]
    #[serde(transparent)]
    struct Helper<T>(#[serde(with = "ethnum::serde::permissive")] T)
    where
        T: Permissive;

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: Permissive,
        D: Deserializer<'de>,
    {
        let option = Option::deserialize(deserializer)?;
        Ok(option.map(|Helper(v)| v))
    }
}

/// Dynamic byte array serialization methods.
pub mod bytes {
    use serde::{
        de::{self, Deserializer},
        Deserialize as _,
    };
    use std::borrow::Cow;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        let s = s
            .strip_prefix("0x")
            .ok_or_else(|| de::Error::custom("storage slot missing '0x' prefix"))?;
        hex::decode(s).map_err(de::Error::custom)
    }
}

/// Fixed byte array serialization methods.
pub mod bytearray {
    use serde::{
        de::{self, Deserializer},
        Deserialize as _,
    };
    use std::borrow::Cow;

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = [0_u8; N];
        let s = Cow::<str>::deserialize(deserializer)?;
        let s = s
            .strip_prefix("0x")
            .ok_or_else(|| de::Error::custom("storage slot missing '0x' prefix"))?;
        hex::decode_to_slice(s, &mut value).map_err(de::Error::custom)?;
        Ok(value)
    }
}
