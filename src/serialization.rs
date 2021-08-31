//! Module with JSON serialization helpers.

use serde_json::{Map, Value};

/// A JSON object.
pub type JsonObject = Map<String, Value>;

/// `U256` serialization methods.
pub mod u256 {
    use ethnum::{AsU256 as _, U256};
    use serde::de::{self, Deserializer, Visitor};
    use std::fmt::{self, Formatter};

    struct U256Visitor;

    impl<'de> Visitor<'de> for U256Visitor {
        type Value = U256;

        fn expecting(&self, f: &mut Formatter) -> fmt::Result {
            f.write_str("number, decimal string or '0x-' prefixed hexadecimal string")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v.as_u256())
        }

        fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v.as_u256())
        }

        fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v.fract() != 0. {
                return Err(de::Error::custom(
                    "invalid conversion from floating point number \
                     with fractional part to 256-bit integer",
                ));
            }
            if !(0.0..(1_u64 << 53) as _).contains(&v) {
                return Err(de::Error::custom(
                    "invalid conversion from floating point number \
                     outside of valid integer range [0, 2^53)",
                ));
            }

            Ok(v.as_u256())
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let (src, radix) = match v.strip_prefix("0x") {
                Some(v) => (v, 16),
                None => (v, 10),
            };
            U256::from_str_radix(src, radix).map_err(de::Error::custom)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(U256Visitor)
    }

    pub mod option {
        use super::*;
        use serde::Deserialize;

        #[derive(Deserialize)]
        #[serde(transparent)]
        struct Helper(#[serde(with = "super")] U256);

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let option = Option::deserialize(deserializer)?;
            Ok(option.map(|Helper(v)| v))
        }
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
