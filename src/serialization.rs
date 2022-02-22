//! Module with JSON serialization helpers.

use serde_json::{Map, Value};

/// A JSON object.
pub type JsonObject = Map<String, Value>;

/// `I256` serialization methods.
pub mod i256 {
    use ethnum::{AsI256 as _, I256, U256};
    use serde::de::{self, Deserializer, Visitor};
    use std::fmt::{self, Formatter};

    struct I256Visitor;

    impl<'de> Visitor<'de> for I256Visitor {
        type Value = I256;

        fn expecting(&self, f: &mut Formatter) -> fmt::Result {
            f.write_str("number, decimal string or '0x-' prefixed hexadecimal string")
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v.as_i256())
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v.as_i256())
        }

        fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v.as_i256())
        }

        fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v.as_i256())
        }

        fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if !(0.0..(1_u64 << 24) as _).contains(&v.abs()) {
                return Err(de::Error::custom(
                    "invalid conversion from single precision floating point \
                     number outside of valid integer range (-2^24, 2^24)",
                ));
            }

            self.visit_f64(v as _)
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
            if !(0.0..(1_u64 << 53) as _).contains(&v.abs()) {
                return Err(de::Error::custom(
                    "invalid conversion from double precision floating point \
                     number outside of valid integer range (-2^53, 2^53)",
                ));
            }

            Ok(v.as_i256())
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let (u, neg) = match v.strip_prefix('-') {
                Some(v) => (v, true),
                None => (v, false),
            };
            let (src, radix) = match u.strip_prefix("0x") {
                Some(u) => (u, 16),
                None => (u, 10),
            };
            let value = U256::from_str_radix(src, radix)
                .map_err(de::Error::custom)?
                .as_i256();
            match (neg, value) {
                (true, I256::MIN) => Ok(value),
                (true, v) if v > 0 => Ok(v.wrapping_neg()),
                (true, I256::ZERO) => Err(de::Error::custom("negative zero is invalid")),
                (true, _) => Err(de::Error::custom("number too small to fit in target type")),
                (false, v) if v >= 0 => Ok(v),
                (false, _) => Err(de::Error::custom("number too big to fit in target type")),
            }
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<I256, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(I256Visitor)
    }
}

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

        fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if !(0.0..(1_u64 << 24) as _).contains(&v) {
                return Err(de::Error::custom(
                    "invalid conversion from single precision floating point \
                     number outside of valid integer range [0, 2^24)",
                ));
            }

            self.visit_f64(v as _)
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
                    "invalid conversion from double precision floating point \
                     number outside of valid integer range [0, 2^53)",
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

#[cfg(test)]
mod tests {
    use super::*;
    use ethnum::{I256, U256};

    macro_rules! assert_deserializes_to {
        ($m:ident: $v:expr => $x:expr) => {{
            use ::serde::de::{value::Error, IntoDeserializer};
            let v = $m::deserialize(IntoDeserializer::<Error>::into_deserializer($v)).unwrap();
            assert_eq!(v, $x);
        }};
    }

    macro_rules! assert_deserializes_err {
        ($m:ident: $v:expr) => {{
            use ::serde::de::{value::Error, IntoDeserializer};
            let v = $m::deserialize(IntoDeserializer::<Error>::into_deserializer($v));
            assert!(v.is_err());
        }};
    }

    #[test]
    fn i256_deserialization() {
        assert_deserializes_to!(i256: -42_i64 => I256::new(-42));
        assert_deserializes_to!(i256: 42_u64 => I256::new(42));

        assert_deserializes_to!(i256: -1337_i128 => I256::new(-1337));
        assert_deserializes_to!(i256: 1337_u128 => I256::new(1337));

        assert_deserializes_to!(i256: 100.0_f32 => I256::new(100));
        assert_deserializes_err!(i256: 4.2_f32);
        assert_deserializes_err!(i256: 16777216.0_f32);

        assert_deserializes_to!(i256: -100.0_f64 => I256::new(-100));
        assert_deserializes_err!(i256: -13.37_f64);
        assert_deserializes_err!(i256: 9007199254740992.0_f32);

        assert_deserializes_to!(i256: "-1" => I256::new(-1));
        assert_deserializes_to!(i256: "1000" => I256::new(1000));
        assert_deserializes_to!(i256: "0x42" => I256::new(0x42));
        assert_deserializes_to!(i256: "-0x2a" => I256::new(-42));

        assert_deserializes_to!(i256: "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" => I256::MAX);
        assert_deserializes_err!(i256: "0x8000000000000000000000000000000000000000000000000000000000000000");
        assert_deserializes_to!(i256: "-0x8000000000000000000000000000000000000000000000000000000000000000" => I256::MIN);
        assert_deserializes_err!(i256: "-0x8000000000000000000000000000000000000000000000000000000000000001");

        assert_deserializes_err!(i256: "-0");
        assert_deserializes_err!(i256: "-0x0");
    }

    #[test]
    fn u256_deserialization() {
        assert_deserializes_to!(u256: 42_u64 => U256::new(42));
        assert_deserializes_to!(u256: 1337_u128 => U256::new(1337));

        assert_deserializes_to!(u256: 100.0_f32 => U256::new(100));
        assert_deserializes_err!(u256: 4.2_f32);
        assert_deserializes_err!(u256: 16777216.0_f32);

        assert_deserializes_to!(u256: 100.0_f64 => U256::new(100));
        assert_deserializes_err!(u256: 13.37_f64);
        assert_deserializes_err!(u256: 9007199254740992.0_f32);

        assert_deserializes_to!(u256: "1000" => U256::new(1000));
        assert_deserializes_to!(u256: "0x42" => U256::new(0x42));

        assert_deserializes_to!(u256: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" => U256::MAX);
        assert_deserializes_err!(u256: "0x10000000000000000000000000000000000000000000000000000000000000000");
    }
}
