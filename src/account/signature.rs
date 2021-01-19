//! Module containing signature data model.

use std::fmt::{self, Display, Formatter};

/// A secp256k1 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    /// Signature V value in Electrum notation.
    pub v: u8,
    /// Signature R value.
    pub r: [u8; 32],
    /// Signature S value.
    pub s: [u8; 32],
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "0x{}{}{:02x}",
            hex::encode(&self.r),
            hex::encode(&self.s),
            self.v
        )
    }
}
