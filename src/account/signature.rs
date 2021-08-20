//! Module containing signature data model.

use ethnum::{AsU256, U256};
use std::fmt::{self, Display, Formatter};

/// The parity of the y-value of a secp256k1 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum YParity {
    /// Even parity.
    Even = 0,
    /// Odd parity.
    Odd = 1,
}

impl AsU256 for YParity {
    fn as_u256(self) -> U256 {
        U256::new(self as _)
    }
}

/// A secp256k1 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    /// Signature V value in Electrum notation.
    pub y_parity: YParity,
    /// Signature R value.
    pub r: [u8; 32],
    /// Signature S value.
    pub s: [u8; 32],
}

impl Signature {
    /// Returns the signature's V value in Electrum notation.
    pub fn v(&self) -> u8 {
        27 + (self.y_parity as u8)
    }

    /// Returns the signature's V value with EIP-155 chain replay protection.
    pub fn v_replay_protected(&self, chain_id: U256) -> U256 {
        self.y_parity.as_u256() + chain_id * 2 + 35
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "0x{}{}{:02x}",
            hex::encode(&self.r),
            hex::encode(&self.s),
            self.v(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_protection() {
        let signature = Signature {
            y_parity: YParity::Even,
            r: [1; 32],
            s: [2; 32],
        };
        assert_eq!(signature.v_replay_protected(U256::new(1)), U256::new(37));
    }

    #[test]
    fn signature_to_string() {
        let signature = Signature {
            y_parity: YParity::Even,
            r: [1; 32],
            s: [2; 32],
        };
        assert_eq!(
            signature.to_string(),
            "0x0101010101010101010101010101010101010101010101010101010101010101\
               0202020202020202020202020202020202020202020202020202020202020202\
               1b",
        );
    }
}
