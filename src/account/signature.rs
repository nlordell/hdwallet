//! Module containing signature data model.

use ethnum::{AsU256 as _, U256};
use k256::ecdsa::recoverable;
use std::fmt::{self, Display, Formatter};

/// A secp256k1 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature(pub recoverable::Signature);

impl Signature {
    /// Returns the y-parity in its 256-bit integer representation.
    ///
    /// Return 0 for even parity, and 1 for odd parity.
    pub fn y_parity(&self) -> U256 {
        u8::from(self.0.recovery_id()).as_u256()
    }

    /// Returns the signature's V value with EIP-155 chain replay protection.
    pub fn v(&self, chain_id: Option<U256>) -> U256 {
        match chain_id {
            Some(chain_id) => self.y_parity() + chain_id * 2 + 35,
            None => self.y_parity() + 27,
        }
    }

    /// Returns the signature's 32-byte R-value in big-endian representation.
    pub fn r(&self) -> U256 {
        U256::from_be_bytes(self.0.r().to_bytes().into())
    }

    /// Returns the signature's 32-byte S-value in big-endian representation.
    pub fn s(&self) -> U256 {
        U256::from_be_bytes(self.0.s().to_bytes().into())
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "0x{:064x}{:064x}{:02x}",
            self.r(),
            self.s(),
            self.v(None),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{self, recoverable::Id};

    impl Signature {
        /// Creates a signature from its raw parts.
        ///
        /// Convinience method used for testing.
        pub fn from_parts(y_parity: u8, r: [u8; 32], s: [u8; 32]) -> Self {
            Self(
                recoverable::Signature::new(
                    &ecdsa::Signature::from_scalars(r, s).unwrap(),
                    Id::new(y_parity).unwrap(),
                )
                .unwrap(),
            )
        }
    }

    #[test]
    fn replay_protection() {
        let signature = Signature::from_parts(0, [1; 32], [2; 32]);
        assert_eq!(signature.v(Some(U256::new(1))), U256::new(37));
    }

    #[test]
    fn signature_to_string() {
        let signature = Signature::from_parts(0, [1; 32], [2; 32]);
        assert_eq!(
            signature.to_string(),
            "0x0101010101010101010101010101010101010101010101010101010101010101\
               0202020202020202020202020202020202020202020202020202020202020202\
               1b",
        );
    }
}
