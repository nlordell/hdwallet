//! Module containing signature data model.

use anyhow::bail;
use ethnum::{AsU256 as _, U256};
use k256::ecdsa::{self, RecoveryId};
use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

/// A secp256k1 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature(pub ecdsa::Signature, pub RecoveryId);

impl Signature {
    /// Returns the y-parity in its 256-bit integer representation.
    ///
    /// Return 0 for even parity, and 1 for odd parity.
    pub fn y_parity(&self) -> U256 {
        u8::from(self.1.is_y_odd()).as_u256()
    }

    /// Returns the signature's 32-byte R-value in big-endian representation.
    pub fn r(&self) -> U256 {
        U256::from_be_bytes(self.0.r().to_bytes().into())
    }

    /// Returns the signature's 32-byte S-value in big-endian representation.
    pub fn s(&self) -> U256 {
        U256::from_be_bytes(self.0.s().to_bytes().into())
    }

    /// Returns the signature's V value with EIP-155 chain replay protection.
    pub fn v(&self, chain_id: Option<U256>) -> U256 {
        match chain_id {
            Some(chain_id) => self.y_parity() + chain_id * 2 + 35,
            None => self.y_parity() + 27,
        }
    }

    /// Creates a signature from its raw parts.
    ///
    /// # Panics
    ///
    /// Panics on invalid signature parts.
    pub fn from_parts(r: [u8; 32], s: [u8; 32], y_parity: u8) -> Self {
        Self(
            ecdsa::Signature::from_scalars(r, s).unwrap(),
            y_parity.try_into().unwrap(),
        )
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

impl FromStr for Signature {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut signature = [0; 65];
        hex::decode_to_slice(s, &mut signature)?;

        let v = signature[64];
        let y_parity = match v {
            27 => 0,
            28 => 1,
            _ => bail!("invalid V-value, must be 27 or 28 but got {v}"),
        };

        Ok(Self::from_parts(
            signature[0..32].try_into().unwrap(),
            signature[32..64].try_into().unwrap(),
            y_parity,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_protection() {
        let signature = Signature::from_parts([1; 32], [2; 32], 0);
        assert_eq!(signature.v(Some(U256::new(1))), U256::new(37));
    }

    #[test]
    fn signature_to_string() {
        let signature = Signature::from_parts([1; 32], [2; 32], 0);
        assert_eq!(
            signature.to_string(),
            "0x0101010101010101010101010101010101010101010101010101010101010101\
               0202020202020202020202020202020202020202020202020202020202020202\
               1b",
        );
    }
}
