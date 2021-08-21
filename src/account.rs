//! Module implementing `secp256k1` private key.

mod address;
mod signature;

pub use self::{
    address::Address,
    signature::{Signature, YParity},
};
use crate::hash;
use anyhow::Result;
pub use secp256k1::PublicKey;
use secp256k1::{
    key::{SecretKey, ONE_KEY},
    Message, Secp256k1,
};
use std::{
    convert::TryInto,
    fmt::{self, Debug, Formatter},
};

/// A struct representing an Ethereum private key.
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    /// Creates a private key from a secret.
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self> {
        let key = SecretKey::from_slice(secret.as_ref())?;
        Ok(PrivateKey(key))
    }

    /// Returns the public key for the private key.
    pub fn public(&self) -> PublicKey {
        let secp = Secp256k1::signing_only();
        PublicKey::from_secret_key(&secp, &self.0)
    }

    /// Returns the public address for the private key.
    pub fn address(&self) -> Address {
        let public_key = self.public().serialize_uncompressed();

        // NOTE: An ethereum address is the last 20 bytes of the keccak hash of
        // the public key. Note that `libsecp256k1` public key is serialized
        // into 65 bytes as the first byte is always 0x04 as a tag to mark a
        // uncompressed public key. Discard it for the public address
        // calculation.
        debug_assert_eq!(public_key[0], 0x04);
        let hash = hash::keccak256(&public_key[1..]);
        Address::from_slice(&hash[12..])
    }

    /// Returns the private key's 32 byte secret.
    pub fn secret(&self) -> [u8; 32] {
        *self.0.as_ref()
    }

    /// Generate a signature for the specified message.
    pub fn sign(&self, message: [u8; 32]) -> Signature {
        let message = Message::from_slice(&message).expect("invalid message");

        let (recovery_id, raw_signature) = Secp256k1::signing_only()
            .sign_recoverable(&message, &self.0)
            .serialize_compact();
        debug_assert!(matches!(recovery_id.to_i32(), 0 | 1));
        debug_assert_eq!(raw_signature.len(), 64);

        Signature {
            y_parity: match recovery_id.to_i32() {
                0 => YParity::Even,
                1 => YParity::Odd,
                n => unreachable!("non 0 or 1 signature y-parity bit {}", n),
            },
            r: raw_signature[..32].try_into().unwrap(),
            s: raw_signature[32..].try_into().unwrap(),
        }
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_tuple("PrivateKey").field(&self.address()).finish()
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0 = ONE_KEY;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ganache::DETERMINISTIC_PRIVATE_KEY;
    use hex_literal::hex;

    #[test]
    fn ganache_determinitic_address() {
        let key = PrivateKey::new(DETERMINISTIC_PRIVATE_KEY).unwrap();
        assert_eq!(
            *key.address(),
            hex!("90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"),
        );
    }

    #[test]
    fn ganache_deterministic_signature() {
        let key = PrivateKey::new(DETERMINISTIC_PRIVATE_KEY).unwrap();
        let message = hash::keccak256(b"\x19Ethereum Signed Message:\n12Hello World!");
        assert_eq!(
            key.sign(message),
            Signature {
                y_parity: YParity::Odd,
                r: hex!("408790f153cbfa2722fc708a57d97a43b24429724cf060df7c915d468c43bd84"),
                s: hex!("61c96aac95ce37d7a31087b6634f4a3ea439a9f704b5c818584fa2a32fa83859"),
            },
        );
    }
}
