//! Module implementing `secp256k1` private key.

mod address;
mod signature;

pub use self::{address::Address, signature::Signature};
use crate::hash;
use anyhow::Result;
use secp256k1::{
    key::{PublicKey, SecretKey, ONE_KEY},
    Message, Secp256k1,
};
use std::fmt::{self, Debug, Formatter};

/// A struct representing an Ethereum private key.
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    /// Creates a private key from a secret.
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self> {
        let key = SecretKey::from_slice(secret.as_ref())?;
        Ok(PrivateKey(key))
    }

    /// Returns the public address for the private key.
    pub fn address(&self) -> Address {
        let secp = Secp256k1::signing_only();
        let public_key = PublicKey::from_secret_key(&secp, &self.0).serialize_uncompressed();

        // NOTE: An ethereum address is the last 20 bytes of the keccak hash of
        // the public key. Note that `libsecp256k1` public key is serialized
        // into 65 bytes as the first byte is always 0x04 as a tag to mark a
        // uncompressed public key. Discard it for the public address
        // calculation.
        debug_assert_eq!(public_key[0], 0x04);
        let hash = hash::keccak256(&public_key[1..]);
        Address::from_slice(&hash[12..])
    }

    /// Generate a signature for the specified message.
    pub fn sign(&self, message: [u8; 32]) -> Signature {
        let message = Message::from_slice(&message).expect("invalid message");

        let (recovery_id, raw_signature) = Secp256k1::signing_only()
            .sign_recoverable(&message, &self.0)
            .serialize_compact();
        debug_assert!(matches!(recovery_id.to_i32(), 0 | 1));

        let mut signature = Signature::default();
        signature.v = 27 + (recovery_id.to_i32() as u8);
        signature.r.copy_from_slice(&raw_signature[..32]);
        signature.s.copy_from_slice(&raw_signature[32..]);

        signature
    }
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_tuple("PrivateKey").field(&self.address()).finish()
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0 = ONE_KEY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const GANACHE_DETERMINISTIC_PRIVATE_KEY: [u8; 32] =
        hex!("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d");

    #[test]
    fn ganache_determinitic_address() {
        let key = PrivateKey::new(GANACHE_DETERMINISTIC_PRIVATE_KEY).unwrap();
        assert_eq!(
            *key.address(),
            hex!("90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"),
        );
    }

    #[test]
    fn ganache_deterministic_signature() {
        let key = PrivateKey::new(GANACHE_DETERMINISTIC_PRIVATE_KEY).unwrap();
        let message = hash::keccak256(b"\x19Ethereum Signed Message:\n12Hello World!");
        assert_eq!(
            key.sign(message),
            Signature {
                v: 28,
                r: hex!("408790f153cbfa2722fc708a57d97a43b24429724cf060df7c915d468c43bd84"),
                s: hex!("61c96aac95ce37d7a31087b6634f4a3ea439a9f704b5c818584fa2a32fa83859"),
            },
        );
    }
}
