//! Module implementing public key operations.

use k256::elliptic_curve::sec1::ToEncodedPoint as _;

/// A public key.
pub struct PublicKey(pub k256::PublicKey);

impl PublicKey {
    /// Returns an uncompressed encoded bytes for the public key.
    pub fn encode_uncompressed(&self) -> [u8; 65] {
        self.0
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("unexpected uncompressed private key length")
    }
}
