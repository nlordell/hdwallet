//! Module implementing various hashing utilities.

use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

/// Returns the Keccak-256 hash of the specified input.
pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data.as_ref());
    hasher.finalize().into()
}

/// Returns the SHA256 hash of the specified input.
pub fn sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref());
    hasher.finalize().into()
}
