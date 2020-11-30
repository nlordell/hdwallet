//! Module implementing various hashing utilities.

use sha2::{Digest, Sha256};

/// Returns the SHA256 hash of the specified input.
pub fn sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref());
    hasher.finalize().into()
}
