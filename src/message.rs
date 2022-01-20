//! Ethereum message for signing.

use crate::hash;
use std::io::Write as _;

/// A message to be signed with an Ethereum specific prefix.
pub struct EthereumMessage<T>(pub T);

impl<T> EthereumMessage<T>
where
    T: AsRef<[u8]>,
{
    /// Computes the 32-byte message used for ECDSA signing with a private key.
    pub fn signing_message(&self) -> [u8; 32] {
        digest(self.0.as_ref())
    }
}

/// Computes the Ethereum-specific digest for a message.
fn digest(data: &[u8]) -> [u8; 32] {
    let mut buffer = Vec::with_capacity(46 + data.len());
    buffer.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    // Display implementation for `usize` should not error when writing to an
    // in memory buffer. Note that the standard library `ToString::to_string`
    // implementation has the same expectation:
    // <https://doc.rust-lang.org/std/string/trait.ToString.html#required-methods>
    write!(buffer, "{}", data.len()).expect("unexpected error writing number");
    buffer.extend_from_slice(data);

    hash::keccak256(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_digest() {
        assert_eq!(
            digest(b"hello world!"),
            hash::keccak256(b"\x19Ethereum Signed Message:\n12hello world!"),
        );
    }
}
