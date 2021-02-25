//! Module defining Ethereum transaction data as well as an RLP encoding
//! implementation.

use crate::account::{Address, Signature};
use ethnum::U256;

/// An Ethereum transaction.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// The nonce for the transaction.
    pub nonce: U256,
    /// The gas price in Wei for the transaction.
    pub gas_price: U256,
    /// The gas limit for the transaction.
    pub gas: U256,
    /// The target address for the transaction. This can also be `None` to
    /// indicate a contract creation transaction.
    pub to: Option<Address>,
    /// The amount of Ether to send with the transaction.
    pub value: U256,
    /// The calldata to use for the transaction.
    pub data: Vec<u8>,
}

impl Transaction {
    /// Returns the RLP encoded transaction with an optional signature.
    pub fn encode(&self, chain_id: u64, signature: Option<Signature>) -> Vec<u8> {
        // NOTE: This is currently not at all optimal in terms of memory
        // allocations, but we don't really care.
        let (v, r, s) = if let Some(Signature { v, r, s }) = signature {
            (
                replay_protection(chain_id, v),
                U256::from_be_bytes(r),
                U256::from_be_bytes(s),
            )
        } else {
            (chain_id, U256::ZERO, U256::ZERO)
        };

        rlp::list(&[
            &rlp::uint(self.nonce)[..],
            &rlp::uint(self.gas_price),
            &rlp::uint(self.gas),
            &if let Some(address) = self.to {
                rlp::bytes(&*address)
            } else {
                rlp::bytes(b"")
            },
            &rlp::uint(self.value),
            &rlp::bytes(&self.data),
            &rlp::uint(v),
            &rlp::uint(r),
            &rlp::uint(s),
        ])
    }
}

/// Tiny RLP encoding implementation.
mod rlp {
    use ethnum::AsU256;

    /// RLP encode some bytes.
    pub fn bytes(bytes: &[u8]) -> Vec<u8> {
        match bytes {
            [x] if *x < 0x80 => vec![*x],
            _ => {
                let mut buf = len(bytes.len(), 0x80);
                buf.extend_from_slice(bytes);
                buf
            }
        }
    }

    /// RLP encode a list.
    pub fn list(items: &[&[u8]]) -> Vec<u8> {
        let total_len = items.iter().map(|item| item.len()).sum();
        let mut buf = len(total_len, 0xc0);
        for item in items {
            buf.extend_from_slice(item);
        }
        buf
    }

    /// RLP encode a length.
    pub fn len(len: usize, offset: u8) -> Vec<u8> {
        if len < 56 {
            vec![len as u8 + offset]
        } else {
            let bl_buf = len.to_be_bytes();
            let bl = {
                let start = len.leading_zeros() / 8;
                &bl_buf[start as usize..]
            };
            let mut buf = vec![bl.len() as u8 + offset + 55];
            buf.extend_from_slice(bl);
            buf
        }
    }

    /// RLP encode a unsigned integer. This ensures that it is shortned to its
    /// shortest little endian byte representation.
    pub fn uint(value: impl AsU256) -> Vec<u8> {
        let value = value.as_u256();
        let start = value.leading_zeros() / 8;
        bytes(&value.to_be_bytes()[start as usize..])
    }
}

/// Apply EIP-155 replay protection to the specified `v` value.
fn replay_protection(chain_id: u64, v: u8) -> u64 {
    assert!(v == 27 || v == 28, "invalid signature v-value");
    let v = v as u64;
    v + 8 + chain_id * 2
}
