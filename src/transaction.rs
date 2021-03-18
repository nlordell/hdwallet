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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account::PrivateKey, ganache::DETERMINISTIC_PRIVATE_KEY, hash};
    use hex_literal::hex;

    const CHAIN_ID: u64 = 0x1337;

    fn transaction() -> Transaction {
        Transaction {
            nonce: U256::new(7777),
            gas_price: U256::new(100_000_000_000),
            gas: U256::new(150_000),
            to: Some(Address(hex!("7070707070707070707070707070707070707070"))),
            value: U256::new(42_000_000_000_000_000_000),
            data: hex!("01020304").into(),
        }
    }

    #[test]
    fn rlp_encode_for_signing() {
        assert_eq!(
            transaction().encode(CHAIN_ID, None),
            hex!(
                "f6821e6185174876e800830249f0947070707070707070707070707070707070
                 707070890246ddf9797668000084010203048213378080"
            ),
        )
    }

    #[test]
    fn rlp_encode_with_signature() {
        let key = PrivateKey::new(DETERMINISTIC_PRIVATE_KEY).unwrap();
        let message = hash::keccak256(transaction().encode(CHAIN_ID, None));
        let signature = key.sign(message);

        assert_eq!(
            transaction().encode(CHAIN_ID, Some(signature)),
            hex!(
                "f876821e6185174876e800830249f09470707070707070707070707070707070
                 70707070890246ddf979766800008401020304822691a076382953503398303f
                 e8c3e3d235e8f71adc39fb90fcda99514e324d96bad253a044351903896d0b6f
                 8a3ee9543c1e23ec3bab29a4ae5cae1a6b7b2c811105264f"
            ),
        )
    }
}
