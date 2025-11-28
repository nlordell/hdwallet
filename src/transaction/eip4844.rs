//! EIP-4844 Ethereum transaction with blobs type definition and RLP encoding.
//!
//! This is currently a work in progress.

use crate::{
    account::Signature, serialization, transaction::accesslist::AccessList, transaction::rlp,
};
use ethaddr::Address;
use ethdigest::Digest;
use ethnum::U256;
use serde::Deserialize;

/// An EIP-4844 Ethereum transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct Eip4844Transaction {
    /// The chain ID for the transaction.
    #[serde(rename = "chainId", with = "ethnum::serde::permissive")]
    pub chain_id: U256,
    /// The nonce for the transaction.
    #[serde(with = "ethnum::serde::permissive")]
    pub nonce: U256,
    /// The maximum priority fee in Wei for the transaction.
    #[serde(rename = "maxPriorityFeePerGas", with = "ethnum::serde::permissive")]
    pub max_priority_fee_per_gas: U256,
    /// The maximum gas price in Wei for the transaction.
    #[serde(rename = "maxFeePerGas", with = "ethnum::serde::permissive")]
    pub max_fee_per_gas: U256,
    /// The gas limit for the transaction.
    #[serde(with = "ethnum::serde::permissive")]
    pub gas: U256,
    /// The target address for the transaction.
    pub to: Address,
    /// The amount of Ether to send with the transaction.
    #[serde(with = "ethnum::serde::permissive")]
    pub value: U256,
    /// The calldata to use for the transaction.
    #[serde(with = "serialization::bytes")]
    pub data: Vec<u8>,
    /// List of addresses and storage keys that the transaction plans to access.
    #[serde(default, rename = "accessList")]
    pub access_list: AccessList,
    /// The maximum gas price in Wei for the additional blobs.
    #[serde(rename = "maxFeePerBlobGas", with = "ethnum::serde::permissive")]
    pub max_fee_per_blob_gas: U256,
    /// List of blob hashes included in the transaction.
    #[serde(rename = "blobVersionedHashes")]
    pub blob_versioned_hashes: Vec<Digest>,
}

impl Eip4844Transaction {
    /// Returns the RLP encoded transaction with an optional signature.
    pub fn rlp_encode(&self, signature: Option<Signature>) -> Vec<u8> {
        let fields = [
            rlp::uint(self.chain_id),
            rlp::uint(self.nonce),
            rlp::uint(self.max_priority_fee_per_gas),
            rlp::uint(self.max_fee_per_gas),
            rlp::uint(self.gas),
            rlp::bytes(&*self.to),
            rlp::uint(self.value),
            rlp::bytes(&self.data),
            self.access_list.rlp_encode(),
            rlp::uint(self.max_fee_per_blob_gas),
            rlp::iter(
                self.blob_versioned_hashes
                    .iter()
                    .map(|hash| rlp::bytes(hash.as_ref())),
            ),
        ];

        let tail = signature.map(|signature| {
            [
                rlp::uint(signature.y_parity()),
                rlp::uint(signature.r()),
                rlp::uint(signature.s()),
            ]
        });

        [
            &[0x03][..],
            &rlp::iter(fields.iter().chain(tail.iter().flatten())),
        ]
        .concat()
    }
}
