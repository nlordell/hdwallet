//! EIp-1559 Ethereum transaction with base gas pricing type definition and RLP encoding.

use crate::{
    account::{Address, Signature},
    serialization,
    transaction::accesslist::AccessList,
    transaction::rlp,
};
use ethnum::{AsU256 as _, U256};
use serde::Deserialize;

/// An EIP-1559 Ethereum transaction.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Eip1559Transaction {
    /// The chain ID for the transaction.
    #[serde(rename = "chainId")]
    #[serde(with = "serialization::u256")]
    pub chain_id: U256,
    /// The nonce for the transaction.
    #[serde(with = "serialization::u256")]
    pub nonce: U256,
    /// The gas price in Wei for the transaction.
    #[serde(rename = "maxPriorityFeePerGas")]
    #[serde(with = "serialization::u256")]
    pub max_priority_fee_per_gas: U256,
    #[serde(rename = "maxFeePerGas")]
    #[serde(with = "serialization::u256")]
    pub max_fee_per_gas: U256,
    /// The gas limit for the transaction.
    #[serde(with = "serialization::u256")]
    pub gas: U256,
    /// The target address for the transaction. This can also be `None` to
    /// indicate a contract creation transaction.
    pub to: Option<Address>,
    /// The amount of Ether to send with the transaction.
    #[serde(with = "serialization::u256")]
    pub value: U256,
    /// The calldata to use for the transaction.
    #[serde(with = "serialization::bytes")]
    pub data: Vec<u8>,
    /// List of addresses and storage keys that the transaction plans to access.
    #[serde(default)]
    #[serde(rename = "accessList")]
    pub access_list: AccessList,
}

impl Eip1559Transaction {
    /// Returns the RLP encoded transaction with an optional signature.
    pub fn rlp_encode(&self, signature: Option<Signature>) -> Vec<u8> {
        let fields = [
            rlp::uint(self.chain_id),
            rlp::uint(self.nonce),
            rlp::uint(self.max_priority_fee_per_gas),
            rlp::uint(self.max_fee_per_gas),
            rlp::uint(self.gas),
            self.to
                .map_or_else(|| rlp::bytes(b""), |to| rlp::bytes(&*to)),
            rlp::uint(self.value),
            rlp::bytes(&self.data),
            self.access_list.rlp_encode(),
        ];

        let tail = signature.map(|signature| {
            [
                rlp::uint(signature.y_parity.as_u256()),
                rlp::uint(U256::from_be_bytes(signature.r)),
                rlp::uint(U256::from_be_bytes(signature.s)),
            ]
        });

        [
            &[0x02][..],
            &rlp::iter(fields.iter().chain(tail.iter().flatten())),
        ]
        .concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::accesslist::StorageSlot;
    use hex_literal::hex;
    use serde_json::json;

    #[test]
    fn deserialize_json() {
        let mut tx = json!({
            "chainId": "0xff",
            "nonce": 42,
            "maxPriorityFeePerGas": 13.37e9,
            "maxFeePerGas": 42e9,
            "gas": 21000,
            "value": "13370000000000000000",
            "data": "0x",
        });
        assert_eq!(
            serde_json::from_value::<Eip1559Transaction>(tx.clone()).unwrap(),
            Eip1559Transaction {
                chain_id: 255.as_u256(),
                nonce: 42.as_u256(),
                max_priority_fee_per_gas: 13.37e9.as_u256(),
                max_fee_per_gas: 42e9.as_u256(),
                gas: 21_000.as_u256(),
                to: None,
                value: 13.37e18.as_u256(),
                data: vec![],
                access_list: AccessList::default(),
            }
        );

        tx["to"] = json!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        tx["accessList"] = json!([[
            "0x0000000000000000000000000000000000000000",
            ["0x0000000000000000000000000000000000000000000000000000000000000000",],
        ]]);
        let deserialized = serde_json::from_value::<Eip1559Transaction>(tx).unwrap();
        assert_eq!(
            deserialized.to.unwrap(),
            Address(hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")),
        );
        assert_eq!(
            deserialized.access_list,
            AccessList(vec![(Address::default(), vec![StorageSlot::default()])]),
        );
    }

    #[test]
    fn encode() {
        assert_eq!(
            Eip1559Transaction {
                chain_id: 1.as_u256(),
                nonce: 66.as_u256(),
                max_priority_fee_per_gas: 28e9.as_u256(),
                max_fee_per_gas: 42e9.as_u256(),
                gas: 30_000.as_u256(),
                to: Some(Address(hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))),
                value: 13.37e18.as_u256(),
                data: vec![],
                access_list: AccessList::default(),
            }
            .rlp_encode(None),
            hex!(
                "02f10142850684ee18008509c765240082753094deadbeefdeadbeefdeadbeefdeadbeefde
                 adbeef88b98bc829a6f9000080c0"
            )
            .to_owned(),
        );
        assert_eq!(
            Eip1559Transaction {
                chain_id: 1.as_u256(),
                nonce: 777.as_u256(),
                max_priority_fee_per_gas: 28e9.as_u256(),
                max_fee_per_gas: 42e9.as_u256(),
                gas: 100_000.as_u256(),
                to: None,
                value: 0.as_u256(),
                data: hex!(
                    "363d3d373d3d3d363d73deadbeefdeadbeefdeadbeefdeadbeefdeadbeef5af43d82803e90
                     3d91602b57fd5bf3"
                )
                .to_vec(),
                access_list: AccessList(vec![
                    (
                        Address(hex!("1111111111111111111111111111111111111111")),
                        vec![
                            StorageSlot(hex!(
                                "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
                            )),
                            StorageSlot(hex!(
                                "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                            )),
                        ],
                    ),
                    (
                        Address(hex!("2222222222222222222222222222222222222222")),
                        vec![],
                    ),
                ]),
            }
            .rlp_encode(None),
            hex!(
                "02f8b801820309850684ee18008509c7652400830186a08080ad363d3d373d3d
                 3d363d73deadbeefdeadbeefdeadbeefdeadbeefdeadbeef5af43d82803e903d
                 91602b57fd5bf3f872f859941111111111111111111111111111111111111111
                 f842a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0
                 a0a0a0a0a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
                 a1a1a1a1d6942222222222222222222222222222222222222222c0"
            )
            .to_vec(),
        );
    }
}
