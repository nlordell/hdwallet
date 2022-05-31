//! Legacy Ethereum transaction type definition and RLP encoding.

use crate::{account::Signature, serialization, transaction::rlp};
use ethaddr::Address;
use ethnum::U256;
use serde::Deserialize;

/// A Legacy Ethereum transaction.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct LegacyTransaction {
    /// The nonce for the transaction.
    #[serde(with = "ethnum::serde::permissive")]
    pub nonce: U256,
    /// The gas price in Wei for the transaction.
    #[serde(rename = "gasPrice", with = "ethnum::serde::permissive")]
    pub gas_price: U256,
    /// The gas limit for the transaction.
    #[serde(with = "ethnum::serde::permissive")]
    pub gas: U256,
    /// The target address for the transaction. This can also be `None` to
    /// indicate a contract creation transaction.
    pub to: Option<Address>,
    /// The amount of Ether to send with the transaction.
    #[serde(with = "ethnum::serde::permissive")]
    pub value: U256,
    /// The calldata to use for the transaction.
    #[serde(with = "serialization::bytes")]
    pub data: Vec<u8>,
    /// Optional chain ID for the transaction.
    #[serde(default, rename = "chainId", with = "serialization::numopt")]
    pub chain_id: Option<U256>,
}

impl LegacyTransaction {
    /// Returns the RLP encoded transaction with an optional signature.
    pub fn rlp_encode(&self, signature: Option<Signature>) -> Vec<u8> {
        let fields = [
            rlp::uint(self.nonce),
            rlp::uint(self.gas_price),
            rlp::uint(self.gas),
            self.to
                .map_or_else(|| rlp::bytes(b""), |to| rlp::bytes(&*to)),
            rlp::uint(self.value),
            rlp::bytes(&self.data),
        ];

        let tail = signature
            .map(|signature| (signature.v(self.chain_id), signature.r(), signature.s()))
            .or_else(|| Some((self.chain_id?, U256::ZERO, U256::ZERO)))
            .map(|(v, r, s)| [rlp::uint(v), rlp::uint(r), rlp::uint(s)]);

        rlp::iter(fields.iter().chain(tail.iter().flatten()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethaddr::address;
    use ethnum::AsU256 as _;
    use hex_literal::hex;
    use serde_json::json;

    #[test]
    fn deserialize_json() {
        let mut tx = json!({
            "chainId": "0xff",
            "nonce": 42,
            "gasPrice": 13.37e9,
            "gas": 21000,
            "value": "13370000000000000000",
            "data": "0x",
        });
        assert_eq!(
            serde_json::from_value::<LegacyTransaction>(tx.clone()).unwrap(),
            LegacyTransaction {
                chain_id: Some(255.as_u256()),
                nonce: 42.as_u256(),
                gas_price: 13.37e9.as_u256(),
                gas: 21_000.as_u256(),
                to: None,
                value: 13.37e18.as_u256(),
                data: vec![],
            }
        );

        tx["to"] = json!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert_eq!(
            serde_json::from_value::<LegacyTransaction>(tx)
                .unwrap()
                .to
                .unwrap(),
            address!("0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"),
        );
    }

    #[test]
    fn encode() {
        assert_eq!(
            LegacyTransaction {
                chain_id: Some(1.as_u256()),
                nonce: 66.as_u256(),
                gas_price: 42e9.as_u256(),
                gas: 30_000.as_u256(),
                to: Some(address!("0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF")),
                value: 13.37e18.as_u256(),
                data: vec![],
            }
            .rlp_encode(None),
            hex!(
                "ec428509c765240082753094deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
                 88b98bc829a6f9000080018080"
            )
            .to_owned(),
        );
        assert_eq!(
            LegacyTransaction {
                chain_id: Some(1.as_u256()),
                nonce: 777.as_u256(),
                gas_price: 42e9.as_u256(),
                gas: 100_000.as_u256(),
                to: None,
                value: 0.as_u256(),
                data: hex!(
                    "363d3d373d3d3d363d73deadbeefdeadbeefdeadbeefdeadbeefdeadbeef5af43d82803e90
                     3d91602b57fd5bf3"
                )
                .to_vec(),
            }
            .rlp_encode(None),
            hex!(
                "f8408203098509c7652400830186a08080ad363d3d373d3d3d363d73deadbeef
                 deadbeefdeadbeefdeadbeefdeadbeef5af43d82803e903d91602b57fd5bf301
                 8080"
            )
            .to_vec(),
        );
    }
}
