//! Module with EIP-2930 access list type definition with RLP encoding and JSON
//! serialization implementation.

use crate::{account::Address, serialization, transaction::rlp};
use serde::Deserialize;

/// An Ethereum virtual machine storage slot.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialOrd, PartialEq)]
#[serde(transparent)]
pub struct StorageSlot(#[serde(with = "serialization::bytearray")] pub [u8; 32]);

impl StorageSlot {
    /// RLP encodes a storage slot.
    pub fn rlp_encode(&self) -> Vec<u8> {
        rlp::bytes(&self.0)
    }
}

/// An EIP-2930 access list.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct AccessList(pub Vec<(Address, Vec<StorageSlot>)>);

impl AccessList {
    /// RLP encodes a storage slot.
    pub fn rlp_encode(&self) -> Vec<u8> {
        rlp::iter(self.0.iter().map(|(address, slots)| {
            rlp::list(&[
                &rlp::bytes(&**address),
                &rlp::iter(slots.iter().map(StorageSlot::rlp_encode)),
            ])
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use serde_json::json;

    #[test]
    fn deserialize_json() {
        assert_eq!(
            serde_json::from_value::<AccessList>(json!([
                [
                    "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
                    [
                        "0x0000000000000000000000000000000000000000000000000000000000000003",
                        "0x0000000000000000000000000000000000000000000000000000000000000007",
                    ]
                ],
                ["0xbb9bc244d798123fde783fcc1c72d3bb8c189413", [],],
            ]))
            .unwrap(),
            AccessList(vec![
                (
                    Address(hex!("de0b295669a9fd93d5f28d9ec85e40f4cb697bae")),
                    vec![
                        StorageSlot(hex!(
                            "0000000000000000000000000000000000000000000000000000000000000003"
                        )),
                        StorageSlot(hex!(
                            "0000000000000000000000000000000000000000000000000000000000000007"
                        ))
                    ]
                ),
                (
                    Address(hex!("bb9bc244d798123fde783fcc1c72d3bb8c189413")),
                    vec![]
                )
            ]),
        )
    }

    #[test]
    fn rlp_encode() {
        assert_eq!(
            AccessList(vec![
                (
                    Address(hex!("de0b295669a9fd93d5f28d9ec85e40f4cb697bae")),
                    vec![
                        StorageSlot(hex!(
                            "0000000000000000000000000000000000000000000000000000000000000003"
                        )),
                        StorageSlot(hex!(
                            "0000000000000000000000000000000000000000000000000000000000000007"
                        ))
                    ]
                ),
                (
                    Address(hex!("bb9bc244d798123fde783fcc1c72d3bb8c189413")),
                    vec![]
                )
            ])
            .rlp_encode(),
            hex!(
                "f872f85994de0b295669a9fd93d5f28d9ec85e40f4cb697baef842a000000000
                 00000000000000000000000000000000000000000000000000000003a0000000
                 0000000000000000000000000000000000000000000000000000000007d694bb
                 9bc244d798123fde783fcc1c72d3bb8c189413c0"
            ),
        );
    }
}
