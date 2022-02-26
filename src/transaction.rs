//! Module defining Ethereum transaction data as well as an RLP encoding
//! implementation.

pub mod accesslist;
mod eip1559;
mod eip2930;
mod legacy;
mod rlp;

pub use self::{
    eip1559::Eip1559Transaction, eip2930::Eip2930Transaction, legacy::LegacyTransaction,
};
use crate::{account::Signature, hash, serialization::JsonObject};
use serde::{
    de::{self, Deserializer},
    Deserialize,
};

/// An Ethereum transaction.
#[derive(Clone, Debug)]
pub enum Transaction {
    Legacy(LegacyTransaction),
    Eip2930(Eip2930Transaction),
    Eip1559(Eip1559Transaction),
}

impl Transaction {
    /// Returns the RLP encoded transaction with an optional signature.
    pub fn signing_message(&self) -> [u8; 32] {
        hash::keccak256(self.rlp_encode(None))
    }

    /// Returns the 32-byte message used for signing.
    pub fn encode(&self, signature: Signature) -> Vec<u8> {
        self.rlp_encode(Some(signature))
    }

    /// Returns the RLP encoded transaction with an optional signature.
    fn rlp_encode(&self, signature: Option<Signature>) -> Vec<u8> {
        match self {
            Transaction::Legacy(tx) => tx.rlp_encode(signature),
            Transaction::Eip2930(tx) => tx.rlp_encode(signature),
            Transaction::Eip1559(tx) => tx.rlp_encode(signature),
        }
    }
}

impl<'de> Deserialize<'de> for Transaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let json = JsonObject::deserialize(deserializer)?;
        if json.contains_key("maxPriorityFeePerGas") || json.contains_key("maxFeePerGas") {
            Ok(Transaction::Eip1559(
                serde_json::from_value(json.into()).map_err(de::Error::custom)?,
            ))
        } else if json.contains_key("accessList") {
            Ok(Transaction::Eip2930(
                serde_json::from_value(json.into()).map_err(de::Error::custom)?,
            ))
        } else {
            Ok(Transaction::Legacy(
                serde_json::from_value(json.into()).map_err(de::Error::custom)?,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account::PrivateKey, ganache::DETERMINISTIC_PRIVATE_KEY};
    use hex_literal::hex;
    use serde_json::{json, Value};

    fn sign_encode(tx: Value) -> Vec<u8> {
        let tx = serde_json::from_value::<Transaction>(tx).unwrap();
        let key = PrivateKey::new(DETERMINISTIC_PRIVATE_KEY).unwrap();
        let signature = key.sign(tx.signing_message());
        tx.encode(signature)
    }

    #[test]
    fn encode_signed_transaction() {
        assert_eq!(
            sign_encode(json!({
                "nonce": 0,
                "gasPrice": 0,
                "gas": 21000,
                "to": "0x0000000000000000000000000000000000000000",
                "value": 0,
                "data": "0x",
            })),
            hex!(
                "f85f808082520894000000000000000000000000000000000000000080801ca0
                 0f1c0e95b7050ac3df5ac3b69a7d41e0b815da462fcd30954b1c37b58ca71c16
                 a068dab467ad79359967a3df1bcfc17292a3839288d05274d0e3e391f8b50841
                 0b"
            ),
        );
        assert_eq!(
            sign_encode(json!({
                "chainId": 1,
                "nonce": 0,
                "gasPrice": 0,
                "gas": 21000,
                "to": "0x0000000000000000000000000000000000000000",
                "value": 0,
                "data": "0x",
            })),
            hex!(
                "f85f8080825208940000000000000000000000000000000000000000808025a0
                 c97442e361bf3940bec722b240c699de22302469756436bbcc5a150a93309b08
                 a02fd3e68ed327dea3d085ec16a8589ebf7871e5a990669f67be82a70cd9dfb4
                 f7"
            ),
        );
        assert_eq!(
            sign_encode(json!({
                "chainId": 1,
                "nonce": 0,
                "gasPrice": 0,
                "gas": 21000,
                "to": "0x0000000000000000000000000000000000000000",
                "value": 0,
                "data": "0x",
                "accessList": [],
            })),
            hex!(
                "01f8610180808252089400000000000000000000000000000000000000008080
                 c080a04366d11301b0a233d0f311f93083583ed316c2ebd7246ccd93f1a320b2
                 57fd65a02e3df28ccda84b829403a04f2d142416f01bdf7036dba12b66e4add6
                 4d59455e"
            ),
        );
        assert_eq!(
            sign_encode(json!({
                "chainId": 1,
                "nonce": 0,
                "maxPriorityFeePerGas": 0,
                "maxFeePerGas": 0,
                "gas": 21000,
                "to": "0x0000000000000000000000000000000000000000",
                "value": 0,
                "data": "0x",
            })),
            hex!(
                "02f8620180808082520894000000000000000000000000000000000000000080
                 80c001a0290dbdecbc884b4cb827015fe0cd7ac90df1a5634d52a2845c21afac
                 ca14b803a03e848dd1a342e5528beff99c42876cf091a68e2090dbbced5a5f7f
                 392d3abcda"
            ),
        );
    }
}
