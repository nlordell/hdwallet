//! Module implementing the `hash` subcommand for `keccak256` hashing data.

use crate::cmd;
use anyhow::Result;
use clap::Parser;
use hdwallet::{
    account::Signature, hash, message::EthereumMessage, transaction::Transaction,
    typeddata::TypedData,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    input: Input,
}

#[derive(Debug, Parser)]
enum Input {
    /// Hash an Ethereum transaction.
    Transaction {
        /// Path to transaction to hash in JSON format.
        #[clap(name = "TRANSACTION")]
        transaction: PathBuf,

        /// Signature for the transaction.
        #[clap(short, long)]
        signature: Option<Signature>,
    },

    /// Hash an Ethereum message.
    Message {
        /// Path to the message to hash in the "eth_sign" scheme. This message
        /// will be prefixed with "\x19Ethereum Signed Message:\n" and its
        /// length before hashing.
        #[clap(name = "MESSAGE")]
        message: PathBuf,
    },

    /// Hash EIP-712 typed data.
    #[clap(name = "typeddata")]
    TypedData {
        /// Path to the EIP-712 typed data in JSON format.
        #[clap(name = "TYPEDDATA")]
        typed_data: PathBuf,

        /// Only compute the struct hash of the main message without mixing in
        /// the domain separator.
        #[clap(short, long)]
        message_hash: bool,
    },

    /// Hash raw data.
    Data {
        /// Path to the data to hash. Use `-` for standard in.
        #[clap(name = "DATA")]
        data: PathBuf,
    },
}

pub fn run(options: Options) -> Result<()> {
    let hash = match options.input {
        Input::Transaction {
            transaction,
            signature,
        } => {
            let transaction =
                serde_json::from_slice::<Transaction>(&cmd::read_input(&transaction)?)?;
            match signature {
                Some(signature) => hash::keccak256(transaction.encode(signature)),
                None => transaction.signing_message(),
            }
        }
        Input::Message { message } => {
            let message = EthereumMessage(cmd::read_input(&message)?);
            message.signing_message()
        }
        Input::TypedData {
            typed_data,
            message_hash,
        } => {
            let typed_data = serde_json::from_slice::<TypedData>(&cmd::read_input(&typed_data)?)?;
            if message_hash {
                typed_data.message_hash()
            } else {
                typed_data.signing_message()
            }
        }
        Input::Data { data } => {
            let data = cmd::read_input(&data)?;
            hash::keccak256(data)
        }
    };
    println!("0x{}", hex::encode(hash));

    Ok(())
}
