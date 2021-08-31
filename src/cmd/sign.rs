//! Module implementing the `sign` subcommand for generating ECDSA signatures.

use crate::cmd::{self, AccountOptions};
use anyhow::{ensure, Context as _, Result};
use hdwallet::{
    hash,
    transaction::{LegacyTransaction, Transaction},
    typeddata::TypedData,
};
use std::{convert::TryInto, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Options {
    #[structopt(subcommand)]
    input: Input,

    #[structopt(flatten)]
    account: AccountOptions,
}

#[derive(Debug, StructOpt)]
#[structopt(rename_all = "lowercase")]
enum Input {
    /// Sign an Ethereum transaction.
    Transaction {
        /// Path to transaction to sign in JSON format.
        #[structopt(name = "TRANSACTION")]
        transaction: PathBuf,

        /// Only output the transaction signature instead of the RLP-encoded
        /// signed transaction.
        #[structopt(long)]
        signature_only: bool,

        /// Force allowing legacy transactions without a chain ID for relay
        /// protection. Use this care!
        #[structopt(long)]
        allow_missing_relay_protection: bool,
    },

    /// Sign an Ethereum message.
    Message {
        /// Path to the message to sign in the "eth_sign" scheme. This message
        /// will be prefixed with "\x19Ethereum Signed Message:\n" and its
        /// length before hashing and singing.
        #[structopt(name = "MESSAGE")]
        message: PathBuf,
    },

    /// Sign EIP-712 typed data.
    TypedData {
        /// Path to the EIP-712 typed data in JSON format.
        #[structopt(name = "TYPEDDATA")]
        typed_data: PathBuf,
    },

    /// Sign a raw data.
    Raw {
        /// The 32 byte message to sign specified as a hexadecimal string.
        #[structopt(name = "BYTES", parse(try_from_str = permissive_hex_digest))]
        message: [u8; 32],
    },
}

pub fn run(options: Options) -> Result<()> {
    let account = options.account.private_key()?;
    match options.input {
        Input::Transaction {
            transaction,
            signature_only,
            allow_missing_relay_protection,
        } => {
            let transaction =
                serde_json::from_slice::<Transaction>(&cmd::read_input(&transaction)?)?;
            if let Transaction::Legacy(LegacyTransaction { chain_id: None, .. }) = &transaction {
                ensure!(
                    allow_missing_relay_protection,
                    "Signed legacy transaction without chain ID. \
                     Use `--allow-missing-relay-protection` if this was intentional.",
                );
            }
            let signature = account.sign(transaction.signing_message());
            if signature_only {
                println!("{}", signature);
            } else {
                println!("0x{}", hex::encode(transaction.encode(signature)));
            }
        }
        Input::Message { message } => {
            let bytes = cmd::read_input(&message)?;
            let message = hash::keccak256({
                let mut buffer = Vec::with_capacity(46 + bytes.len());
                buffer.extend_from_slice(b"\x19Ethereum Signed Message:\n");
                buffer.extend_from_slice(bytes.len().to_string().as_bytes());
                buffer.extend_from_slice(&bytes);
                buffer
            });
            println!("{}", account.sign(message));
        }
        Input::TypedData { typed_data } => {
            let bytes = cmd::read_input(&typed_data)?;
            let typed_data = serde_json::from_slice::<TypedData>(&bytes)?;
            println!("{}", account.sign(typed_data.digest()));
        }
        Input::Raw { message } => {
            println!("{}", account.sign(message));
        }
    }
    Ok(())
}

fn permissive_hex_digest(s: &str) -> Result<[u8; 32]> {
    cmd::permissive_hex(s)?[..]
        .try_into()
        .context("message for signing must be exactly 32 bytes long")
}
