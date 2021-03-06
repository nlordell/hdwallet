//! Module implementing the `sign` subcommand for generating ECDSA signatures.

use crate::{
    account::Address,
    cmd::{self, AccountOptions},
    hash,
    transaction::Transaction,
};
use anyhow::{anyhow, Context as _, Result};
use ethnum::U256;
use std::{convert::TryInto, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Options {
    #[structopt(subcommand)]
    data: Data,

    #[structopt(flatten)]
    account: AccountOptions,
}

#[derive(Debug, StructOpt)]
enum Data {
    /// Sign an Ethereum transaction.
    Transaction {
        #[structopt(flatten)]
        transaction: TransactionOptions,

        /// The chain ID to sign this transaction for. Use 0 to indicate no
        /// relay protection should be used.
        #[structopt(short, long, env)]
        chain_id: u64,

        /// Only output the transaction signature instead of the RLP-encoded
        /// signed transaction.
        #[structopt(long)]
        signature_only: bool,
    },

    /// Sign an Ethereum message.
    Message {
        /// Path to the message to sign in the "eth_sign" scheme. This message
        /// will be prefixed with "\x19Ethereum Signed Message:\n" and its
        /// length before hashing and singing.
        #[structopt(name = "MESSAGE")]
        message: PathBuf,
    },

    /// Sign a raw data.
    Raw {
        /// The 32 byte message to sign specified as a hexadecimal string.
        #[structopt(name = "BYTES", parse(try_from_str = permissive_hex_digest))]
        message: [u8; 32],
    },
}

#[derive(Debug, StructOpt)]
struct TransactionOptions {
    /// The transaction nonce.
    #[structopt(short, long)]
    nonce: U256,

    /// The value of the transaction. This can be either a decimal GWei
    /// value, or a "0x"-prefixed hexadecimal Wei value.
    #[structopt(short = "p", long, parse(try_from_str = gwei))]
    gas_price: U256,

    /// The gas limit for the transaction. Can use `M` and `K` suffixes for
    /// million and thousand respectively.
    #[structopt(short, long, default_value = "21K", parse(try_from_str = gas))]
    gas: U256,

    /// The transaction recipient. Omit for contract creation transactions.
    #[structopt(short, long)]
    to: Option<Address>,

    /// The value of the transaction. This can be either a decimal Ether
    /// value, or a "0x"-prefixed hexadecimal Wei value.
    #[structopt(short, long, default_value = "0", parse(try_from_str = ether))]
    value: U256,

    /// The transaction input calldata.
    #[structopt(short, long, default_value = "0x", parse(try_from_str = cmd::permissive_hex))]
    data: Box<[u8]>,
}

impl Data {
    fn message(&self) -> Result<[u8; 32]> {
        match self {
            Data::Transaction {
                transaction,
                chain_id,
                ..
            } => Ok(hash::keccak256(
                &transaction.as_parameters().signing_message(*chain_id),
            )),
            Data::Message { message } => {
                let bytes = cmd::read_input(&message)?;

                let mut buffer = Vec::with_capacity(46 + bytes.len());
                buffer.extend_from_slice(b"\x19Ethereum Signed Message:\n");
                buffer.extend_from_slice(bytes.len().to_string().as_bytes());
                buffer.extend_from_slice(&bytes);

                Ok(hash::keccak256(&buffer))
            }
            Data::Raw { message } => Ok(*message),
        }
    }
}

impl TransactionOptions {
    fn as_parameters(&self) -> Transaction {
        Transaction {
            nonce: self.nonce,
            gas_price: self.gas_price,
            gas: self.gas,
            to: self.to,
            value: self.value,
            data: self.data.clone().into(),
        }
    }
}

pub fn run(options: Options) -> Result<()> {
    let message = options.data.message()?;
    let signature = options.account.private_key()?.sign(message);

    match options.data {
        Data::Transaction {
            transaction,
            chain_id,
            signature_only: false,
        } => println!(
            "0x{}",
            hex::encode(
                transaction
                    .as_parameters()
                    .encode(chain_id, Some(signature))
            )
        ),
        _ => println!("{}", signature),
    }
    Ok(())
}

fn permissive_hex_digest(s: &str) -> Result<[u8; 32]> {
    cmd::permissive_hex(s)?[..]
        .try_into()
        .context("message for signing must be exactly 32 bytes long")
}

fn ether(s: &str) -> Result<U256> {
    parse_unit(s, 18)
}

fn gwei(s: &str) -> Result<U256> {
    parse_unit(s, 9)
}

fn parse_unit(s: &str, decimals: u8) -> Result<U256> {
    if let Some(hex) = s.strip_prefix("0x") {
        Ok(U256::from_str_radix(hex, 16)?)
    } else {
        let radix = U256::new(10).pow(decimals as _);
        let (n, frac) = match s.find('.') {
            Some(i) => {
                let (n, frac) = s.split_at(i);
                let frac = {
                    let digits = &frac[1..];
                    let offset = decimals
                        .checked_sub(digits.len().try_into()?)
                        .ok_or_else(|| anyhow!("fractional part too long"))?;
                    digits.parse::<U256>()? * U256::new(10).pow(offset as _)
                };

                (n.parse::<U256>()?, frac)
            }
            None => (s.parse::<U256>()?, U256::ZERO),
        };

        Ok(n.checked_mul(radix)
            .and_then(|n| n.checked_add(frac))
            .ok_or_else(|| anyhow!("Ξ value too high"))?)
    }
}

fn gas(s: &str) -> Result<U256> {
    let (n, radix) = match s.as_bytes().last().map(u8::to_ascii_lowercase) {
        Some(b'm') => (&s[..s.len() - 1], 1_000_000),
        Some(b'k') => (&s[..s.len() - 1], 1_000),
        _ => (s, 1),
    };

    n.parse::<U256>()?
        .checked_mul(U256::new(radix))
        .ok_or_else(|| anyhow!("gas limit too high"))
}
