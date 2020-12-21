//! Module implementing the `sign` subcommand for generating ECDSA signatures.

use crate::{account::Address, cmd::AccountOptions, hash};
use anyhow::{anyhow, Context as _, Result};
use ethnum::U256;
use std::convert::TryInto;
use structopt::{clap::arg_enum, StructOpt};

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
        /// The transaction nonce.
        #[structopt(short, long)]
        nonce: u64,

        /// The value of the transaction. This can be either a decimal GWei
        /// value, or a hexadecimal Wei value.
        #[structopt(short = "p", long, parse(try_from_str = gwei))]
        gas_price: U256,

        /// The gas limit for the transaction. Can use `M` and `K` suffixes for
        /// million and thousand respectively.
        #[structopt(short, long, default_value = "21K", parse(try_from_str = gas))]
        gas: u64,

        /// The transaction recipient. Omit for contract creation transactions.
        #[structopt(short, long)]
        to: Option<Address>,

        /// The value of the transaction. This can be either a decimal Ether
        /// value, or a "0x"-prefixed hexadecimal Wei value.
        #[structopt(short, long, default_value = "0", parse(try_from_str = ether))]
        value: U256,

        /// The transaction input calldata.
        #[structopt(short, long, default_value = "0x", parse(try_from_str = permissive_hex))]
        data: Box<[u8]>,
    },

    /// Sign an Ethereum message.
    Message {
        /// The message format. Specify "hex" if the message is a hexadecimal
        /// encoded string.
        #[structopt(
            short,
            long,
            default_value = "string",
            case_insensitive = true,
            possible_values = &Format::variants(),
        )]
        format: Format,

        /// The message to sign in the "eth_sign" scheme. This message will be
        /// prefixed with "\x19Ethereum Signed Message:\n" and its length before
        /// hashing and singing.
        #[structopt(name = "MESSAGE")]
        message: String,
    },

    /// Sign a raw data.
    Raw {
        /// The message should be Keccak-256 hashed for signing.
        #[structopt(short, long)]
        hash: bool,

        /// The 32 byte message or binary data to sign specified as a
        /// hexadecimal string. If "hash" is not specified, then the specified
        /// value must be exactly 32 bytes long.
        #[structopt(name = "BYTES", parse(try_from_str = permissive_hex))]
        bytes: Box<[u8]>,
    },
}

arg_enum! {
    #[derive(Debug)]
    enum Format {
        String,
        Hex,
    }
}

impl Data {
    fn message(self) -> Result<[u8; 32]> {
        match self {
            Data::Transaction { .. } => {
                todo!("rlp encode transaction")
            }
            Data::Message { format, message } => {
                let bytes = match format {
                    Format::String => message.into_bytes().into_boxed_slice(),
                    Format::Hex => permissive_hex(&message)?,
                };

                let mut buffer = Vec::new();
                buffer.extend_from_slice(b"\x19Ethereum Signed Message:\n");
                buffer.extend_from_slice(bytes.len().to_string().as_bytes());
                buffer.extend_from_slice(&bytes);

                Ok(hash::keccak256(&buffer))
            }
            Data::Raw { hash, bytes } => {
                if hash {
                    Ok(hash::keccak256(&bytes))
                } else {
                    bytes
                        .as_ref()
                        .try_into()
                        .context("data for signing must be exactly 32 bytes long or hashed")
                }
            }
        }
    }
}

pub fn run(options: Options) -> Result<()> {
    let message = options.data.message()?;
    let signature = options.account.private_key()?.sign(message);
    println!("{}", signature);
    Ok(())
}

fn permissive_hex(s: &str) -> Result<Box<[u8]>> {
    let trimmed = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    let hex_string = trimmed.strip_prefix("0x").unwrap_or(&trimmed);
    let bytes = hex::decode(&hex_string)?;
    // NOTE: Use a boxed slice instead of a `Vec` as the former has special
    // scemantics with `structopt`.
    Ok(bytes.into_boxed_slice())
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

fn gas(s: &str) -> Result<u64> {
    let (n, radix) = match s.as_bytes().last().map(u8::to_ascii_lowercase) {
        Some(b'm') => (&s[..s.len() - 1], 1_000_000),
        Some(b'k') => (&s[..s.len() - 1], 1_000),
        _ => (s, 1),
    };

    n.parse::<u64>()?
        .checked_mul(radix)
        .ok_or_else(|| anyhow!("gas limit too high"))
}
