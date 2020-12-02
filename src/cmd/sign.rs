//! Module implementing the `sign` subcommand for generating ECDSA signatures.

use crate::{cmd::AccountOptions, hash};
use anyhow::{Context as _, Result};
use std::convert::TryInto;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "Sign a message")]
pub struct Options {
    #[structopt(flatten)]
    account: AccountOptions,

    /// The message should be Keccak-256 hashed for signing.
    #[structopt(short, long)]
    hash_message: bool,

    /// The 32 byte message or binary data to sign specified as a hexadecimal
    /// string. If "hash-data" is not specified, then the specified value must
    /// be exactly 32 bytes long.
    #[structopt(name = "MESSAGE", parse(try_from_str = permissive_hex))]
    message: Box<[u8]>,
}

pub fn run(options: Options) -> Result<()> {
    let message = if options.hash_message {
        hash::keccak256(&options.message)
    } else {
        options
            .message
            .as_ref()
            .try_into()
            .context("message for signing must be exactly 32 bytes long or hashed")?
    };
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
