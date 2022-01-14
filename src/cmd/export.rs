//! Module implementing the `export` subcommand for displaying an account's
//! private key.

use crate::cmd::AccountOptions;
use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(flatten)]
    account: AccountOptions,
}

pub fn run(options: Options) -> Result<()> {
    let key = options.account.private_key()?;
    println!("0x{}", hex::encode(key.secret()));
    Ok(())
}
