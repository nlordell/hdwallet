//! Module implementing the `address` subcommand for displaying the public
//! address for corresponding account.

use crate::cmd::AccountOptions;
use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(flatten)]
    account: AccountOptions,
}

pub fn run(options: Options) -> Result<()> {
    println!(
        "0x{}",
        hex::encode(
            options
                .account
                .private_key()?
                .public()
                .encode_uncompressed()
                .as_slice()
        )
    );
    Ok(())
}
