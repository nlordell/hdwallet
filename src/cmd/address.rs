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
    println!("{}", options.account.private_key()?.address());
    Ok(())
}
