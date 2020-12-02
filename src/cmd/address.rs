//! Module implementing the `address` subcommand for displaying the public
//! address for corresponding account.

use crate::cmd::AccountOptions;
use anyhow::Result;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Options {
    #[structopt(flatten)]
    account: AccountOptions,
}

pub fn run(options: Options) -> Result<()> {
    println!("{}", options.account.private_key()?.address());
    Ok(())
}
