//! Module implementing the `new` subcommand for generating a mnemonic for a new
//! hierarchical deterministic wallet.

use anyhow::Result;
use clap::Parser;
use hdwallet::mnemonic::{Language, Mnemonic};

#[derive(Debug, Parser)]
pub struct Options {
    /// The number of words for the mnemonic phrase.
    #[clap(short = 'n', long, default_value_t = 12)]
    length: usize,

    /// The language to generate the mnemonic for.
    #[clap(short, long, default_value_t)]
    language: Language,
}

pub fn run(options: Options) -> Result<()> {
    let mnemonic = Mnemonic::random(options.language, options.length)?;
    println!("{}", mnemonic);
    Ok(())
}
