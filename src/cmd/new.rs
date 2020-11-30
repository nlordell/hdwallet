//! Module implementing the `new` subcommand for generating a mnemonic for a new
//! hierarchical deterministic wallet.

use crate::mnemonic::{Language, Mnemonic};
use anyhow::Result;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "generate a new HD wallet mnemonic")]
pub struct Options {
    /// The number of words for the mnemonic phrase.
    #[structopt(short = "n", long, default_value = "12")]
    length: usize,

    /// The language to generate the mnemonic for.
    #[structopt(short, long, default_value)]
    language: Language,
}

pub fn run(options: Options) -> Result<()> {
    let mnemonic = Mnemonic::random(options.language, options.length)?;
    println!("{}", mnemonic);
    Ok(())
}
